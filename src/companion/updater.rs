//! Host side of the Companion Protocol: session handshake, device info, and
//! the firmware update sequence (status, start, write, finish).

use crate::companion::firmware::Image;
use crate::companion::frame::{self, Frame, Reassembler, Sequence, SessionAccept};
use crate::companion::protocol::{self, DeviceInfo, StartReply, Status, UpdateStatus, WriteReply};
use std::time::{Duration, Instant};

/// A packet transport to one Pendragon device's companion HID collection.
/// `send`/`recv` carry one HID report's payload, i.e. everything after the
/// `0x0c` report ID.
pub trait Link {
    fn send(&mut self, payload: &[u8]) -> Result<(), String>;
    /// Next device report, or `None` after `timeout`.
    fn recv(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String>;
    /// Frame payload bytes one report can carry (its length minus the data
    /// frame header). Depends on the report size, which is not known to be
    /// the same on every Pendragon device.
    fn max_fragment_data(&self) -> usize;
}

#[derive(Debug, Clone)]
pub struct Options {
    pub session_timeout: Duration,
    pub response_timeout: Duration,
    /// SDK timeout for the start and finish commands.
    pub mutation_timeout: Duration,
    pub write_timeout: Duration,
    pub ack_timeout: Duration,
    pub attempts: u32,
    /// Matches `UpdateDeviceFirmwareAsync(foreground: true)`, which is the
    /// only path proven to work without `XboxAccessoriesService` running.
    pub foreground: bool,
    /// Overrides the finish command's flags byte. The SDK sends 3 instead of
    /// the foreground bit when its feed check marks the update as required
    /// (0x180043e50, fed from 0x180019fa0); what bit 1 does on the device is
    /// not known, so this is a knob (`XBOXCTL_NANO_FINISH_FLAGS`), not a rule.
    pub finish_flags: Option<u8>,
    /// Ack the device's own unsolicited `1d` frames (sent as `05 <handle+1>
    /// 1d <seq> 00`, repeated with a constant sequence for the whole session).
    /// A physical Nano stopped answering after about 1,430 unacked repeats
    /// (about three minutes); whether an ack keeps it alive is untested, so
    /// this is off unless `XBOXCTL_NANO_ACK_1D=1`.
    pub ack_device_1d: bool,
}

/// The device's own unsolicited message opcode seen during a Nano session.
const OP_DEVICE_1D: u8 = 0x1d;

impl Default for Options {
    fn default() -> Self {
        Self {
            session_timeout: Duration::from_secs(5),
            response_timeout: Duration::from_secs(4),
            mutation_timeout: Duration::from_secs(20),
            write_timeout: Duration::from_secs(100),
            ack_timeout: Duration::from_millis(500),
            attempts: 5,
            foreground: true,
            finish_flags: std::env::var("XBOXCTL_NANO_FINISH_FLAGS")
                .ok()
                .and_then(|value| value.parse().ok()),
            ack_device_1d: std::env::var("XBOXCTL_NANO_ACK_1D").is_ok_and(|value| value == "1"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    UpToDate,
    Begin { resume_offset: u32, total: u32 },
    Progress { done: u32, total: u32 },
    Finished,
}

pub struct Session<'a, L: Link> {
    link: &'a mut L,
    options: Options,
    handle: u8,
    /// Smallest of what the host offered and what the device accepted.
    max_message: u16,
    version: [u8; 3],
    seq: Sequence,
    /// Sequence of the first frame of the last reply accepted from the device.
    last_rx: Option<u8>,
}

impl<'a, L: Link> Session<'a, L> {
    /// Open a session: send the control packet and wait for the device's
    /// accept. `session_id` should be unpredictable so a stale reply from a
    /// previous session cannot be mistaken for this one.
    pub fn open(link: &'a mut L, session_id: u32, options: Options) -> Result<Self, String> {
        let deadline = Instant::now() + options.session_timeout;
        let attempts = options.attempts.max(1);
        let interval = options.session_timeout / attempts;
        for _ in 0..attempts {
            if Instant::now() >= deadline { break; }
            link.send(&frame::open_session(session_id))?;
            let reply_deadline = (Instant::now() + interval).min(deadline);
            loop {
                let remaining = reply_deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() { break; }
                let Some(bytes) = link.recv(remaining)? else { break; };
                if let Some(accept) = SessionAccept::parse(&bytes, session_id, 0) {
                    return Ok(Self {
                        link,
                        max_message: accept.max_message.min(frame::SESSION_MAX_MESSAGE),
                        handle: accept.handle,
                        version: accept.version,
                        seq: Sequence::default(),
                        last_rx: None,
                        options,
                    });
                }
            }
        }
        Err(format!("device did not accept a session after {attempts} attempts"))
    }

    /// The finish flags override in effect, if any.
    pub fn finish_flags(&self) -> Option<u8> {
        self.options.finish_flags
    }

    /// Set the finish command's flags byte for this session.
    pub fn set_finish_flags(&mut self, flags: u8) {
        self.options.finish_flags = Some(flags);
    }

    /// Next device report. With `ack_device_1d`, also acks the device's own
    /// unsolicited `1d` frames on handle + 1 before handing the report on.
    fn recv(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        let bytes = self.link.recv(timeout)?;
        if self.options.ack_device_1d {
            if let Some(frame) = bytes.as_deref().and_then(Frame::parse) {
                if frame.kind == frame::TYPE_SINGLE
                    && frame.handle == self.handle.wrapping_add(1)
                    && frame.opcode == OP_DEVICE_1D
                {
                    self.link.send(&frame::ack(frame.handle, frame.opcode, frame.seq))?;
                }
            }
        }
        Ok(bytes)
    }

    /// Send one message as one or more data frames, waiting for the device's
    /// ack after every fragment (stop-and-wait, as the protocol requires). A
    /// message that fits one report needs no ack.
    fn send_message(&mut self, opcode: u8, payload: &[u8]) -> Result<(), String> {
        let max_data = self.link.max_fragment_data();
        if max_data == 0 {
            return Err("report too small for the companion protocol".to_owned());
        }
        for report in frame::fragments(self.handle, opcode, &mut self.seq, payload, max_data) {
            let sent = Frame::parse(&report).expect("fragments() produces valid frames");
            if !sent.is_fragment() {
                self.link.send(&report)?;
                continue;
            }
            // A physical Nano was seen to leave a fragment unacked mid-write
            // while still sending other traffic. Resend the same fragment,
            // same sequence, as the device does with its own unacked frames.
            let sends = self.options.attempts.max(1);
            let mut acked = false;
            for _ in 0..sends {
                self.link.send(&report)?;
                let deadline = Instant::now() + self.options.ack_timeout;
                while !acked {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    let Some(bytes) = self.recv(remaining)? else {
                        break;
                    };
                    let Some(ack) = Frame::parse(&bytes) else {
                        continue;
                    };
                    acked = ack.kind == frame::TYPE_ACK
                        && ack.handle == self.handle
                        && ack.opcode == opcode
                        && ack.seq == sent.seq.wrapping_add(1);
                }
                if acked {
                    break;
                }
            }
            if !acked {
                return Err(format!(
                    "no ack for message fragment {:#04x} after {sends} sends",
                    sent.seq
                ));
            }
        }
        Ok(())
    }

    /// Send a request and return the reassembled reply, acking any fragments
    /// of it as they arrive. Retries the whole exchange on timeout.
    fn request(
        &mut self,
        opcode: u8,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        self.request_with_attempts(opcode, payload, timeout, self.options.attempts)
    }

    /// Mutating commands use one application-level attempt. A timeout does
    /// not establish whether a device applied a command, so resubmitting it
    /// could leave a fresh late reply available for the following command.
    fn request_with_attempts(
        &mut self,
        opcode: u8,
        payload: &[u8],
        timeout: Duration,
        attempts: u32,
    ) -> Result<Vec<u8>, String> {
        for _ in 0..attempts {
            self.send_message(opcode, payload)?;
            let deadline = Instant::now() + timeout;
            let mut reassembler = Reassembler::default();
            // Sequence the next fragment of the reply being reassembled must carry.
            let mut expected = None;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() { break; }
                let Some(bytes) = self.recv(remaining)? else {
                    break;
                };
                let Some(frame) = Frame::parse(&bytes) else {
                    continue;
                };
                if frame.kind == frame::TYPE_ACK || frame.handle != self.handle {
                    continue;
                }
                // Physical Nanos retry even TYPE_SINGLE replies until acked.
                // Also acknowledge delayed replies to our previous request.
                if frame.is_fragment() || frame.kind == frame::TYPE_SINGLE {
                    self.link
                        .send(&frame::ack(self.handle, frame.opcode, frame.seq))?;
                }
                if frame.opcode != opcode { continue; }
                // A physical Nano resends a reply with its original sequence
                // until it sees the ack. Update replies carry no offset, so a
                // resent "write ok" must never answer the next request.
                // Start/write/finish never retry the whole command on a
                // timeout; a late reply must not be mistaken for a retry's.
                //
                // Seen on hardware: a reply's first frame carries the sequence
                // of the request's last frame plus five, and its fragments
                // count up from there, so replies to consecutive one-frame
                // requests overlap (06 07, then 07 08). Only a message's first
                // frame can be judged stale; later fragments must simply
                // continue the current message.
                if matches!(frame.kind, frame::TYPE_SINGLE | frame::TYPE_FIRST) {
                    if self.last_rx.is_some_and(|last| frame.seq.wrapping_sub(last).wrapping_sub(1) >= 0x80) {
                        continue;
                    }
                    self.last_rx = Some(frame.seq);
                } else if expected != Some(frame.seq) {
                    continue;
                }
                expected = Some(frame.seq.wrapping_add(1));
                if let Some(message) = reassembler.push(&frame) {
                    return Ok(message);
                }
            }
        }
        Err(format!(
            "no response to opcode {opcode:#04x} after {} attempts",
            attempts
        ))
    }

    pub fn device_info(&mut self) -> Result<DeviceInfo, String> {
        let opcode = protocol::device_info_opcode(self.version);
        let response = self.request(
            opcode,
            &protocol::device_info_request(),
            self.options.response_timeout,
        )?;
        let mut info = if opcode == protocol::OP_DEVICE_INFO_LEGACY {
            DeviceInfo::parse_legacy(&response)
        } else {
            DeviceInfo::parse(&response)
        }.ok_or_else(|| "malformed device information reply".to_owned())?;
        if opcode == protocol::OP_DEVICE_INFO_LEGACY && info.is_updatable() {
            let status = self.update_status()?;
            if !matches!(status.status, Status::Ok | Status::NotUpdating) {
                return Err(format!("firmware status failed: {:?}", status.status));
            }
            info.firmware_version = status.running_version;
        }
        Ok(info)
    }

    fn update_status(&mut self) -> Result<UpdateStatus, String> {
        let timeout = self.options.response_timeout;
        let response = self.request(protocol::OP_UPDATE, &protocol::status_request(), timeout)?;
        UpdateStatus::parse(&response).ok_or_else(|| "malformed update status reply".to_owned())
    }

    fn start_update(&mut self, status: &UpdateStatus, image: &Image) -> Result<StartReply, String> {
        let timeout = self.options.mutation_timeout;
        let request = protocol::start_request(
            status.token,
            image.version,
            self.options.foreground,
            status.mode,
        );
        let response = self.request_with_attempts(protocol::OP_UPDATE, &request, timeout, 1)?;
        StartReply::parse(&response).ok_or_else(|| "malformed update start reply".to_owned())
    }

    fn write_block(&mut self, slot: u8, offset: u32, data: &[u8]) -> Result<WriteReply, String> {
        let timeout = self.options.write_timeout;
        let request = protocol::write_request(slot, offset, data);
        let response = self.request_with_attempts(protocol::OP_UPDATE, &request, timeout, 1)?;
        WriteReply::parse_for_version(&response, self.version)
            .ok_or_else(|| "malformed write reply".to_owned())
    }

    fn finish_update(&mut self, slot: u8) -> Result<Status, String> {
        let timeout = self.options.mutation_timeout;
        let mut request = protocol::finish_request(slot, self.options.foreground);
        if let Some(flags) = self.options.finish_flags {
            request[2] = flags;
        }
        let response = self.request_with_attempts(protocol::OP_UPDATE, &request, timeout, 1)?;
        protocol::finish_status(&response).ok_or_else(|| "malformed finish reply".to_owned())
    }

    /// Run the firmware update sequence: status, start, write the image from
    /// the device's resume offset, finish. The device is expected to restart
    /// into the new firmware by itself a second or two after finishing; this
    /// does not wait for that.
    pub fn update(&mut self, image: &Image, events: &mut dyn FnMut(&Event)) -> Result<(), String> {
        if image.data.len() > 0x00ff_ffff {
            return Err("firmware image exceeds the 24-bit transfer limit; not starting".to_owned());
        }
        if self.max_message <= 5 {
            return Err("negotiated message size cannot hold a write payload; not starting".to_owned());
        }
        let status = self.update_status()?;
        if !matches!(status.status, Status::Ok | Status::NotUpdating) {
            return Err(format!("device reported update status {:?}", status.status));
        }
        if status.running_version == image.version {
            events(&Event::UpToDate);
            return Ok(());
        }
        if status.mode == 5 {
            return Err(
                "device is waiting for update consent (mode 5); this is not implemented".to_owned(),
            );
        }
        if status.max_chunk == 0 {
            return Err("device reports zero maximum write size; not starting".to_owned());
        }

        let start = self.start_update(&status, image)?;
        if start.status != Status::Ok {
            return Err(format!("update start failed: {:?}", start.status));
        }
        let total = image.data.len() as u32;
        if start.resume_offset > total {
            return Err(format!(
                "resume offset {} exceeds image size {total}; not writing or finishing",
                start.resume_offset
            ));
        }
        events(&Event::Begin {
            resume_offset: start.resume_offset,
            total,
        });

        let chunk = (usize::from(self.max_message) - 5)
            .min(usize::from(status.max_chunk));
        let mut offset = start.resume_offset as usize;
        while offset < image.data.len() {
            let end = (offset + chunk).min(image.data.len());
            let reply = self.write_block(start.slot, offset as u32, &image.data[offset..end])?;
            if reply.status != Status::Ok {
                return Err(format!("write at {offset:#x} failed: {:?}", reply.status));
            }
            // Flag bit 0: a physical Nano (protocol 2.0.13) sets it on its
            // first write reply. The SDK only records it and keeps writing
            // (0x180044d70), so do the same.
            offset = end;
            events(&Event::Progress {
                done: offset as u32,
                total,
            });
        }

        // Fail before `finish` if the device's own count disagrees: the old
        // firmware keeps running and the transfer can be resumed.
        let final_status = self.update_status()?;
        if final_status.status != Status::Ok {
            return Err(format!("device reported final update status {:?}; not finishing", final_status.status));
        }
        let written = final_status.bytes_written.ok_or_else(||
            "device did not report bytes written; not finishing".to_owned()
        )?;
        if written != total {
            return Err(format!(
                "device reports {written} of {total} bytes written; not finishing"
            ));
        }

        let status = self.finish_update(start.slot)?;
        if status != Status::Ok {
            return Err(format!("finish failed: {status:?}"));
        }
        events(&Event::Finished);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::companion::device::{CompanionEndpoint, FakeNano};
    use std::collections::VecDeque;

    struct MockLink {
        endpoint: CompanionEndpoint,
        queue: VecDeque<Vec<u8>>,
        protocol_version: [u8; 3],
        sent: Vec<Vec<u8>>,
        drop_session_replies: u32,
        /// Queue every device data frame twice, as an unacked Nano does.
        resend_replies: bool,
        resume_override: Option<u32>,
        status_requests: u32,
        final_status_failure: bool,
        final_status_short: bool,
        drop_subcommand_reply: Option<u8>,
        /// Swallow this many fragment frames before the device sees them.
        lose_fragments: u32,
    }

    impl MockLink {
        fn new(firmware_version: [u16; 4]) -> Self {
            Self {
                endpoint: CompanionEndpoint::new(FakeNano::tala(firmware_version)),
                queue: VecDeque::new(),
                protocol_version: [2, 0, 22],
                sent: Vec::new(),
                drop_session_replies: 0,
                resend_replies: false,
                resume_override: None,
                status_requests: 0,
                final_status_failure: false,
                final_status_short: false,
                drop_subcommand_reply: None,
                lose_fragments: 0,
            }
        }
    }

    impl Link for MockLink {
        fn send(&mut self, payload: &[u8]) -> Result<(), String> {
            self.sent.push(payload.to_vec());
            if self.lose_fragments > 0 && Frame::parse(payload).is_some_and(|f| f.is_fragment()) {
                self.lose_fragments -= 1;
                return Ok(());
            }
            let mut replies = self.endpoint.handle_report(payload);
            if let Some(request) = Frame::parse(payload) {
                if request.opcode == protocol::OP_UPDATE && request.kind == frame::TYPE_SINGLE {
                    if request.payload.first() == self.drop_subcommand_reply.as_ref() {
                        replies.clear();
                    }
                    if request.payload.first() == Some(&protocol::SUB_STATUS) {
                        self.status_requests += 1;
                        if self.status_requests == 2 {
                            if let Some(reply) = replies.iter_mut().find(|r| r[0] != frame::TYPE_ACK) {
                                if self.final_status_failure { reply[6] = 6; }
                                if self.final_status_short {
                                    reply[0] = frame::TYPE_SINGLE;
                                    reply[4] = 34;
                                    reply.truncate(5 + 34);
                                }
                            }
                        }
                    } else if request.payload.first() == Some(&protocol::SUB_START) {
                        if let Some(offset) = self.resume_override {
                            if let Some(reply) = replies.iter_mut().find(|r| r[0] != frame::TYPE_ACK) {
                                reply[7..11].copy_from_slice(&offset.to_le_bytes());
                            }
                        }
                    }
                }
            }
            if payload.first() == Some(&0xff) {
                if self.drop_session_replies > 0 {
                    self.drop_session_replies -= 1;
                    return Ok(());
                }
                for reply in &mut replies {
                    reply[6..9].copy_from_slice(&self.protocol_version);
                }
            }
            for reply in replies {
                if self.resend_replies && !matches!(reply[0], 0xff | frame::TYPE_ACK) {
                    self.queue.push_back(reply.clone());
                }
                self.queue.push_back(reply);
            }
            Ok(())
        }

        fn recv(&mut self, _timeout: Duration) -> Result<Option<Vec<u8>>, String> {
            Ok(self.queue.pop_front())
        }

        fn max_fragment_data(&self) -> usize {
            57
        }
    }

    fn open(link: &mut MockLink) -> Session<'_, MockLink> {
        Session::open(link, 0x1234_5678, Options::default()).unwrap()
    }

    #[test]
    fn reads_fragmented_device_info() {
        let mut link = MockLink::new([6, 19, 49, 0]);
        let mut session = open(&mut link);
        let info = session.device_info().unwrap();
        assert_eq!((info.vendor_id, info.product_id), (0x045e, 0x0b4c));
        assert_eq!(info.hardware_revision, 0x0c06);
        assert_eq!(info.firmware_version, [6, 19, 49, 0]);
        assert!(info.is_updatable());
    }

    #[test]
    fn acks_device_1d_frames_only_when_enabled() {
        for enabled in [false, true] {
            let mut link = MockLink::new([6, 19, 50, 0]);
            let options = Options { ack_device_1d: enabled, ..Options::default() };
            let mut session = Session::open(&mut link, 0x1234_5678, options).unwrap();
            let device_handle = session.handle.wrapping_add(1);
            session
                .link
                .queue
                .push_back(vec![frame::TYPE_SINGLE, device_handle, OP_DEVICE_1D, 7, 0]);
            session.device_info().unwrap();
            drop(session);
            let ack = frame::ack(device_handle, OP_DEVICE_1D, 7);
            assert_eq!(link.sent.iter().any(|p| *p == ack), enabled, "enabled={enabled}");
        }
    }

    #[test]
    fn retries_session_when_the_first_accept_is_lost() {
        let mut link = MockLink::new([6, 9, 444, 0]);
        link.drop_session_replies = 1;
        let session = open(&mut link);
        drop(session);
        assert_eq!(link.sent.iter().filter(|p| p[0] == 0xff).count(), 2);
    }

    #[test]
    fn legacy_hello_reads_firmware_through_status_without_writing() {
        let mut link = MockLink::new([6, 9, 444, 0]);
        link.protocol_version = [2, 0, 13];
        let mut session = open(&mut link);
        let info = session.device_info().unwrap();
        assert_eq!(info.hardware_revision, 0x0c06);
        assert_eq!(info.firmware_version, [6, 9, 444, 0]);
        assert!(link.endpoint.device.written_data().is_empty());
        assert!(link.sent.iter().any(|p| p[0] == frame::TYPE_ACK && p[2] == protocol::OP_DEVICE_INFO_LEGACY));
    }

    #[test]
    fn unrelated_packet_flood_cannot_prevent_request_timeout() {
        struct Flood;
        impl Link for Flood {
            fn send(&mut self, _: &[u8]) -> Result<(), String> { Ok(()) }
            fn recv(&mut self, _: Duration) -> Result<Option<Vec<u8>>, String> {
                Ok(Some(vec![frame::TYPE_SINGLE, 3, 0x1d, 0, 0]))
            }
            fn max_fragment_data(&self) -> usize { 58 }
        }
        let mut link = Flood;
        let mut session = Session {
            link: &mut link, handle: 2, version: [2, 0, 13], max_message: 0x1002,
            seq: Sequence::default(), last_rx: None, options: Options { attempts: 1, ..Options::default() },
        };
        assert!(session.request(0x23, &[0; 12], Duration::from_millis(2)).is_err());
    }

    #[test]
    fn updates_to_the_image_version() {
        let mut link = MockLink::new([6, 19, 49, 0]);
        let image = Image {
            version: [6, 19, 50, 0],
            data: (0..0x2000u32).map(|i| i as u8).collect(),
        };
        let mut events = Vec::new();
        let mut record = |event: &Event| events.push(event.clone());
        {
            let mut session = open(&mut link);
            session.update(&image, &mut record).unwrap();
        }
        assert!(matches!(
            events[0],
            Event::Begin {
                resume_offset: 0,
                ..
            }
        ));
        assert!(events.contains(&Event::Finished));
        assert_eq!(link.endpoint.device.written_data(), &image.data[..]);
        assert_eq!(link.endpoint.device.firmware_version, image.version);
    }

    #[test]
    fn resent_replies_do_not_answer_the_next_request() {
        let mut link = MockLink::new([6, 9, 444, 0]);
        link.resend_replies = true;
        let image = Image {
            version: [6, 19, 50, 0],
            data: (0..0x2000u32).map(|i| i as u8).collect(),
        };
        open(&mut link).update(&image, &mut |_: &Event| {}).unwrap();
        assert_eq!(link.endpoint.device.written_data(), &image.data[..]);
    }

    #[test]
    fn refuses_to_finish_when_the_device_count_is_short() {
        let mut link = MockLink::new([6, 9, 444, 0]);
        link.endpoint.device.lose_bytes = 1;
        let image = Image { version: [6, 19, 50, 0], data: vec![0x55; 0x1800] };
        let error = open(&mut link).update(&image, &mut |_: &Event| {}).unwrap_err();
        assert!(error.contains("not finishing"), "{error}");
        assert_eq!(link.endpoint.device.firmware_version, [6, 9, 444, 0]);
    }

    #[test]
    fn resends_a_fragment_the_device_did_not_ack() {
        let mut link = MockLink::new([6, 9, 444, 0]);
        link.lose_fragments = 3;
        let image = Image { version: [6, 19, 50, 0], data: (0..0x1800u32).map(|i| i as u8).collect() };
        open(&mut link).update(&image, &mut |_: &Event| {}).unwrap();
        assert_eq!(link.endpoint.device.written_data(), &image.data[..]);
    }

    #[test]
    fn gives_up_when_a_fragment_is_never_acked() {
        let mut link = MockLink::new([6, 9, 444, 0]);
        link.lose_fragments = u32::MAX;
        let image = Image { version: [6, 19, 50, 0], data: vec![0x55; 0x1800] };
        let error = open(&mut link).update(&image, &mut |_: &Event| {}).unwrap_err();
        assert!(error.contains("no ack for message fragment"), "{error}");
        assert_eq!(link.endpoint.device.firmware_version, [6, 9, 444, 0]);
    }

    #[test]
    fn finish_flags_can_be_overridden() {
        let mut link = MockLink::new([6, 9, 444, 0]);
        let options = Options { finish_flags: Some(3), ..Options::default() };
        let image = Image { version: [6, 19, 50, 0], data: vec![0x55; 0x100] };
        Session::open(&mut link, 1, options).unwrap().update(&image, &mut |_: &Event| {}).unwrap();
        let finish = link.sent.iter().filter_map(|p| Frame::parse(p))
            .find(|f| f.payload.first() == Some(&protocol::SUB_FINISH)).unwrap();
        assert_eq!(finish.payload, [protocol::SUB_FINISH, 0, 3]);
    }

    #[test]
    fn keeps_writing_when_write_replies_set_flag_bit_0() {
        let mut link = MockLink::new([6, 9, 444, 0]);
        link.endpoint.device.write_flags = 1;
        let image = Image { version: [6, 19, 50, 0], data: vec![0x55; 0x1800] };
        open(&mut link).update(&image, &mut |_: &Event| {}).unwrap();
        assert_eq!(link.endpoint.device.written_data(), &image.data[..]);
        assert_eq!(link.endpoint.device.firmware_version, image.version);
    }

    fn sent_subcommand(link: &MockLink, subcommand: u8) -> bool {
        link.sent.iter().filter_map(|bytes| Frame::parse(bytes)).any(|frame|
            frame.opcode == protocol::OP_UPDATE && frame.payload.first() == Some(&subcommand)
        )
    }

    #[test]
    fn default_mutating_timeouts_match_the_sdk() {
        let options = Options::default();
        assert_eq!(options.mutation_timeout, Duration::from_secs(20));
        assert_eq!(options.write_timeout, Duration::from_secs(100));
        assert_eq!(options.response_timeout, Duration::from_secs(4));
    }

    #[test]
    fn lost_mutating_replies_do_not_resubmit_commands() {
        for subcommand in [protocol::SUB_START, protocol::SUB_WRITE, protocol::SUB_FINISH] {
            let mut link = MockLink::new([6, 9, 444, 0]);
            link.drop_subcommand_reply = Some(subcommand);
            let image = Image { version: [6, 19, 50, 0], data: vec![0x55; 2] };
            let mut session = open(&mut link);
            let failed = match subcommand {
                protocol::SUB_START => {
                    let status = session.update_status().unwrap();
                    session.start_update(&status, &image).is_err()
                }
                protocol::SUB_WRITE => session.write_block(0, 0, &image.data).is_err(),
                protocol::SUB_FINISH => session.finish_update(0).is_err(),
                _ => unreachable!(),
            };
            assert!(failed);
            let submissions = link.sent.iter().filter_map(|p| Frame::parse(p)).filter(|frame|
                frame.opcode == protocol::OP_UPDATE && frame.payload.first() == Some(&subcommand)
            ).count();
            assert_eq!(submissions, 1, "subcommand {subcommand:#x} was resubmitted");
        }
    }

    #[test]
    fn lost_read_replies_still_use_configured_retries() {
        let mut link = MockLink::new([6, 9, 444, 0]);
        link.drop_subcommand_reply = Some(protocol::SUB_STATUS);
        let mut session = open(&mut link);
        assert!(session.update_status().is_err());
        let submissions = link.sent.iter().filter_map(|p| Frame::parse(p)).filter(|frame|
            frame.opcode == protocol::OP_UPDATE && frame.payload.first() == Some(&protocol::SUB_STATUS)
        ).count();
        assert_eq!(submissions, Options::default().attempts as usize);
    }

    #[test]
    fn rejects_oversized_image_before_start() {
        let mut link = MockLink::new([6, 9, 444, 0]);
        let image = Image { version: [6, 19, 50, 0], data: vec![0; 0x0100_0000] };
        let error = open(&mut link).update(&image, &mut |_| {}).unwrap_err();
        assert!(error.contains("24-bit"), "{error}");
        assert!(!sent_subcommand(&link, protocol::SUB_START));
        assert!(link.endpoint.device.written_data().is_empty());
    }

    #[test]
    fn rejects_zero_device_chunk_before_start() {
        let mut link = MockLink::new([6, 9, 444, 0]);
        link.endpoint.device.max_chunk = 0;
        let image = Image { version: [6, 19, 50, 0], data: vec![0x55; 0x100] };
        let error = open(&mut link).update(&image, &mut |_| {}).unwrap_err();
        assert!(error.contains("zero maximum"), "{error}");
        assert!(!sent_subcommand(&link, protocol::SUB_START));
    }

    #[test]
    fn rejects_message_too_small_for_write_before_start() {
        for maximum in [0, 4, 5] {
            let mut link = MockLink::new([6, 9, 444, 0]);
            let image = Image { version: [6, 19, 50, 0], data: vec![0x55; 0x100] };
            let mut session = open(&mut link);
            session.max_message = maximum;
            let error = session.update(&image, &mut |_| {}).unwrap_err();
            assert!(error.contains("message size"), "{error}");
            assert!(!sent_subcommand(&link, protocol::SUB_START));
        }
    }

    #[test]
    fn rejects_resume_past_image_without_write_or_finish() {
        let mut link = MockLink::new([6, 9, 444, 0]);
        link.resume_override = Some(0x101);
        let image = Image { version: [6, 19, 50, 0], data: vec![0x55; 0x100] };
        let error = open(&mut link).update(&image, &mut |_| {}).unwrap_err();
        assert!(error.contains("resume offset"), "{error}");
        assert!(sent_subcommand(&link, protocol::SUB_START));
        assert!(!sent_subcommand(&link, protocol::SUB_WRITE));
        assert!(!sent_subcommand(&link, protocol::SUB_FINISH));
    }

    #[test]
    fn refuses_finish_without_a_written_counter() {
        let mut link = MockLink::new([6, 9, 444, 0]);
        link.final_status_short = true;
        let image = Image { version: [6, 19, 50, 0], data: vec![0x55; 0x100] };
        let error = open(&mut link).update(&image, &mut |_| {}).unwrap_err();
        assert!(error.contains("did not report bytes"), "{error}");
        assert!(!sent_subcommand(&link, protocol::SUB_FINISH));
    }

    #[test]
    fn refuses_finish_when_final_status_fails_even_with_complete_count() {
        let mut link = MockLink::new([6, 9, 444, 0]);
        link.final_status_failure = true;
        let image = Image { version: [6, 19, 50, 0], data: vec![0x55; 0x100] };
        let error = open(&mut link).update(&image, &mut |_| {}).unwrap_err();
        assert!(error.contains("final update status DeviceFailed"), "{error}");
        assert_eq!(link.endpoint.device.written_data().len(), image.data.len());
        assert!(!sent_subcommand(&link, protocol::SUB_FINISH));
    }

    #[test]
    fn already_up_to_date_writes_nothing() {
        let mut link = MockLink::new([6, 19, 50, 0]);
        let image = Image {
            version: [6, 19, 50, 0],
            data: vec![0xaa; 0x100],
        };
        let mut events = Vec::new();
        let mut record = |event: &Event| events.push(event.clone());
        let mut session = open(&mut link);
        session.update(&image, &mut record).unwrap();
        assert_eq!(events, vec![Event::UpToDate]);
        assert!(link.endpoint.device.written_data().is_empty());
    }
}
