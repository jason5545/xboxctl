//! A fake Pendragon device driving the companion protocol state machine, used
//! as the device side in tests. Mirrors the QEMU fake Nano's
//! `hid-reply=companion` mode (see `docs/nano.md`): it answers the session,
//! acks and reassembles fragments, and replies to device info and the update
//! subcommands.

use crate::companion::frame::{self, Frame, Reassembler, Sequence};
use crate::companion::protocol;
use std::collections::VecDeque;

/// Fragment payload size the fake device uses for its own replies; matches
/// the 63-byte reports the QEMU fake Nano exposes.
const FRAGMENT_DATA: usize = 57;

/// Session handle the fake device hands out. Must not be the host's own
/// sequence byte (0), which `open_session` always sends.
const HANDLE: u8 = 0x7e;

/// The device's unsolicited frames come on the handle after the session's.
const KEEPALIVE_HANDLE: u8 = HANDLE + 1;
const KEEPALIVE_OPCODE: u8 = 0x1d;
/// Constant for a whole session on the physical Nano.
const KEEPALIVE_SEQ: u8 = 0x40;

pub struct FakeNano {
    pub vendor_id: u16,
    pub product_id: u16,
    pub hardware_revision: u16,
    pub firmware_version: [u16; 4],
    pub max_chunk: u16,
    token: [u8; 16],
    slot: u8,
    written: Vec<u8>,
    /// Test knobs: under-report the written count; flags byte of write replies.
    pub lose_bytes: u32,
    pub write_flags: u8,
    /// Mode byte of the status reply (27); a physical Nano reports `4`.
    pub mode: u8,
    /// Slot the start reply hands out; a physical Nano returned 1, 2, 3.
    pub start_slot: u8,
    /// The feed's `req` version. As on a physical Nano, a device below it
    /// discards the staged image unless finish carries flag bit 1.
    pub required_version: Option<[u16; 4]>,
    /// Keep a partly written image across sessions and report where to
    /// resume, as a physical Nano did after an aborted run.
    pub resume: bool,
    /// Version of the image being staged, for resume.
    staged_version: Option<[u16; 4]>,
}

impl FakeNano {
    pub fn tala(firmware_version: [u16; 4]) -> Self {
        Self {
            vendor_id: 0x045e,
            product_id: 0x0b4c,
            hardware_revision: 0x0c06,
            firmware_version,
            max_chunk: 0x0800,
            token: *b"fake-nano-token!",
            slot: 0,
            written: Vec::new(),
            lose_bytes: 0,
            write_flags: 0,
            mode: 0,
            start_slot: 0,
            required_version: None,
            resume: false,
            staged_version: None,
        }
    }

    pub fn written_data(&self) -> &[u8] {
        &self.written
    }

    fn device_info_response(&self) -> Vec<u8> {
        let mut out = vec![0u8; 0x4e];
        out[0..2].copy_from_slice(&self.vendor_id.to_le_bytes());
        out[2..4].copy_from_slice(&self.product_id.to_le_bytes());
        out[4..6].copy_from_slice(&self.hardware_revision.to_le_bytes());
        out[0x29..0x2d].copy_from_slice(&protocol::CAP_UPDATABLE.to_le_bytes());
        for (i, word) in self.firmware_version.iter().enumerate() {
            out[0x33 + i * 2..0x33 + i * 2 + 2].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    fn update_response(&mut self, payload: &[u8]) -> Vec<u8> {
        match payload.first().copied() {
            Some(protocol::SUB_STATUS) => {
                // 80 bytes, as a physical Nano answers.
                let mut out = vec![0u8; 80];
                out[0] = protocol::SUB_STATUS;
                out[2..18].copy_from_slice(&self.token);
                for (i, word) in self.firmware_version.iter().enumerate() {
                    out[18 + i * 2..18 + i * 2 + 2].copy_from_slice(&word.to_le_bytes());
                }
                out[27] = self.mode;
                out[32..34].copy_from_slice(&self.max_chunk.to_le_bytes());
                let written = (self.written.len() as u32).saturating_sub(self.lose_bytes);
                out[60..64].copy_from_slice(&written.to_le_bytes());
                out
            }
            Some(protocol::SUB_START) if payload.len() >= 27 => {
                let version: [u16; 4] = std::array::from_fn(|i| {
                    u16::from_le_bytes([payload[17 + i * 2], payload[17 + i * 2 + 1]])
                });
                let resume_offset = if self.resume && self.staged_version == Some(version) {
                    self.written.len() as u32
                } else {
                    self.written.clear();
                    0
                };
                self.staged_version = Some(version);
                self.slot = self.start_slot;
                let mut out = vec![protocol::SUB_START, 0];
                out.extend_from_slice(&resume_offset.to_le_bytes());
                out.push(self.slot);
                out
            }
            Some(protocol::SUB_WRITE | protocol::SUB_FINISH) if payload.get(1) != Some(&self.slot) => {
                // Wrong slot: refuse, as a device would for a slot it did
                // not hand out.
                if payload[0] == protocol::SUB_WRITE {
                    vec![payload[0], 6, 0]
                } else {
                    vec![payload[0], 6]
                }
            }
            Some(protocol::SUB_WRITE) if payload.len() >= 5 => {
                let offset = u32::from_le_bytes([payload[2], payload[3], payload[4], 0]) as usize;
                let data = &payload[5..];
                let end = offset + data.len();
                if self.written.len() < end {
                    self.written.resize(end, 0);
                }
                self.written[offset..end].copy_from_slice(data);
                vec![protocol::SUB_WRITE, 0, self.write_flags]
            }
            Some(protocol::SUB_FINISH) => {
                // The new version travelled in the start request; a real
                // device would have kept it, but the fake only needs to show
                // the update took effect once finish succeeds.
                vec![protocol::SUB_FINISH, 0]
            }
            _ => vec![payload.first().copied().unwrap_or(0), 13],
        }
    }
}

pub struct CompanionEndpoint {
    pub device: FakeNano,
    /// Send an unsolicited `05 <handle+1> 1d <seq> 00` after every host
    /// report, and go silent once more than this many are left unacked: a
    /// model of the physical Nano that stopped answering after about 1,430
    /// unacked repeats. The real trigger is a guess.
    pub keepalive_limit: Option<u32>,
    unacked_keepalive: u32,
    /// Silent until [`CompanionEndpoint::replug`].
    pub dead: bool,
    /// How many times finish was accepted but the image was discarded.
    pub discarded_finishes: u32,
    reassembler: Reassembler,
    device_seq: Sequence,
    pending: VecDeque<Vec<u8>>,
    /// New firmware version from the last `11` start request, applied when
    /// `13` finishes successfully.
    pending_version: Option<[u16; 4]>,
}

impl CompanionEndpoint {
    pub fn new(device: FakeNano) -> Self {
        Self {
            device,
            reassembler: Reassembler::default(),
            device_seq: Sequence::default(),
            pending: VecDeque::new(),
            pending_version: None,
            keepalive_limit: None,
            unacked_keepalive: 0,
            dead: false,
            discarded_finishes: 0,
        }
    }

    /// Unplug and plug back in: protocol state resets, a staged image stays.
    pub fn replug(&mut self) {
        self.reassembler = Reassembler::default();
        self.device_seq = Sequence::default();
        self.pending.clear();
        self.unacked_keepalive = 0;
        self.dead = false;
    }

    /// Feed one incoming HID report payload (after the `0x0c` ID); returns
    /// the report payloads to send back, in order.
    pub fn handle_report(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        if self.dead {
            return Vec::new();
        }
        if let Some(frame) = Frame::parse(bytes) {
            if frame.kind == frame::TYPE_ACK
                && frame.handle == KEEPALIVE_HANDLE
                && frame.opcode == KEEPALIVE_OPCODE
            {
                if frame.seq == KEEPALIVE_SEQ.wrapping_add(1) {
                    self.unacked_keepalive = 0;
                }
                return Vec::new();
            }
        }
        let mut out = self.handle_protocol(bytes);
        if let Some(limit) = self.keepalive_limit {
            if self.unacked_keepalive >= limit {
                self.dead = true;
                return Vec::new();
            }
            self.unacked_keepalive += 1;
            out.push(vec![frame::TYPE_SINGLE, KEEPALIVE_HANDLE, KEEPALIVE_OPCODE, KEEPALIVE_SEQ, 0]);
        }
        out
    }

    fn handle_protocol(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        if bytes.first() == Some(&0xff) {
            return self.session_accept(bytes);
        }
        let Some(frame) = Frame::parse(bytes) else {
            return Vec::new();
        };
        if frame.kind == frame::TYPE_ACK {
            return self.pending.pop_front().into_iter().collect();
        }
        let mut out = Vec::new();
        if frame.is_fragment() {
            out.push(frame::ack(HANDLE, frame.opcode, frame.seq));
        }
        if let Some(message) = self.reassembler.push(&frame) {
            if frame.opcode == protocol::OP_UPDATE {
                if message.first() == Some(&protocol::SUB_START) && message.len() >= 25 {
                    self.pending_version = Some(std::array::from_fn(|i| {
                        u16::from_le_bytes([message[17 + i * 2], message[17 + i * 2 + 1]])
                    }));
                } else if message.first() == Some(&protocol::SUB_FINISH)
                    && message.get(1) == Some(&self.device.slot)
                    && let Some(version) = self.pending_version.take()
                {
                    let flags = message.get(2).copied().unwrap_or(0);
                    let below_required = self
                        .device
                        .required_version
                        .is_some_and(|required| self.device.firmware_version < required);
                    if below_required && flags & 2 == 0 {
                        // Seen on a physical Nano: finish `13 00`, restart,
                        // back on the old firmware with the image discarded.
                        self.discarded_finishes += 1;
                    } else {
                        self.device.firmware_version = version;
                    }
                    // Written bytes stay readable for tests; nothing is
                    // left to resume.
                    self.device.staged_version = None;
                }
            }
            let response = match frame.opcode {
                protocol::OP_DEVICE_INFO => self.device.device_info_response(),
                protocol::OP_DEVICE_INFO_LEGACY => self.device.device_info_response()[..0x33].to_vec(),
                protocol::OP_UPDATE => self.device.update_response(&message),
                _ => vec![frame.opcode, 13],
            };
            out.extend(self.queue_response(frame.opcode, &response));
        }
        out
    }

    fn session_accept(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        if bytes.len() < 11 {
            return Vec::new();
        }
        let mut reply = vec![0xff, HANDLE];
        reply.extend_from_slice(&bytes[2..6]);
        reply.extend_from_slice(&[2, 0, 22]);
        reply.extend_from_slice(&frame::SESSION_MAX_MESSAGE.to_le_bytes());
        vec![reply]
    }

    /// Queue `payload` as one or more outgoing frames, returning the first
    /// and keeping the rest for release as the host acks them.
    fn queue_response(&mut self, opcode: u8, payload: &[u8]) -> Vec<Vec<u8>> {
        // As a physical Nano numbers them: fragments count up from the
        // message's first sequence, and the next message starts one after
        // this one started, so consecutive replies overlap.
        let mut seq = self.device_seq;
        self.device_seq.take();
        let mut frames = frame::fragments(HANDLE, opcode, &mut seq, payload, FRAGMENT_DATA);
        let first = frames.remove(0);
        self.pending = frames.into();
        vec![first]
    }
}
