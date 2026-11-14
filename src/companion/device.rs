//! A fake Pendragon device driving the companion protocol state machine, used
//! as the device side in tests. Mirrors the QEMU fake Nano's
//! `hid-reply=companion` mode (see `docs/nano.md`): it answers the session,
//! acks and reassembles fragments, and replies to device info and the update
//! subcommands.

use crate::companion::frame::{self, Frame, Reassembler, Sequence};
use crate::companion::protocol;
use crate::companion::settings;
use std::collections::{BTreeMap, VecDeque};

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

/// How the fake answers `1d` telemetry requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryReply {
    /// One queued record per request, then an empty reply.
    Records,
    /// Never answers them.
    Silent,
    /// Always a record, never the empty reply.
    Endless,
}

/// What one fake telemetry record holds; the real layout is not known.
const TELEMETRY_RECORD: [u8; 24] = [0xa5; 24];

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
    /// Go silent after this many host reports since the last replug, acked
    /// or not: a model of the physical Nano (6.9.444.0) that stopped
    /// answering about 3m46s after it was plugged in although every `1d` was
    /// acked. What really ends it is not known; a count of reports stands in
    /// for the time.
    pub link_lifetime: Option<u32>,
    reports: u32,
    /// Whether [`CompanionEndpoint::reset`] (a USB reset from the host)
    /// revives a silent device the way a replug does. Not known for the
    /// physical Nano, so tests cover both.
    pub reset_revives: bool,
    /// Telemetry as Sean13128 read the SDK: queue a record every this many
    /// host reports and tap for it with an empty `05 <handle+1> 1d <seq> 00`,
    /// resent until acked; the host fetches records with `1d` requests on
    /// the session until an empty reply.
    pub telemetry_every: Option<u32>,
    /// Go silent once a record has waited this many host reports unfetched:
    /// one guess at what ends a physical Nano's link after about 3.5
    /// minutes, not established.
    pub telemetry_deadline: Option<u32>,
    pub telemetry_reply: TelemetryReply,
    telemetry_queued: u32,
    /// Report count when the oldest unfetched record was queued.
    telemetry_since: Option<u32>,
    tap_unacked: bool,
    /// Records the host fetched.
    pub telemetry_fetched: u32,
    /// Button mappings by slot (flags byte, entries), preloaded with what a
    /// physical Nano reported for slots 00, 01, 10 and 11.
    pub mappings: BTreeMap<u8, (u8, Vec<Vec<u8>>)>,
    /// `set mapping` requests accepted.
    pub mapping_writes: u32,
    /// Store a `set mapping` request's entries as sent. Off, the fake does
    /// what a physical Nano (6.19.50.0) did with a full 28-entry write whose
    /// button targets were all `00`: it stored the default profile (slot
    /// 00's five entries) instead. Off, it also applies written button
    /// entries with a non-zero target on top of that default; whether a
    /// Nano does is what the next hardware run tries.
    pub store_as_written: bool,
    /// `delete profile` requests accepted; a deleted slot reads back blank.
    pub profile_deletes: u32,
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
            link_lifetime: None,
            reports: 0,
            reset_revives: true,
            telemetry_every: None,
            telemetry_deadline: None,
            telemetry_reply: TelemetryReply::Records,
            telemetry_queued: 0,
            telemetry_since: None,
            tap_unacked: false,
            telemetry_fetched: 0,
            mappings: nano_mappings(),
            mapping_writes: 0,
            store_as_written: false,
            profile_deletes: 0,
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
        self.reports = 0;
        self.tap_unacked = self.telemetry_queued > 0;
        self.dead = false;
    }

    /// Queue `count` telemetry records and tap for them.
    pub fn queue_telemetry(&mut self, count: u32) {
        if count > 0 {
            self.telemetry_queued += count;
            self.telemetry_since.get_or_insert(self.reports);
            self.tap_unacked = true;
        }
    }

    /// A USB reset from the host: a replug if [`Self::reset_revives`], else
    /// nothing.
    pub fn reset(&mut self) {
        if self.reset_revives {
            self.replug();
        }
    }

    /// Feed one incoming HID report payload (after the `0x0c` ID); returns
    /// the report payloads to send back, in order.
    pub fn handle_report(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        if self.dead {
            return Vec::new();
        }
        self.reports += 1;
        if self.link_lifetime.is_some_and(|lifetime| self.reports > lifetime) {
            self.dead = true;
            return Vec::new();
        }
        if let Some(frame) = Frame::parse(bytes) {
            if frame.kind == frame::TYPE_ACK
                && frame.handle == KEEPALIVE_HANDLE
                && frame.opcode == KEEPALIVE_OPCODE
            {
                if frame.seq == KEEPALIVE_SEQ.wrapping_add(1) {
                    self.unacked_keepalive = 0;
                    self.tap_unacked = false;
                }
                return Vec::new();
            }
        }
        if let (Some(deadline), Some(since)) = (self.telemetry_deadline, self.telemetry_since)
            && self.reports - since > deadline
        {
            self.dead = true;
            return Vec::new();
        }
        let mut out = self.handle_protocol(bytes);
        if self.telemetry_every.is_some_and(|every| self.reports.is_multiple_of(every)) {
            self.queue_telemetry(1);
        }
        if self.tap_unacked {
            out.push(vec![frame::TYPE_SINGLE, KEEPALIVE_HANDLE, KEEPALIVE_OPCODE, KEEPALIVE_SEQ, 0]);
        }
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
                KEEPALIVE_OPCODE => match self.telemetry_reply {
                    TelemetryReply::Silent => return out,
                    TelemetryReply::Endless => TELEMETRY_RECORD.to_vec(),
                    TelemetryReply::Records if self.telemetry_queued > 0 => {
                        self.telemetry_queued -= 1;
                        self.telemetry_fetched += 1;
                        if self.telemetry_queued == 0 {
                            self.telemetry_since = None;
                        }
                        TELEMETRY_RECORD.to_vec()
                    }
                    TelemetryReply::Records => Vec::new(),
                },
                settings::OP_EXTERNAL => self.external_response(&message),
                protocol::OP_DEVICE_INFO => self.device.device_info_response(),
                protocol::OP_DEVICE_INFO_LEGACY => self.device.device_info_response()[..0x33].to_vec(),
                protocol::OP_UPDATE => self.device.update_response(&message),
                _ => vec![frame.opcode, 13],
            };
            out.extend(self.queue_response(frame.opcode, &response));
        }
        out
    }

    /// `1e` settings messages. What a physical Nano answers to a slot it
    /// does not have, or to a write without the end marker, is not known;
    /// the fake answers `02` (bad argument).
    fn external_response(&mut self, message: &[u8]) -> Vec<u8> {
        match message {
            [settings::SETTINGS_MESSAGE_ID, settings::SUB_GET_MAPPING, slot] => match self.mappings.get(slot) {
                Some((flags, entries)) => {
                    let mut out = vec![0, settings::SUB_GET_MAPPING, *flags, *slot, entries.len() as u8];
                    for entry in entries {
                        out.extend_from_slice(entry);
                    }
                    out
                }
                None => vec![0x02],
            },
            [settings::SETTINGS_MESSAGE_ID, settings::SUB_SET_MAPPING, slot, count, rest @ ..] => {
                let Ok(mut entries) = settings::parse_entries(rest, usize::from(*count)) else {
                    return vec![0x02];
                };
                if entries.last().map(Vec::as_slice) != Some(&settings::END_MARKER[..]) {
                    return vec![0x02];
                }
                entries.pop();
                let flags = self.mappings.get(slot).map_or(0, |(flags, _)| *flags);
                let stored = if self.store_as_written {
                    entries
                } else {
                    let mut stored = default_profile();
                    for entry in &entries {
                        if let [0x05, 0x00, settings::ENTRY_BUTTON, physical, target] = entry.as_slice()
                            && *target != 0
                        {
                            stored = settings::with_button(&stored, *physical, *target);
                        }
                    }
                    stored
                };
                self.mappings.insert(*slot, (flags, stored));
                self.mapping_writes += 1;
                vec![0, settings::SUB_SET_MAPPING, 0]
            }
            [settings::SETTINGS_MESSAGE_ID, settings::SUB_DELETE_PROFILE, slot] if *slot & 0x0f != 0 => {
                let flags = self.mappings.get(slot).map_or(0, |(flags, _)| *flags);
                self.mappings.insert(*slot, (flags, blank_profile()));
                self.profile_deletes += 1;
                vec![0, settings::SUB_DELETE_PROFILE, 0]
            }
            [settings::SETTINGS_MESSAGE_ID, ..] => vec![0x02],
            _ => vec![0x43],
        }
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

fn default_profile() -> Vec<Vec<u8>> {
    use settings::tests::{bytes, NANO_SLOT_00};
    settings::parse_mapping(&bytes(NANO_SLOT_00)).unwrap().entries
}

/// What a physical Nano's unused slots read as: 28 entries, every button
/// target `00`.
fn blank_profile() -> Vec<Vec<u8>> {
    use settings::tests::{bytes, NANO_SLOT_01};
    settings::parse_mapping(&bytes(NANO_SLOT_01)).unwrap().entries
}

/// Slots 00–07 and 10–17 as a physical Nano (6.19.50.0) reported them:
/// the active default in 00 (and its shift layer 10), every other slot
/// blank.
fn nano_mappings() -> BTreeMap<u8, (u8, Vec<Vec<u8>>)> {
    let mut out = BTreeMap::new();
    out.insert(0x00, (0x80, default_profile()));
    out.insert(0x10, (0x00, default_profile()));
    for slot in (0x01..=0x07).chain(0x11..=0x17) {
        out.insert(slot, (0x00, blank_profile()));
    }
    out
}
