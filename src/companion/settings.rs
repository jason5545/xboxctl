//! Button mappings on a Pendragon accessory, as the Xbox Accessories app
//! reads and writes them (see `docs/nano-settings.md`). External message
//! `1e` with message ID `02`:
//!
//! ```text
//! get mapping   02 08 <slot>                    reply 00 08 <flags> <slot> <count> <entries>
//! set mapping   02 09 <slot> <count> <entries>  entries end with the marker 03 00 00
//! ```
//!
//! An entry is `<length:u16 LE> <type> <data>`, the length counting the whole
//! entry. A button mapping is `05 00 01 <physical> <target>`. The reply
//! layout was read from a physical Nano (6.19.50.0, over Bluetooth); the
//! request layout and the end marker come from the app (`0x180dac01c`, and
//! `0x180dae830`, which the Pendragon path `0x180faf4f8` always adds).

/// Message ID the app's settings messages carry.
pub const SETTINGS_MESSAGE_ID: u8 = 0x02;
pub const OP_EXTERNAL: u8 = 0x1e;
pub const SUB_GET_MAPPING: u8 = 0x08;
pub const SUB_SET_MAPPING: u8 = 0x09;
pub const SUB_DELETE_PROFILE: u8 = 0x0a;
pub const SUB_GET_ACTIVE_MODE: u8 = 0x03;
pub const SUB_SET_ACTIVE_MODE: u8 = 0x06;
pub const ENTRY_BUTTON: u8 = 0x01;
/// Written last by the app; not in the device's replies.
pub const END_MARKER: [u8; 3] = [0x03, 0x00, 0x00];
/// The Action button's short press, as seen in a physical Nano's profile.
pub const ACTION_SHORT_PRESS: u8 = 0x1c;

/// One slot's mapping as a `get mapping` reply carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    /// `0x80` on the slot a physical Nano reported as active; not settled.
    pub flags: u8,
    pub slot: u8,
    pub entries: Vec<Vec<u8>>,
}

pub fn get_mapping_request(slot: u8) -> Vec<u8> {
    vec![SETTINGS_MESSAGE_ID, SUB_GET_MAPPING, slot]
}

/// Split a byte run into entries, checking each length.
pub fn parse_entries(mut bytes: &[u8], count: usize) -> Result<Vec<Vec<u8>>, String> {
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        if bytes.len() < 3 {
            return Err(format!("entry {index} is cut short"));
        }
        let length = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        if length < 3 || length > bytes.len() {
            return Err(format!("entry {index} has bad length {length}"));
        }
        entries.push(bytes[..length].to_vec());
        bytes = &bytes[length..];
    }
    if !bytes.is_empty() {
        return Err(format!("{} bytes after the last entry", bytes.len()));
    }
    Ok(entries)
}

/// Parse a `get mapping` reply (the external message's status byte
/// included).
pub fn parse_mapping(reply: &[u8]) -> Result<Mapping, String> {
    let [status, sub, flags, slot, count, rest @ ..] = reply else {
        return Err(format!("mapping reply of {} bytes is too short", reply.len()));
    };
    if *status != 0 {
        return Err(format!("device refused get mapping with status {status:#04x}"));
    }
    if *sub != SUB_GET_MAPPING {
        return Err(format!("reply is for subcommand {sub:#04x}, not get mapping"));
    }
    Ok(Mapping {
        flags: *flags,
        slot: *slot,
        entries: parse_entries(rest, usize::from(*count))?,
    })
}

/// A `set mapping` request writing `entries` to `slot`, end marker added.
pub fn set_mapping_request(slot: u8, entries: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let count = u8::try_from(entries.len() + 1).map_err(|_| "too many entries".to_owned())?;
    let mut out = vec![SETTINGS_MESSAGE_ID, SUB_SET_MAPPING, slot, count];
    for entry in entries {
        out.extend_from_slice(entry);
    }
    out.extend_from_slice(&END_MARKER);
    Ok(out)
}

/// A `set mapping` request in the app's full mode (`0x180dae6c4` with its
/// flag clear): every entry, no end marker.
pub fn set_mapping_request_full(slot: u8, entries: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let count = u8::try_from(entries.len()).map_err(|_| "too many entries".to_owned())?;
    let mut out = vec![SETTINGS_MESSAGE_ID, SUB_SET_MAPPING, slot, count];
    for entry in entries {
        out.extend_from_slice(entry);
    }
    Ok(out)
}

/// Write one slot's mapping in full mode (see [`set_mapping_request_full`]).
pub fn write_mapping_full<L: Link>(session: &mut Session<'_, L>, slot: u8, entries: &[Vec<u8>]) -> Result<(), String> {
    let reply = session.command(OP_EXTERNAL, &set_mapping_request_full(slot, entries)?)?;
    check_set_reply(&reply)
}

/// Each button's own target, from the app's two code tables
/// (`0x180dadc9c` physical, `0x180d15f80` target) for the same button.
/// `None` for the Action button's codes, which are inputs only.
pub fn identity_target(physical: u8) -> Option<u8> {
    match physical {
        0x00..=0x03 => Some(physical + 0x1a),
        0x04..=0x11 => Some(physical),
        0x1a => Some(0x02),
        0x1b => Some(0x03),
        _ => None,
    }
}

/// A full-mode profile from a blank slot's entries: every button entry set
/// to its own target, then `physical` replaced by `change`.
pub fn full_profile(blank: &[Vec<u8>], physical: u8, change: Vec<u8>) -> Vec<Vec<u8>> {
    blank
        .iter()
        .map(|entry| match entry.as_slice() {
            [0x05, 0x00, ENTRY_BUTTON, p, _] if *p == physical => change.clone(),
            [0x05, 0x00, ENTRY_BUTTON, p, target] => button_entry(*p, identity_target(*p).unwrap_or(*target)),
            _ => entry.clone(),
        })
        .collect()
}

/// Check a `set mapping` reply: status `00`, subcommand `09`, and the
/// result byte after it `00` (a Nano answers `01` for a write it refused).
pub fn check_set_reply(reply: &[u8]) -> Result<(), String> {
    match reply {
        [0, SUB_SET_MAPPING, 0, ..] | [0, SUB_SET_MAPPING] => Ok(()),
        [0, SUB_SET_MAPPING, result, ..] => Err(format!("device refused the mapping (result {result:#04x})")),
        [status, ..] => Err(format!("device refused set mapping with status {status:#04x}")),
        [] => Err("empty set mapping reply".to_owned()),
    }
}

pub fn delete_profile_request(slot: u8) -> Vec<u8> {
    vec![SETTINGS_MESSAGE_ID, SUB_DELETE_PROFILE, slot]
}

pub fn button_entry(physical: u8, target: u8) -> Vec<u8> {
    vec![0x05, 0x00, ENTRY_BUTTON, physical, target]
}

/// The target `physical` maps to, if the entries have a mapping for it.
pub fn button_target(entries: &[Vec<u8>], physical: u8) -> Option<u8> {
    entries.iter().find_map(|entry| match entry.as_slice() {
        [0x05, 0x00, ENTRY_BUTTON, p, target] if *p == physical => Some(*target),
        _ => None,
    })
}

/// `entries` with `physical` mapped to `target`: the existing entry changed
/// in place, or a new one added after the last button entry.
pub fn with_button(entries: &[Vec<u8>], physical: u8, target: u8) -> Vec<Vec<u8>> {
    let mut out = entries.to_vec();
    if let Some(entry) = out
        .iter_mut()
        .find(|entry| matches!(entry.as_slice(), [0x05, 0x00, ENTRY_BUTTON, p, _] if *p == physical))
    {
        entry[4] = target;
        return out;
    }
    let at = out
        .iter()
        .rposition(|entry| entry.get(2) == Some(&ENTRY_BUTTON))
        .map_or(0, |index| index + 1);
    out.insert(at, button_entry(physical, target));
    out
}

use crate::companion::updater::{Link, Session};
use std::time::Duration;

const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Read one slot's mapping.
pub fn read_mapping<L: Link>(session: &mut Session<'_, L>, slot: u8) -> Result<Mapping, String> {
    let reply = session.query(OP_EXTERNAL, &get_mapping_request(slot), READ_TIMEOUT)?;
    let mapping = parse_mapping(&reply)?;
    if mapping.slot != slot {
        return Err(format!("asked for slot {slot:#04x}, got {:#04x}", mapping.slot));
    }
    Ok(mapping)
}

/// Write one slot's mapping.
pub fn write_mapping<L: Link>(session: &mut Session<'_, L>, slot: u8, entries: &[Vec<u8>]) -> Result<(), String> {
    let reply = session.command(OP_EXTERNAL, &set_mapping_request(slot, entries)?)?;
    check_set_reply(&reply)
}

/// Delete one slot's profile.
pub fn delete_profile<L: Link>(session: &mut Session<'_, L>, slot: u8) -> Result<(), String> {
    match session.command(OP_EXTERNAL, &delete_profile_request(slot))?.as_slice() {
        [0, SUB_DELETE_PROFILE, ..] => Ok(()),
        [status, ..] => Err(format!("device refused delete profile with status {status:#04x}")),
        [] => Err("empty delete profile reply".to_owned()),
    }
}

pub const ENTRY_FLAG_0D: u8 = 0x0d;
pub const ENTRY_GUID: u8 = 0x11;
pub const ENTRY_NAME: u8 = 0x12;
/// Bytes of the name field in a type `12` entry.
pub const NAME_LEN: usize = 128;

pub fn guid_entry(guid: [u8; 16]) -> Vec<u8> {
    let mut out = vec![0x13, 0x00, ENTRY_GUID];
    out.extend_from_slice(&guid);
    out
}

/// A type `12` entry: the name in UTF-8, zero padded (cut to fit).
pub fn name_entry(name: &str) -> Vec<u8> {
    let mut out = vec![0x83, 0x00, ENTRY_NAME];
    let mut bytes = name.as_bytes().to_vec();
    bytes.truncate(NAME_LEN);
    bytes.resize(NAME_LEN, 0);
    out.extend(bytes);
    out
}

/// A profile as the app writes one in its differences-only mode, the one
/// the Pendragon path uses: changed buttons, then the GUID and the name
/// (sort key 0, in the writer's order), then the type `0d` flag (sort key
/// 500); [`set_mapping_request`] adds the end marker (sort key 1000).
pub fn profile_entries(changes: &[Vec<u8>], guid: [u8; 16], name: &str, flag_0d: bool) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = changes.to_vec();
    out.push(guid_entry(guid));
    out.push(name_entry(name));
    out.push(vec![0x04, 0x00, ENTRY_FLAG_0D, u8::from(flag_0d)]);
    out
}

pub const ENTRY_KEYBOARD: u8 = 0x09;

/// A type `09` keyboard mapping (`0x180dae270`): `<physical> <key> <byte>`.
/// The key is the low byte of the app's keyboard mapping value, probably a
/// Windows virtual-key code; the last byte is a field of the mapping, maybe
/// modifiers. Both readings are guesses.
pub fn keyboard_entry(physical: u8, key: u8, extra: u8) -> Vec<u8> {
    vec![0x06, 0x00, ENTRY_KEYBOARD, physical, key, extra]
}

/// One change to a button, for [`write_profile_then_reset`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// A type `01` entry: an ordinary button, or a system command target
    /// (`0x49` + `ProgrammableKeyAction`).
    Target(u8),
    /// A type `09` entry.
    Keyboard { key: u8, extra: u8 },
}

impl Change {
    pub fn entry(self, physical: u8) -> Vec<u8> {
        match self {
            Change::Target(target) => button_entry(physical, target),
            Change::Keyboard { key, extra } => keyboard_entry(physical, key, extra),
        }
    }
}

/// The entry in `entries` for `physical`, of any type that has one.
pub fn entry_for(entries: &[Vec<u8>], physical: u8) -> Option<&[u8]> {
    entries
        .iter()
        .find(|entry| matches!(entry.get(2), Some(&ENTRY_BUTTON | &ENTRY_KEYBOARD)) && entry.get(3) == Some(&physical))
        .map(Vec::as_slice)
}

/// The active mode reply's two bytes after the subcommand: a physical Nano
/// on its default profile answered `80 00`. Which byte is the slot is not
/// settled.
pub fn get_active_mode<L: Link>(session: &mut Session<'_, L>) -> Result<[u8; 2], String> {
    let reply = session.query(OP_EXTERNAL, &[SETTINGS_MESSAGE_ID, SUB_GET_ACTIVE_MODE], READ_TIMEOUT)?;
    match reply.as_slice() {
        [0, SUB_GET_ACTIVE_MODE, a, b, ..] => Ok([*a, *b]),
        [status, ..] => Err(format!("device refused get active mode with status {status:#04x}")),
        [] => Err("empty get active mode reply".to_owned()),
    }
}

/// Make `slot` the active profile (`06 <slot>`). A physical Nano answers
/// like get active mode, `00 06 80 <slot>`: the slot it is now on.
pub fn set_active_mode<L: Link>(session: &mut Session<'_, L>, slot: u8) -> Result<(), String> {
    match session.command(OP_EXTERNAL, &[SETTINGS_MESSAGE_ID, SUB_SET_ACTIVE_MODE, slot])?.as_slice() {
        [0, SUB_SET_ACTIVE_MODE, _, now, ..] if *now == slot => Ok(()),
        [0, SUB_SET_ACTIVE_MODE, flags, now, ..] => {
            Err(format!("device stayed on {flags:#04x} {now:#04x} instead of slot {slot:#04x}"))
        }
        [status, ..] => Err(format!("device refused set active mode with status {status:#04x}")),
        [] => Err("empty set active mode reply".to_owned()),
    }
}

/// What [`write_profile_then_reset`] saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileThenReset {
    pub before: Mapping,
    pub written: Mapping,
    pub reset: Mapping,
}

/// Write a whole profile the app's way (one button changed, a GUID, a
/// name, the `0d` flag) to `slot`, read it back, then reset the slot the
/// way the app's "restore defaults" does, an empty differences-only write
/// (`09 <slot> 01 03 00 00`), and read again. The reset runs even when the
/// write went unanswered. Never touches slot 00 or 10.
pub fn write_profile_then_reset<L: Link>(
    session: &mut Session<'_, L>,
    slot: u8,
    physical: u8,
    change: Change,
    guid: [u8; 16],
    name: &str,
    log: &mut dyn FnMut(&str),
) -> Result<ProfileThenReset, String> {
    if slot & 0x0f == 0 {
        return Err("slot 00 holds the default profile; not writing it".to_owned());
    }
    let before = read_mapping(session, slot)?;
    let show = |entries: &[Vec<u8>]| entry_for(entries, physical).map_or("none".to_owned(), crate::usb::hex);
    log(&format!("slot {slot:#04x} before: {} entries, {physical:#04x}: {}", before.entries.len(), show(&before.entries)));
    let change_entry = change.entry(physical);
    // An empty name means the change alone, without the GUID, name and 0d.
    let entries = if name.is_empty() {
        vec![change_entry.clone()]
    } else {
        profile_entries(std::slice::from_ref(&change_entry), guid, name, false)
    };
    log(&format!(
        "writing {} entries: {}{}",
        entries.len(),
        crate::usb::hex(&change_entry),
        if name.is_empty() { String::new() } else { format!(", GUID, name {name:?}, 0d") }
    ));
    let written = write_mapping(session, slot, &entries);
    if let Err(error) = &written {
        log(&format!("write failed: {error}"));
    }
    let after = written.clone().and_then(|()| read_mapping(session, slot));
    if let Ok(mapping) = &after {
        log(&format!("read back: {} entries, {physical:#04x}: {}", mapping.entries.len(), show(&mapping.entries)));
        for entry in &mapping.entries {
            log(&format!("  {}", crate::usb::hex(entry)));
        }
    }

    log(&format!("resetting slot {slot:#04x} to defaults (09 {slot:02x} 01 03 00 00)"));
    let reset = write_mapping(session, slot, &[])
        .and_then(|()| read_mapping(session, slot))
        .map_err(|error| {
            format!("resetting failed: {error}; holding the pairing button for about 8 seconds clears the settings")
        })?;
    log(&format!(
        "after reset: {} entries, {physical:#04x}: {}, {}",
        reset.entries.len(),
        show(&reset.entries),
        if reset.entries == before.entries { "same as before" } else { "NOT the same as before" }
    ));
    let written = after?;
    Ok(ProfileThenReset { before, written, reset })
}

/// What [`write_one_then_delete`] saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneThenDelete {
    pub before: Mapping,
    pub written: Mapping,
    pub deleted: Mapping,
    /// The deleted slot reads the same as `blank_reference`.
    pub deleted_is_blank: bool,
}

/// The app's way: write only the one button entry (and the end marker) to
/// `slot`, read back, then delete the slot's profile and read again,
/// comparing with `blank_reference`, an unused slot read beforehand. The
/// delete runs even when the write went unanswered.
pub fn write_one_then_delete<L: Link>(
    session: &mut Session<'_, L>,
    slot: u8,
    physical: u8,
    target: u8,
    blank_reference: u8,
    log: &mut dyn FnMut(&str),
) -> Result<OneThenDelete, String> {
    if slot & 0x0f == 0 {
        return Err("slot 00 holds the default profile; not deleting it".to_owned());
    }
    let blank = read_mapping(session, blank_reference)?;
    let before = read_mapping(session, slot)?;
    log(&format!(
        "slot {slot:#04x}: {} entries, {physical:#04x} -> {:02x?}; blank reference {blank_reference:#04x}: {} entries",
        before.entries.len(),
        button_target(&before.entries, physical),
        blank.entries.len()
    ));
    log(&format!("writing only {physical:#04x} -> {target:#04x}"));
    let written = write_mapping(session, slot, &[button_entry(physical, target)]);
    if let Err(error) = &written {
        log(&format!("write failed: {error}"));
    }
    let after = written.clone().and_then(|()| read_mapping(session, slot));
    if let Ok(mapping) = &after {
        log(&format!(
            "read back: {} entries, {physical:#04x} -> {:02x?}",
            mapping.entries.len(),
            button_target(&mapping.entries, physical)
        ));
    }

    log(&format!("deleting the profile in slot {slot:#04x}"));
    let deleted = delete_profile(session, slot).and_then(|()| read_mapping(session, slot)).map_err(|error| {
        format!("deleting failed: {error}; holding the pairing button for about 8 seconds clears the settings")
    })?;
    let deleted_is_blank = deleted.entries == blank.entries;
    log(&format!(
        "after delete: {} entries, {physical:#04x} -> {:02x?}, {}",
        deleted.entries.len(),
        button_target(&deleted.entries, physical),
        if deleted_is_blank { "same as the blank reference" } else { "NOT the same as the blank reference" }
    ));
    let written = after?;
    Ok(OneThenDelete { before, written, deleted, deleted_is_blank })
}

/// What [`remap_and_restore`] saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundTrip {
    pub original: Mapping,
    pub changed: Mapping,
    pub restored: Mapping,
}

/// Map `physical` to `target` in `slot`, read it back, then write the
/// original entries back and read again. The original is restored even
/// when the changed mapping does not read back as written; an error after
/// the first write names the original entries so they can be put back by
/// hand. The original goes back even when the first write went unanswered.
pub fn remap_and_restore<L: Link>(
    session: &mut Session<'_, L>,
    slot: u8,
    physical: u8,
    target: u8,
    log: &mut dyn FnMut(&str),
) -> Result<RoundTrip, String> {
    let original = read_mapping(session, slot)?;
    let before = button_target(&original.entries, physical);
    log(&format!("slot {slot:#04x}: {} entries, {physical:#04x} -> {before:02x?}", original.entries.len()));
    if before == Some(target) {
        return Err(format!("{physical:#04x} already maps to {target:#04x}; pick another target"));
    }
    let wanted = with_button(&original.entries, physical, target);
    log(&format!("writing {physical:#04x} -> {target:#04x}"));
    // From here on the original is always written back, even if this write
    // went unanswered: it may still have been applied.
    let written = write_mapping(session, slot, &wanted);
    if let Err(error) = &written {
        log(&format!("write failed: {error}"));
    }
    let changed = written.clone().and_then(|()| read_mapping(session, slot));
    match &changed {
        Ok(mapping) => log(&format!(
            "read back: {physical:#04x} -> {:02x?}, {}",
            button_target(&mapping.entries, physical),
            if mapping.entries == wanted { "entries as written" } else { "entries differ from what was written" }
        )),
        Err(error) if written.is_ok() => log(&format!("read back failed: {error}")),
        Err(_) => {}
    }

    log("writing the original back");
    let restore = write_mapping(session, slot, &original.entries).and_then(|()| read_mapping(session, slot));
    let restored = match restore {
        Ok(mapping) if mapping.entries == original.entries => mapping,
        other => {
            let entries: Vec<String> = original.entries.iter().map(|e| crate::usb::hex(e)).collect();
            let what = match other {
                Ok(_) => "the restored slot does not match the original".to_owned(),
                Err(error) => format!("restoring failed: {error}"),
            };
            return Err(format!("{what}; original entries of slot {slot:#04x}: {}", entries.join(" | ")));
        }
    };
    log(&format!("restored: {physical:#04x} -> {:02x?}, entries match the original", button_target(&restored.entries, physical)));

    let changed = changed?;
    if button_target(&changed.entries, physical) != Some(target) {
        return Err(format!("the write was accepted but {physical:#04x} did not read back as {target:#04x}"));
    }
    Ok(RoundTrip { original, changed, restored })
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// `1e 02 08 01` from a physical Nano (6.19.50.0) over Bluetooth.
    pub const NANO_SLOT_01: &str = "00 08 00 01 1c 04 00 0d 00 05 00 01 00 00 05 00 01 01 00 05 00 01 02 00 05 00 01 03 00 05 00 01 04 00 05 00 01 05 00 05 00 01 06 00 05 00 01 07 00 05 00 01 08 00 05 00 01 09 00 05 00 01 0a 00 05 00 01 0b 00 05 00 01 0c 00 05 00 01 0d 00 05 00 01 0e 00 05 00 01 0f 00 05 00 01 1a 00 05 00 01 1b 00 05 00 01 1c 00 05 00 01 1d 00 05 00 01 1e 00 08 00 03 00 00 00 00 00 13 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 06 00 06 00 01 00 07 00 04 00 00 00 00 1c 00 05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 14 02";
    /// `1e 02 08 00` from the same Nano.
    pub const NANO_SLOT_00: &str = "00 08 80 00 05 05 00 01 00 05 05 00 01 01 07 05 00 01 02 04 05 00 01 03 06 08 00 03 00 64 64 64 64";

    pub fn bytes(hex: &str) -> Vec<u8> {
        hex.split_whitespace().map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
    }

    #[test]
    fn parses_the_nanos_slots() {
        let one = parse_mapping(&bytes(NANO_SLOT_01)).unwrap();
        assert_eq!((one.flags, one.slot, one.entries.len()), (0, 1, 28));
        let buttons: Vec<u8> = one.entries.iter().filter(|e| e[2] == ENTRY_BUTTON).map(|e| e[3]).collect();
        let mut expected: Vec<u8> = (0x00..=0x0f).collect();
        expected.extend([0x1a, 0x1b, 0x1c, 0x1d, 0x1e]);
        assert_eq!(buttons, expected);
        assert_eq!(button_target(&one.entries, ACTION_SHORT_PRESS), Some(0));

        let zero = parse_mapping(&bytes(NANO_SLOT_00)).unwrap();
        assert_eq!((zero.flags, zero.slot, zero.entries.len()), (0x80, 0, 5));
        assert_eq!(button_target(&zero.entries, 0x02), Some(0x04));
        assert_eq!(button_target(&zero.entries, ACTION_SHORT_PRESS), None);
    }

    #[test]
    fn rejects_bad_replies() {
        assert!(parse_mapping(&[0x43]).is_err());
        assert!(parse_mapping(&[0x02, 0x08, 0, 1, 0]).is_err());
        assert!(parse_mapping(&[0x00, 0x08, 0, 1, 1, 0x09, 0x00, 0x01]).is_err());
        assert!(parse_mapping(&[0x00, 0x08, 0, 1, 1, 0x05, 0x00, 0x01, 0x1c, 0x00, 0xff]).is_err());
    }

    #[test]
    fn set_request_round_trips_with_the_end_marker() {
        let one = parse_mapping(&bytes(NANO_SLOT_01)).unwrap();
        let request = set_mapping_request(1, &one.entries).unwrap();
        assert_eq!(&request[..4], &[0x02, 0x09, 0x01, 29]);
        assert_eq!(&request[request.len() - 3..], &END_MARKER);
        let back = parse_entries(&request[4..], 29).unwrap();
        assert_eq!(&back[..28], &one.entries[..]);
        assert_eq!(request.len(), 4 + 181 + 3);
    }

    #[test]
    fn changes_only_the_one_button() {
        let one = parse_mapping(&bytes(NANO_SLOT_01)).unwrap();
        let changed = with_button(&one.entries, ACTION_SHORT_PRESS, 0x04);
        assert_eq!(changed.len(), one.entries.len());
        let differing: Vec<usize> = (0..changed.len()).filter(|&i| changed[i] != one.entries[i]).collect();
        assert_eq!(differing.len(), 1);
        assert_eq!(changed[differing[0]], button_entry(ACTION_SHORT_PRESS, 0x04));

        let zero = parse_mapping(&bytes(NANO_SLOT_00)).unwrap();
        let added = with_button(&zero.entries, ACTION_SHORT_PRESS, 0x04);
        assert_eq!(added.len(), 6);
        assert_eq!(added[4], button_entry(ACTION_SHORT_PRESS, 0x04));
    }

    struct EndpointLink {
        endpoint: crate::companion::device::CompanionEndpoint,
        queue: std::collections::VecDeque<Vec<u8>>,
        /// Swallow the reply to the n-th set mapping (1-based).
        lose_set_reply: Option<u32>,
        sets: u32,
    }

    impl EndpointLink {
        fn new() -> Self {
            let device = crate::companion::device::FakeNano::tala([6, 19, 50, 0]);
            Self {
                endpoint: crate::companion::device::CompanionEndpoint::new(device),
                queue: Default::default(),
                lose_set_reply: None,
                sets: 0,
            }
        }
    }

    impl Link for EndpointLink {
        fn send(&mut self, payload: &[u8]) -> Result<(), String> {
            let before = self.endpoint.mapping_writes;
            let replies = self.endpoint.handle_report(payload);
            if self.endpoint.mapping_writes != before {
                self.sets += 1;
                if self.lose_set_reply == Some(self.sets) {
                    return Ok(());
                }
            }
            self.queue.extend(replies);
            Ok(())
        }
        fn recv(&mut self, _: Duration) -> Result<Option<Vec<u8>>, String> {
            Ok(self.queue.pop_front())
        }
        fn max_fragment_data(&self) -> usize {
            58
        }
    }

    fn options() -> crate::companion::updater::Options {
        crate::companion::updater::Options {
            mutation_timeout: Duration::from_millis(1),
            ..Default::default()
        }
    }

    #[test]
    fn remaps_the_action_button_and_puts_it_back() {
        let mut link = EndpointLink::new();
        link.endpoint.store_as_written = true;
        let original = link.endpoint.mappings.clone();
        let mut session = Session::open(&mut link, 1, options()).unwrap();
        let mut lines = Vec::new();
        let trip = remap_and_restore(&mut session, 0x01, ACTION_SHORT_PRESS, 0x04, &mut |line| lines.push(line.to_owned())).unwrap();
        drop(session);
        assert_eq!(button_target(&trip.changed.entries, ACTION_SHORT_PRESS), Some(0x04));
        assert_eq!(trip.restored, trip.original);
        assert_eq!(link.endpoint.mappings, original);
        assert_eq!(link.endpoint.mapping_writes, 2);
        assert!(lines.iter().any(|line| line.contains("entries as written")), "{lines:?}");
    }

    #[test]
    fn restores_even_when_a_write_reply_is_lost() {
        let mut link = EndpointLink::new();
        link.endpoint.store_as_written = true;
        let original = link.endpoint.mappings.clone();
        link.lose_set_reply = Some(1);
        let mut session = Session::open(&mut link, 1, options()).unwrap();
        // The first write is applied but its reply lost.
        let error = remap_and_restore(&mut session, 0x01, ACTION_SHORT_PRESS, 0x04, &mut |_| {}).unwrap_err();
        assert!(error.contains("no response"), "{error}");
        drop(session);
        assert_eq!(link.endpoint.mapping_writes, 2);
        assert_eq!(link.endpoint.mappings, original);
    }

    #[test]
    fn says_what_to_put_back_when_restoring_fails() {
        let mut link = EndpointLink::new();
        link.endpoint.store_as_written = true;
        link.lose_set_reply = Some(2);
        let mut session = Session::open(&mut link, 1, options()).unwrap();
        let error = remap_and_restore(&mut session, 0x01, ACTION_SHORT_PRESS, 0x04, &mut |_| {}).unwrap_err();
        assert!(error.contains("restoring failed") && error.contains("05 00 01 1c 00"), "{error}");
    }

    #[test]
    fn refuses_a_target_the_button_already_has() {
        let mut link = EndpointLink::new();
        let mut session = Session::open(&mut link, 1, options()).unwrap();
        assert!(remap_and_restore(&mut session, 0x01, ACTION_SHORT_PRESS, 0x00, &mut |_| {}).is_err());
        drop(session);
        assert_eq!(link.endpoint.mapping_writes, 0);
    }

    #[test]
    fn a_slot_the_device_does_not_have_is_not_written() {
        let mut link = EndpointLink::new();
        let mut session = Session::open(&mut link, 1, options()).unwrap();
        assert!(remap_and_restore(&mut session, 0x08, ACTION_SHORT_PRESS, 0x04, &mut |_| {}).is_err());
        drop(session);
        assert_eq!(link.endpoint.mapping_writes, 0);
    }

    #[test]
    fn a_full_write_of_a_blank_slot_reads_back_as_the_default_like_on_the_nano() {
        // What a physical Nano did: the full blank list written to slot 01
        // read back as slot 00's five entries, the change dropped.
        let mut link = EndpointLink::new();
        let mut session = Session::open(&mut link, 1, options()).unwrap();
        let error = remap_and_restore(&mut session, 0x01, ACTION_SHORT_PRESS, 0x04, &mut |_| {}).unwrap_err();
        assert!(error.contains("does not match the original"), "{error}");
        assert_eq!(read_mapping(&mut session, 0x01).unwrap().entries, read_mapping(&mut session, 0x00).unwrap().entries);
    }

    #[test]
    fn one_entry_then_delete_leaves_the_slot_blank() {
        let mut link = EndpointLink::new();
        let mut session = Session::open(&mut link, 1, options()).unwrap();
        let trip = write_one_then_delete(&mut session, 0x01, ACTION_SHORT_PRESS, 0x04, 0x02, &mut |_| {}).unwrap();
        drop(session);
        assert_eq!(button_target(&trip.written.entries, ACTION_SHORT_PRESS), Some(0x04));
        assert!(trip.deleted_is_blank);
        assert_eq!(link.endpoint.mappings, crate::companion::device::CompanionEndpoint::new(
            crate::companion::device::FakeNano::tala([6, 19, 50, 0])).mappings);
        assert_eq!((link.endpoint.mapping_writes, link.endpoint.profile_deletes), (1, 1));
    }

    #[test]
    fn deletes_even_when_the_one_entry_write_goes_unanswered() {
        let mut link = EndpointLink::new();
        link.lose_set_reply = Some(1);
        let mut session = Session::open(&mut link, 1, options()).unwrap();
        let error = write_one_then_delete(&mut session, 0x01, ACTION_SHORT_PRESS, 0x04, 0x02, &mut |_| {}).unwrap_err();
        assert!(error.contains("no response"), "{error}");
        drop(session);
        assert_eq!(link.endpoint.profile_deletes, 1);
        assert_eq!(link.endpoint.mappings[&0x01].1, link.endpoint.mappings[&0x02].1);
    }

    #[test]
    fn never_deletes_the_default_slot() {
        let mut link = EndpointLink::new();
        let mut session = Session::open(&mut link, 1, options()).unwrap();
        assert!(write_one_then_delete(&mut session, 0x00, ACTION_SHORT_PRESS, 0x04, 0x02, &mut |_| {}).is_err());
        assert!(write_one_then_delete(&mut session, 0x10, ACTION_SHORT_PRESS, 0x04, 0x02, &mut |_| {}).is_err());
        drop(session);
        assert_eq!((link.endpoint.mapping_writes, link.endpoint.profile_deletes), (0, 0));
    }

    #[test]
    fn builds_a_profile_the_apps_way() {
        let entries = profile_entries(&[button_entry(ACTION_SHORT_PRESS, 0x04)], [0xab; 16], "xboxctl test", false);
        let request = set_mapping_request(0x01, &entries).unwrap();
        assert_eq!(&request[..4], &[0x02, 0x09, 0x01, 5]);
        let back = parse_entries(&request[4..], 5).unwrap();
        assert_eq!(back[0], button_entry(ACTION_SHORT_PRESS, 0x04));
        assert_eq!((back[1].len(), back[1][2]), (19, ENTRY_GUID));
        assert_eq!((back[2].len(), back[2][2]), (131, ENTRY_NAME));
        assert_eq!(&back[2][3..15], b"xboxctl test");
        assert_eq!(back[3], vec![0x04, 0x00, 0x0d, 0x00]);
        assert_eq!(back[4], END_MARKER.to_vec());
        assert_eq!(set_mapping_request(0x01, &[]).unwrap(), vec![0x02, 0x09, 0x01, 0x01, 0x03, 0x00, 0x00]);
    }

    #[test]
    fn writes_a_profile_then_resets_to_the_default() {
        let mut link = EndpointLink::new();
        let mut session = Session::open(&mut link, 1, options()).unwrap();
        // Where the Nano's slot 01 is now: the default profile.
        write_mapping(&mut session, 0x01, &[]).unwrap();
        let trip = write_profile_then_reset(&mut session, 0x01, ACTION_SHORT_PRESS, Change::Target(0x04), [1; 16], "xboxctl test", &mut |_| {}).unwrap();
        assert_eq!(button_target(&trip.written.entries, ACTION_SHORT_PRESS), Some(0x04));
        assert_eq!(trip.reset, trip.before);
        assert_eq!(read_mapping(&mut session, 0x00).unwrap().entries, trip.reset.entries);
    }

    #[test]
    fn resets_even_when_the_profile_write_goes_unanswered() {
        let mut link = EndpointLink::new();
        link.lose_set_reply = Some(1);
        let mut session = Session::open(&mut link, 1, options()).unwrap();
        let error = write_profile_then_reset(&mut session, 0x01, ACTION_SHORT_PRESS, Change::Target(0x04), [1; 16], "t", &mut |_| {}).unwrap_err();
        assert!(error.contains("no response"), "{error}");
        drop(session);
        assert_eq!(link.endpoint.mapping_writes, 2);
    }

    #[test]
    fn never_writes_a_profile_to_the_default_slot() {
        let mut link = EndpointLink::new();
        let mut session = Session::open(&mut link, 1, options()).unwrap();
        assert!(write_profile_then_reset(&mut session, 0x10, ACTION_SHORT_PRESS, Change::Target(0x04), [1; 16], "t", &mut |_| {}).is_err());
        drop(session);
        assert_eq!(link.endpoint.mapping_writes, 0);
    }

    #[test]
    fn writes_a_keyboard_mapping_as_a_type_09_entry() {
        assert_eq!(Change::Keyboard { key: 0x7c, extra: 0 }.entry(ACTION_SHORT_PRESS), vec![0x06, 0x00, 0x09, 0x1c, 0x7c, 0x00]);
        let mut link = EndpointLink::new();
        let mut session = Session::open(&mut link, 1, options()).unwrap();
        let mut lines = Vec::new();
        write_profile_then_reset(&mut session, 0x01, ACTION_SHORT_PRESS, Change::Keyboard { key: 0x7c, extra: 0 }, [1; 16], "t", &mut |l| {
            lines.push(l.to_owned())
        })
        .unwrap();
        assert!(lines.iter().any(|l| l.contains("06 00 09 1c 7c 00")), "{lines:?}");
    }

    #[test]
    fn switches_the_active_mode_and_back() {
        let mut link = EndpointLink::new();
        let mut session = Session::open(&mut link, 1, options()).unwrap();
        assert_eq!(get_active_mode(&mut session).unwrap(), [0x80, 0x00]);
        set_active_mode(&mut session, 0x01).unwrap();
        assert_eq!(get_active_mode(&mut session).unwrap(), [0x80, 0x01]);
        set_active_mode(&mut session, 0x00).unwrap();
        assert_eq!(get_active_mode(&mut session).unwrap(), [0x80, 0x00]);
    }

    #[test]
    fn builds_a_full_profile_from_the_blank_layout() {
        let blank = parse_mapping(&bytes(NANO_SLOT_01)).unwrap().entries;
        let full = full_profile(&blank, ACTION_SHORT_PRESS, keyboard_entry(ACTION_SHORT_PRESS, 0x41, 0));
        assert_eq!(full.len(), 28);
        assert_eq!(button_target(&full, 0x04), Some(0x04));
        assert_eq!(button_target(&full, 0x00), Some(0x1a));
        assert_eq!(button_target(&full, 0x1a), Some(0x02));
        assert_eq!(button_target(&full, 0x1d), Some(0x00));
        assert!(full.contains(&keyboard_entry(ACTION_SHORT_PRESS, 0x41, 0)));
        assert_eq!(full.iter().filter(|e| e[2] != ENTRY_BUTTON).count(), blank.iter().filter(|e| e[2] != ENTRY_BUTTON).count() + 1);
        let request = set_mapping_request_full(0x01, &full).unwrap();
        assert_eq!(&request[..4], &[0x02, 0x09, 0x01, 28]);
        assert_ne!(&request[request.len() - 3..], &END_MARKER);
    }
}
