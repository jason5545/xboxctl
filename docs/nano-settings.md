---
permalink: /nano-settings/
title: Nano settings messages
nav_order: 6
description: "How the Xbox Accessories app reads and writes Xbox Nano Controller settings (button remapping, the Action button, profiles, battery, factory reset) over the Companion Protocol, from static analysis of the app and tests on a retail Nano over Bluetooth LE."
---

# Nano settings messages
{: .no_toc }

How the Xbox Accessories app (2610.2610.13002.0, x64) reads and writes the
settings of a Pendragon device such as the Nano: button remapping, the Action
button, profiles, the friendly name, battery and factory reset. It builds on
[Xbox Nano Controller](../nano/), which covers sessions, fragments,
acknowledgements and the firmware update; read that first.

The protocol was worked out by **static analysis** of the app; no Xbox
console or working Windows install was available, so no Windows traffic was
captured. Much of it has since been tried on a retail Nano (6.19.50.0,
protocol 2.0.22) over Bluetooth LE from macOS; see
[On a physical Nano](#on-a-physical-nano). The headline result: the Action
button can be mapped to a keyboard key, and the controller then sends that
key in its keyboard input report. Every section says how sure it is:

- **seen**: observed on a physical Nano;
- **confirmed**: read directly from code, the bytes are not in doubt;
- **likely**: the code path is clear but one link was inferred;
- **guess**: a reading of names or structure, not traced through code.

<details open markdown="block">
  <summary>Contents</summary>
  {: .text-delta }
- TOC
{:toc}
</details>

## Where the logic lives

Three files in the app package matter, all native code:

| file | SHA-256 | role |
|------|---------|------|
| `xaccessories_sdk_uwp.dll` | `cfd25a1a…ed92d1b` | Companion Protocol SDK: sessions, opcodes, HID and GATT transport |
| `Devices.Abstraction.dll` | `abcc143e…3a767d248` | C++/WinRT layer: `MessageSender`, `Pendragon`, heartbeat |
| `Devices.App.dll` | `bcabcba8…ec2a2832` | the app, compiled with .NET Native |

The SDK has no remapping or profile API. Its `Pendragon` class offers
battery, firmware, power, factory reset, Wi-Fi and connection profiles, and a
generic `SendReceiveHighPriorityMessageAsync(deviceId, messageId, data)`.
Everything about buttons and profiles is built by the app as raw bytes and
pushed through that generic call. So the settings protocol is defined by
`Devices.App.dll`, not by the SDK or by `XboxAccessoriesService`, and none of
it needs the service.

Addresses below are virtual addresses in these x64 files, image base
`0x180000000`.

## Opcode names

The SDK has a table of short names for every request opcode
(`0x180039450`). The ones [Xbox Nano Controller](../nano/) already covers are
included for completeness. **Confirmed** (names); the meaning of a name is a
reading.

| opcode | SDK name | opcode | SDK name |
|--------|----------|--------|----------|
| `01` | echo | `1e` | extmsg |
| `02` | batt | `1f` | extmsg no (no reply data) |
| `03` | fwup | `20` | troubl3 |
| `05` | wi pair | `21` | fwpkt |
| `07` | ctool | `22` | troubl4 |
| `0b` | fwetl | `23` | hello5 |
| `0d` | crash | `24` | rst |
| `0e` | user pair | `25` | fgfwup |
| `0f` | rigfail | `26` | conn erase |
| `10` | wi scan | `27` | conn pers |
| `11` | wi set2 | `28` | st haud |
| `16` | st rigfail | `29` | wmac get |
| `17` | conn query | `2a` | wmac set |
| `18` | conn set | `2b` | wmac rst |
| `19` | st sub | `2c` | factrst |
| `1a` | st unsub | `2d` | enr flt |
| `1b` | st batt | `2e` | hello6 |
| `1c` | hello4 | `2f` | (end of table) |
| `1d` | tele | | |

"st" is "shoulder tap", the SDK's term for a message the device starts.

- **`1d` is telemetry**, not a keep-alive. An empty `1d` from the device is a
  tap saying records are waiting; the SDK answers with empty `1d` requests
  (5 s timeout) until a reply is empty (`0x180076af0`), only when the device
  has capability bit 9. **Seen**: right after a session opened on handle
  `02`, a Nano sent `05 03 1d 38 00` on handle `03`; `1d` requests on the
  session's own handle `02` returned 24 records, text-labelled statistics
  (`TlsHeapStats`, `PerfStats`, `HeapStats`, `Boot`, `DeviceCount`), then an
  empty reply. `xboxctl` now fetches them the same way. Whether leaving them
  unfetched is what made the Nano go silent mid-update over USB has not been
  tested.
- The device information request is chosen by protocol version
  (`0x1800744b0`): `1c` below 2.0.4, `23` below 2.0.22, `2e` from 2.0.22.

All SDK requests go through one send function, `0x1800739e0(device, reply,
opcode, payload, length, timeout_ms)`; requests that expect no reply go
through `0x180073e10`.

## Capability bits

The `u32` at offset `0x29` of the device information reply fills the SDK's
`PendragonSupportedComponents` in field order (in the device information
handler `0x1800744b0`, which writes them to device fields
`+0x2ce`…`+0x2d7`). **Confirmed.**

| bit | component | gates |
|-----|-----------|-------|
| 0 | Debug | |
| 1 | Battery | `02` battery |
| 2 | FwUpdate | updates, `24` power |
| 3 | ModeManagement | |
| 4 | Wifi | `20`/`22` |
| 5 | Logging | |
| 6 | PacketTracing | |
| 7 | CrashDumps | `0d` crash dumps |
| 8 | Shouldertaps | `19`/`1a` subscriptions |
| 9 | Telemetry | `1d` telemetry |

A retail Nano on 6.19.50.0 reports `0x3ff`: all ten. **Seen.**

Three more device information fields:

- `0x25` (u32): the device's current shoulder tap subscription mask (`19`/`1a`
  below). The SDK stores it where `19` keeps its mask. **Likely.**
- `0x2d` (u32): `ExternalMessageSupportedComponents`, and `0x31` (u16):
  `ExternalMessageVersion`. **Confirmed** names: the SDK copies the two
  device fields (`+0x2d8`, `+0x2dc`) into the public `PendragonDeviceInfo`
  struct, whose winmd fields have exactly these names, in this order
  (`0x180078210`). A Nano reports `00000003` and `0001`. What the bits mean
  is not known: the SDK only copies them into that struct and into
  telemetry, it never checks them before sending `1e`. If bit *n* stands for
  message ID *n*+1, `3` would mean IDs `01` and `02`, which fits a Nano
  answering `02` and rejecting `0d`, but that is a **guess**.

## External messages (`1e`/`1f`)

Every app-defined message, including all settings messages below, is an
external message. **Confirmed** (`0x1800765a0`):

```
request:  1e <message id> <data>      a reply with data is wanted
          1f <message id> <data>      only a status is wanted
reply:    <status> <data>
```

- The request payload is at most the session maximum (`0x1002`), so `data`
  can be up to `0x1000` bytes.
- The reply always starts with a status byte, for `1f` too: `00` success,
  `02` invalid argument, `43` not supported, anything else an unexpected
  error. A `1f` reply must have no data after the status.
- `Devices.Abstraction` decides between the two by the request's response
  length cap: `0` sends `1f` (`SendHighPriorityMessageAsync`), anything else
  `1e` (`SendReceiveHighPriorityMessageAsync`). **Confirmed** in
  `MessageSender` (`0x180093de0`, Pendragon branch).

How the message ID is chosen (`MessageSender`, **confirmed** from code):

- A request whose class is a GIP class (`0x1000` GipCommand, `0x1001`,
  `0x1002` GipStandardLatency) keeps its message ID.
- A request of class `Default` with an ID below `0x100` is sent with message
  ID `02` instead, and `Devices.Abstraction` logs a warning.

The app picks the message ID per message, not per device (`0x180b90e44`,
**confirmed**): every app message object has a `byte?` property, and the
request's ID is that value or, when it is unset, `0d`. All the `V2…`
messages set it to `2` in their constructors; the older, non-V2 versions of
the same messages leave it unset and go out as `0d`. The Pendragon-only
sender `0x180f98ca4` ("Gip Command - sendReceiveMessage") always uses ID
`02`. So on a Nano everything below is `1e 02 …`. **Seen**: a Nano rejects
`1e 0d …` with status `02` and answers every `1e 02 …` request below.

## Settings messages (`1e 02`)

The app's button and profile code (classes `V2GetMappingMessage`,
`V2SetMappingMessage`, `V2GetActiveModeMessage`, `V2SetActiveModeMessage`,
`V2AddProfileMessage`, `V2DeleteProfileMessage`, `V2ResetProfileMessage`)
sends every message as a `Devices.Abstraction.MessageRequest` with class
`GipStandardLatency` and transport `Auto` (`0x180b90e44`), which on a
Pendragon device becomes an external message with ID `02`. The first data
byte is a subcommand. On the wire:

```
05 <handle> 1e <seq> <len> 02 <subcommand> <arguments>
```

Replies below include the external message's status byte (`00`). Request
layouts are **confirmed** from code; reply layouts are **seen** on a Nano
unless marked.

| sub | message | request data | reply |
|-----|---------|--------------|-------|
| `03` | get active mode | `03` | `00 03 80 <slot>` |
| `04` | set friendly name | `04` + name, 128 bytes on Pendragon devices | not tried |
| `05` | get friendly name | `05` | `00 05` + 129 bytes |
| `06` | set active mode | `06 <slot>` | `00 06 80 <slot now active>` |
| `07` | transient state (heartbeat) | `07 00` | not tried, see below |
| `08` | get mapping | `08 <slot>` | `00 08 <flags> <slot> <count> <entries>` |
| `09` | set mapping | `09 <slot> <count> <entries>` | `00 09 <result>`: `00` taken, `01` refused |
| `0a` | delete profile | `0a <slot>` | `00 0a 01` on a Nano; nothing changed |
| `0b` | reset profile | `0b <slot>` | not tried |
| `0c` | add profile | `0c <slot>` | not tried |

What the `80` in the active mode replies means is not known; slot `00`'s
`08` reply carries the same `80` as its flags byte, the other slots `00`.

### Friendly name (`05`, `04`)

The `05` reply is a 2-byte header and the name from offset 2: the app takes
at most 128 bytes (fewer if the reply is shorter) and decodes them with a
.NET `Encoding` (`0x180fa6fc0`; non-Pendragon devices: 32 bytes,
`0x180cf822c`). Only the decoding is traced, not the header bytes. A Nano
without a custom name answered status `00`, `05` and 129 zero bytes: an
empty name. **Seen.** `04` writes `04` followed by the name padded to 128
bytes (`0x180f9cdf0`, which throws when the encoded name is longer); this is
the controller's own name, not a button setting, and has not been tried.

### Slots

`<slot>` in `06`, `08`, `0a` and `0c` is built by `0x180d1766c`: a slot index
0–7, plus `0x10` when a flag is set. **Confirmed** bytes. The flag is
probably the shift layer: the app keeps a second, "shifted" mapping for every
button (`ShiftedActionShortPressButtonMapping` and so on). **Guess.**
The Pendragon path (`0x180faf4b4`, `0x180faf4f8`) computes the slot as a base
taken from the device object (`+0x2c`) plus the profile index minus one,
plus `0x10` with the flag. Where that base comes from has not been traced.

On a Nano all sixteen slots answer `08`. **Seen:**

- Slot `00` (flags `80`) is the active default profile, 5 entries:
  `05 00 01 00 05`, `05 00 01 01 07`, `05 00 01 02 04`, `05 00 01 03 06`
  and `08 00 03 00 64 64 64 64`. Slot `10` has the same entries, flags `00`.
- Every other slot read the same 28 entries: one `04 00 0d 00`, 21 button
  entries `05 00 01 <physical> 00` (physical `00`–`0f` and `1a`–`1e`),
  `08 00 03 00 00 00 00 00`, a 19-byte type `08` entry of zeros,
  `06 00 06 00 01 00`, `07 00 04 00 00 00 00`, a 28-byte type `05` entry of
  zeros and `04 00 14 02`. This is what an unused slot looks like.

The app has strings for three configuration slots
(`NarratorConfigurationSlot1Active` to `…Slot3Active`), so it may offer fewer
profiles than the device has slots. **Guess.**

`06` (`0x180da8048`) and most other messages also store a u16 filled by a
runtime helper next to the message, probably a host-side transaction ID. It
is not part of the data: `06 <slot>` alone switched a Nano's profile.

### Mapping entries

`08` replies and `09` requests carry a list of entries. Each entry is
**confirmed** as:

```
<length:u16> <type> <data>      length counts the whole entry, itself included
```

The app reads the entry count from the `08` reply's fourth byte after the
status and the entries from the fifth (`0x180d13a08`). An entry shorter than
3 bytes, or running past the end, is an error.

A `09` request is `09 <slot> <count>` followed by entries (`0x180dac01c`,
which appends each entry and bumps the count). The app splits the entries
over several `09` messages when they do not fit the per-message limit it is
given (`0x180daba5c`); each message has its own count.

### Two ways to write a profile

The app's profile writer (`0x180daab60`) has a flag that decides between two
modes, and the same flag makes the message constructor (`0x180dae6c4`) add
the end marker `03 00 00` (`0x180dae830`). **Confirmed.**

- **Full mode** (flag clear): every ordinary button gets an entry, mapped or
  not, and the analog, rumble and other entries are written whether or not
  they differ from the default. No end marker. The result has the same shape
  as the 28-entry layout of an unused slot.
- **Differences mode** (flag set): only buttons and settings that differ from
  the default, then the end marker.

The flag comes from an interface call the call graph does not resolve, so
which mode the app uses for a Nano is not known.

**Seen on a Nano: only full-mode writes are stored.**

- A full-mode write of the unused-slot layout, every button mapped to itself
  and one button changed, no end marker: result `00`. Reading the slot back
  gave 14 entries: the four `00`–`03` entries, the changed button, the
  Action button's other two entries and the seven non-button entries. Buttons
  mapped to themselves were dropped. So the device keeps what differs from
  its own default.
- Differences-mode writes (one changed entry, with or without the GUID, name
  and `0d` entries the app would add, then the end marker) were answered
  `00` or `01`, and nothing changed when the slot was read back or used.
- An end marker alone (`09 <slot> 01 03 00 00`) resets the slot to the
  default: it then reads back as slot `00`'s five entries. That is what the
  app's "restore defaults" sends (`0x180fafa6c` → `0x180faf4f8`, a message
  with the end marker and nothing else). The very first write, the
  unused-slot layout with the Action button changed and the end marker
  added, was answered `00` and also left the slot at the default.
- `0a <slot>` (delete) answered `01` and changed nothing, on a slot that had
  been reset to the default.

### Entry types

Entry types the app writes (`0x180dab900`–`0x180daf000`). Lengths and type
bytes are **confirmed**; meanings are a **guess** unless stated. Sort keys
order the entries: 0 for most, so they keep the writer's order.

| type | length | data | written by | reading |
|------|--------|------|------------|---------|
| `00` | 3 | none | `0x180dae830`, sort key 1000 | end marker, differences mode only |
| `01` | 5 | `<physical> <target>` | `0x180dadf64` | button mapping, **seen** (below) |
| `02` | 4 | one byte of flags | `0x180dada38` | analog options (stick/trigger swap and inversion) |
| `03` | 8 | a bool, four bytes | `0x180dad928` | four values, `64` (100) each on the default profile; maybe rumble strengths |
| `04` | 7 or 11 | four or eight bytes | `0x180dad7c0`, `0x180dad680` | |
| `05` | 28 | 25 bytes | `0x180dad374` | |
| `06` | 6 | `00 01 <byte>` | `0x180dad298` | |
| `08` | 8 or 19 | a 4-byte colour and settings | `0x180dacf10`, `0x180dad144` | the Nexus (Xbox button) light, see below |
| `09` | 6 | `<physical> <key> <byte>` | `0x180dae270` | keyboard mapping, **seen** (below) |
| `0a`, `0c` | 4 | one byte | `0x180dacdfc`, `0x180dacd20` | |
| `0b` | 5 | `<physical> <bool>` | `0x180dadba8` | a per-button flag, written alongside button mappings |
| `0d` | 4 | a bool | `0x180dacc54`, sort key 500 | |
| `0e` | 107 | 104 bytes | `0x180dac9b0` | |
| `0f` | 54 | 51 bytes | `0x180dac81c` | |
| `11` | 19 | 16 bytes | `0x180dacb44` | the profile GUID, written only when it is not empty |
| `12` | 131 | 128 bytes | `0x180dac368` | profile name, UTF-8, padded; written only when not empty |
| `14` | 4 | one byte | not found in the writer | seen as `04 00 14 02` in every unused slot |
| (two bytes from the caller) | up to 613 | caller-supplied bytes | `0x180dac5b8` | not identified |

Type `08` is not a programmable command, as an earlier version of this page
guessed. Both writers serialise a 32-byte structure through `0x180dad008`,
which writes `ff 00 00 00` when the structure's first byte is `ff` (or a
double in it is past a threshold) and otherwise `00` and three bytes of a
packed colour. The 8-byte form is `08 00 08 <byte> <colour>`; the 19-byte form
is `13 00 08 <colour> <byte> <byte> 00 01` and eight zero bytes. The values
come from the same objects as the app's Nexus colour and brightness pages.
**Likely.**

### Button mappings

The app keeps each button's mapping as a `u32` with flag bits
(`0x180dae3c8`, `0x180daab60`, `0x180dadf64`). **Confirmed** bits:

| bits | kind | written as |
|------|------|------------|
| none | ordinary button | type `01`, target from the target table |
| 24 | system command | type `01`, target from the target table |
| 28 | programmable command | type `01`, target = a command index the app keeps per button |
| 30 | keyboard key | type `09`: `06 00 09 <physical> <low byte of the value> <a byte of the mapping>` |

In full mode every ordinary button gets an entry. The Action button's three
inputs (and the scroll wheel presses of another Pendragon device) are
skipped while they equal their per-device default (`0x180d1f7b4` for the
double press).

The physical and target codes come from two tables, both indexed by the
app's internal button enum: physical `0x180dadc9c`, target `0x180d15f80`.
**Confirmed** codes; the button names are read from the enum's order and
from the Nano's own profile, and are **likely** unless marked.

| button | physical | as a target |
|--------|----------|-------------|
| A, B, X, Y | `04`–`07` | `04`–`07` |
| LB, RB | `0c`, `0d` | `0c`, `0d` |
| LT, RT | `10`, `11` | `10`, `11` |
| left, right stick click | `0e`, `0f` | `0e`, `0f` |
| D-pad up, down, left, right | `08`–`0b` | `08`–`0b` |
| stick directions (guess) | `12`–`19` | `12`–`19`, in a different order |
| four paddles (guess; not on a Nano) | `00`–`03` | `1a`–`1d` |
| Menu, View | `1a`, `1b` | `02`, `03` |
| Nexus (Xbox button) | — | `01` |
| **Action button, short / long / double press** | **`1c`, `1d`, `1e`** (**seen** in the Nano's profile) | not a target |
| scroll wheel left/right press (another device) | `1f`, `20` | |
| nothing | | `00` |

Physical and target codes differ for the paddles and for Menu and View, so a
button mapped to itself is not always `<code> <same code>`: the Nano's
paddle entries in slot `00` are probably that kind of default, not a remap.
**Guess.**

System commands are `0x1000000 + N` in the app, with `N` a
`ProgrammableKeyAction` (`Devices.Abstraction.winmd`); their target is
`0x49 + N`:

| target | action | target | action |
|--------|--------|--------|--------|
| `4a` | ShowGuide | `53` | MediaVolumeUp |
| `4b` | TakeScreenshot | `54` | MediaVolumeDown |
| `4c` | RecordClip | `55` | MediaMute |
| `4d` | SendMessage | `56` | ViewAchievements |
| `4e` | Bing | `58` | ViewParty |
| `4f` | LaunchApp | `59` | RecordClipStartStop |
| `52` | MediaPlayPause | `5b` | ShareUI |
| | | `5c`–`5e` | QuickSettings, HighContrast, NightMode |

### What the Action button does

**Seen on a Nano:**

- Mapping the Action button to an ordinary button is refused:
  `05 00 01 1c 04` (A) got result `01` in differences mode, with and without
  the GUID and name. It has not been tried in full mode without the end
  marker.
- Mapping it to a keyboard key works. A full-mode write with
  `06 00 09 1c <key> 00`, then `06 01` to make that slot active: every press
  of the Action button sent the controller's keyboard input report (report
  ID 5) with the key, `05 00 00 <key> 00 00 00 00 00`, and an all-zero
  report on release.
- The key byte is a HID keyboard usage, not a Windows virtual-key code: `04`
  arrived as `a`, `41` as F8. What the last byte of the entry does is not
  known; it was `00` in both tests (modifiers is one reading).
- A system command target (`05 00 01 1c 52`, media play/pause) was accepted
  (`00`) in differences mode, which stores nothing, so it is untested.

Out of the box the Action button sends nothing over HID on a Mac: its default
action is carried out by Windows (`ProgrammableKeyDetails.ExecuteMappedFunction`),
which on macOS has no counterpart.

**macOS drops the keyboard reports.** The Nano's HID descriptor has game pad
(`1/5`), pointer, keyboard (`1/6`), mouse and the vendor collection, but
macOS creates only a game pad service for it (`hidutil list` shows usage
`1/5` alone), so the keyboard report types nothing. A program that opens the
HID device itself (IOKit or hidapi, shared, no extra permission) does receive
report 5.

## Transient state heartbeat (`07 00`)

`Devices.Abstraction`'s `PendragonController::RunHeartbeatTick`
(`0x1800888d0`) calls `Pendragon::TryHeartbeatTransientStatePhysicalAsync`
every second while the app holds a heartbeat (`IPendragonApi.Acquire…` /
`Release…TransientStatePhysicalHeartbeat`) and the device needs one
(`RequiresHeartbeatForTransientStatePhysical`). Its coroutine
(`0x180092d10`) sends a `MessageRequest` with ID `0d`, class `0x1002` and
data `07 00`, and waits 800 ms. **Confirmed** bytes. Unlike the app's
messages this one has its ID fixed at `0d`, so on a Nano it would go out as
`1e 0d 07 00`, which the Nano rejects for every other `0d` request. It is
only sent when the device reports `RequiresHeartbeatForTransientStatePhysical`,
so a Nano probably never gets it. **Likely.** It is not a keep-alive for the
session either: nothing in it refers to the link. None of the tests on this
page needed it.

What "transient state physical" means is unknown. The app sets it through
`BaseDevice.TrySetTransientStatePhysical` (and for GIP controllers when one
is added), so it may switch the controller into a mode that reports unmapped
(physical) buttons while the remapping UI is open. **Guess.**

## Other requests

### `02`: battery

`0x180078340`. **Confirmed.** Empty request, 5 s timeout, only with
capability bit 1. The reply has no status byte:

| protocol | reply |
|----------|-------|
| below 2.0.22 | `<present> <percent> <charging>`, each byte non-zero for true; at least 3 bytes |
| 2.0.22 and later | `<flags> <percent>`, flags bit 0 present, bit 1 charging; at least 2 bytes |

A Nano on protocol 2.0.22 answered `01 46`: a battery, not charging, 70%.
**Seen.**

`1b` (`st batt`) is the device-initiated battery notification. **Seen**: a
Nano sent `05 03 1b 3d 02 01 46`, the same `<flags> <percent>` as the `02`
reply, every few seconds and with the same sequence while it went unacked.

### `19`/`1a`: shoulder tap subscription

`19` (`0x1800799d0`) sends a `u32` mask and gets back the device's new `u32`
mask; `1a` (`0x18008aa20`) the same for unsubscribing. **Confirmed** framing.
The mask is the SDK's `PendragonShouldertapsFlags` (winmd), so these are
subscriptions to device-initiated notifications:

| bit | flag |
|-----|------|
| `01` | RigFailure |
| `02` | BatteryStats |
| `04` | Telemetry |
| `08` | FirmwareUpdate |
| `10` | ConnectionChange |
| `20` | ExternalMessage |
| `40` | HostAudio |

After the device information, and only for a device with capability bit 8,
the SDK starts from `0x3b` (RigFailure, BatteryStats, FirmwareUpdate,
ConnectionChange, ExternalMessage), clears bit `02`, `08` or `01` depending
on the battery, update and Wi-Fi capabilities, and compares the result with
the device's current mask (offset `0x25` above). The rest of that branch
was not traced. Incoming taps are checked against a mask in the SDK
(`0x180049cf8`; `16`→1, `1b`→2, `1d`→4, `03`→8, `17`→`0x10`, `1f`→`0x20`,
`28`→`0x40`) and dropped when their bit is clear. Without sending `19`, a
Nano still sent `1d` and `1b` taps. **Seen.**

Taps come on the handle after a session's own, but not always the current
session's. A second session on the same Bluetooth connection got handle
`04`, while the device kept sending its taps on `03`, the first session's
handle + 1. **Seen.** `xboxctl` therefore acks frames on any handle other
than its session's.

### `2c`: factory reset

`0x18007f580`. **Confirmed.** `2c <reboot>`, one byte, `1` to restart
afterwards. Sent without a reply, and only to devices on protocol 2.0.18 or
later. This is the "wipe your settings" reset and **must not be sent while
testing**.

### `24`: power

`0x180079b80`, `24 <byte>` without a reply, as in
[Xbox Nano Controller](../nano/#24-power). **Confirmed.**

### Other app messages

Also built on the same base class, not tied to the Nano:

- ID `0e`, class `GipCommand`: `<enable> <r> <g> <b> <x>` (`0x180e6da2c`),
  probably the Nexus LED colour override (`NexusColorOverrideMessage`).
- ID `0b`, class `GipCommand`, one byte (`0x180cf3294`). Unknown.
- ID `02` through the Pendragon-only sender: `01 <command> <setting>
  <payload>` messages (`0x180f9911c`) for the Norland headset's settings
  (`NorlandSettingLevelToPCPSettingValue`), not the Nano.

## GATT transport

Over Bluetooth LE the SDK uses `BluetoothCompanionTransport` on top of a
`PAL::BluetoothLEHelper`, which calls the WinRT GATT API. **Confirmed** from
code unless noted.

- **Service and characteristic.** Service
  `00000000-16e2-469d-8013-a85ccd1a3f11`, characteristic
  `00000004-16e2-469d-8013-a85ccd1a3f11`, both directions on the one
  characteristic (constructor `0x1800ba020`). The host writes with response
  (`WriteValueAsync`); the device answers by indication. **Seen.**
- **No report ID.** Each GATT value is one whole Companion Protocol frame,
  starting with the frame type, unlike HID's `0c` report ID. **Seen.**
- **Frame size.** The SDK caps a frame at the smaller of the GATT maximum PDU
  and 247 bytes, minus 3. `xboxctl` sends the same 63-byte frames it uses over
  USB, and fragmented requests of up to 189 bytes went through.
- **Standalone `06`.** A Nano also sends one-byte values `06` on the
  characteristic, about two a second while a session is open. The SDK only
  logs them. **Seen.**
- The Nano exposes two more services, `4D504100-…` and `27391C7D-…`; not
  looked at.

On macOS the HID route does not work over Bluetooth: the Bluetooth HID device
refuses output report `0c` (`IOHIDDeviceSetReport` returns
`kIOReturnNotFound`, while the rumble report 3 goes through). The GATT
characteristic does work, through CoreBluetooth. CoreBluetooth needs its own
Bluetooth permission, so `xboxctl` uses a small helper app,
`tools/nano-ble-bridge`, and talks to it over a Unix socket.

## On a physical Nano

All of the above marked **seen** comes from one retail Nano (`045e:0b4f`,
hardware revision `0x0c06`, firmware 6.19.50.0, protocol 2.0.22) over
Bluetooth LE from macOS, with hidden `xboxctl` commands (macOS only, each
taking `--ble <path to nano-ble.app>`):

| command | what it does | writes? |
|---------|--------------|---------|
| `nano-probe` | device info, battery, active mode, mappings of slots `00`, `01`, `10`, `11`, friendly name | no |
| `nano-hold` | holds a session open, fetching telemetry when tapped, battery every 15 s | no |
| `nano-remap-test` | lists slots `00`–`07` and `10`–`17`, then one of several write experiments on a spare slot, each followed by a reset to the default | yes, slot `01` |
| `nano-activate-test --full` | full-mode write of a keyboard key to a spare slot, makes it active, asks aloud for presses, then switches back to slot `00` and resets the spare slot | yes, slot `01` and the active slot |

Every write test left the controller as it was: slot `00` active and slot
`01` holding the default (it had been an unused 28-entry slot before the
first test; a reset brings a slot to the default, not back to unused).

## Safe to try first

On a Nano, in this order:

1. Read-only: `02` (battery), `1e 02 03` (active mode), `1e 02 08 <slot>`
   (mappings), `1e 02 05` (friendly name). `nano-probe` sends these.
2. Writes to a slot other than `00`/`10`, in full mode: read an unused slot,
   change one entry, write it with `09` and no end marker, read it back.
   Undo with `09 <slot> 01 03 00 00`.
3. `06 <slot>` to try a written slot, and `06 00` to go back.

Not safe to try blind:

- `2c`: factory reset.
- Writing slot `00`, the default profile.
- `0b` (reset profile) and `0c` (add profile): not tried; their effect on a
  slot is not known.
- `04` (friendly name): changes the controller's name.

## Open questions

- Which mode the app uses for a Nano, and why the device acknowledges
  differences-mode writes without storing them.
- What `80` in the active mode replies and in slot `00`'s flags means, and
  what `0a`'s and `09`'s result `01` means beyond "not done".
- Whether system command targets (`4a`…`5e`) work when written in full mode,
  and how the controller reports them to the host.
- How programmable commands (bit 28) store the command a button runs.
- What the last byte of a type `09` keyboard entry does.
- What entry type `14` is; the app's writer does not produce it.
- How to get the keyboard reports to macOS as typing: a user-space program
  reading the HID device, or a tool that seizes the device such as
  Karabiner-Elements (not tried).
- Whether fetching telemetry keeps a Nano answering through a full update
  over USB.
