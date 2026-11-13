---
permalink: /nano-settings/
title: Nano settings messages
nav_order: 6
description: "Reverse engineering notes on how the Xbox Accessories app reads and writes Xbox Nano Controller settings (button remapping, the Action button, profiles, battery, factory reset) over the Companion Protocol. Static analysis only; nothing here has been sent to a controller yet."
---

# Nano settings messages
{: .no_toc }

How the Xbox Accessories app (2610.2610.13002.0, x64) reads and writes the
settings of a Pendragon device such as the Nano: button remapping, the Action
button, profiles, the friendly name, battery and factory reset. It builds on
[Xbox Nano Controller](../nano/), which covers sessions, fragments,
acknowledgements and the firmware update; read that first.

This is **static analysis only**. No Xbox console or working Windows install
was available, so no traffic was captured, and none of these requests has
been sent to a Nano. Every section says how sure it is:

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
| `xaccessories_sdk_uwp.dll` | `cfd25a1a…ed92d1b` | Companion Protocol SDK: sessions, opcodes, HID transport |
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
included for completeness. **Confirmed** (names), the meaning of a name is a
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

Two things follow from this table:

- **`1d` is telemetry**, not a keep-alive. The SDK pulls it with an empty
  `1d` request (5 s timeout) and keeps asking until a reply is empty
  (`0x180076af0`), only when the device has capability bit 9. The
  unsolicited `05 <handle+1> 1d …` frames seen on a physical Nano are
  presumably the device side of the same channel. That fits the finding that
  acking them does not stop the link from dropping.
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
| 8 | Shouldertaps | |
| 9 | Telemetry | `1d` telemetry |

Two more device information fields, **likely**:

- `0x25` (u32): the device's current state-subscription mask (`19`/`1a`
  below). The SDK stores it where `19` keeps its mask.
- `0x2d` (u32) and `0x31` (u16): the `ExternalMessageSupportedComponents`
  and `ExternalMessageVersion` fields of the SDK's connection telemetry
  (`0x1800592b0`). By the name, which `1e` message IDs the device accepts;
  whether the u32 is a bitmask indexed by message ID is a **guess**.

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

How the message ID is chosen (`MessageSender`, **confirmed** from code,
purpose a guess):

- A request whose class is a GIP class (`0x1000` GipCommand, `0x1001`,
  `0x1002` GipStandardLatency) keeps its message ID. All button and profile
  messages are of this kind and use ID **`0d`**.
- A request of class `Default` with an ID below `0x100` is sent with message
  ID **`02`** instead, and the SDK logs a warning. This is probably the
  origin of the `1e 02 05` the app sends right after the device information,
  but which app message that is has not been traced.

## Settings messages (`1e 0d`)

The app's button and profile code (classes `V2GetMappingMessage`,
`V2SetMappingMessage`, `V2GetActiveModeMessage`, `V2SetActiveModeMessage`,
`V2AddProfileMessage`, `V2DeleteProfileMessage`, `V2ResetProfileMessage`)
sends every message as a `Devices.Abstraction.MessageRequest` with message ID
`0d`, class `GipStandardLatency` and transport `Auto`, which on a Pendragon
device becomes an external message (`0x180cf3fe0`, `0x180cf7414`,
`0x180cf7db0`). The first data byte is a subcommand. On the wire:

```
05 <handle> 1e <seq> <len> 0d <subcommand> <arguments>
```

The response length cap (the size of the reply buffer the app allocates)
selects `1e`; all of these have a non-zero cap.

Whether the Nano answers them is not known. What ties them to the Nano is
that the same writer code knows the Action button (below) and that the app
has Nano-specific configuration types (`PendragonDeviceCHardwareConfiguration`,
`ConfigurationTypeValuePendragonDeviceC`, `SupportsPendragonDeviceCRemapping`,
`HasActionButton`). The physical Nano's `ExternalMessageSupportedComponents`
may settle it, and is in the device information reply `xboxctl info`
already reads; a `1e 0d 03` that comes back with status `43` would settle it
the other way.

| sub | message | request data | reply buffer | confidence |
|-----|---------|--------------|--------------|------------|
| `03` | get active mode | `03` | 3 bytes | confirmed bytes, name likely |
| `04` | set friendly name | `04` + name (32 bytes; 128 in `PendragonSetFriendlyNameMessage`) | 2 bytes | likely |
| `05` | get friendly name | `05` | `0x22` bytes | guess |
| `06` | set active mode | `06 <slot>` | 3 bytes | confirmed |
| `07` | transient state (heartbeat) | `07 00` | | likely, see below |
| `08` | get mapping | `08 <slot>` | up to `0x400` bytes | confirmed |
| `09` | set mapping | `09 <slot> <count> <entries>` | 3 bytes | confirmed |
| `0a` | delete profile | `0a <slot>` | 3 bytes | confirmed |
| `0b` | reset profile | `0b <slot>` | 3 bytes | confirmed |
| `0c` | add profile | `0c <slot>` | 3 bytes | confirmed |

The layout of the 3-byte replies has not been traced.

### Slot byte

`<slot>` in `06`, `08`, `0a` and `0c` is built by `0x180d1766c`: a slot index
0–7, plus `0x10` when a flag is set. **Confirmed** bytes. The flag is
probably the shift layer: the app keeps a second, "shifted" mapping for every
button (`ShiftedActionShortPressButtonMapping` and so on). **Guess.**

`0b` (reset) computes its slot differently (`0x180da8770`): a base slot taken
from the device object (`+0x2c`) plus the index minus one, plus `0x10` with
the flag. Where that base comes from has not been traced.

`06` (`0x180da8048`) and most other messages also store a u16 filled by a
runtime helper next to the message, probably a host-side transaction ID. It
is not part of the data. **Guess.**

### Mapping entries

`08` replies and `09` requests carry a list of entries. Each entry is
**confirmed** as:

```
<length:u16> <type> <data>      length counts the whole entry, itself included
```

The `08` reply has the entry count in byte 3 and the entries from byte 4
(`0x180d13a08`); bytes 0–2 are not interpreted there. An entry shorter than 3
bytes, or running past the end, is an error.

A `09` request is `09 <slot> <count>` followed by entries
(`0x180dac01c`). The app splits the entries over several `09` messages when
they do not fit the per-message limit it is given (`0x180daba5c`); each
message has its own count. Which limit a Nano gets is not known; the
session's `GetMaxMessageByteCount` is the obvious candidate. **Guess.**

Entry types the app writes (`0x180dab900`–`0x180daf000`). Lengths and type
bytes are **confirmed**; meanings are a **guess** unless stated.

| type | length | data | reading |
|------|--------|------|---------|
| `00` | 3 | none | written with sort key 1000, so it comes last: an end marker |
| `01` | 5 | `<physical> <target>` | button mapping, **confirmed** (below) |
| `02` | 4 | one byte of flags | analog options (stick/trigger swap and inversion) |
| `03` | 8 | five bytes | |
| `04` | 7 or 11 | four or eight bytes | |
| `05` | 28 | 25 bytes | |
| `06` | 6 | `00 01 <byte>` | |
| `08` | 8 or 19 | slot, action, `00 01`, data | programmable command (screenshot, record, …) |
| `09` | 6 | `<physical> <byte> <byte>` | keyboard mapping, used when bit 30 of the mapping is set |
| `0a`, `0c`, `0d` | 4 | one byte | `0d` is a boolean |
| `0b` | 5 | `<physical> <bool>` | a per-button flag, written alongside button mappings |
| `0e` | 107 | 104 bytes | |
| `0f` | 54 | 51 bytes | |
| `11` | 19 | 16 bytes | probably the profile GUID (`ReadProfileGuidAsync`) |
| `12` | 131 | 128 bytes | profile name, UTF-8, padded |
| (two bytes from the caller) | up to 613 | caller-supplied bytes | not identified (`0x180dac5b8`) |

### Button mappings

A button mapping entry is `05 00 01 <physical> <target>` (`0x180dadf64`).
**Confirmed.** The app writes one only when a button differs from its
default (`0x180daab60`). When the mapping is a programmable command (bit 28
of the app's mapping value), `<target>` is instead the ID of a type `08`
command entry.

The physical and target codes come from two tables in the app
(`0x180dadc9c`, `0x180d15f80`). Codes `00`–`0f` follow
`GipButtonMapVal` order (Enroll, Nexus, Menu, View, A, B, X, Y, D-pad up,
down, left, right, LB, RB, LS, RS), and A, B, X, Y, the bumpers, stick clicks
and the D-pad get the same code in both tables. **Likely.** The rest:

| physical code | button | confidence |
|---------------|--------|------------|
| `04`–`07` | A, B, X, Y | likely |
| `08`–`0b` | D-pad up, down, left, right | likely |
| `0c`, `0d` | LB, RB | likely |
| `0e`, `0f` | left, right stick click | likely |
| `10`, `11` | LT, RT | guess |
| `00`–`03` | four paddles or rear buttons (not on a Nano) | guess |
| `12`–`19` | stick directions | guess |
| `1a`, `1b` | Menu, View | guess |
| **`1c`** | **Action button, short press** | likely |
| **`1d`** | **Action button, long press** | likely |
| **`1e`** | **Action button, double press** | likely |
| `1f`, `20` | scroll wheel left/right press (Pendragon device B) | guess |

The Action button codes come from the app's internal button enum: its last
three values before the system and keyboard commands are named
`ActionShortPress`, `ActionLongPress`, `ActionDoublePress`, the writer
compares exactly those three against per-device defaults, and the target
table rejects them as targets (they are inputs only). Short and long press
have fixed defaults; the double-press default depends on the device type
(`0x180d1f7b4`).

Targets use the same codes for ordinary buttons; `00` means "nothing". Menu,
View and Nexus as targets are `02`, `03`, `01`. Keyboard keys (the app's
`Keyboard_*` values, bit 30) go into a type `09` entry instead.

### What the Action button does

The Action button's choices in the app are `ProgrammableKeyAction` values
(`Devices.Abstraction.winmd`): `TakeScreenshot` (2), `RecordClip` (3),
`ShowGuide` (1), media keys (9–12), `ShareUI` (18) and so on. These are
**executed by Windows**, not by the controller:
`ProgrammableKeyDetails.ExecuteMappedFunction(deviceProviderId)`. So the
controller presumably stores only "Action short press → programmable command
N" and reports a programmable-key event when it is pressed. How that event
reaches the host is **not known**: no HID report on macOS, which fits a
vendor-specific path (the companion channel inside a session, or Windows'
`xboxgamecontrollerdriver`). On macOS the useful part is the mapping itself:
remapping the Action button to an ordinary button target (an entry
`05 00 01 1c <target>`) would make it produce normal gamepad input.
**Guess**, untested.

## Transient state heartbeat (`1e 0d 07 00`)

`Devices.Abstraction`'s `PendragonController::RunHeartbeatTick`
(`0x1800888d0`) calls `Pendragon::TryHeartbeatTransientStatePhysicalAsync`
every second while the app holds a heartbeat (`IPendragonApi.Acquire…` /
`Release…TransientStatePhysicalHeartbeat`) and the device needs one
(`RequiresHeartbeatForTransientStatePhysical`). Its coroutine
(`0x180092d10`) sends a `MessageRequest` with ID `0d`, class `0x1002` and
data `07 00`, and waits 800 ms. **Likely:** the bytes are confirmed; that the
Pendragon path turns it into `1e 0d 07 00` follows from `MessageSender`.

What "transient state physical" means is unknown. The app sets it through
`BaseDevice.TrySetTransientStatePhysical` (and for GIP controllers when one
is added), so it may switch the controller into a mode that reports
unmapped (physical) buttons while the remapping UI is open. **Guess.** It is not used by the firmware updater, so it does not explain
the update link drop.

## Other requests

### `02`: battery

`0x180078340`. **Confirmed.** Empty request, 5 s timeout, only with
capability bit 1. The reply has no status byte:

| protocol | reply |
|----------|-------|
| below 2.0.22 | `<present> <percent> <charging>`, each byte non-zero for true; at least 3 bytes |
| 2.0.22 and later | `<flags> <percent>`, flags bit 0 present, bit 1 charging; at least 2 bytes |

`1b` (`st batt`) is probably the device-initiated battery notification;
not traced.

### `19`/`1a`: state subscription

`19` (`0x1800799d0`) sends a `u32` mask and gets back the device's new `u32`
mask; `1a` (`0x18008aa20`) the same for unsubscribing. **Confirmed** framing,
mask bits unknown. After the device information, and only for a device
with capability bit 8, the SDK computes a mask `0x3b`, minus bit 1 if the
device has a battery, minus bit 3 if it is updatable and minus bit 0 if it
has Wi-Fi, and compares it with the device's current mask (offset `0x25`
above). The rest of that branch was not traced.

### `2c`: factory reset

`0x18007f580`. **Confirmed.** `2c <reboot>`, one byte, `1` to restart
afterwards. Sent without a reply, and only to devices on protocol 2.0.18 or
later. This is the "wipe your settings" reset and **must not be sent while
testing**.

### `24`: power

`0x180079b80`, `24 <byte>` without a reply, as in
[Xbox Nano Controller](../nano/#24-power). **Confirmed.**

### Other app messages

Also built on the same base class, not sent through `0d` or not tied to the
Nano:

- ID `0e`, class `GipCommand`: `<enable> <r> <g> <b> <x>` (`0x180e6da2c`),
  probably the Nexus LED colour override (`NexusColorOverrideMessage`). Not
  relevant to the Nano.
- ID `0b`, class `GipCommand`, one byte (`0x180cf3294`). Unknown.

## Safe to try first

Read-only requests, in the order worth trying on a physical Nano. Each needs
an open session (see [Xbox Nano Controller](../nano/)):

1. `02`: battery. Read-only; needs capability bit 1, which tells whether the
   Nano reports one.
2. The device information reply's offset `0x2d` (`xboxctl info` already
   reads it): which external message IDs the Nano supports. Compare it with
   the result of the next request.
3. `1e 0d 03`: get active mode. Read-only, 3-byte reply.
4. `1e 0d 08 00`: get mapping for slot 0. Read-only; the reply's entries
   would show the Nano's real physical codes, including the Action button's.
   Then `08 01`…, and `08 10` for the shifted layer.
5. `1e 0d 05`: get friendly name. Probably read-only.
6. `17`: connection profile query. Read-only, but its payload has not been
   traced.

Not safe to try blind: `06` (switches the active profile), `09`, `0a`–`0c`,
`04`, `07`, `2a`/`2b` (Wi-Fi MAC), `24` (power) and above all `2c` (factory
reset). `1d` is harmless but drains the device's telemetry buffer.

## Open questions

- Whether the Nano accepts `1e 0d` at all, and the layout of the 3-byte
  replies and of the `08` reply's first three bytes.
- The meaning of most entry types and of the slot flag `0x10`.
- The per-message limit for `09`.
- How an Action button press reaches Windows when it is mapped to a
  programmable command.
- Which app message produces `1e 02 05`.

Nothing here needed `XboxAccessoriesService`; the settings logic is in the
app package.
