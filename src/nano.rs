//! Status and firmware update for Pendragon accessories (the Xbox Nano
//! Controller and relatives), which speak Microsoft's Companion Protocol over
//! HID instead of GIP. Called from `main.rs`'s `info` and `update` commands
//! once device selection finds a Pendragon accessory rather than a GIP
//! controller. See `docs/nano.md` for what is and is not known about this
//! protocol, and its biggest caveat: none of it has been checked against a
//! physical Nano yet.

use crate::companion::{
    firmware::Image,
    protocol::DeviceInfo,
    updater::{
        finish_flags_for, resume_after_lost_link, Event, Expected, FinishFlags, Options, Reconnect,
        Session,
    },
};
use crate::feed;
use crate::usb::{self, NanoDevice, NanoLink};
use std::{
    cell::Cell,
    fs,
    io::{self, BufRead, Write},
    path::Path,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// How long to wait for the device to re-enumerate after an update; it has
/// been seen to restart itself about 1.5 s after `finish`.
const RESTART_TIMEOUT: Duration = Duration::from_secs(30);

fn version(parts: [u16; 4]) -> String {
    format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], parts[3])
}

/// Not cryptographically random, just unlikely to repeat; it only needs to
/// tell this session's open request apart from a stale one.
fn session_id() -> u32 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    nanos ^ std::process::id()
}

fn open_session<L: crate::companion::updater::Link>(link: &mut L) -> Result<Session<'_, L>, String> {
    Session::open(link, session_id(), Options::default())
}

fn print_device_info(info: &DeviceInfo) {
    println!("Hardware revision {:#06x}", info.hardware_revision);
    println!("Firmware          {}", version(info.firmware_version));
    println!(
        "Updatable         {}",
        if info.is_updatable() { "yes" } else { "no" }
    );
}

pub fn status(nano: &NanoDevice, trace: bool) -> Result<(), String> {
    let mut link = NanoLink::open(nano, trace)?;
    let mut session = open_session(&mut link)?;
    print_device_info(&session.device_info()?);
    Ok(())
}

/// The image to install: a local PPAS file, or the current firmware for the
/// device's hardware revision from Microsoft's flight feed (see
/// `feed::NANO_FEED_URL`; it is not the feed the Xbox Accessories app's own
/// update check uses, and has not been checked against physical hardware).
///
/// Also returns the feed entry's `req` version, which decides the finish
/// flags (see `Session::choose_finish_flags`); a local file has none.
fn load_image(
    image_path: Option<&Path>,
    info: &DeviceInfo,
) -> Result<(Image, Option<[u16; 4]>), String> {
    if let Some(path) = image_path {
        let bytes = fs::read(path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?;
        return Ok((Image::parse(&bytes)?, None));
    }
    let feed = feed::fetch_nano_feed()?;
    let entry = feed
        .device_by_hardware_revision(info.vendor_id, info.hardware_revision)
        .ok_or_else(|| {
            format!(
                "the flight feed has no entry for hardware revision {:#06x}",
                info.hardware_revision
            )
        })?;
    let file = entry
        .files
        .first()
        .ok_or_else(|| format!("the feed lists no firmware for {}", entry.id))?;
    let directory = feed::cache_dir();
    let (path, image) = feed::download_image(&feed, file, &directory)?;
    println!(
        "{} ({}) firmware {} [{}], SHA-256 verified",
        entry.id,
        entry.codename,
        image.version_string(),
        file.tag
    );
    println!("{}", path.display());
    Ok((image, entry.required_version()))
}

/// The finish flags, worded for the user.
fn describe_finish_flags(choice: FinishFlags) -> String {
    match choice {
        FinishFlags::Override(flags) => format!("{flags} (XBOXCTL_NANO_FINISH_FLAGS)"),
        FinishFlags::Required { flags, required } => format!(
            "{flags} (firmware is below the feed's required {})",
            version(required)
        ),
        FinishFlags::Default => "1 (default)".to_owned(),
    }
}

pub fn update(
    nano: &NanoDevice,
    image_path: Option<&Path>,
    dry_run: bool,
    yes: bool,
    trace: bool,
) -> Result<(), String> {
    // One session from the first read to the write, so the device is read
    // and written within as little of its link's life as possible: a
    // physical retail Nano (6.9.444.0) stopped answering about three and a
    // half minutes after it was plugged in, acks or not, until it was
    // replugged. Frames that arrive while the image downloads or the prompt
    // waits queue up and are acked by the recheck below. If the link drops
    // anyway, before or during the write, `resume_after_lost_link` brings
    // the device back and carries on from where it stopped.
    let mut link = NanoLink::open(nano, trace)?;
    let mut session = open_session(&mut link)?;
    let info = session.device_info()?;
    print_device_info(&info);
    if !info.is_updatable() {
        return Err("the device does not report itself as updatable".to_owned());
    }

    let (image, required) = load_image(image_path, &info)?;
    println!(
        "Image: firmware {} ({:#x} bytes)",
        image.version_string(),
        image.data.len()
    );
    if image.version == info.firmware_version {
        println!("The device already runs this firmware; nothing to do.");
        return Ok(());
    }
    if image.version < info.firmware_version {
        return Err(format!(
            "the image ({}) is older than the device's firmware ({}); refusing to downgrade",
            image.version_string(),
            version(info.firmware_version)
        ));
    }
    let options = Options::default();
    let planned = finish_flags_for(options.finish_flags, info.firmware_version, required);
    println!("Finish flags      {}", describe_finish_flags(planned));
    println!(
        "1d acks           {}",
        if options.ack_device_1d {
            "on"
        } else {
            "off (XBOXCTL_NANO_ACK_1D=0)"
        }
    );
    if dry_run {
        println!(
            "Would update {} -> {}",
            version(info.firmware_version),
            image.version_string()
        );
        return Ok(());
    }
    if !yes {
        println!(
            "\nThis writes firmware to the device and will restart it. Keep it connected \
             until the update finishes. This path has been checked against a model of the \
             retail Nano, not against the hardware itself (see docs/nano.md); an interrupted \
             or failed update may leave the device unusable."
        );
        print!("Type 'update' to continue: ");
        io::stdout().flush().ok();
        let mut answer = String::new();
        io::stdin()
            .lock()
            .read_line(&mut answer)
            .map_err(|error| error.to_string())?;
        if answer.trim() != "update" {
            return Err("cancelled".to_owned());
        }
    }

    // A session opened after a lost link must finish with the same flags.
    let mut resume_options = options.clone();
    resume_options.finish_flags = match planned {
        FinishFlags::Override(flags) | FinishFlags::Required { flags, .. } => Some(flags),
        FinishFlags::Default => None,
    };
    let expected = Expected {
        hardware_revision: info.hardware_revision,
        firmware_version: info.firmware_version,
    };

    // Set when a reconnected device turns out to run the new firmware
    // already: the finish went through before the link dropped.
    let up_to_date = Cell::new(false);
    let mut line = crate::progress::ProgressLine::new();
    let mut report = |event: &Event| match event {
        Event::UpToDate => {
            up_to_date.set(true);
            line.finish("The device already runs the new firmware.")
        }
        Event::Begin {
            resume_offset,
            total,
        } => {
            line.break_line();
            println!("  writing from byte {resume_offset} of {total:#x}");
        }
        Event::Progress { done, total } => {
            let percent = u64::from(*done) * 100 / u64::from(*total).max(1);
            line.update(&format!("  writing {percent:>3}%"), percent);
        }
        Event::Finished => {
            line.finish("Finished. The device restarts itself into the new firmware.")
        }
    };
    // Same session, read again: the device must still answer and be the one
    // shown above. A device that stopped answering here (a slow download or
    // prompt) has nothing written yet and goes the lost-link way below.
    let first = match session.device_info() {
        Ok(now) => {
            if now.hardware_revision != info.hardware_revision
                || now.firmware_version != info.firmware_version
            {
                return Err(format!(
                    "the device changed since it was read (hardware {:#06x}, firmware {} -> {:#06x}, {}); \
                     not writing. Run the command again.",
                    info.hardware_revision,
                    version(info.firmware_version),
                    now.hardware_revision,
                    version(now.firmware_version)
                ));
            }
            let chosen = session.choose_finish_flags(now.firmware_version, required);
            if chosen != planned {
                return Err(format!(
                    "finish flags changed between the check and the write ({} -> {}); not writing",
                    describe_finish_flags(planned),
                    describe_finish_flags(chosen)
                ));
            }
            session.update(&image, &mut report)
        }
        Err(error) => Err(format!("the device stopped answering before the write ({error})")),
    };
    let lost = session.link_lost();
    // Release the interface before the device drops off USB and comes back
    // under a (possibly different) bus address.
    drop(link);

    if let Err(error) = first {
        if !lost {
            return Err(error);
        }
        println!("\nThe device stopped answering ({error}). Reconnecting to carry on...");
        let mut reconnect = NanoReconnect::new(nano, trace);
        resume_after_lost_link(&mut reconnect, expected, &image, &resume_options, &mut report)?;
    }
    drop(report);
    if up_to_date.get() {
        return Ok(());
    }

    println!("Waiting for the device to restart...");
    match wait_for_restart(nano) {
        Some(restarted) => match query_after_restart(&restarted, trace) {
            Ok(info) if info.firmware_version == image.version => {
                println!(
                    "Device is back, now running firmware {}",
                    version(info.firmware_version)
                );
                Ok(())
            }
            Ok(info) => Err(format!(
                "the device came back running {}, not {}; the update did not take",
                version(info.firmware_version),
                image.version_string()
            )),
            Err(error) => Err(format!(
                "the device came back but did not answer ({error}), so the update is \
                 unverified. Unplug it, plug it back in and run `info`."
            )),
        },
        None => Err(format!(
            "the device did not come back within {} s, so the update is unverified. \
             Unplug it, plug it back in and run `info`.",
            RESTART_TIMEOUT.as_secs()
        )),
    }
}

/// Read-only probes from `docs/nano-settings.md` ("Safe to try first"),
/// sent over macOS HID so they work over Bluetooth too. Prints raw replies;
/// interpreting them is the point of running it.
#[cfg(target_os = "macos")]
pub fn probe(ble_bridge: Option<&Path>, trace: bool) -> Result<(), String> {
    use crate::nano_hid::{self, BleLink, HidLink};
    if let Some(app) = ble_bridge {
        println!("Bluetooth LE GATT channel via {}", app.display());
        let mut link = BleLink::launch(app, trace)?;
        return probe_on(&mut link);
    }
    let found = nano_hid::find()?;
    // macOS refuses output report 0x0c over Bluetooth LE (IOHIDDeviceSetReport
    // returns kIOReturnNotFound, while the rumble report 3 goes through), so
    // prefer USB when both are there; over Bluetooth use --ble instead.
    let Some(nano) = found.iter().find(|n| !n.bluetooth).or(found.first()) else {
        return Err("no Nano companion collection found over HID (Bluetooth or USB)".to_owned());
    };
    println!("{}", nano.describe());
    let mut link = HidLink::open(nano, trace)?;
    probe_on(&mut link)
}

#[cfg(target_os = "macos")]
fn probe_on<L: crate::companion::updater::Link>(link: &mut L) -> Result<(), String> {
    use crate::usb::hex;
    let mut session = open_session(link)?;
    let protocol = session.protocol_version();
    println!("Protocol          {}.{}.{}", protocol[0], protocol[1], protocol[2]);

    let timeout = Duration::from_secs(5);
    let info_opcode = crate::companion::protocol::device_info_opcode(protocol);
    match session.query(info_opcode, &crate::companion::protocol::device_info_request(), timeout) {
        Ok(reply) => {
            println!("Device info {info_opcode:#04x} ({} bytes): {}", reply.len(), hex(&reply));
            if reply.len() >= 0x33 {
                let capabilities = u32::from_le_bytes(reply[0x29..0x2d].try_into().unwrap());
                let components = u32::from_le_bytes(reply[0x2d..0x31].try_into().unwrap());
                println!("  capabilities    {capabilities:#010x}");
                println!("  ext. components {components:#010x} (+ u16 {:#06x})", u16::from_le_bytes([reply[0x31], reply[0x32]]));
            }
        }
        Err(error) => println!("Device info {info_opcode:#04x}: {error}"),
    }

    let probes: [(&str, u8, &[u8]); 7] = [
        ("battery            02", 0x02, &[]),
        ("get active mode    1e 0d 03", 0x1e, &[0x0d, 0x03]),
        ("get mapping 00     1e 0d 08 00", 0x1e, &[0x0d, 0x08, 0x00]),
        ("get mapping 01     1e 0d 08 01", 0x1e, &[0x0d, 0x08, 0x01]),
        ("get mapping 10     1e 0d 08 10", 0x1e, &[0x0d, 0x08, 0x10]),
        ("get friendly name  1e 0d 05", 0x1e, &[0x0d, 0x05]),
        ("external 02 05     1e 02 05", 0x1e, &[0x02, 0x05]),
    ];
    for (label, opcode, payload) in probes {
        match session.query(opcode, payload, timeout) {
            Ok(reply) => println!("{label}: {} bytes: {}", reply.len(), hex(&reply)),
            Err(error) => println!("{label}: {error}"),
        }
    }
    Ok(())
}

/// How long to wait for the device to come back after a USB reset, and for
/// a replug when one is asked for.
const RESET_TIMEOUT: Duration = Duration::from_secs(10);
const REPLUG_TIMEOUT: Duration = Duration::from_secs(180);

/// Brings a Nano back after it stopped answering mid-update, for
/// [`resume_after_lost_link`]: first a USB reset (no hands needed, if it
/// works on the device), then, when that brought no progress, a replug the
/// user is asked for. Either way the update then carries on by itself.
struct NanoReconnect {
    vendor_id: u16,
    product_id: u16,
    trace: bool,
    link: Option<NanoLink>,
}

impl NanoReconnect {
    fn new(nano: &NanoDevice, trace: bool) -> Self {
        Self { vendor_id: nano.vendor_id, product_id: nano.product_id, trace, link: None }
    }

    fn find(&self) -> Result<Option<NanoDevice>, String> {
        let mut found: Vec<NanoDevice> = usb::find_nano_devices()?
            .into_iter()
            .filter(|d| d.vendor_id == self.vendor_id && d.product_id == self.product_id)
            .collect();
        match found.len() {
            0 => Ok(None),
            1 => Ok(found.pop()),
            _ => Err("several of these devices are connected; leave only the one being updated".to_owned()),
        }
    }

    fn wait(&self, present: bool, timeout: Duration) -> Result<bool, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.find()?.is_some() == present {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Reconnect for NanoReconnect {
    type Link = NanoLink;

    fn recover(&mut self, stage: u32) -> Result<(), String> {
        // Release the old interface first: a reset or replug invalidates it.
        self.link = None;
        if stage == 0 {
            println!("  resetting the USB connection");
            if let Some(device) = self.find()?
                && let Err(error) = usb::reset_nano(&device)
            {
                println!("  {error}");
            }
            // It may drop off the bus and come back, or stay put.
            thread::sleep(Duration::from_millis(500));
            self.wait(true, RESET_TIMEOUT)?;
        } else {
            println!(
                "  Unplug the controller and plug it back in; the update then carries on by itself."
            );
            if !self.wait(false, REPLUG_TIMEOUT)? || !self.wait(true, REPLUG_TIMEOUT)? {
                return Err(format!(
                    "the controller was not replugged within {} s; the update was not finished and \
                     the old firmware is still running. Plug it in and run the command again: it \
                     resumes where it stopped.",
                    REPLUG_TIMEOUT.as_secs()
                ));
            }
            println!("  controller is back");
        }
        // Let it finish enumerating before the interface is claimed.
        thread::sleep(Duration::from_millis(500));
        Ok(())
    }

    fn link(&mut self) -> Result<&mut NanoLink, String> {
        if self.link.is_none() {
            let device = self.find()?.ok_or_else(|| "the controller is not connected".to_owned())?;
            self.link = Some(NanoLink::open(&device, self.trace)?);
        }
        Ok(self.link.as_mut().expect("opened above"))
    }

    fn session_id(&mut self) -> u32 {
        session_id()
    }
}

/// Re-enumeration can briefly race the device finishing its own boot: the
/// interface may not be claimable yet, or a session opened too early may get
/// no reply. Retry for a few seconds before giving up, as GIP's own restart
/// handling (`UsbLink::reconnect`) tolerates the same transient errors.
fn query_after_restart(nano: &NanoDevice, trace: bool) -> Result<DeviceInfo, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let attempt = (|| {
            let mut link = NanoLink::open(nano, trace)?;
            let mut session = open_session(&mut link)?;
            session.device_info()
        })();
        match attempt {
            Ok(info) => return Ok(info),
            Err(error) if Instant::now() >= deadline => return Err(error),
            Err(_) => thread::sleep(Duration::from_millis(200)),
        }
    }
}

/// Wait for a Pendragon accessory of the same model as `nano` to drop off the
/// bus and come back, up to [`RESTART_TIMEOUT`] total. The device has been
/// seen to restart itself about 1.5 s after `finish`, so it is usually still
/// there right after the update finishes; waiting for it to disappear first
/// (as GIP controllers' restart handling also does, in `UsbLink::reconnect`)
/// avoids mistaking the pre-restart device still running the old firmware
/// for the restarted one. Matched by VID/PID: this transport does not read a
/// serial number to tell two identical accessories apart.
fn wait_for_restart(nano: &NanoDevice) -> Option<NanoDevice> {
    let deadline = Instant::now() + RESTART_TIMEOUT;
    let matches = |d: &NanoDevice| d.vendor_id == nano.vendor_id && d.product_id == nano.product_id;
    let present = || {
        usb::find_nano_devices()
            .unwrap_or_default()
            .into_iter()
            .find(|d| matches(d))
    };

    while present().is_some() {
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(100));
    }
    loop {
        if let Some(found) = present() {
            return Some(found);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(100));
    }
}
