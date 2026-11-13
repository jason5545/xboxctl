//! A Pendragon accessory's companion collection through macOS's HID stack
//! instead of libusb. This reaches the Nano over Bluetooth LE (`045e:0b4f`)
//! as well as USB, needs no root, and opens the device shared, so macOS and
//! games keep receiving its input. The Bluetooth HID descriptor has the same
//! vendor collection as USB: usage page `0xff45`, usage `0x63`, report `0x0c`,
//! 63 bytes in and out.

use crate::companion::{frame::REPORT_ID, updater::Link};
use hidapi::{BusType, HidApi, HidDevice};
use std::{
    ffi::CString,
    time::{Duration, Instant},
};

const VENDOR_ID: u16 = 0x045e;
const USAGE_PAGE: u16 = 0xff45;
const USAGE: u16 = 0x63;
/// Report length after the report ID, as the descriptor declares it.
const REPORT_LEN: usize = 63;

/// A companion collection found through HID.
pub struct HidNano {
    pub product_id: u16,
    pub bluetooth: bool,
    path: CString,
}

impl HidNano {
    pub fn describe(&self) -> String {
        format!(
            "{:04x}:{:04x} over {}",
            VENDOR_ID,
            self.product_id,
            if self.bluetooth { "Bluetooth" } else { "USB" }
        )
    }
}

fn api() -> Result<HidApi, String> {
    HidApi::new().map_err(|error| format!("could not start HID: {error}"))
}

/// Every Microsoft device with the companion collection, over any transport.
pub fn find() -> Result<Vec<HidNano>, String> {
    let api = api()?;
    let mut found: Vec<HidNano> = Vec::new();
    for device in api.device_list() {
        if device.vendor_id() != VENDOR_ID
            || device.usage_page() != USAGE_PAGE
            || device.usage() != USAGE
        {
            continue;
        }
        if found.iter().any(|known| known.path.as_c_str() == device.path()) {
            continue;
        }
        found.push(HidNano {
            product_id: device.product_id(),
            bluetooth: matches!(device.bus_type(), BusType::Bluetooth),
            path: device.path().to_owned(),
        });
    }
    Ok(found)
}

/// The companion collection as a [`Link`]: `0x0c` reports, the payload after
/// the ID, zero padded.
pub struct HidLink {
    device: HidDevice,
    // Kept alive while the device is open.
    _api: HidApi,
    trace: bool,
}

impl HidLink {
    pub fn open(nano: &HidNano, trace: bool) -> Result<Self, String> {
        let api = api()?;
        let device = api
            .open_path(&nano.path)
            .map_err(|error| format!("could not open {}: {error}", nano.describe()))?;
        Ok(Self { device, _api: api, trace })
    }
}

impl Link for HidLink {
    fn send(&mut self, payload: &[u8]) -> Result<(), String> {
        if payload.len() > REPORT_LEN {
            return Err(format!(
                "message of {} bytes does not fit the {REPORT_LEN}-byte output report",
                payload.len()
            ));
        }
        let mut report = vec![0u8; REPORT_LEN + 1];
        report[0] = REPORT_ID;
        report[1..1 + payload.len()].copy_from_slice(payload);
        self.device
            .write(&report)
            .map_err(|error| format!("HID write failed: {error}"))?;
        if self.trace {
            eprintln!("OUT {}", crate::usb::hex(&report));
        }
        Ok(())
    }

    fn recv(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        let deadline = Instant::now() + timeout;
        let mut buffer = [0u8; 128];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
            let length = self
                .device
                .read_timeout(&mut buffer, millis)
                .map_err(|error| format!("HID read failed: {error}"))?;
            if length == 0 {
                return Ok(None);
            }
            // The same device also delivers its gamepad, keyboard and mouse
            // reports; only full companion reports are messages, as in the
            // SDK's own receive check.
            if buffer[0] == REPORT_ID && length > REPORT_LEN {
                let payload = buffer[1..=REPORT_LEN].to_vec();
                if self.trace {
                    eprintln!("IN  {}", crate::usb::hex(&payload));
                }
                return Ok(Some(payload));
            }
        }
    }

    fn max_fragment_data(&self) -> usize {
        REPORT_LEN - 5
    }
}

/// The Nano's companion protocol over its Bluetooth LE GATT channel
/// (service `00000000-16e2-469d-8013-a85ccd1a3f11`, characteristic
/// `00000004-…`, written and indicated), which macOS does not hide behind
/// its HID driver the way it refuses output report `0x0c`. CoreBluetooth
/// lives in a small helper app (`tools/nano-ble-bridge`) so it gets its own
/// Bluetooth permission; this side talks to it over a Unix socket in
/// messages of `<u16 LE length><frame>`, a zero-length one meaning ready.
pub struct BleLink {
    stream: std::os::unix::net::UnixStream,
    trace: bool,
}

impl BleLink {
    pub fn launch(app: &std::path::Path, trace: bool) -> Result<Self, String> {
        use std::os::unix::net::UnixStream;
        let base = std::env::temp_dir().join(format!("nano-ble-{}", std::process::id()));
        let socket = base.with_extension("sock");
        let log = base.with_extension("log");
        let status = std::process::Command::new("open")
            .arg("-n")
            .arg(app)
            .arg("--args")
            .arg(&socket)
            .arg(&log)
            .status()
            .map_err(|error| format!("could not start {}: {error}", app.display()))?;
        if !status.success() {
            return Err(format!("could not start {}", app.display()));
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        let stream = loop {
            match UnixStream::connect(&socket) {
                Ok(stream) => break stream,
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
                Err(error) => {
                    return Err(format!(
                        "the Bluetooth bridge did not come up ({error}); see {}",
                        log.display()
                    ));
                }
            }
        };
        let mut link = Self { stream, trace };
        // Wait for "ready": the bridge connected and subscribed.
        match link.read_message(Duration::from_secs(20))? {
            Some(message) if message.is_empty() => Ok(link),
            _ => Err(format!(
                "the Bluetooth bridge did not get ready; see {}",
                log.display()
            )),
        }
    }

    fn read_message(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        use std::io::{ErrorKind, Read};
        self.stream
            .set_read_timeout(Some(timeout.max(Duration::from_millis(1))))
            .map_err(|error| error.to_string())?;
        let mut header = [0u8; 2];
        match self.stream.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Ok(None);
            }
            Err(error) => return Err(format!("Bluetooth bridge closed: {error}")),
        }
        let length = usize::from(u16::from_le_bytes(header));
        let mut body = vec![0u8; length];
        self.stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| error.to_string())?;
        self.stream
            .read_exact(&mut body)
            .map_err(|error| format!("Bluetooth bridge closed: {error}"))?;
        Ok(Some(body))
    }
}

impl Link for BleLink {
    fn send(&mut self, payload: &[u8]) -> Result<(), String> {
        use std::io::Write;
        let mut message = (payload.len() as u16).to_le_bytes().to_vec();
        message.extend_from_slice(payload);
        self.stream
            .write_all(&message)
            .map_err(|error| format!("Bluetooth bridge write failed: {error}"))?;
        if self.trace {
            eprintln!("OUT {}", crate::usb::hex(payload));
        }
        Ok(())
    }

    fn recv(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            match self.read_message(remaining)? {
                None => return Ok(None),
                Some(message) if message.is_empty() => continue,
                Some(message) => {
                    if self.trace {
                        eprintln!("IN  {}", crate::usb::hex(&message));
                    }
                    return Ok(Some(message));
                }
            }
        }
    }

    fn max_fragment_data(&self) -> usize {
        // Same as over USB; whether the GATT channel takes larger frames has
        // not been tried.
        REPORT_LEN - 5
    }
}
