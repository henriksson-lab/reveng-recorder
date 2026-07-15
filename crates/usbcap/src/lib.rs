//! USB capture backend (DESIGN.md §4).
//!
//! - [`parse`] — pure USBPcap header parsing (cross-platform, tested).
//! - [`UsbIdxRecord`] — the 24-byte `frames.idx` record layout.
//! - [`UsbCaptureSource`] — drives `USBPcapCMD.exe` (Windows only); a stub elsewhere.

#[cfg(windows)]
pub mod devs;
#[cfg(windows)]
pub mod ioctl;
pub mod parse;
pub mod pcap;
pub mod pcapng;
pub mod reader;
pub mod writer;

pub use reader::{UsbFrame, UsbReader};
pub use writer::UsbWriter;

/// USBPcap transfer-type codes, as stored in [`reveng_core::event::UsbFrameHeader::transfer`]
/// (USBPcap.h `USBPCAP_TRANSFER_*`). Used by capture-side transfer-type filtering.
pub const XFER_ISO: u8 = 0;
pub const XFER_INTERRUPT: u8 = 1;
pub const XFER_CONTROL: u8 = 2;
pub const XFER_BULK: u8 = 3;

use reveng_core::clock::Clock;
use reveng_core::event::{SourceKind, TrafficKind, TrafficRecord, UsbFrameHeader};
use reveng_core::index::FixedRecord;
use reveng_core::source::CaptureSource;
use std::process::{Child, Command, Stdio};

/// A device the user can select as a capture target (from `reveng-rec devices`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct UsbDevice {
    pub usbpcap: String,
    pub bus: u16,
    pub address: u16,
    pub vid: String,
    pub pid: String,
    pub product: String,
}

/// Selection filter for a capture (mirrors the `--device-*` flags, §11.1).
#[derive(Debug, Clone, Default)]
pub struct UsbSelection {
    pub usbpcap_device: Option<String>,
    pub vidpid: Vec<String>,
    pub serial: Option<String>,
    pub address: Vec<u16>,
    pub all_devices: bool,
}

/// The 24-byte fixed-width `frames.idx` record (DESIGN.md §8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbIdxRecord {
    pub ts_ns: i64,
    pub byte_offset: u64,
    pub endpoint: u8,
    pub dir: u8,
    pub xfer: u8,
    pub status: u8,
    pub data_length: u32,
}

impl FixedRecord for UsbIdxRecord {
    const SIZE: usize = 24;

    fn ts_ns(&self) -> i64 {
        self.ts_ns
    }

    fn write_to(&self, buf: &mut [u8]) {
        buf[0..8].copy_from_slice(&self.ts_ns.to_le_bytes());
        buf[8..16].copy_from_slice(&self.byte_offset.to_le_bytes());
        buf[16] = self.endpoint;
        buf[17] = self.dir;
        buf[18] = self.xfer;
        buf[19] = self.status;
        buf[20..24].copy_from_slice(&self.data_length.to_le_bytes());
    }

    fn read_from(buf: &[u8]) -> Self {
        UsbIdxRecord {
            ts_ns: i64::from_le_bytes(buf[0..8].try_into().unwrap()),
            byte_offset: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            endpoint: buf[16],
            dir: buf[17],
            xfer: buf[18],
            status: buf[19],
            data_length: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
        }
    }
}

/// The USBPcapCMD executable name; overridable via `USBPCAPCMD` for non-default installs.
fn usbpcapcmd() -> String {
    std::env::var("USBPCAPCMD").unwrap_or_else(|_| "USBPcapCMD.exe".to_string())
}

/// Enumerate attached USB devices and their USBPcap control device (DESIGN.md §11.1).
///
/// Pure Win32 (SetupAPI + CfgMgr) via [`devs`] — no `USBPcapCMD` subprocess, no fragile
/// device-tree text parsing. Each [`UsbDevice`] carries the `\\.\USBPcapN` that filters its
/// root hub, its USB address, and VID/PID.
pub fn list_devices() -> anyhow::Result<Vec<UsbDevice>> {
    #[cfg(windows)]
    {
        devs::list()
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("USB enumeration requires Windows")
    }
}

/// Pull `VID_1234`/`PID_ABCD` (or `1234:abcd`) out of a description, if present.
fn extract_vidpid(s: &str) -> (String, String) {
    let up = s.to_ascii_uppercase();
    let grab = |key: &str| -> Option<String> {
        let i = up.find(key)?;
        let hex: String = up[i + key.len()..]
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .take(4)
            .collect();
        (hex.len() == 4).then_some(hex)
    };
    if let (Some(v), Some(p)) = (grab("VID_"), grab("PID_")) {
        return (v, p);
    }
    // Fall back to a `1234:abcd` form.
    if let Some((a, b)) = s.split_once(':') {
        let v: String = a.trim().chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
        let p: String = b.trim().chars().take(4).collect();
        if v.chars().all(|c| c.is_ascii_hexdigit()) && p.chars().all(|c| c.is_ascii_hexdigit()) && v.len() == 4 && p.len() == 4 {
            return (v.to_ascii_uppercase(), p.to_ascii_uppercase());
        }
    }
    (String::new(), String::new())
}

/// Stops an in-flight capture from another thread: for the direct backend it cancels the
/// parked `ReadFile` (driver EOF); for the CLI fallback it kills `USBPcapCMD`, closing the
/// pipe. Cheaply cloneable and `Send`, so the orchestrator can stop an idle reader thread.
#[derive(Clone)]
pub struct Killer(std::sync::Arc<dyn Fn() + Send + Sync>);

impl Killer {
    fn noop() -> Self {
        Killer(std::sync::Arc::new(|| {}))
    }

    pub fn kill(&self) {
        (self.0)()
    }
}

/// The pcap byte stream feeding [`UsbCaptureSource`]: a USBPcap device handle (direct backend)
/// or `USBPcapCMD`'s stdout (CLI fallback), both boxed behind `Read`.
type PcapStream = pcap::PcapReader<Box<dyn std::io::Read + Send>>;

/// USB capture source that reads the classic-libpcap stream from the USBPcap driver and folds
/// its wall-clock timestamps onto the session timeline via [`Clock`] (DESIGN.md §2, §4).
///
/// By default it talks to `\\.\USBPcapN` directly via IOCTLs ([`ioctl`]); setting
/// `REVENG_USBPCAP_CLI` forces the legacy `USBPcapCMD.exe -o -` subprocess path.
pub struct UsbCaptureSource {
    selection: UsbSelection,
    clock: Clock,
    /// CLI fallback only: the child process, kept so `stop` can kill/reap it.
    child: std::sync::Arc<std::sync::Mutex<Option<Child>>>,
    killer: Killer,
    reader: Option<PcapStream>,
    /// Driver snaplen (bytes captured per transfer); `0` = the default (unlimited). Small
    /// control/interrupt transfers are unaffected; a modest cap truncates bulk/isoc firehoses
    /// (camera/audio) in the kernel while the index keeps the original on-wire length.
    snaplen: u32,
    /// Driver kernel buffer size in bytes; `0` = the default. Larger tolerates bursts.
    buffer: u32,
}

impl UsbCaptureSource {
    pub fn new(selection: UsbSelection, clock: Clock) -> Self {
        Self {
            selection,
            clock,
            child: std::sync::Arc::new(std::sync::Mutex::new(None)),
            killer: Killer::noop(),
            reader: None,
            snaplen: 0,
            buffer: 0,
        }
    }

    /// Set the driver snaplen / buffer size (bytes) before `start`. `0` keeps the default.
    pub fn set_capture_opts(&mut self, snaplen: u32, buffer: u32) {
        self.snaplen = snaplen;
        self.buffer = buffer;
    }

    /// A handle that can stop the capture from another thread (valid after `start`).
    pub fn killer(&self) -> Killer {
        self.killer.clone()
    }

    fn require_device(&self) -> anyhow::Result<&str> {
        self.selection
            .usbpcap_device
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("no USBPcap control device selected (\\\\.\\USBPcapN)"))
    }

    /// Direct backend: open the control device and read the driver's pcap stream via IOCTLs.
    #[cfg(windows)]
    fn start_direct(&mut self) -> anyhow::Result<()> {
        let dev = self.require_device()?.to_string();
        // No explicit address filter → capture the whole hub; else filter to the resolved set.
        let filter_all = self.selection.all_devices || self.selection.address.is_empty();
        let snaplen = if self.snaplen == 0 { ioctl::DEFAULT_SNAPLEN } else { self.snaplen };
        let buffer = if self.buffer == 0 { ioctl::DEFAULT_BUFFER } else { self.buffer };
        let cap = ioctl::open_capture(&dev, &self.selection.address, filter_all, snaplen, buffer)?;
        let k = cap.killer;
        self.killer = Killer(std::sync::Arc::new(move || k.kill()));
        // Buffer at the driver's granularity so each ReadFile drains a full kernel buffer.
        let stream: Box<dyn std::io::Read + Send> =
            Box::new(std::io::BufReader::with_capacity(buffer as usize, cap.reader));
        self.set_reader(stream)
    }

    /// CLI fallback: drive `USBPcapCMD.exe -o -` and read its stdout.
    fn start_cli(&mut self) -> anyhow::Result<()> {
        let dev = self.require_device()?;
        let mut cmd = Command::new(usbpcapcmd());
        cmd.arg("-d").arg(dev).arg("-o").arg("-");
        if !self.selection.all_devices && !self.selection.address.is_empty() {
            let list = self
                .selection
                .address
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(",");
            cmd.arg("--devices").arg(list);
        }
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());

        let mut child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to spawn {} ({e}); USBPcap installed? admin?", usbpcapcmd()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("USBPcapCMD produced no stdout pipe"))?;
        let child = std::sync::Arc::new(std::sync::Mutex::new(Some(child)));
        self.child = child.clone();
        self.killer = Killer(std::sync::Arc::new(move || {
            if let Ok(mut g) = child.lock() {
                if let Some(c) = g.as_mut() {
                    let _ = c.kill();
                }
            }
        }));
        self.set_reader(Box::new(stdout))
    }

    /// Wrap a byte stream in a pcap reader and validate its link type.
    fn set_reader(&mut self, stream: Box<dyn std::io::Read + Send>) -> anyhow::Result<()> {
        let reader = pcap::PcapReader::new(stream)?;
        if reader.header().linktype != pcap::DLT_USBPCAP {
            anyhow::bail!(
                "expected DLT_USBPCAP ({}), got linktype {}",
                pcap::DLT_USBPCAP,
                reader.header().linktype
            );
        }
        self.reader = Some(reader);
        Ok(())
    }
}

impl CaptureSource for UsbCaptureSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Usb
    }

    fn start(&mut self) -> anyhow::Result<()> {
        let force_cli = std::env::var_os("REVENG_USBPCAP_CLI").is_some();
        #[cfg(windows)]
        {
            if force_cli {
                self.start_cli()
            } else {
                self.start_direct()
            }
        }
        #[cfg(not(windows))]
        {
            let _ = force_cli;
            self.start_cli()
        }
    }

    fn next(&mut self) -> anyhow::Result<Option<TrafficRecord>> {
        let reader = match self.reader.as_mut() {
            Some(r) => r,
            None => return Ok(None),
        };
        let rec = match reader.next_record()? {
            Some(r) => r,
            None => return Ok(None),
        };
        let ts_ns = self.clock.wall_to_session_ns(rec.unix_ns);
        let header = parse::parse_packet_header(&rec.data).unwrap_or(UsbFrameHeader {
            bus: 0,
            device: 0,
            endpoint: 0,
            transfer: 0xff,
            status: 0,
            data_length: 0,
        });
        Ok(Some(TrafficRecord {
            ts_ns,
            source: SourceKind::Usb,
            kind: TrafficKind::Usb(header),
            payload: rec.data,
        }))
    }

    fn stop(&mut self) -> anyhow::Result<()> {
        self.reader = None;
        if let Some(mut child) = self.child.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reveng_core::index::IndexFile;

    #[test]
    fn idx_record_roundtrips_through_file() {
        let path = std::env::temp_dir().join("reveng_usbidx_test.bin");
        let _ = std::fs::remove_file(&path);
        let mut idx = IndexFile::<UsbIdxRecord>::create(&path).unwrap();
        let rec = UsbIdxRecord {
            ts_ns: 123_456,
            byte_offset: 4096,
            endpoint: 0x81,
            dir: 1,
            xfer: 2,
            status: 0,
            data_length: 64,
        };
        idx.append(&rec).unwrap();
        assert_eq!(idx.get(0).unwrap(), rec);
        let _ = std::fs::remove_file(&path);
    }
}
