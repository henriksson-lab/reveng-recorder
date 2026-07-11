//! USB capture backend (DESIGN.md §4).
//!
//! - [`parse`] — pure USBPcap header parsing (cross-platform, tested).
//! - [`UsbIdxRecord`] — the 24-byte `frames.idx` record layout.
//! - [`UsbCaptureSource`] — drives `USBPcapCMD.exe` (Windows only); a stub elsewhere.

pub mod parse;
pub mod pcapng;

use reveng_core::event::{SourceKind, TrafficRecord};
use reveng_core::index::FixedRecord;
use reveng_core::source::CaptureSource;

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

/// Enumerate attach devices via USBPcap. Windows-only; stubbed elsewhere.
pub fn list_devices() -> anyhow::Result<Vec<UsbDevice>> {
    #[cfg(windows)]
    {
        // TODO: run USBPcapCMD device enumeration and parse the tree (DESIGN.md §11.1).
        anyhow::bail!("USB device enumeration not yet implemented")
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("USB capture requires Windows + USBPcap")
    }
}

/// USB capture source that reads the pcap stream from `USBPcapCMD.exe -o -`.
pub struct UsbCaptureSource {
    #[allow(dead_code)]
    selection: UsbSelection,
}

impl UsbCaptureSource {
    pub fn new(selection: UsbSelection) -> Self {
        Self { selection }
    }
}

impl CaptureSource for UsbCaptureSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Usb
    }

    fn start(&mut self) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            // TODO: spawn USBPcapCMD with the resolved device filter, read stdout pipe,
            // parse headers (see `parse`), write usb.pcapng + append frames.idx.
            anyhow::bail!("USB capture not yet implemented")
        }
        #[cfg(not(windows))]
        {
            anyhow::bail!("USB capture requires Windows + USBPcap")
        }
    }

    fn next(&mut self) -> anyhow::Result<Option<TrafficRecord>> {
        Ok(None)
    }

    fn stop(&mut self) -> anyhow::Result<()> {
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
