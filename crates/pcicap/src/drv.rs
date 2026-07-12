//! Driver-only PCIe capture client (Windows only) — the "lighter tier" of DESIGN.md §4a.
//!
//! Talks to the `reveng-pcidrv` KMDF driver's control device `\\.\RevengPciCap` over the shared
//! ABI (`driver/reveng-pcidrv/reveng_pci_abi.h`): pick the target by BDF with a `SET_TARGET`
//! IOCTL, then `ReadFile` a stream of fixed 32-byte events and map them to [`PcieEvent`]. No
//! hypervisor, so VBS may stay on. Mirrors the USBPcap direct-IOCTL client in `reveng-usbcap`.
//!
//! Until the driver is installed, `start()` fails at the `CreateFile` — everything above the
//! [`CaptureSource`] seam is unaffected (same contract as [`crate::HvPcieSource`]).

#![cfg(windows)]

use reveng_core::clock::Clock;
use reveng_core::event::{Dir, PcieEvent, SourceKind, TrafficKind, TrafficRecord};
use reveng_core::source::CaptureSource;
use std::io::{self, BufReader, Read};
use std::sync::Arc;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::Win32::System::IO::{CancelIoEx, DeviceIoControl};

// --- shared ABI (keep in lockstep with reveng_pci_abi.h) --------------------------------

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}
const FILE_DEVICE_UNKNOWN: u32 = 0x0000_0022;
const IOCTL_REVENG_PCI_SET_TARGET: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x800, 0, 0);

const KIND_CONFIG: u8 = 0;
const KIND_MMIO: u8 = 1;
const KIND_IRQ: u8 = 2;
const KIND_DMA: u8 = 3;

const EVENT_SIZE: usize = 32;

/// Target PCIe device by address (matches `REVENG_PCI_TARGET`).
#[derive(Clone, Copy, Debug)]
pub struct Bdf {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl Bdf {
    /// 12 bytes: `segment:u16, bus, device, function, pad[3]` (little-endian, packed).
    fn to_ioctl_bytes(self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..2].copy_from_slice(&self.segment.to_le_bytes());
        b[2] = self.bus;
        b[3] = self.device;
        b[4] = self.function;
        b
    }
}

// --- handle ownership (mirrors reveng_usbcap::ioctl) ------------------------------------

struct OwnedHandle(HANDLE);
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Stops a parked `ReadFile` on the capture handle so the reader wakes and sees EOF.
#[derive(Clone)]
pub struct Killer(Arc<OwnedHandle>);
impl Killer {
    pub fn kill(&self) {
        unsafe {
            let _ = CancelIoEx(self.0 .0, None);
        }
    }
}

/// Blocking reader over the driver's event stream; a cancel/close surfaces as clean EOF.
struct DeviceReader {
    handle: Arc<OwnedHandle>,
}
impl Read for DeviceReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut read: u32 = 0;
        match unsafe { ReadFile(self.handle.0, Some(buf), Some(&mut read), None) } {
            Ok(()) => Ok(read as usize),
            Err(e) => {
                const ABORTED: i32 = 0x8007_03E3u32 as i32; // ERROR_OPERATION_ABORTED
                const INVALID_HANDLE: i32 = 0x8007_0006u32 as i32; // ERROR_INVALID_HANDLE
                let code = e.code().0;
                if code == ABORTED || code == INVALID_HANDLE {
                    Ok(0)
                } else {
                    Err(io::Error::from_raw_os_error(code))
                }
            }
        }
    }
}

// --- the source -------------------------------------------------------------------------

/// PCIe capture source backed by the `reveng-pcidrv` KMDF driver (config/IRQ/MMIO/DMA events).
pub struct DrvPcieSource {
    target: Bdf,
    clock: Clock,
    reader: Option<BufReader<DeviceReader>>,
    killer: Option<Killer>,
}

impl DrvPcieSource {
    pub fn new(target: Bdf, clock: Clock) -> Self {
        Self {
            target,
            clock,
            reader: None,
            killer: None,
        }
    }

    pub fn killer(&self) -> Option<Killer> {
        self.killer.clone()
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

impl CaptureSource for DrvPcieSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Pcie
    }

    fn start(&mut self) -> anyhow::Result<()> {
        let path = wide("\\\\.\\RevengPciCap");
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path.as_ptr()),
                0xC000_0000u32, // GENERIC_READ | GENERIC_WRITE
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        }
        .map_err(|e| anyhow::anyhow!("open \\\\.\\RevengPciCap failed: {e} (is reveng-pcidrv installed? admin?)"))?;
        if handle == INVALID_HANDLE_VALUE {
            anyhow::bail!("\\\\.\\RevengPciCap returned an invalid handle");
        }
        let owned = Arc::new(OwnedHandle(handle));

        // Select the device to capture.
        let target = self.target.to_ioctl_bytes();
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                owned.0,
                IOCTL_REVENG_PCI_SET_TARGET,
                Some(target.as_ptr() as *const _),
                target.len() as u32,
                None,
                0,
                Some(&mut returned),
                None,
            )
        }
        .map_err(|e| anyhow::anyhow!("SET_TARGET failed: {e}"))?;

        self.killer = Some(Killer(owned.clone()));
        self.reader = Some(BufReader::with_capacity(
            64 * EVENT_SIZE,
            DeviceReader { handle: owned },
        ));
        Ok(())
    }

    fn next(&mut self) -> anyhow::Result<Option<TrafficRecord>> {
        let reader = match self.reader.as_mut() {
            Some(r) => r,
            None => return Ok(None),
        };
        loop {
            let mut buf = [0u8; EVENT_SIZE];
            match read_full(reader, &mut buf)? {
                false => return Ok(None), // clean EOF at a record boundary
                true => {}
            }
            // TODO(M3+): convert ts_qpc against the shared QPC origin for tight timing. For now
            // (config/IRQ bring-up) stamp at receipt on the session clock.
            let ts_ns = self.clock.now_ns();
            if let Some(ev) = decode_event(&buf, ts_ns) {
                return Ok(Some(TrafficRecord {
                    ts_ns,
                    source: SourceKind::Pcie,
                    kind: TrafficKind::Pcie(ev),
                    payload: Vec::new(),
                }));
            }
            // Unknown kind: skip and read the next record.
        }
    }

    fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(k) = &self.killer {
            k.kill();
        }
        self.reader = None;
        Ok(())
    }
}

/// Read exactly `buf.len()` bytes, or return `Ok(false)` on a clean EOF at a record boundary.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> anyhow::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(false);
                }
                anyhow::bail!("reveng-pcidrv stream ended mid-event");
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}

fn decode_event(b: &[u8; EVENT_SIZE], ts_ns: i64) -> Option<PcieEvent> {
    let kind = b[8];
    let dir = if b[9] == 0 { Dir::In } else { Dir::Out };
    let width = b[10];
    let bar = b[11];
    let offset = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
    let value = u64::from_le_bytes(b[16..24].try_into().unwrap());
    let addr = u64::from_le_bytes(b[24..32].try_into().unwrap());
    match kind {
        KIND_CONFIG => Some(PcieEvent::Config {
            ts_ns,
            offset: offset as u16,
            width,
            value: value as u32,
            dir,
        }),
        KIND_MMIO => Some(PcieEvent::Mmio {
            ts_ns,
            bar,
            offset,
            width,
            value,
            dir,
        }),
        KIND_IRQ => Some(PcieEvent::Irq {
            ts_ns,
            vector: value as u16,
        }),
        KIND_DMA => Some(PcieEvent::Dma {
            ts_ns,
            dir,
            dev_addr: addr,
            len: value as u32,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: u8, dir: u8, width: u8, bar: u8, offset: u32, value: u64, addr: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[8] = kind;
        b[9] = dir;
        b[10] = width;
        b[11] = bar;
        b[12..16].copy_from_slice(&offset.to_le_bytes());
        b[16..24].copy_from_slice(&value.to_le_bytes());
        b[24..32].copy_from_slice(&addr.to_le_bytes());
        b
    }

    #[test]
    fn decodes_config_and_mmio() {
        let c = decode_event(&ev(KIND_CONFIG, 0, 4, 0, 0x04, 0x0010_0006, 0), 42).unwrap();
        assert_eq!(
            c,
            PcieEvent::Config { ts_ns: 42, offset: 4, width: 4, value: 0x0010_0006, dir: Dir::In }
        );
        let m = decode_event(&ev(KIND_MMIO, 1, 4, 2, 0x40, 1, 0), 7).unwrap();
        assert_eq!(
            m,
            PcieEvent::Mmio { ts_ns: 7, bar: 2, offset: 0x40, width: 4, value: 1, dir: Dir::Out }
        );
    }

    #[test]
    fn bdf_ioctl_bytes_layout() {
        let b = Bdf { segment: 0, bus: 3, device: 0, function: 1 }.to_ioctl_bytes();
        assert_eq!(b[2], 3);
        assert_eq!(b[3], 0);
        assert_eq!(b[4], 1);
    }
}
