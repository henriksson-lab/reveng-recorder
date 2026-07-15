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
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
const IOCTL_REVENG_PCI_MMIO_SNAP: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x801, 0, 0);
const IOCTL_REVENG_PCI_DMA_SNAP: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x802, 0, 0);

/// How often live mode triggers an MMIO BAR snapshot (bounds out-of-band register reads).
const MMIO_SNAP_INTERVAL: Duration = Duration::from_millis(100);
/// Default bytes/BAR to snapshot; override with `REVENG_MMIO_BYTES`. Covers xHCI runtime+doorbells.
const DEFAULT_MMIO_BYTES: u32 = 16384;

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

/// Stops the reader: sets a stop flag the poll loop checks (so an *unbounded* live capture — no
/// deadline — ends promptly) and cancels any parked `ReadFile` so a blocked read wakes at once.
#[derive(Clone)]
pub struct Killer {
    handle: Arc<OwnedHandle>,
    stop: Arc<AtomicBool>,
}
impl Killer {
    pub fn kill(&self) {
        self.stop.store(true, Ordering::Relaxed);
        unsafe {
            let _ = CancelIoEx(self.handle.0, None);
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
///
/// Two modes: **snapshot** ([`new`]) drains whatever is queued (e.g. the M1 config-space dump)
/// and stops at the first empty read — used when the driver produces a finite burst. **live**
/// ([`new_live`]) keeps polling an empty ring until an optional deadline — used for the M2
/// interrupt filter, where events stream in over time and an empty read just means "not yet".
pub struct DrvPcieSource {
    target: Bdf,
    clock: Clock,
    reader: Option<DeviceReader>,
    handle: Option<Arc<OwnedHandle>>,
    killer: Option<Killer>,
    poll: bool,
    /// MMIO/DMA snapshotting — shared atomics so the recording window can toggle them live.
    trace_mmio: Arc<AtomicBool>,
    trace_dma: Arc<AtomicBool>,
    mmio_bytes: u32,
    max_duration: Option<Duration>,
    deadline: Option<Instant>,
    last_snap: Option<Instant>,
    /// Set by [`Killer`] to end an unbounded live poll loop (no deadline) promptly.
    stop: Arc<AtomicBool>,
}

impl DrvPcieSource {
    /// Snapshot mode: stop at the first empty read (M1 config-space dump).
    pub fn new(target: Bdf, clock: Clock) -> Self {
        Self {
            target,
            clock,
            reader: None,
            handle: None,
            killer: None,
            poll: false,
            trace_mmio: Arc::new(AtomicBool::new(false)),
            trace_dma: Arc::new(AtomicBool::new(false)),
            mmio_bytes: DEFAULT_MMIO_BYTES,
            max_duration: None,
            deadline: None,
            last_snap: None,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Live mode: keep polling the ring until `max_duration` elapses (M2 interrupt stream). With
    /// `trace_mmio`, also periodically snapshot the attached filter's MMIO BARs (M3).
    pub fn new_live(
        target: Bdf,
        clock: Clock,
        max_duration: Option<Duration>,
        trace_mmio: bool,
        trace_dma: bool,
    ) -> Self {
        Self {
            target,
            clock,
            reader: None,
            handle: None,
            killer: None,
            poll: true,
            trace_mmio: Arc::new(AtomicBool::new(trace_mmio)),
            trace_dma: Arc::new(AtomicBool::new(trace_dma)),
            mmio_bytes: std::env::var("REVENG_MMIO_BYTES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_MMIO_BYTES),
            max_duration,
            deadline: None,
            last_snap: None,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn killer(&self) -> Option<Killer> {
        self.killer.clone()
    }

    /// Shared `(trace_mmio, trace_dma)` flags, so the recording window can pause/resume the noisy
    /// MMIO/DMA snapshot sources mid-capture.
    pub fn trace_handles(&self) -> (Arc<AtomicBool>, Arc<AtomicBool>) {
        (self.trace_mmio.clone(), self.trace_dma.clone())
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

        self.stop.store(false, Ordering::Relaxed);
        self.killer = Some(Killer {
            handle: owned.clone(),
            stop: self.stop.clone(),
        });
        self.reader = Some(DeviceReader {
            handle: owned.clone(),
        });
        self.handle = Some(owned);
        self.deadline = self.max_duration.map(|d| Instant::now() + d);
        self.last_snap = None;
        Ok(())
    }

    fn next(&mut self) -> anyhow::Result<Option<TrafficRecord>> {
        if self.reader.is_none() {
            return Ok(None);
        }
        loop {
            // In live mode, periodically ask the driver to snapshot the BARs (M3) and/or follow
            // the Event Ring (M4) so changed registers/TRBs land in the ring we're about to read.
            let mmio_on = self.trace_mmio.load(Ordering::Relaxed);
            let dma_on = self.trace_dma.load(Ordering::Relaxed);
            if mmio_on || dma_on {
                let due = self
                    .last_snap
                    .map(|t| t.elapsed() >= MMIO_SNAP_INTERVAL)
                    .unwrap_or(true);
                if due {
                    if mmio_on {
                        ioctl_snap(&self.handle, IOCTL_REVENG_PCI_MMIO_SNAP, self.mmio_bytes);
                    }
                    if dma_on {
                        ioctl_snap(&self.handle, IOCTL_REVENG_PCI_DMA_SNAP, 0);
                    }
                    self.last_snap = Some(Instant::now());
                }
            }
            let mut buf = [0u8; EVENT_SIZE];
            let stop = self.stop.clone();
            let got = {
                let reader = self.reader.as_mut().unwrap();
                read_event(reader, &mut buf, self.poll, self.deadline, &stop)?
            };
            if !got {
                return Ok(None); // EOF (snapshot) or deadline reached (live)
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
        self.handle = None;
        Ok(())
    }
}

/// Trigger one snapshot IOCTL (M3 MMIO or M4 DMA), which pushes change events into the driver's
/// ring. `arg` is passed as the IOCTL input (e.g. MMIO snapshot length); 0 sends no input.
fn ioctl_snap(handle: &Option<Arc<OwnedHandle>>, code: u32, arg: u32) {
    if let Some(h) = handle {
        let mut returned = 0u32;
        let inbuf = arg.to_le_bytes();
        let (in_ptr, in_len) = if arg != 0 {
            (Some(inbuf.as_ptr() as *const _), inbuf.len() as u32)
        } else {
            (None, 0)
        };
        unsafe {
            let _ = DeviceIoControl(h.0, code, in_ptr, in_len, None, 0, Some(&mut returned), None);
        }
    }
}

/// Read exactly one event. Returns `Ok(false)` to signal end-of-stream:
/// - snapshot mode (`poll == false`): an empty read at a record boundary is a clean EOF.
/// - live mode (`poll == true`): an empty read means "ring momentarily empty" — sleep briefly
///   and retry until `deadline` (if any) passes, then end.
fn read_event(
    r: &mut impl Read,
    buf: &mut [u8],
    poll: bool,
    deadline: Option<Instant>,
    stop: &AtomicBool,
) -> anyhow::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled != 0 {
                    anyhow::bail!("reveng-pcidrv stream ended mid-event");
                }
                if !poll {
                    return Ok(false); // snapshot: clean EOF
                }
                // Stop requested (window Stop / max-seconds / hotkey) — end even with no
                // deadline. Checked at the event boundary so we never truncate a record.
                if stop.load(Ordering::Relaxed) {
                    return Ok(false);
                }
                if let Some(dl) = deadline {
                    if Instant::now() >= dl {
                        return Ok(false); // live: capture window elapsed
                    }
                }
                std::thread::sleep(Duration::from_millis(1)); // ring empty; poll again
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
    // Diagnostic: the driver's connect marker (IRQ with width sentinel 0xFF) carries the full
    // IoConnectInterruptEx outcome — status in `value`, mode in `bar` (1=msg,2=line,0=fail),
    // message count in `offset`, line vector in `addr`.
    if kind == KIND_IRQ && width == 0xFF && std::env::var_os("REVENG_DRV_DEBUG").is_some() {
        let mode = match bar {
            1 => "message-based",
            2 => "line-based",
            _ => "FAILED",
        };
        eprintln!(
            "[drv] CONNECT marker: status=0x{:08X} mode={mode} msg_count={offset} line_vec=0x{addr:X}",
            value as u32
        );
    }
    // M3 MMIO snapshot marker (kind=MMIO, width=0xFF): how many BARs mapped + first snap length.
    if kind == KIND_MMIO && width == 0xFF && std::env::var_os("REVENG_DRV_DEBUG").is_some() {
        eprintln!("[drv] MMIO marker: bars_mapped={value} bar0_snaplen={offset}");
    }
    // M4 DMA marker (kind=DMA, width=0xFF): `offset` is the stage — 0=read ERSTBA, 1=ring mapped,
    // 7/8=map failed, 9=ERST not in RAM, 10=segment not in RAM (both = likely IOMMU translation).
    if kind == KIND_DMA && width == 0xFF && std::env::var_os("REVENG_DRV_DEBUG").is_some() {
        let stage = match offset {
            0 => "erstba",
            1 => "ring-mapped-ok",
            7 => "seg-map-failed",
            8 => "erst-map-failed",
            9 => "erst-not-in-ram(IOMMU?)",
            10 => "seg-not-in-ram(IOMMU?)",
            _ => "?",
        };
        eprintln!("[drv] DMA marker[{stage}]: addr=0x{addr:X} value=0x{value:X}");
    }
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
