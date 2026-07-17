//! The live "recording" note-taking window (Slint).
//!
//! Slint owns the main thread (its event loop requires it); the USB capture pipeline runs on
//! a worker. The window stamps each note on the shared master [`Clock`] the instant the user
//! presses Enter, shows it in a scrollback log (with where in the stream it landed), forwards
//! `(ts_ns, text)` to the engine, and renders a live per-source rate/volume dashboard sampled
//! from the shared [`LiveStats`] — aggregates only, never contents, so PCIe's firehose can't
//! drown the UI. The window stays up until the worker finishes (surviving finalize).

use crate::record::RecordSummary;
use crate::record_usb::{EpStat, LiveStats, NotesUi};
use anyhow::Result;
use reveng_core::clock::Clock;
use slint::{ComponentHandle, ModelRc, VecModel};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

slint::include_modules!();

/// What the device picker returned: the USB devices (as `VID:PID`) and one PCIe device (BDF) to
/// co-log. Empty/None = record input + notes only.
pub struct PickerChoice {
    pub usb_vidpids: Vec<String>,
    pub pci_bdf: Option<String>,
}

/// Show the device picker (shown when `record` is launched with no device specified) and return
/// the user's selection, or `None` if they closed it without starting. Must run on the main thread.
pub fn run_device_picker(
    usb: Vec<(String, String)>, // (label, "VID:PID")
    pci: Vec<(String, String)>, // (label, BDF)
    usb_note: &str,             // shown under the USB header (e.g. USBPcap-missing guidance)
    pci_note: &str,             // shown under the PCIe header (e.g. reveng-pcidrv status)
) -> Result<Option<PickerChoice>> {
    let window = DevicePicker::new().map_err(|e| anyhow::anyhow!("create picker: {e}"))?;

    let usb_rows: Vec<DevItem> = usb.iter().map(|(l, _)| DevItem { label: l.as_str().into() }).collect();
    let pci_rows: Vec<DevItem> = pci.iter().map(|(l, _)| DevItem { label: l.as_str().into() }).collect();
    window.set_usb_devices(ModelRc::from(Rc::new(VecModel::from(usb_rows))));
    window.set_pci_devices(ModelRc::from(Rc::new(VecModel::from(pci_rows))));
    window.set_usb_note(usb_note.into());
    window.set_pci_note(pci_note.into());

    let usb_checked = Rc::new(RefCell::new(vec![false; usb.len()]));
    let pci_checked = Rc::new(RefCell::new(vec![false; pci.len()]));
    let started = Rc::new(Cell::new(false));

    {
        let usb_checked = usb_checked.clone();
        window.on_usb_toggled(move |idx, checked| {
            if let Some(slot) = usb_checked.borrow_mut().get_mut(idx as usize) {
                *slot = checked;
            }
        });
    }
    {
        let pci_checked = pci_checked.clone();
        window.on_pci_toggled(move |idx, checked| {
            if let Some(slot) = pci_checked.borrow_mut().get_mut(idx as usize) {
                *slot = checked;
            }
        });
    }
    {
        let started = started.clone();
        window.on_start(move || {
            started.set(true);
            let _ = slint::quit_event_loop();
        });
    }

    window.run().map_err(|e| anyhow::anyhow!("run picker: {e}"))?;

    if !started.get() {
        return Ok(None); // closed without starting
    }
    let usb_vidpids = usb
        .iter()
        .zip(usb_checked.borrow().iter())
        .filter(|(_, &c)| c)
        .map(|((_, vp), _)| vp.clone())
        .collect();
    // Only one PCIe device can be co-logged today — take the first checked.
    let pci_bdf = pci
        .iter()
        .zip(pci_checked.borrow().iter())
        .find(|(_, &c)| c)
        .map(|((_, bdf), _)| bdf.clone());
    Ok(Some(PickerChoice { usb_vidpids, pci_bdf }))
}

/// PCIe rate (events/sec) above which the dashboard flags the stream as "hot".
const PCIE_HOT_RATE: f64 = 20_000.0;
/// Session size above which the header flags a growing-large warning (2 GiB).
const SIZE_WARN_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Show the recording window and run `record` (the USB capture) on a worker thread until it
/// finishes or the user stops it. `out` is the session dir (sampled for on-disk size);
/// `usb_active`/`pcie_active` decide which dashboard rows appear. Must run on the main thread.
#[allow(clippy::too_many_arguments)]
pub fn run_recording_window<F>(
    clock: Clock,
    out: PathBuf,
    usb_active: bool,
    pcie_active: bool,
    mem_active: bool, // memory snapshots armed (--mem-pid/--mem-process) → show the Snapshot button
    trace: Option<(Arc<AtomicBool>, Arc<AtomicBool>)>, // (mmio, dma) live toggles, drv only
    record: F,
) -> Result<RecordSummary>
where
    F: FnOnce(NotesUi) -> Result<RecordSummary> + Send + 'static,
{
    let (note_tx, note_rx) = std::sync::mpsc::channel::<(i64, String)>();
    // Memory-snapshot trigger: the window holds the sender, the capture loop the receiver.
    let (snap_tx, snap_rx) = std::sync::mpsc::channel::<i64>();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let worker_done = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Mutex::new(LiveStats::default()));

    let wiring = NotesUi {
        note_rx,
        snap_rx: mem_active.then_some(snap_rx),
        stop_flag: stop_flag.clone(),
        stats: stats.clone(),
    };

    // Run capture on a worker; signal completion no matter how it ends (including an early
    // startup error) so the window can always close.
    let wd = worker_done.clone();
    let handle = std::thread::Builder::new()
        .name("usb-record".into())
        .spawn(move || {
            let r = record(wiring);
            wd.store(true, Ordering::Relaxed);
            r
        })?;

    let window = RecordWindow::new().map_err(|e| anyhow::anyhow!("create window: {e}"))?;
    window.set_usb_active(usb_active);
    window.set_pcie_active(pcie_active);
    window.set_mem_active(mem_active);
    let notes_model: Rc<VecModel<NoteRow>> = Rc::new(VecModel::default());
    window.set_notes(ModelRc::from(notes_model.clone()));

    // Snapshot button → stamp on the master clock and trigger a memory snapshot on the worker.
    if mem_active {
        let clock = clock.clone();
        let weak = window.as_weak();
        let count = Rc::new(Cell::new(0u32));
        window.on_snapshot(move || {
            let _ = snap_tx.send(clock.now_ns());
            count.set(count.get() + 1);
            if let Some(w) = weak.upgrade() {
                w.set_snap_count(format!("{} snapshot(s)", count.get()).as_str().into());
            }
        });
    }

    // Live MMIO/DMA trace toggles (drv backend): checkboxes flip the shared flags mid-capture.
    if let Some((mmio, dma)) = trace {
        window.set_trace_available(true);
        window.set_trace_mmio_on(mmio.load(Ordering::Relaxed));
        window.set_trace_dma_on(dma.load(Ordering::Relaxed));
        window.on_trace_mmio_toggled(move |on| mmio.store(on, Ordering::Relaxed));
        window.on_trace_dma_toggled(move |on| dma.store(on, Ordering::Relaxed));
    }

    // Enter → stamp on the master clock, show in the log (with stream position), forward it.
    {
        let clock = clock.clone();
        let model = notes_model.clone();
        let stats = stats.clone();
        window.on_submit(move |text| {
            let text = text.trim().to_string();
            if text.is_empty() {
                return;
            }
            let ts = clock.now_ns();
            let pos = {
                let g = stats.lock().unwrap();
                fmt_pos(usb_active, pcie_active, g.usb_frames, g.pcie_events)
            };
            model.push(NoteRow {
                time: fmt_elapsed(ts).as_str().into(),
                text: text.as_str().into(),
                pos: pos.as_str().into(),
            });
            let _ = note_tx.send((ts, text));
        });
    }

    // Stop button → ask the worker to finalize; keep the window up until it does.
    {
        let stop_flag = stop_flag.clone();
        let weak = window.as_weak();
        window.on_stop(move || {
            stop_flag.store(true, Ordering::Relaxed);
            if let Some(w) = weak.upgrade() {
                w.set_recording(false);
                w.set_status("finalizing…".into());
            }
        });
    }

    // Window close (X) behaves like Stop, but we keep the window shown through finalize.
    {
        let stop_flag = stop_flag.clone();
        let weak = window.as_weak();
        window.window().on_close_requested(move || {
            stop_flag.store(true, Ordering::Relaxed);
            if let Some(w) = weak.upgrade() {
                w.set_recording(false);
                w.set_status("finalizing…".into());
            }
            slint::CloseRequestResponse::KeepWindowShown
        });
    }

    // From the UI thread: tick the elapsed clock, sample the live dashboard, and quit once
    // the worker is done. Rates are deltas between ticks.
    let timer = slint::Timer::default();
    {
        let weak = window.as_weak();
        let clock = clock.clone();
        let worker_done = worker_done.clone();
        let stats = stats.clone();
        let out = out.clone();
        let mut last_ns = clock.now_ns();
        let mut last_usb = 0u64;
        let mut last_pcie = 0u64;
        let mut ep_prev: BTreeMap<u8, u64> = BTreeMap::new();
        let mut hinted: BTreeSet<u8> = BTreeSet::new();
        timer.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(250),
            move || {
                if worker_done.load(Ordering::Relaxed) {
                    let _ = slint::quit_event_loop();
                    return;
                }
                let Some(w) = weak.upgrade() else {
                    return;
                };
                if !w.get_recording() {
                    return; // frozen during finalize
                }
                let now = clock.now_ns();
                w.set_elapsed(fmt_elapsed(now).as_str().into());

                let (uf, ub, pe, pb, by_ep, pk) = {
                    let g = stats.lock().unwrap();
                    (
                        g.usb_frames,
                        g.usb_bytes,
                        g.pcie_events,
                        g.pcie_bytes,
                        g.usb_by_ep.clone(),
                        (g.pcie_config, g.pcie_mmio, g.pcie_dma, g.pcie_irq),
                    )
                };
                let dt = (now - last_ns) as f64 / 1e9;
                let usb_rate = if dt > 0.0 { (uf - last_usb) as f64 / dt } else { 0.0 };
                let pcie_rate = if dt > 0.0 { (pe - last_pcie) as f64 / dt } else { 0.0 };
                last_ns = now;
                last_usb = uf;
                last_pcie = pe;

                w.set_usb_stats(
                    format!("{} fr · {} · {}", fmt_count(uf), fmt_bytes(ub), fmt_rate(usb_rate))
                        .as_str()
                        .into(),
                );
                w.set_usb_endpoints(fmt_top_endpoints(&by_ep).as_str().into());
                w.set_pcie_stats(
                    format!("{} ev · {} · {}", fmt_count(pe), fmt_bytes(pb), fmt_rate(pcie_rate))
                        .as_str()
                        .into(),
                );
                w.set_pcie_kinds(fmt_pcie_kinds(pk.0, pk.1, pk.2, pk.3).as_str().into());
                w.set_pcie_hot(pcie_rate >= PCIE_HOT_RATE);

                // Adaptive: nudge once per endpoint that sustains a high byte-rate (default stays
                // lossless; the hint just points at the reduction flags).
                if dt > 0.0 {
                    for (&ep, st) in &by_ep {
                        let prev = ep_prev.get(&ep).copied().unwrap_or(0);
                        let mb_per_s = (st.bytes.saturating_sub(prev)) as f64 / dt / (1024.0 * 1024.0);
                        if !hinted.contains(&ep) {
                            if let Some(msg) = hot_hint(ep, st.transfer, mb_per_s) {
                                eprintln!("{msg}");
                                hinted.insert(ep);
                            }
                        }
                        ep_prev.insert(ep, st.bytes);
                    }
                }

                let size = session_size(&out);
                w.set_size_text(fmt_bytes(size).as_str().into());
                w.set_size_warn(size >= SIZE_WARN_BYTES);
            },
        );
    }

    window.run().map_err(|e| anyhow::anyhow!("run window: {e}"))?;

    match handle.join() {
        Ok(r) => r,
        Err(_) => anyhow::bail!("recording thread panicked"),
    }
}

/// Session-relative `ns` → `mm:ss`.
fn fmt_elapsed(ns: i64) -> String {
    let secs = (ns / 1_000_000_000).max(0);
    format!("{:02}:{:02}", secs / 60, secs % 60)
}

/// Compact count: `938`, `12.3k`, `1.2M`.
fn fmt_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1e6)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1e3)
    } else {
        n.to_string()
    }
}

/// Compact rate: `830/s`, `42.1k/s`, `1.2M/s`.
fn fmt_rate(r: f64) -> String {
    if r >= 1_000_000.0 {
        format!("{:.1}M/s", r / 1e6)
    } else if r >= 1_000.0 {
        format!("{:.1}k/s", r / 1e3)
    } else {
        format!("{:.0}/s", r)
    }
}

/// Human byte size (binary units).
fn fmt_bytes(b: u64) -> String {
    const K: f64 = 1024.0;
    let f = b as f64;
    if f >= K * K * K {
        format!("{:.1} GB", f / (K * K * K))
    } else if f >= K * K {
        format!("{:.1} MB", f / (K * K))
    } else if f >= K {
        format!("{:.1} KB", f / K)
    } else {
        format!("{b} B")
    }
}

/// Where a note landed in the stream(s), for the log's third column.
fn fmt_pos(usb: bool, pcie: bool, usb_frames: u64, pcie_events: u64) -> String {
    match (usb, pcie) {
        (true, true) => format!("usb {} · pcie {}", fmt_count(usb_frames), fmt_count(pcie_events)),
        (true, false) => format!("usb {}", fmt_count(usb_frames)),
        (false, true) => format!("pcie {}", fmt_count(pcie_events)),
        (false, false) => String::new(),
    }
}

/// Short transfer-type tag for the dashboard.
fn xfer_short(t: u8) -> &'static str {
    match t {
        0 => "iso",
        1 => "int",
        2 => "ctl",
        3 => "blk",
        _ => "?",
    }
}

/// Byte-rate (MB/s) above which an endpoint is flagged as a firehose.
const HOT_MB_PER_S: f64 = 5.0;

/// One-time nudge for a high-bandwidth endpoint pointing at the reduction flags. Pure/tested.
fn hot_hint(endpoint: u8, transfer: u8, mb_per_s: f64) -> Option<String> {
    if mb_per_s < HOT_MB_PER_S {
        return None;
    }
    let drop = match transfer {
        0 => " or --drop-isoc",
        3 => " or --drop-bulk",
        _ => "",
    };
    Some(format!(
        "ep 0x{endpoint:02x} ({}) {mb_per_s:.0} MB/s — consider --usb-snaplen 256{drop}",
        xfer_short(transfer)
    ))
}

/// PCIe events by kind for the recording-window panel, e.g. `cfg 64 · mmio 1.2k · dma 245`.
/// Kinds with a zero count are omitted.
fn fmt_pcie_kinds(config: u64, mmio: u64, dma: u64, irq: u64) -> String {
    let mut parts = Vec::new();
    for (label, n) in [("cfg", config), ("mmio", mmio), ("dma", dma), ("irq", irq)] {
        if n > 0 {
            parts.push(format!("{label} {}", fmt_count(n)));
        }
    }
    parts.join(" · ")
}

/// Top endpoints by captured bytes, e.g. `0x81 iso 88.0 MB · 0x02 blk 1.2 MB`.
fn fmt_top_endpoints(by_ep: &BTreeMap<u8, EpStat>) -> String {
    let mut v: Vec<(&u8, &EpStat)> = by_ep.iter().collect();
    v.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes));
    v.iter()
        .take(3)
        .map(|(ep, st)| format!("0x{:02x} {} {}", ep, xfer_short(st.transfer), fmt_bytes(st.bytes)))
        .collect::<Vec<_>>()
        .join(" · ")
}

/// On-disk session size — the big traffic logs (skips the screenshots dir walk).
fn session_size(out: &Path) -> u64 {
    ["usb.pcapng", "pcie.bin", "frames.idx", "pcie.idx", "events.ndjson"]
        .iter()
        .filter_map(|f| std::fs::metadata(out.join(f)).ok())
        .map(|m| m.len())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_formatters() {
        assert_eq!(fmt_count(938), "938");
        assert_eq!(fmt_count(12_345), "12.3k");
        assert_eq!(fmt_count(1_200_000), "1.2M");
        assert_eq!(fmt_rate(830.0), "830/s");
        assert_eq!(fmt_rate(42_100.0), "42.1k/s");
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1536), "1.5 KB");
        assert_eq!(fmt_bytes(2 * 1024 * 1024), "2.0 MB");
        assert_eq!(fmt_elapsed(83_000_000_000), "01:23");
        assert_eq!(fmt_pos(true, true, 8_900, 900_000), "usb 8.9k · pcie 900.0k");
        assert_eq!(fmt_pos(false, true, 0, 40_000), "pcie 40.0k");
        assert_eq!(fmt_pos(true, false, 1_234, 0), "usb 1.2k");
    }

    #[test]
    fn hot_hint_fires_only_above_threshold() {
        assert!(hot_hint(0x81, 0, 1.0).is_none());
        let h = hot_hint(0x81, 0, 42.0).unwrap();
        assert!(h.contains("0x81") && h.contains("iso") && h.contains("--drop-isoc"));
        let b = hot_hint(0x02, 3, 10.0).unwrap();
        assert!(b.contains("--drop-bulk"));
        // control endpoint over threshold: still hint snaplen, no drop suggestion.
        let c = hot_hint(0x00, 2, 10.0).unwrap();
        assert!(c.contains("--usb-snaplen") && !c.contains("--drop"));
    }

    #[test]
    fn pcie_kinds_omits_zeros() {
        assert_eq!(fmt_pcie_kinds(64, 0, 0, 0), "cfg 64");
        assert_eq!(fmt_pcie_kinds(64, 1200, 245, 3), "cfg 64 · mmio 1.2k · dma 245 · irq 3");
        assert_eq!(fmt_pcie_kinds(0, 0, 0, 0), "");
    }

    #[test]
    fn top_endpoints_sorted_by_bytes() {
        let mut m = BTreeMap::new();
        m.insert(0x02u8, EpStat { frames: 1, bytes: 100, transfer: 3 });
        m.insert(0x81u8, EpStat { frames: 1, bytes: 9_000_000, transfer: 0 });
        let s = fmt_top_endpoints(&m);
        assert!(s.starts_with("0x81 iso"));
    }
}
