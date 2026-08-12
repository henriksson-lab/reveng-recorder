//! Live USB recording orchestration (DESIGN.md §3 thread model, §6, §7).
//!
//! Wires the moving parts around the checkpoint engine:
//! - one or more **reader threads** draining a [`CaptureSource`] into the shared
//!   `usb.pcapng` + `frames.idx`, bumping a traffic counter (must never block — §3). The
//!   source is either the USBPcap driver (whole transfers) or a Cynthion analyzer (raw wire
//!   packets); see [`UsbBackend`], and §4.1 for what differs downstream;
//! - the **engine**, which turns clicks / special keys / traffic-interval ticks into
//!   checkpoints anchored to the nearest preceding frame, then finalizes the session by
//!   injecting checkpoint comments into the pcapng (§4).
//!
//! Two more parts run only when the target is *this* machine — the **input hooks**
//! (`winput`) feeding events over a channel, and the **screenshot worker** (`winshot`)
//! grabbing PNGs off the hot path with burst coalescing (§6). Both are absent under
//! [`UsbRecordOpts::traffic_only`], which exists because a hardware analyzer usually watches
//! a bus belonging to some other computer (§4.4).

use crate::record::RecordSummary;
use anyhow::Result;
use reveng_core::checkpoint::{Checkpoint, CheckpointConfig, CheckpointType};
use reveng_core::clock::Clock;
use reveng_core::event::{PcieEvent, SourceKind, TrafficAnchor, TrafficKind, UsbFrameHeader};
use reveng_core::index::IndexFile;
use reveng_core::session::{SessionRecord, SessionWriter};
use reveng_core::source::CaptureSource;
use reveng_pcicap::PcieLog;
use reveng_usbcap::wire::PacketKind as WireKind;
use reveng_usbcap::{UsbCaptureSource, UsbIdxRecord, UsbSelection, UsbWriter};
use reveng_winput::{InputEvent, InputKind};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A screenshot request: `(checkpoint id, ts_ns, capture scope, cursor position)`. Sent from
/// the engine to the `winshot` worker so the grab happens off the hot path.
type ShotRequest = (u64, i64, reveng_winshot::Scope, (i32, i32));

/// Which USB capture backend this session records with.
///
/// Mutually exclusive by construction, which also settles a hazard the design worried about:
/// a USBPcap source and a Cynthion source watching the same device would both report its
/// traffic into the one `usb.pcapng`, at two different abstraction levels.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UsbBackend {
    /// The Windows USBPcap kernel driver: whole transfers, needs Administrator.
    UsbPcap,
    /// A Cynthion hardware analyzer: raw wire packets, no kernel driver, any OS.
    Cynthion { speed: reveng_cynthion::Speed },
}

impl UsbBackend {
    pub fn name(self) -> &'static str {
        match self {
            UsbBackend::UsbPcap => "usbpcap",
            UsbBackend::Cynthion { .. } => "cynthion",
        }
    }

    /// Only the USBPcap driver needs elevation; the analyzer is opened as a plain USB device.
    pub fn needs_admin(self) -> bool {
        matches!(self, UsbBackend::UsbPcap)
    }

    fn capture_format(self) -> reveng_usbcap::CaptureFormat {
        match self {
            UsbBackend::UsbPcap => reveng_usbcap::CaptureFormat::UsbPcap,
            UsbBackend::Cynthion { .. } => reveng_usbcap::CaptureFormat::Wire,
        }
    }
}

/// When to grab a screenshot.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScreenshotWhen {
    Mousedown,
    Mouseup,
    Both,
    None,
}

/// Sentinel file inside a session directory that asks a running capture to stop.
/// A file rather than a signal or socket: it works from any process, needs no
/// handle to the recorder, survives elevation boundaries, and is trivially
/// inspectable when a run ends unexpectedly.
pub const STOP_FILE: &str = ".stop";

pub struct UsbRecordOpts {
    /// One capture per USBPcap control device (root hub) to record in parallel — each gets
    /// its own reader thread folding frames into the one `usb.pcapng` on the shared clock.
    ///
    /// **Empty means "no traffic capture"**, and the run still produces a session from
    /// whatever else is enabled — notes always, plus input and screenshots unless
    /// [`Self::traffic_only`] is set. That is how the UI runs with no device, no USBPcap and
    /// no admin.
    ///
    /// For [`UsbBackend::Cynthion`] there is nothing to select — the analyzer records
    /// whatever is physically routed through it — so the list holds one placeholder entry
    /// purely to mean "capture is on".
    pub selections: Vec<UsbSelection>,
    /// Which capture backend to open. Decides the source, the pcapng link type, and how the
    /// reader thread must interpret each packet — a USBPcap header parse over a wire packet
    /// reads the PID and CRC as an endpoint and a length, and quietly produces nonsense.
    pub backend: UsbBackend,
    /// Keep Start-of-Frame packets in a wire capture. SOF carries no data and, at high speed,
    /// arrives every 125 µs — it would dominate a capture's volume. Dropped by default (and
    /// counted, so the reduction is visible); keep them for bus-timing work.
    pub keep_sof: bool,
    pub cfg: CheckpointConfig,
    pub screenshot_on: ScreenshotWhen,
    pub screenshot_on_keys: bool,
    pub scope: reveng_winshot::Scope,
    pub min_interval_ms: u64,
    /// VK of the stop-hotkey trigger (fires with Ctrl+Alt held). Default VK_PAUSE (0x13).
    pub stop_vk: u16,
    /// Optional bounded capture: auto-stop after this long. Independent of `headless` — a
    /// windowed run auto-closes when it fires. `None` = until stop hotkey / Stop button.
    pub max_duration: Option<Duration>,
    /// Run without the Slint recording window (unattended automation). Orthogonal to
    /// `max_duration`. `false` = show the window (the default interactive experience).
    pub headless: bool,
    /// **Remote-target mode**: record bus traffic and notes only — no input hooks, no
    /// screenshots, no UI-Automation/OCR.
    ///
    /// With a hardware analyzer the capture host is usually *not* the machine being driven,
    /// so the host-side correlation features would faithfully record the operator's own
    /// desktop instead of the target's. Worse, they would do it while looking like they were
    /// capturing the target.
    ///
    /// Notes stay. On a past camera bring-up they were the single most valuable correlation
    /// signal ("usb is in", "starting software", "inserting the tray"), and they matter more
    /// here, not less: when the operator is driving a second machine, nothing else on this
    /// host knows what is happening over there.
    ///
    /// This also shrinks what the tool *is*: with input and screen capture off it is a
    /// traffic sniffer and nothing else, and the consent banner says so rather than being
    /// suppressed.
    pub traffic_only: bool,
    /// Driver snaplen in bytes (`0` = unlimited default). Truncates big transfers in the kernel.
    pub snaplen: u32,
    /// Driver kernel buffer size in bytes (`0` = default).
    pub buffer: u32,
    /// USBPcap transfer-type codes to drop before writing (e.g. isoc). Empty = keep all.
    pub drop_transfers: Vec<u8>,
    /// If set, capture only these endpoint numbers (direction-agnostic, `0x0F`-masked).
    pub endpoints: Option<Vec<u8>>,
    /// Stop once total captured traffic bytes (USB + PCIe) reach this budget. `None` = no cap.
    pub max_bytes: Option<u64>,
    /// Abort early if no new USB frame arrives for this long — kills the "0 frames after the full
    /// timer" waste when the device wasn't actually streaming. `None` = wait for the real stop.
    pub abort_if_idle: Option<Duration>,
    /// Stop cleanly when this file appears. The out-of-band stop: a caller that
    /// cannot press the hotkey (a script, another process, an agent driving the
    /// bench) creates it with `reveng-rec stop <session>` when the interesting
    /// part is over, instead of guessing a `--max-seconds` up front and either
    /// truncating the run or waiting out a timer. `None` = no file watch.
    pub stop_file: Option<std::path::PathBuf>,
    /// Stop once this many USB frames have been captured (a bounded, traffic-driven run). `None` = no cap.
    pub stop_after_frames: Option<u64>,
    /// Arm manual process-memory snapshots against this PID (the decoded-form oracle). The
    /// window shows a Snapshot button; each press dumps the target's memory + emits a checkpoint
    /// carrying `mem_snapshot_id`. `None` = feature off.
    pub mem_pid: Option<u32>,
    /// Arm memory snapshots against the first process matching this image name (alt to `mem_pid`).
    pub mem_process: Option<String>,
    /// Compress each memory snapshot's `regions.bin` with deflate (smaller on disk, a little CPU).
    pub mem_compress: bool,
}

/// Wiring from the live "recording" note window (`notes_ui`) into the capture loop.
/// The window runs on the main thread; the capture pipeline runs on a worker and drains
/// these. Absent for headless/automation runs (`--max-seconds`, `REVENG_NO_NOTES_UI`).
pub struct NotesUi {
    /// `(ts_ns stamped at Enter, note text)`, one per submitted note.
    pub note_rx: Receiver<(i64, String)>,
    /// `ts_ns` stamped when the window's Snapshot button is pressed — a manual memory-snapshot
    /// trigger. `None` when memory snapshots aren't armed (`--mem-pid`/`--mem-process` unset).
    pub snap_rx: Option<Receiver<i64>>,
    /// Set by the window's Stop button / close; a stop condition for the capture loop.
    pub stop_flag: Arc<AtomicBool>,
    /// Live per-source counters the window samples to render its rate/volume dashboard —
    /// essential once PCIe is firehosing tens of thousands of events/sec.
    pub stats: Arc<Mutex<LiveStats>>,
}

/// Per-endpoint capture tally (identifies *which* endpoint is the firehose).
#[derive(Default, Clone, Copy)]
pub struct EpStat {
    pub frames: u64,
    pub bytes: u64,
    /// USBPcap transfer-type code last seen on this endpoint (0=iso 1=intr 2=ctrl 3=bulk).
    pub transfer: u8,
}

/// Monotonic per-source capture counters, published by the reader threads and sampled by the
/// recording window (rates are computed there from deltas). Aggregates only — never contents.
#[derive(Default)]
pub struct LiveStats {
    pub usb_frames: u64,
    pub usb_bytes: u64,
    pub usb_dropped: u64,
    /// Per-endpoint (by endpoint byte) frame/byte tallies, for the dashboard + hot-endpoint hint.
    pub usb_by_ep: std::collections::BTreeMap<u8, EpStat>,
    pub pcie_events: u64,
    pub pcie_bytes: u64,
    /// PCIe event counts by kind, for the recording-window PCIe panel.
    pub pcie_config: u64,
    pub pcie_mmio: u64,
    pub pcie_dma: u64,
    pub pcie_irq: u64,
}

/// Capture-side packet filter (reduction for high-data devices like cameras): drop chosen
/// transfer types (e.g. isoc) and/or restrict to an endpoint allow-list. Empty = keep all
/// (the lossless default). Never silent — drops are counted and surfaced.
#[derive(Clone, Default)]
pub struct PacketFilter {
    /// USBPcap transfer-type codes to drop (0=iso 1=intr 2=ctrl 3=bulk).
    pub drop_transfers: Vec<u8>,
    /// Endpoint numbers to keep (direction-agnostic); `None` = all endpoints.
    pub endpoints: Option<Vec<u8>>,
}

impl PacketFilter {
    fn is_active(&self) -> bool {
        !self.drop_transfers.is_empty() || self.endpoints.is_some()
    }
}

/// Should this packet be kept? Unparseable headers are always kept (never lose data we can't
/// classify). Endpoint matching is direction-agnostic (`0x0F`-masked). Pure — unit-tested.
fn keep_packet(header: Option<&UsbFrameHeader>, filter: &PacketFilter) -> bool {
    let Some(h) = header else {
        return true;
    };
    if filter.drop_transfers.contains(&h.transfer) {
        return false;
    }
    if let Some(allow) = &filter.endpoints {
        if !allow.contains(&(h.endpoint & 0x0F)) {
            return false;
        }
    }
    true
}

/// Extra (traffic-driven) stop conditions beyond duration/byte budget. Pure — unit-tested.
/// `since_last_frame` is time since the last USB frame arrived (or since start if none have).
fn extra_stop_reason(
    frames: u64,
    since_last_frame: Duration,
    abort_if_idle: Option<Duration>,
    stop_after_frames: Option<u64>,
) -> Option<&'static str> {
    if stop_after_frames.is_some_and(|n| frames >= n) {
        return Some("--stop-after-frames reached");
    }
    if abort_if_idle.is_some_and(|t| since_last_frame >= t) {
        return Some("--abort-if-idle: no new traffic");
    }
    None
}

/// A PCIe source captured *concurrently* with USB (`--with-pcie`), folded into the same
/// session on the shared clock. Its own reader thread writes `pcie.bin`/`pcie.idx`, and every
/// checkpoint gains a secondary anchor to the nearest preceding PCIe event, so one checkpoint
/// reaches both wires. The source is already `start()`ed by the caller; `stop` unblocks a
/// parked `next()` at finalize (e.g. `CancelIoEx` for the driver backend).
pub struct PcieCapture {
    pub source: Box<dyn CaptureSource + Send>,
    pub stop: Box<dyn Fn() + Send + Sync>,
    /// Extra `meta.json` fields describing the PCIe acquisition.
    pub meta: serde_json::Value,
    /// Live MMIO/DMA snapshot toggles (drv backend only), so the window can pause them.
    pub trace_mmio: Option<Arc<AtomicBool>>,
    pub trace_dma: Option<Arc<AtomicBool>>,
}

/// Shared PCIe-reader→engine state: the latest PCIe event, for secondary-anchor resolution.
#[derive(Default)]
struct PcieState {
    latest_index: Option<u64>,
    latest_offset: u64,
    /// Total PCIe event bytes seen (for the `--max-bytes` budget).
    total_bytes: u64,
}

/// Shared, readers→engine traffic state (the `bytes_since_ckpt` counter + latest frame).
/// One instance is shared across all parallel reader threads, so it also serializes the
/// merged frame index: `last_ts` clamps arrival-order timestamps non-decreasing (frames
/// from different hubs interleave) so `frames.idx` stays binary-searchable.
#[derive(Default)]
struct TrafficState {
    latest_index: Option<u64>,
    latest_offset: u64,
    total_frames: u64,
    bytes_since: u64,
    /// Highest timestamp written so far (merged-index monotonicity clamp).
    last_ts: i64,
    /// Total USB payload bytes written (for the `--max-bytes` budget).
    total_bytes: u64,
    /// Reader threads still running; when it reaches 0 (all sources ended) the session is done.
    active_sources: usize,
    /// Packets dropped by the capture-side filter (transfer-type / endpoint), for the summary.
    dropped: u64,
    done: bool,
    error: Option<String>,
}

struct UsbReaderGuard {
    stop: Arc<AtomicBool>,
    /// Out-of-band stop handles, one per source. `CaptureSource` has no cancellation
    /// method, so a source parked in a blocking `next()` can only be unblocked from
    /// outside — without these, finalize hangs. Boxed rather than `Killer` so any
    /// backend can supply its own (the PCIe path already does exactly this).
    killers: Vec<Box<dyn Fn() + Send + Sync>>,
    readers: Vec<std::thread::JoinHandle<Result<()>>>,
}

impl UsbReaderGuard {
    fn new(stop: Arc<AtomicBool>) -> Self {
        Self {
            stop,
            killers: Vec::new(),
            readers: Vec::new(),
        }
    }

    fn stop_and_join(&mut self, state: &Arc<Mutex<TrafficState>>) {
        self.stop.store(true, Ordering::Relaxed);
        for killer in &self.killers {
            killer();
        }
        for reader in self.readers.drain(..) {
            if reader.join().is_err() {
                record_reader_error(state, "USB reader thread panicked".into());
            }
        }
        self.killers.clear();
    }
}

impl Drop for UsbReaderGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for killer in &self.killers {
            killer();
        }
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

struct PcieReaderGuard {
    stop: Option<Box<dyn Fn() + Send + Sync>>,
    reader: Option<std::thread::JoinHandle<Result<()>>>,
}

impl PcieReaderGuard {
    fn stop_and_join(&mut self, state: &Arc<Mutex<TrafficState>>) {
        if let Some(stop) = self.stop.take() {
            stop();
        }
        if self
            .reader
            .take()
            .is_some_and(|reader| reader.join().is_err())
        {
            record_reader_error(state, "PCIe reader thread panicked".into());
        }
    }
}

impl Drop for PcieReaderGuard {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

pub fn run_usb_capture(
    clock: Clock,
    out: &Path,
    mut opts: UsbRecordOpts,
    ui: Option<NotesUi>,
    pcie: Option<PcieCapture>,
) -> Result<RecordSummary> {
    // Every session is stoppable out-of-band by default: `reveng-rec stop <session>`
    // drops this file in, and the poll loop finalizes cleanly. Placed here rather
    // than in the option builder because only this layer knows the session path.
    if opts.stop_file.is_none() {
        opts.stop_file = Some(out.join(STOP_FILE));
    }
    // The clock is created by the caller so the notes window shares this exact origin.
    let (note_rx, snap_rx, ui_stop, stats) = match ui {
        Some(u) => (Some(u.note_rx), u.snap_rx, Some(u.stop_flag), Some(u.stats)),
        None => (None, None, None, None),
    };
    let session = SessionWriter::create(out)?;
    let shots_dir = session.screenshots_dir();
    let memsnaps_dir = session.memsnaps_dir();

    let state = Arc::new(Mutex::new(TrafficState::default()));
    let reader_stop = Arc::new(AtomicBool::new(false));

    // --- readers: one per USBPcap control device (root hub) captured in parallel, or the
    // single Cynthion source, all folded into the shared `usb.pcapng`/`frames.idx`. Start
    // them up front so open errors surface here. Empty `selections` = no capture at all; the
    // window still runs on whatever else is enabled, needing no device and no admin.
    let mut usb_threads = UsbReaderGuard::new(reader_stop.clone());

    // Start each selected control device, skipping (not aborting on) any that fail — one hub
    // that won't open must not take down the others. Collect the survivors, then create the
    // shared writer only if at least one opened (else it's the no-capture case).
    let filter = PacketFilter {
        drop_transfers: opts.drop_transfers.clone(),
        endpoints: opts.endpoints.clone(),
    };
    // Started sources paired with their out-of-band stop handle. Boxed as
    // `CaptureSource` so a second USB backend (a hardware sniffer) can be mixed in
    // here without touching the reader thread, the writer, or anything downstream.
    let mut sources: Vec<(Box<dyn CaptureSource + Send>, Box<dyn Fn() + Send + Sync>)> = Vec::new();
    match opts.backend {
        UsbBackend::UsbPcap => {
            for selection in &opts.selections {
                let mut source = UsbCaptureSource::new(selection.clone(), clock.clone());
                source.set_capture_opts(opts.snaplen, opts.buffer);
                match source.start() {
                    Ok(()) => {
                        let killer = source.killer();
                        sources.push((Box::new(source), Box::new(move || killer.kill())));
                    }
                    Err(e) => eprintln!(
                        "usb capture skipped for {}: {e}",
                        selection.usbpcap_device.as_deref().unwrap_or("?")
                    ),
                }
            }
        }
        // One analyzer taps one bus, so there is exactly one source — no per-hub selection,
        // and `--device-*` has nothing to act on.
        UsbBackend::Cynthion { speed } => {
            if !opts.selections.is_empty() {
                let mut source = reveng_cynthion::CynthionSource::new(clock.clone(), speed);
                // Bus events have no place in a USB 2.0 pcapng, so they go beside it. Without
                // this the capture keeps no record of a bus reset, a speed change, or the
                // analyzer overflowing — and cannot tell an idle bus from a mis-sampled one.
                let sidecar = reveng_cynthion::events::sidecar_path(&session.usb_pcapng());
                if let Err(e) = source.log_events_to(&sidecar) {
                    eprintln!("bus-event sidecar disabled: {e}");
                }
                match source.start() {
                    Ok(()) => {
                        let stopper = source.stopper();
                        sources.push((Box::new(source), Box::new(move || stopper.stop())));
                    }
                    Err(e) => eprintln!("cynthion capture failed to start: {e}"),
                }
            }
        }
    }
    let writer = if sources.is_empty() {
        None
    } else {
        // The link type is how the session records which backend wrote it — and, for a wire
        // capture, the speed it was sampled at, which nothing in the packet bytes recovers.
        let w = match opts.backend {
            UsbBackend::UsbPcap => UsbWriter::create(session.usb_pcapng(), session.frames_idx())?,
            UsbBackend::Cynthion { speed } => UsbWriter::create_wire(
                session.usb_pcapng(),
                session.frames_idx(),
                speed.link_type(),
            )?,
        };
        Some(Arc::new(Mutex::new(w)))
    };
    if let Some(writer) = &writer {
        state.lock().unwrap().active_sources = sources.len();
        for (i, (source, killer)) in sources.into_iter().enumerate() {
            usb_threads.killers.push(killer);
            let writer = writer.clone();
            let state = state.clone();
            let reader_stop = reader_stop.clone();
            let stats = stats.clone();
            let filter = filter.clone();
            let format = opts.backend.capture_format();
            let keep_sof = opts.keep_sof;
            usb_threads.readers.push(
                std::thread::Builder::new()
                    .name(format!("usbcap-reader-{i}"))
                    .spawn(move || {
                        reader_loop(
                            source,
                            writer,
                            state,
                            reader_stop,
                            stats,
                            filter,
                            format,
                            keep_sof,
                        )
                    })?,
            );
        }
    }

    // --- monitor layout: logged once at session start, so screenshot coordinates are
    //     interpretable later (which monitor, what bounds, DPI/scaling). ---
    //     Skipped in --traffic-only: there are no screenshots to interpret, and enumerating
    //     this host's displays would only describe the wrong machine.
    if !opts.traffic_only {
        match reveng_winshot::enumerate_displays() {
            Ok(displays) => {
                if let Ok(json) = serde_json::to_string_pretty(&displays) {
                    let _ = std::fs::write(session.displays_json(), json);
                }
            }
            Err(e) => eprintln!("display enumeration failed: {e}"),
        }
    }

    // --- screenshot + UI-Automation worker ---
    // Carries (id, ts_ns, scope, cursor). Per checkpoint it: (1) grabs the PNG and appends
    // capture geometry to `screenshots.ndjson` (the spatial index), and (2) snapshots the
    // UI-Automation widget tree of the clicked window to `ui/<id>.json` (typed controls +
    // rects + live states/values — the structured screen-side oracle).
    // Not spawned in --traffic-only, which also disposes of the UI-Automation/OCR snapshot
    // it performs: both describe *this* host's screen, which in remote-target mode is not
    // the machine under test.
    let shots_meta_path = session.screenshots_meta();
    let ui_dir = session.ui_dir();
    let (shot_tx, shot_rx) = std::sync::mpsc::channel::<ShotRequest>();
    // `drop` explicitly: shadowing the binding would leave the original Sender alive to the
    // end of the function, so `shot_rx.recv()` would never return and the join below would
    // hang forever.
    let shot_tx = if opts.traffic_only {
        drop(shot_tx);
        None
    } else {
        Some(shot_tx)
    };
    if !opts.traffic_only {
        let _ = std::fs::create_dir_all(&ui_dir);
    }
    let shot_worker = std::thread::Builder::new()
        .name("winshot-worker".into())
        .spawn(move || {
            let mut meta = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&shots_meta_path)
                .ok();
            while let Ok((id, ts_ns, scope, cursor)) = shot_rx.recv() {
                let path = shots_dir.join(format!("{id:06}.png"));
                match reveng_winshot::capture_to(&path, scope) {
                    Ok(geom) => {
                        if let Some(f) = meta.as_mut() {
                            let line = serde_json::json!({
                                "id": id, "ts_ns": ts_ns,
                                "origin_x": geom.origin_x, "origin_y": geom.origin_y,
                                "width": geom.width, "height": geom.height,
                                "cursor_x": geom.cursor_x, "cursor_y": geom.cursor_y,
                                "monitor_index": geom.monitor_index, "dpi": geom.dpi,
                                "scope": geom.scope,
                            });
                            use std::io::Write as _;
                            let _ = writeln!(f, "{line}");
                        }
                    }
                    Err(e) => eprintln!("screenshot {id} failed: {e}"),
                }
                // UIA snapshot of the window the user clicked (fall back to foreground when the
                // cursor is unset, e.g. interval checkpoints). Best-effort — a thin/empty tree
                // just means no `ui/<id>.json`.
                let ui = if cursor != (0, 0) {
                    reveng_winui::snapshot_at_point(cursor.0, cursor.1)
                } else {
                    reveng_winui::snapshot_foreground()
                };
                if let Ok(els) = ui {
                    if !els.is_empty() {
                        if let Ok(json) = serde_json::to_vec(&els) {
                            let _ = std::fs::write(ui_dir.join(format!("{id:06}.json")), json);
                        }
                    }
                }
            }
        })?;

    // --- memory-snapshot worker (manual trigger via the window's Snapshot button) ---
    // The target is opened here (so failure surfaces up front) and moved into the worker; each
    // trigger dumps its committed private memory to `memsnaps/<id:06>/`. `mem_tx` stays `None`
    // when the feature is off or the target can't be opened, so a stray press is a no-op.
    let (mem_tx, mem_rx) = std::sync::mpsc::channel::<(u64, i64)>();
    let (mem_worker, mem_tx) = match open_mem_source(&opts) {
        None => (None, None),
        Some(Err(e)) => {
            eprintln!("memory snapshots disabled: {e}");
            (None, None)
        }
        Some(Ok(src)) => {
            eprintln!("memory snapshots armed for pid {}", src.pid());
            let dir = memsnaps_dir.clone();
            let compress = opts.mem_compress;
            let h = std::thread::Builder::new()
                .name("memcap-worker".into())
                .spawn(move || {
                    while let Ok((id, ts)) = mem_rx.recv() {
                        let d = dir.join(format!("{id:06}"));
                        match src.snapshot(id, ts, &d, compress) {
                            Ok(m) => eprintln!(
                                "memory snapshot #{id}: {} regions, {} B ({} B on disk)",
                                m.regions.len(),
                                m.total_bytes,
                                m.stored_bytes
                            ),
                            Err(e) => eprintln!("memory snapshot #{id} failed: {e}"),
                        }
                    }
                })?;
            (Some(h), Some(mem_tx))
        }
    };
    let mut mem_next_id: u64 = 0;

    // --- input hooks ---
    // Not installed in --traffic-only. This is the difference between "a traffic sniffer"
    // and "a keylogger that also sniffs traffic", so it is a real absence, not a filter
    // applied after capture: with the capture host separate from the target, every keystroke
    // the hooks would see belongs to the operator, not to the experiment.
    let (in_tx, in_rx) = std::sync::mpsc::channel::<InputEvent>();
    let hooks = if opts.traffic_only {
        drop(in_tx);
        None
    } else {
        Some(reveng_winput::install(clock.clone(), move |ev| {
            let _ = in_tx.send(ev);
        })?)
    };

    // --- concurrent PCIe capture (--with-pcie): its own reader thread writing pcie.bin, plus
    //     a shared latest-event cell so each checkpoint anchors to the nearest preceding PCIe
    //     event as well as the USB frame. The source is already started by the caller. ---
    let mut pcie_meta: Option<serde_json::Value> = None;
    let (pcie_state, mut pcie_thread) = if let Some(pcie) = pcie {
        // trace_mmio/dma toggles are held by the source + window; not needed here.
        let PcieCapture {
            source, stop, meta, ..
        } = pcie;
        let log = PcieLog::create(session.pcie_bin(), session.pcie_idx())?;
        let st = Arc::new(Mutex::new(PcieState::default()));
        let handle = {
            let st = st.clone();
            let traffic = state.clone();
            let reader_stop = reader_stop.clone();
            let stats = stats.clone();
            std::thread::Builder::new()
                .name("pcie-reader".into())
                .spawn(move || pcie_reader_loop(source, log, st, traffic, reader_stop, stats))?
        };
        pcie_meta = Some(meta);
        (
            Some(st),
            Some(PcieReaderGuard {
                stop: Some(stop),
                reader: Some(handle),
            }),
        )
    } else {
        (None, None)
    };

    // --- the checkpoint engine --- (USB is primary when at least one USB source started)
    let usb_active = writer.is_some();
    let mut engine = Engine::new(
        session,
        &opts,
        shot_tx,
        clock.clone(),
        usb_active,
        pcie_state.clone(),
    );
    engine.emit(
        CheckpointType::SessionStart,
        "session_start",
        0,
        None,
        false,
        (0, 0),
        None,
    )?;

    let start = Instant::now();
    let interval_ns = (opts.cfg.interval_ms as i64).saturating_mul(1_000_000);
    // Idle-abort / frame-cap bookkeeping: track the last time a new USB frame arrived.
    let mut last_frames = 0u64;
    let mut last_frame_at = start;
    let run_result = (|| -> Result<()> {
        loop {
            match in_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(ev) => engine.on_input(&ev, &state)?,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                // In --traffic-only there are no input hooks, so the channel is closed from
                // the start. That is not the end of the run — pace the loop and carry on, or
                // every traffic-only session would finish the instant it began.
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) if opts.traffic_only => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }

            // Remember the target app's foreground so a note (typed into our own window) is
            // attributed to what the user was actually working in. Not in --traffic-only:
            // the foreground window here belongs to the operator's machine, not the target,
            // so recording it would be both useless and outside what that mode promises.
            if !opts.traffic_only && !reveng_winput::foreground_is_self() {
                engine.last_foreign_fg = Some(reveng_winput::foreground_context());
            }

            // Notes typed into the recording window become Manual checkpoints, anchored to the
            // frame live at the moment the user pressed Enter (the note-vs-wire correlation).
            if let Some(rx) = &note_rx {
                while let Ok((ts, text)) = rx.try_recv() {
                    let anchor = anchor_of(&state.lock().unwrap());
                    engine.emit(
                        CheckpointType::Manual,
                        "note",
                        ts,
                        anchor,
                        false,
                        (0, 0),
                        Some(text),
                    )?;
                    state.lock().unwrap().bytes_since = 0;
                }
            }

            // A Snapshot-button press dumps the target's memory (on the worker) and emits a
            // checkpoint carrying `mem_snapshot_id`, anchored to the frame live at that instant —
            // so `mem diff`/`mem scan` pair the decoded memory with the on-the-wire bytes.
            if let Some(rx) = &snap_rx {
                while let Ok(ts) = rx.try_recv() {
                    let Some(tx) = &mem_tx else {
                        eprintln!("memory snapshot requested but capture is disabled");
                        continue;
                    };
                    let mem_id = mem_next_id;
                    mem_next_id += 1;
                    let _ = tx.send((mem_id, ts));
                    let anchor = anchor_of(&state.lock().unwrap());
                    engine.next_mem_snapshot_id = Some(mem_id);
                    engine.emit(
                        CheckpointType::Manual,
                        "mem_snapshot",
                        ts,
                        anchor,
                        false,
                        (0, 0),
                        None,
                    )?;
                }
            }

            // Interval checkpoint: only during sustained traffic with no user action (§7).
            if opts.cfg.interval_ms > 0 {
                let now = clock.now_ns();
                if now - engine.last_ckpt_ts >= interval_ns {
                    let (fire, anchor) = {
                        let s = state.lock().unwrap();
                        (s.bytes_since >= opts.cfg.interval_bytes, anchor_of(&s))
                    };
                    if fire {
                        engine.emit(
                            CheckpointType::Interval,
                            "interval",
                            now,
                            anchor,
                            false,
                            (0, 0),
                            None,
                        )?;
                        state.lock().unwrap().bytes_since = 0;
                    }
                }
            }

            // Stop conditions: hotkey, notes-window Stop/close, reader EOF, bounded duration, byte
            // budget (USB + PCIe totals), idle-abort, or frame cap.
            let over_budget = opts.max_bytes.is_some_and(|mb| {
                let usb = state.lock().unwrap().total_bytes;
                let pcie = pcie_state
                    .as_ref()
                    .map_or(0, |p| p.lock().unwrap().total_bytes);
                usb + pcie >= mb
            });
            // Refresh idle timer: a new frame since last poll resets the "no traffic" clock.
            let frames_now = state.lock().unwrap().total_frames;
            if frames_now != last_frames {
                last_frames = frames_now;
                last_frame_at = Instant::now();
            }
            let extra = extra_stop_reason(
                frames_now,
                last_frame_at.elapsed(),
                opts.abort_if_idle,
                opts.stop_after_frames,
            );
            let stop_file_seen = opts
                .stop_file
                .as_ref()
                .map(|path| path.exists())
                .unwrap_or(false);
            if engine.stop_requested
                || stop_file_seen
                || ui_stop
                    .as_ref()
                    .map(|f| f.load(Ordering::Relaxed))
                    .unwrap_or(false)
                || state.lock().unwrap().done
                || state.lock().unwrap().error.is_some()
                || opts
                    .max_duration
                    .map(|d| start.elapsed() >= d)
                    .unwrap_or(false)
                || over_budget
                || extra.is_some()
            {
                if over_budget {
                    eprintln!("reached --max-bytes budget; stopping");
                }
                if stop_file_seen {
                    eprintln!("stop file seen; stopping");
                }
                if let Some(reason) = extra {
                    eprintln!("{reason} ({frames_now} frames captured); stopping");
                }
                break;
            }
        }
        Ok(())
    })();

    // --- finalize: tear down threads, then inject checkpoint comments (§4) ---
    if let Some(h) = hooks {
        h.stop();
    }
    usb_threads.stop_and_join(&state);
    if let Some(w) = writer {
        w.lock().unwrap().flush()?;
        drop(w); // close the pcapng file before finalize reads/rewrites it
    }
    if let Some(mut pcie_thread) = pcie_thread.take() {
        pcie_thread.stop_and_join(&state);
    }
    drop(engine.shot_tx.take());
    let _ = shot_worker.join();
    drop(mem_tx); // close the channel so the memcap worker drains its queue and exits
    if let Some(h) = mem_worker {
        let _ = h.join();
    }

    // All capture/worker resources are stopped before an event/checkpoint write failure escapes.
    run_result?;

    let final_ts = clock.now_ns();
    let stop_anchor = anchor_of(&state.lock().unwrap());
    engine.emit(
        CheckpointType::SessionStop,
        "session_stop",
        final_ts,
        stop_anchor,
        false,
        (0, 0),
        None,
    )?;

    let (total_frames, dropped) = {
        let s = state.lock().unwrap();
        (s.total_frames, s.dropped)
    };
    if dropped > 0 {
        eprintln!("dropped {dropped} USB packets via capture filter (transfer-type/endpoint)");
    }
    engine.finalize(&clock, &opts, total_frames, pcie_meta.as_ref())?;

    if let Some(error) = state.lock().unwrap().error.clone() {
        anyhow::bail!(error);
    }

    Ok(RecordSummary {
        events: total_frames,
        checkpoints: engine.checkpoints_written,
    })
}

fn anchor_of(s: &TrafficState) -> Option<TrafficAnchor> {
    s.latest_index.map(|event_index| TrafficAnchor {
        source: SourceKind::Usb,
        event_index,
        byte_offset: s.latest_offset,
    })
}

/// Open the memory-snapshot target from the opts (`--mem-pid` wins over `--mem-process`), or
/// `None` when the feature isn't armed. Enables `SeDebugPrivilege` first (best-effort) so a
/// cross-user/other target opens once elevated.
fn open_mem_source(opts: &UsbRecordOpts) -> Option<Result<reveng_memcap::MemSnapshotSource>> {
    if opts.mem_pid.is_none() && opts.mem_process.is_none() {
        return None;
    }
    let _ = crate::elevate::enable_debug_privilege();
    if let Some(pid) = opts.mem_pid {
        Some(reveng_memcap::MemSnapshotSource::open(pid))
    } else {
        Some(reveng_memcap::MemSnapshotSource::by_name(
            opts.mem_process.as_deref().unwrap(),
        ))
    }
}

/// A reader thread: drain one source into the shared `usb.pcapng` + `frames.idx`, bumping
/// the shared counter. Runs one per selected control device; the writer is shared so all
/// hubs merge into one ordered index.
fn reader_loop(
    mut source: Box<dyn CaptureSource + Send>,
    writer: Arc<Mutex<UsbWriter>>,
    state: Arc<Mutex<TrafficState>>,
    reader_stop: Arc<AtomicBool>,
    stats: Option<Arc<Mutex<LiveStats>>>,
    filter: PacketFilter,
    format: reveng_usbcap::CaptureFormat,
    keep_sof: bool,
) -> Result<()> {
    let wire = format == reveng_usbcap::CaptureFormat::Wire;
    let filtering = filter.is_active();
    // Wire-only: the endpoint of the transaction in progress. DATA and handshake packets
    // carry no endpoint of their own, so per-endpoint stats need the last token carried
    // forward — the same rule the index derivation follows.
    let mut wire_endpoint: u8 = 0;
    let mut wire_transfer: u8 = reveng_usbcap::XFER_UNKNOWN;
    loop {
        if reader_stop.load(Ordering::Relaxed) {
            break;
        }
        match source.next() {
            Ok(Some(rec)) => {
                // Parse the header once if either the filter or the dashboard needs it.
                //
                // Only for USBPcap. A wire packet has no such header — running the parser
                // over one reads the PID byte and CRC as an endpoint and a length, and the
                // result is not an error, just wrong: mis-filtered packets and a dashboard
                // full of endpoints that were never on the bus.
                let header = if !wire && (filtering || stats.is_some()) {
                    reveng_usbcap::parse::parse_packet_header(&rec.payload)
                } else {
                    None
                };
                if wire {
                    if let Some(p) = reveng_usbcap::wire::decode(&rec.payload) {
                        if let (Some(ep), true) = (p.endpoint, p.kind == WireKind::Token) {
                            wire_endpoint = ep;
                            wire_transfer = if ep == 0 {
                                reveng_usbcap::XFER_CONTROL
                            } else {
                                reveng_usbcap::XFER_UNKNOWN
                            };
                        }
                        // SOF belongs to no transaction, so dropping it cannot break
                        // reassembly — which is exactly why it is the one wire packet safe
                        // to filter at the source.
                        if !keep_sof && p.kind == WireKind::Sof {
                            state.lock().unwrap().dropped += 1;
                            if let Some(stats) = &stats {
                                stats.lock().unwrap().usb_dropped += 1;
                            }
                            continue;
                        }
                    }
                }
                // Capture-side reduction (camera/isoc firehose): drop filtered packets before
                // writing, but count them so the drop is visible, never silent.
                if filtering && !wire && !keep_packet(header.as_ref(), &filter) {
                    state.lock().unwrap().dropped += 1;
                    if let Some(stats) = &stats {
                        stats.lock().unwrap().usb_dropped += 1;
                    }
                    continue;
                }
                let payload_len = rec.payload.len() as u64;
                {
                    // Hold `state` across the append so the merged index stays ordered: clamp the
                    // arrival timestamp non-decreasing (hubs interleave), then append under the
                    // writer lock. Serializes writes across readers — correct, it's one file.
                    let mut s = state.lock().unwrap();
                    let ts = rec.ts_ns.max(s.last_ts);
                    s.last_ts = ts;
                    let (idx, off) = match writer.lock().unwrap().append_packet(ts, &rec.payload) {
                        Ok(result) => result,
                        Err(e) => {
                            s.error = Some(format!("writing USB capture: {e:#}"));
                            break;
                        }
                    };
                    s.latest_index = Some(idx);
                    s.latest_offset = off;
                    s.total_frames = idx + 1;
                    s.bytes_since = s.bytes_since.saturating_add(payload_len);
                    s.total_bytes = s.total_bytes.saturating_add(payload_len);
                }
                if let Some(stats) = &stats {
                    let mut g = stats.lock().unwrap();
                    g.usb_frames += 1;
                    g.usb_bytes += payload_len;
                    if wire {
                        let e = g.usb_by_ep.entry(wire_endpoint).or_default();
                        e.frames += 1;
                        e.bytes += payload_len;
                        e.transfer = wire_transfer;
                    } else if let Some(h) = &header {
                        let e = g.usb_by_ep.entry(h.endpoint).or_default();
                        e.frames += 1;
                        e.bytes += payload_len;
                        e.transfer = h.transfer;
                    }
                }
            }
            Ok(None) => {
                mark_source_ended(&state);
                break;
            }
            Err(e) => {
                eprintln!("usb reader stopped: {e}");
                record_reader_error(&state, format!("USB capture reader failed: {e:#}"));
                mark_source_ended(&state);
                break;
            }
        }
    }
    let _ = source.stop();
    Ok(())
}

/// A source ended; when the last one does, the session is done.
fn mark_source_ended(state: &Arc<Mutex<TrafficState>>) {
    let mut s = state.lock().unwrap();
    s.active_sources = s.active_sources.saturating_sub(1);
    if s.active_sources == 0 {
        s.done = true;
    }
}

fn record_reader_error(state: &Arc<Mutex<TrafficState>>, error: String) {
    let mut s = state.lock().unwrap();
    if s.error.is_none() {
        s.error = Some(error);
    }
}

struct Engine {
    session: SessionWriter,
    next_id: u64,
    checkpoints_written: u64,
    /// (frame_index, comment) for checkpoints that anchored to a frame — injected at finalize.
    comments: Vec<(u64, String)>,
    last_ckpt_ts: i64,
    last_shot_ts: Option<i64>,
    min_interval_ns: i64,
    shot_tx: Option<std::sync::mpsc::Sender<ShotRequest>>,
    scope: reveng_winshot::Scope,
    cfg: CheckpointConfig,
    shot_when: ScreenshotWhen,
    shot_on_keys: bool,
    // stop-hotkey modifier tracking
    ctrl_down: bool,
    alt_down: bool,
    stop_vk: u16,
    stop_requested: bool,
    /// Whether USB is a configured source. When true, USB is the primary anchor and PCIe (if
    /// any) is secondary; when false (PCIe-only), PCIe becomes the primary anchor.
    usb_active: bool,
    /// Latest PCIe event, when co-logging (`--with-pcie`) or PCIe-only; source of a checkpoint's
    /// PCIe anchor.
    pcie_state: Option<Arc<Mutex<PcieState>>>,
    /// Most recent foreground app that wasn't our own window — used as the context for a note
    /// checkpoint (while typing a note, *our* window is foreground, which isn't useful).
    last_foreign_fg: Option<(Option<String>, Option<String>)>,
    /// Set immediately before `emit` to stamp the next checkpoint with a memory-snapshot id;
    /// `emit` `take()`s it so it applies to exactly one checkpoint.
    next_mem_snapshot_id: Option<u64>,
    _clock: Clock,
}

impl Engine {
    fn new(
        session: SessionWriter,
        opts: &UsbRecordOpts,
        // `None` in --traffic-only: there is no screenshot worker to send to, so a
        // checkpoint that would have carried a screenshot simply carries none.
        shot_tx: Option<std::sync::mpsc::Sender<ShotRequest>>,
        clock: Clock,
        usb_active: bool,
        pcie_state: Option<Arc<Mutex<PcieState>>>,
    ) -> Self {
        Self {
            session,
            next_id: 0,
            checkpoints_written: 0,
            comments: Vec::new(),
            last_ckpt_ts: 0,
            last_shot_ts: None,
            min_interval_ns: (opts.min_interval_ms as i64) * 1_000_000,
            shot_tx,
            scope: opts.scope,
            cfg: opts.cfg.clone(),
            shot_when: opts.screenshot_on,
            shot_on_keys: opts.screenshot_on_keys,
            ctrl_down: false,
            alt_down: false,
            stop_vk: opts.stop_vk,
            stop_requested: false,
            usb_active,
            pcie_state,
            last_foreign_fg: None,
            next_mem_snapshot_id: None,
            _clock: clock,
        }
    }

    /// Emit a checkpoint: enrich context, optionally request a screenshot, persist it.
    /// `note` carries a user-supplied annotation (Manual checkpoints); it is preserved
    /// unless a coalesced screenshot needs to record why it was skipped.
    fn emit(
        &mut self,
        kind: CheckpointType,
        cause: &str,
        ts_ns: i64,
        anchor: Option<TrafficAnchor>,
        want_screenshot: bool,
        cursor: (i32, i32),
        note: Option<String>,
    ) -> Result<()> {
        let id = self.next_id;
        self.next_id += 1;

        let (fg_process, fg_window) = if matches!(kind, CheckpointType::SessionStart) {
            (None, None)
        } else if matches!(kind, CheckpointType::Manual) {
            // A note is typed into our own window; attribute it to the target app instead.
            self.last_foreign_fg
                .clone()
                .unwrap_or_else(reveng_winput::foreground_context)
        } else {
            reveng_winput::foreground_context()
        };

        // Screenshot with burst coalescing (§6): skip if within the min-interval floor.
        let mut screenshot_id = None;
        let mut note = note;
        if want_screenshot {
            let ok = self
                .last_shot_ts
                .map(|last| ts_ns - last >= self.min_interval_ns)
                .unwrap_or(true);
            if ok {
                screenshot_id = Some(id);
                self.last_shot_ts = Some(ts_ns);
                if let Some(tx) = &self.shot_tx {
                    let _ = tx.send((id, ts_ns, self.scope, cursor));
                }
            } else {
                note = Some("screenshot_skipped".to_string());
            }
        }

        // Primary anchor = the configured primary source: USB when a USB source is active, else
        // PCIe (a PCIe-only session anchors clicks/notes to PCIe events, same as USB does to
        // frames). Any other concurrently-captured source goes in `anchors` (co-logging).
        let pcie_anchor = self
            .pcie_state
            .as_ref()
            .and_then(|st| pcie_anchor_of(&st.lock().unwrap()));
        let (anchor, anchors): (Option<TrafficAnchor>, Vec<TrafficAnchor>) = if self.usb_active {
            (anchor, pcie_anchor.into_iter().collect())
        } else {
            (pcie_anchor, Vec::new())
        };

        // Checkpoint comments are injected into the USB pcapng, which only exists when USB is
        // active — so only record them then.
        if self.usb_active {
            if let Some(a) = &anchor {
                let proc = fg_process.clone().unwrap_or_else(|| "?".into());
                self.comments.push((
                    a.event_index,
                    format!("CHECKPOINT #{id} — {cause} in {proc}"),
                ));
            }
        }

        let ckpt = Checkpoint {
            id,
            ts_ns,
            kind,
            cause: cause.to_string(),
            anchor,
            anchors,
            screenshot_id,
            mem_snapshot_id: self.next_mem_snapshot_id.take(),
            fg_process,
            fg_window,
            cursor,
            note,
        };
        self.session
            .append_record(&SessionRecord::Checkpoint(ckpt))?;
        self.checkpoints_written += 1;
        self.last_ckpt_ts = ts_ns;
        Ok(())
    }

    fn on_input(&mut self, ev: &InputEvent, state: &Arc<Mutex<TrafficState>>) -> Result<()> {
        // Track modifiers + detect the stop hotkey (Ctrl+Alt+<stop_vk>) first, so it still
        // fires even when our own notes window happens to be focused.
        if let Some(vk) = ev.vk {
            let down = matches!(ev.kind, InputKind::KeyDown);
            match vk {
                0x11 | 0xA2 | 0xA3 => self.ctrl_down = down, // CONTROL / L / R
                0x12 | 0xA4 | 0xA5 => self.alt_down = down,  // MENU(Alt) / L / R
                _ => {}
            }
            if down && vk == self.stop_vk && self.ctrl_down && self.alt_down {
                self.stop_requested = true;
                return Ok(());
            }
        }

        // While the user is typing into our own notes window, ignore input entirely: don't
        // log the keystrokes (the note itself is the record) and don't let Return/Tab/Esc
        // trip a spurious checkpoint. The stop hotkey above still works.
        if reveng_winput::foreground_is_self() {
            return Ok(());
        }

        // Every input event is truth — persist it (§8).
        self.session
            .append_record(&SessionRecord::Input(ev.clone()))?;

        let cfg = self.cfg.clone();
        let anchor = anchor_of(&state.lock().unwrap());
        match ev.kind {
            InputKind::MouseDown => {
                if let Some(btn) = &ev.button {
                    if cfg.mouse_triggers(btn) {
                        let want = matches!(
                            self.shot_when,
                            ScreenshotWhen::Mousedown | ScreenshotWhen::Both
                        );
                        self.emit(
                            CheckpointType::Click,
                            &format!("{btn}ButtonDown"),
                            ev.ts_ns,
                            anchor,
                            want,
                            (ev.x, ev.y),
                            None,
                        )?;
                        state.lock().unwrap().bytes_since = 0;
                    }
                }
            }
            InputKind::MouseUp => {
                if let Some(btn) = &ev.button {
                    if cfg.on_mouseup && cfg.mouse_triggers(btn) {
                        let want = matches!(
                            self.shot_when,
                            ScreenshotWhen::Mouseup | ScreenshotWhen::Both
                        );
                        self.emit(
                            CheckpointType::Click,
                            &format!("{btn}ButtonUp"),
                            ev.ts_ns,
                            anchor,
                            want,
                            (ev.x, ev.y),
                            None,
                        )?;
                        state.lock().unwrap().bytes_since = 0;
                    }
                }
            }
            InputKind::Wheel => {
                if cfg.on_wheel {
                    self.emit(
                        CheckpointType::Click,
                        "Wheel",
                        ev.ts_ns,
                        anchor,
                        false,
                        (ev.x, ev.y),
                        None,
                    )?;
                    state.lock().unwrap().bytes_since = 0;
                }
            }
            InputKind::KeyDown => {
                if let Some(vk) = ev.vk {
                    let name = vk_name(vk);
                    let triggers =
                        cfg.on_any_key || name.map(|n| cfg.key_triggers(n)).unwrap_or(false);
                    if triggers {
                        let label = name
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| format!("VK_0x{vk:02X}"));
                        self.emit(
                            CheckpointType::KeyDown,
                            &label,
                            ev.ts_ns,
                            anchor,
                            self.shot_on_keys,
                            (ev.x, ev.y),
                            None,
                        )?;
                        state.lock().unwrap().bytes_since = 0;
                    }
                }
            }
            InputKind::KeyUp => {}
        }
        Ok(())
    }

    /// Flush, inject checkpoint comments into the pcapng, rewrite `frames.idx` offsets, and
    /// write `meta.json` with the clock anchor (§2, §4, §8).
    fn finalize(
        &mut self,
        clock: &Clock,
        opts: &UsbRecordOpts,
        total_frames: u64,
        pcie_meta: Option<&serde_json::Value>,
    ) -> Result<()> {
        use reveng_usbcap::pcapng;

        let pcapng_path = self.session.usb_pcapng();
        let idx_path = self.session.frames_idx();

        if !self.comments.is_empty() && pcapng_path.exists() {
            let data = std::fs::read(&pcapng_path)?;
            let (new_data, new_offsets) = pcapng::inject_comments(&data, &self.comments)?;
            if new_offsets.len() as u64 != total_frames {
                anyhow::bail!(
                    "pcapng/index frame count mismatch: pcapng has {}, index has {total_frames}",
                    new_offsets.len()
                );
            }
            std::fs::write(&pcapng_path, &new_data)?;

            // Rewrite frames.idx so byte_offsets match the recommented pcapng.
            if idx_path.exists() {
                let mut old = IndexFile::<UsbIdxRecord>::open(&idx_path)?;
                let n = old.len();
                let mut records = Vec::with_capacity(n as usize);
                for i in 0..n {
                    records.push(old.get(i)?);
                }
                let mut fresh = IndexFile::<UsbIdxRecord>::create(&idx_path)?;
                for (i, mut rec) in records.into_iter().enumerate() {
                    if let Some(off) = new_offsets.get(i) {
                        rec.byte_offset = *off;
                    }
                    fresh.append(&rec)?;
                }
            }
        }

        let mut meta = serde_json::json!({
            "tool": "reveng-rec",
            "version": env!("CARGO_PKG_VERSION"),
            "source": if pcie_meta.is_some() { "usb+pcie" } else { "usb" },
            // Which backend recorded this, so a later reader knows what the packets are
            // before decoding any. The pcapng link type says the same thing; this is the
            // human-readable copy, and it carries the capture speed a wire session needs.
            "acquisition": opts.backend.name(),
            "capture_speed": match opts.backend {
                UsbBackend::Cynthion { speed } => Some(format!("{speed:?}")),
                UsbBackend::UsbPcap => None,
            },
            // Folded from the sidecar so the headline facts — did the analyzer overflow, was
            // there a bus reset — are answerable without opening another file.
            "bus_events": reveng_cynthion::events::read_summary(
                reveng_cynthion::events::sidecar_path(&self.session.usb_pcapng()),
            )
            .ok()
            .flatten(),
            // Session provenance: what this recording actually contains. A later reader must
            // not assume a session has input events or screenshots just because the schema
            // has room for them — in traffic-only mode there are none, by design rather than
            // by accident.
            "traffic_only": opts.traffic_only,
            "clock": {
                "kind": "QPC-backed monotonic (std::Instant)",
                "wall_ns_at_origin": clock.wall_ns_at_origin(),
            },
            "frames": total_frames,
            "checkpoints": self.checkpoints_written,
            "checkpoint_config": opts.cfg,
        });
        if let (Some(obj), Some(pcie)) = (meta.as_object_mut(), pcie_meta) {
            obj.insert("pcie".into(), pcie.clone());
        }
        self.session.write_meta(&meta)?;
        Ok(())
    }
}

/// A concurrent PCIe reader thread: drain the source into `pcie.bin`/`pcie.idx` on the shared
/// clock, publishing the latest event for secondary-anchor resolution. The source is already
/// started; a parked `next()` is unblocked at finalize via the `PcieCapture::stop` handle.
fn pcie_reader_loop(
    mut source: Box<dyn CaptureSource + Send>,
    mut log: PcieLog,
    state: Arc<Mutex<PcieState>>,
    traffic: Arc<Mutex<TrafficState>>,
    reader_stop: Arc<AtomicBool>,
    stats: Option<Arc<Mutex<LiveStats>>>,
) -> Result<()> {
    loop {
        if reader_stop.load(Ordering::Relaxed) {
            break;
        }
        match source.next() {
            Ok(Some(rec)) => {
                if let TrafficKind::Pcie(ev) = &rec.kind {
                    let bytes = crate::record::event_bytes(ev);
                    let (idx, off) = match log.append(ev) {
                        Ok(result) => result,
                        Err(e) => {
                            record_reader_error(&traffic, format!("writing PCIe capture: {e:#}"));
                            break;
                        }
                    };
                    {
                        let mut s = state.lock().unwrap();
                        s.latest_index = Some(idx);
                        s.latest_offset = off;
                        s.total_bytes = s.total_bytes.saturating_add(bytes);
                    }
                    // Co-logging: PCIe traffic also drives interval checkpoints, so a
                    // PCIe-busy / USB-idle stretch still gets periodic markers (§7).
                    {
                        let mut t = traffic.lock().unwrap();
                        t.bytes_since = t.bytes_since.saturating_add(bytes);
                    }
                    if let Some(stats) = &stats {
                        let mut g = stats.lock().unwrap();
                        g.pcie_events += 1;
                        g.pcie_bytes += bytes;
                        match ev {
                            PcieEvent::Config { .. } => g.pcie_config += 1,
                            PcieEvent::Mmio { .. } => g.pcie_mmio += 1,
                            PcieEvent::Dma { .. } => g.pcie_dma += 1,
                            PcieEvent::Irq { .. } => g.pcie_irq += 1,
                        }
                    }
                }
            }
            Ok(None) => break, // EOF (bounded/replay source) or unblocked (live)
            Err(e) => {
                eprintln!("pcie reader stopped: {e}");
                record_reader_error(&traffic, format!("PCIe capture reader failed: {e:#}"));
                break;
            }
        }
    }
    let _ = source.stop();
    Ok(())
}

fn pcie_anchor_of(s: &PcieState) -> Option<TrafficAnchor> {
    s.latest_index.map(|event_index| TrafficAnchor {
        source: SourceKind::Pcie,
        event_index,
        byte_offset: s.latest_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use reveng_usbcap::{XFER_BULK, XFER_CONTROL, XFER_ISO};

    fn hdr(endpoint: u8, transfer: u8) -> UsbFrameHeader {
        UsbFrameHeader {
            bus: 0,
            device: 0,
            endpoint,
            transfer,
            status: 0,
            data_length: 0,
        }
    }

    #[test]
    fn idle_abort_fires_when_no_frames_arrive() {
        // No frames, no timer running long enough yet → keep going.
        assert_eq!(
            extra_stop_reason(
                0,
                Duration::from_secs(2),
                Some(Duration::from_secs(5)),
                None
            ),
            None
        );
        // No frames for longer than the idle timeout → abort.
        assert_eq!(
            extra_stop_reason(
                0,
                Duration::from_secs(6),
                Some(Duration::from_secs(5)),
                None
            ),
            Some("--abort-if-idle: no new traffic")
        );
    }

    #[test]
    fn frame_cap_takes_priority_and_idle_off_by_default() {
        // No idle/cap configured → never an extra stop, however long idle.
        assert_eq!(
            extra_stop_reason(0, Duration::from_secs(999), None, None),
            None
        );
        // Frame cap reached, even while traffic is flowing (idle timer just reset).
        assert_eq!(
            extra_stop_reason(
                100,
                Duration::from_millis(0),
                Some(Duration::from_secs(5)),
                Some(100)
            ),
            Some("--stop-after-frames reached")
        );
    }

    #[test]
    fn default_filter_keeps_everything() {
        let f = PacketFilter::default();
        assert!(!f.is_active());
        assert!(keep_packet(Some(&hdr(0x81, XFER_ISO)), &f));
    }

    #[test]
    fn drops_chosen_transfer_types_keeps_control() {
        let f = PacketFilter {
            drop_transfers: vec![XFER_ISO],
            endpoints: None,
        };
        assert!(f.is_active());
        assert!(!keep_packet(Some(&hdr(0x81, XFER_ISO)), &f)); // isoc dropped
        assert!(keep_packet(Some(&hdr(0x00, XFER_CONTROL)), &f)); // control kept
        assert!(keep_packet(Some(&hdr(0x02, XFER_BULK)), &f)); // bulk kept
    }

    #[test]
    fn endpoint_allow_list_is_direction_agnostic() {
        let f = PacketFilter {
            drop_transfers: vec![],
            endpoints: Some(vec![1, 2]),
        };
        assert!(keep_packet(Some(&hdr(0x81, XFER_BULK)), &f)); // ep 1 IN
        assert!(keep_packet(Some(&hdr(0x02, XFER_BULK)), &f)); // ep 2 OUT
        assert!(!keep_packet(Some(&hdr(0x83, XFER_BULK)), &f)); // ep 3 excluded
    }

    #[test]
    fn unparseable_header_is_always_kept() {
        let f = PacketFilter {
            drop_transfers: vec![XFER_ISO],
            endpoints: Some(vec![9]),
        };
        assert!(keep_packet(None, &f));
    }
}

/// Map a virtual-key code to a checkpoint key name (matching `CheckpointConfig` defaults).
fn vk_name(vk: u16) -> Option<&'static str> {
    Some(match vk {
        0x0D => "Return",
        0x1B => "Escape",
        0x09 => "Tab",
        0x08 => "Back",
        0x2E => "Delete",
        0x20 => "Space",
        0x70 => "F1",
        0x71 => "F2",
        0x72 => "F3",
        0x73 => "F4",
        0x74 => "F5",
        0x75 => "F6",
        0x76 => "F7",
        0x77 => "F8",
        0x78 => "F9",
        0x79 => "F10",
        0x7A => "F11",
        0x7B => "F12",
        _ => return None,
    })
}
