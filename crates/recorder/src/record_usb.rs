//! Live USB recording orchestration (DESIGN.md §3 thread model, §6, §7).
//!
//! Wires the four moving parts around the checkpoint engine:
//! - a **reader thread** draining `USBPcapCMD` into `usb.pcapng` + `frames.idx`, bumping a
//!   shared traffic counter (must never block — §3);
//! - the **input hooks** (`winput`) feeding events over a channel;
//! - a **screenshot worker** (`winshot`) grabbing PNGs off the hot path with burst
//!   coalescing (§6);
//! - the **engine**, which turns clicks / special keys / traffic-interval ticks into
//!   checkpoints anchored to the nearest preceding frame, then finalizes the session by
//!   injecting checkpoint comments into the pcapng (§4).

use crate::record::RecordSummary;
use anyhow::Result;
use reveng_core::checkpoint::{Checkpoint, CheckpointConfig, CheckpointType};
use reveng_core::clock::Clock;
use reveng_core::event::{SourceKind, TrafficAnchor};
use reveng_core::index::IndexFile;
use reveng_core::session::{SessionRecord, SessionWriter};
use reveng_core::source::CaptureSource;
use reveng_usbcap::{Killer, UsbCaptureSource, UsbIdxRecord, UsbSelection, UsbWriter};
use reveng_winput::{InputEvent, InputKind};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// When to grab a screenshot.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScreenshotWhen {
    Mousedown,
    Mouseup,
    Both,
    None,
}

pub struct UsbRecordOpts {
    /// One capture per USBPcap control device (root hub) to record in parallel — each gets
    /// its own reader thread folding frames into the one `usb.pcapng` on the shared clock.
    /// Empty = no capture at all: the pipeline still records input + screenshots + notes and
    /// shows the window, so the UI runs with no USB device / no USBPcap / no admin.
    pub selections: Vec<UsbSelection>,
    pub cfg: CheckpointConfig,
    pub screenshot_on: ScreenshotWhen,
    pub screenshot_on_keys: bool,
    pub scope: reveng_winshot::Scope,
    pub min_interval_ms: u64,
    /// VK of the stop-hotkey trigger (fires with Ctrl+Alt held). Default VK_PAUSE (0x13).
    pub stop_vk: u16,
    /// Optional bounded capture (for automation/tests); `None` = until stop hotkey.
    pub max_duration: Option<Duration>,
}

/// Wiring from the live "recording" note window (`notes_ui`) into the capture loop.
/// The window runs on the main thread; the capture pipeline runs on a worker and drains
/// these. Absent for headless/automation runs (`--max-seconds`, `REVENG_NO_NOTES_UI`).
pub struct NotesUi {
    /// `(ts_ns stamped at Enter, note text)`, one per submitted note.
    pub note_rx: Receiver<(i64, String)>,
    /// Set by the window's Stop button / close; a stop condition for the capture loop.
    pub stop_flag: Arc<AtomicBool>,
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
    /// Reader threads still running; when it reaches 0 (all sources ended) the session is done.
    active_sources: usize,
    done: bool,
}

pub fn run_usb_capture(
    clock: Clock,
    out: &Path,
    opts: UsbRecordOpts,
    ui: Option<NotesUi>,
) -> Result<RecordSummary> {
    // The clock is created by the caller so the notes window shares this exact origin.
    let (note_rx, ui_stop) = match ui {
        Some(u) => (Some(u.note_rx), Some(u.stop_flag)),
        None => (None, None),
    };
    let session = SessionWriter::create(out)?;
    let shots_dir = session.screenshots_dir();

    let state = Arc::new(Mutex::new(TrafficState::default()));
    let reader_stop = Arc::new(AtomicBool::new(false));

    // --- readers: one per selected control device (root hub), captured in parallel and
    // folded into the single shared `usb.pcapng`/`frames.idx`. Start them up front so
    // spawn/open errors surface here. Empty `selections` = no capture at all (the window
    // still runs: input + screenshots + notes only, no USB source, no admin needed).
    let mut killers: Vec<Killer> = Vec::new();
    let mut readers = Vec::new();

    // Start each selected control device, skipping (not aborting on) any that fail — one hub
    // that won't open must not take down the others. Collect the survivors, then create the
    // shared writer only if at least one opened (else it's the no-capture case).
    let mut sources = Vec::new();
    for selection in &opts.selections {
        let mut source = UsbCaptureSource::new(selection.clone(), clock.clone());
        match source.start() {
            Ok(()) => sources.push(source),
            Err(e) => eprintln!(
                "usb capture skipped for {}: {e}",
                selection.usbpcap_device.as_deref().unwrap_or("?")
            ),
        }
    }
    let writer = if sources.is_empty() {
        None
    } else {
        let w = UsbWriter::create(session.usb_pcapng(), session.frames_idx())?;
        Some(Arc::new(Mutex::new(w)))
    };
    if let Some(writer) = &writer {
        state.lock().unwrap().active_sources = sources.len();
        for (i, source) in sources.into_iter().enumerate() {
            killers.push(source.killer());
            let writer = writer.clone();
            let state = state.clone();
            let reader_stop = reader_stop.clone();
            readers.push(
                std::thread::Builder::new()
                    .name(format!("usbcap-reader-{i}"))
                    .spawn(move || reader_loop(source, writer, state, reader_stop))?,
            );
        }
    }

    // --- screenshot worker ---
    let (shot_tx, shot_rx) = std::sync::mpsc::channel::<(u64, reveng_winshot::Scope)>();
    let shot_worker = std::thread::Builder::new()
        .name("winshot-worker".into())
        .spawn(move || {
            while let Ok((id, scope)) = shot_rx.recv() {
                let path = shots_dir.join(format!("{id:06}.png"));
                if let Err(e) = reveng_winshot::capture_to(&path, scope) {
                    eprintln!("screenshot {id} failed: {e}");
                }
            }
        })?;

    // --- input hooks ---
    let (in_tx, in_rx) = std::sync::mpsc::channel::<InputEvent>();
    let hooks = reveng_winput::install(clock.clone(), move |ev| {
        let _ = in_tx.send(ev);
    })?;

    // --- the checkpoint engine ---
    let mut engine = Engine::new(session, &opts, shot_tx, clock.clone());
    engine.emit(CheckpointType::SessionStart, "session_start", 0, None, false, (0, 0), None)?;

    let start = Instant::now();
    let interval_ns = (opts.cfg.interval_ms as i64).saturating_mul(1_000_000);
    loop {
        match in_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(ev) => engine.on_input(&ev, &state)?,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }

        // Notes typed into the recording window become Manual checkpoints, anchored to the
        // frame live at the moment the user pressed Enter (the note-vs-wire correlation).
        if let Some(rx) = &note_rx {
            while let Ok((ts, text)) = rx.try_recv() {
                let anchor = anchor_of(&state.lock().unwrap());
                engine.emit(CheckpointType::Manual, "note", ts, anchor, false, (0, 0), Some(text))?;
                state.lock().unwrap().bytes_since = 0;
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
                    engine.emit(CheckpointType::Interval, "interval", now, anchor, false, (0, 0), None)?;
                    state.lock().unwrap().bytes_since = 0;
                }
            }
        }

        // Stop conditions: hotkey, notes-window Stop/close, reader EOF, or bounded duration.
        if engine.stop_requested
            || ui_stop.as_ref().map(|f| f.load(Ordering::Relaxed)).unwrap_or(false)
            || state.lock().unwrap().done
            || opts.max_duration.map(|d| start.elapsed() >= d).unwrap_or(false)
        {
            break;
        }
    }

    // --- finalize: tear down threads, then inject checkpoint comments (§4) ---
    hooks.stop();
    reader_stop.store(true, Ordering::Relaxed);
    for k in &killers {
        k.kill(); // unblock readers parked in a blocking pipe read
    }
    for r in readers {
        let _ = r.join();
    }
    if let Some(w) = writer {
        w.lock().unwrap().flush()?;
        drop(w); // close the pcapng file before finalize reads/rewrites it
    }
    drop(engine.shot_tx.take());
    let _ = shot_worker.join();

    let final_ts = clock.now_ns();
    let stop_anchor = anchor_of(&state.lock().unwrap());
    engine.emit(CheckpointType::SessionStop, "session_stop", final_ts, stop_anchor, false, (0, 0), None)?;

    let total_frames = state.lock().unwrap().total_frames;
    engine.finalize(&clock, &opts, total_frames)?;

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

/// A reader thread: drain one source into the shared `usb.pcapng` + `frames.idx`, bumping
/// the shared counter. Runs one per selected control device; the writer is shared so all
/// hubs merge into one ordered index.
fn reader_loop(
    mut source: UsbCaptureSource,
    writer: Arc<Mutex<UsbWriter>>,
    state: Arc<Mutex<TrafficState>>,
    reader_stop: Arc<AtomicBool>,
) -> Result<()> {
    loop {
        if reader_stop.load(Ordering::Relaxed) {
            break;
        }
        match source.next() {
            Ok(Some(rec)) => {
                // Hold `state` across the append so the merged index stays ordered: clamp the
                // arrival timestamp non-decreasing (hubs interleave), then append under the
                // writer lock. Serializes writes across readers — correct, since it's one file.
                let mut s = state.lock().unwrap();
                let ts = rec.ts_ns.max(s.last_ts);
                s.last_ts = ts;
                let (idx, off) = writer.lock().unwrap().append_packet(ts, &rec.payload)?;
                s.latest_index = Some(idx);
                s.latest_offset = off;
                s.total_frames = idx + 1;
                s.bytes_since = s.bytes_since.saturating_add(rec.payload.len() as u64);
            }
            Ok(None) => {
                mark_source_ended(&state);
                break;
            }
            Err(e) => {
                eprintln!("usb reader stopped: {e}");
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

struct Engine {
    session: SessionWriter,
    next_id: u64,
    checkpoints_written: u64,
    /// (frame_index, comment) for checkpoints that anchored to a frame — injected at finalize.
    comments: Vec<(u64, String)>,
    last_ckpt_ts: i64,
    last_shot_ts: Option<i64>,
    min_interval_ns: i64,
    shot_tx: Option<std::sync::mpsc::Sender<(u64, reveng_winshot::Scope)>>,
    scope: reveng_winshot::Scope,
    cfg: CheckpointConfig,
    shot_when: ScreenshotWhen,
    shot_on_keys: bool,
    // stop-hotkey modifier tracking
    ctrl_down: bool,
    alt_down: bool,
    stop_vk: u16,
    stop_requested: bool,
    _clock: Clock,
}

impl Engine {
    fn new(
        session: SessionWriter,
        opts: &UsbRecordOpts,
        shot_tx: std::sync::mpsc::Sender<(u64, reveng_winshot::Scope)>,
        clock: Clock,
    ) -> Self {
        Self {
            session,
            next_id: 0,
            checkpoints_written: 0,
            comments: Vec::new(),
            last_ckpt_ts: 0,
            last_shot_ts: None,
            min_interval_ns: (opts.min_interval_ms as i64) * 1_000_000,
            shot_tx: Some(shot_tx),
            scope: opts.scope,
            cfg: opts.cfg.clone(),
            shot_when: opts.screenshot_on,
            shot_on_keys: opts.screenshot_on_keys,
            ctrl_down: false,
            alt_down: false,
            stop_vk: opts.stop_vk,
            stop_requested: false,
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
                    let _ = tx.send((id, self.scope));
                }
            } else {
                note = Some("screenshot_skipped".to_string());
            }
        }

        if let Some(a) = &anchor {
            let proc = fg_process.clone().unwrap_or_else(|| "?".into());
            self.comments
                .push((a.event_index, format!("CHECKPOINT #{id} — {cause} in {proc}")));
        }

        let ckpt = Checkpoint {
            id,
            ts_ns,
            kind,
            cause: cause.to_string(),
            anchor,
            screenshot_id,
            fg_process,
            fg_window,
            cursor,
            note,
        };
        self.session.append_record(&SessionRecord::Checkpoint(ckpt))?;
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
        self.session.append_record(&SessionRecord::Input(ev.clone()))?;

        let cfg = self.cfg.clone();
        let anchor = anchor_of(&state.lock().unwrap());
        match ev.kind {
            InputKind::MouseDown => {
                if let Some(btn) = &ev.button {
                    if cfg.mouse_triggers(btn) {
                        let want = matches!(self.shot_when, ScreenshotWhen::Mousedown | ScreenshotWhen::Both);
                        self.emit(CheckpointType::Click, &format!("{btn}ButtonDown"), ev.ts_ns, anchor, want, (ev.x, ev.y), None)?;
                        state.lock().unwrap().bytes_since = 0;
                    }
                }
            }
            InputKind::MouseUp => {
                if let Some(btn) = &ev.button {
                    if cfg.on_mouseup && cfg.mouse_triggers(btn) {
                        let want = matches!(self.shot_when, ScreenshotWhen::Mouseup | ScreenshotWhen::Both);
                        self.emit(CheckpointType::Click, &format!("{btn}ButtonUp"), ev.ts_ns, anchor, want, (ev.x, ev.y), None)?;
                        state.lock().unwrap().bytes_since = 0;
                    }
                }
            }
            InputKind::Wheel => {
                if cfg.on_wheel {
                    self.emit(CheckpointType::Click, "Wheel", ev.ts_ns, anchor, false, (ev.x, ev.y), None)?;
                    state.lock().unwrap().bytes_since = 0;
                }
            }
            InputKind::KeyDown => {
                if let Some(vk) = ev.vk {
                    let name = vk_name(vk);
                    let triggers = cfg.on_any_key
                        || name.map(|n| cfg.key_triggers(n)).unwrap_or(false);
                    if triggers {
                        let label = name.map(|s| s.to_string()).unwrap_or_else(|| format!("VK_0x{vk:02X}"));
                        self.emit(CheckpointType::KeyDown, &label, ev.ts_ns, anchor, self.shot_on_keys, (ev.x, ev.y), None)?;
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
    fn finalize(&mut self, clock: &Clock, opts: &UsbRecordOpts, total_frames: u64) -> Result<()> {
        use reveng_usbcap::pcapng;

        let pcapng_path = self.session.usb_pcapng();
        let idx_path = self.session.frames_idx();

        if !self.comments.is_empty() && pcapng_path.exists() {
            let data = std::fs::read(&pcapng_path)?;
            let (new_data, new_offsets) = pcapng::inject_comments(&data, &self.comments)?;
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

        let meta = serde_json::json!({
            "tool": "reveng-rec",
            "version": env!("CARGO_PKG_VERSION"),
            "source": "usb",
            "acquisition": "usbpcap",
            "clock": {
                "kind": "QPC-backed monotonic (std::Instant)",
                "wall_ns_at_origin": clock.wall_ns_at_origin(),
            },
            "frames": total_frames,
            "checkpoints": self.checkpoints_written,
            "checkpoint_config": opts.cfg,
        });
        self.session.write_meta(&meta)?;
        Ok(())
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
