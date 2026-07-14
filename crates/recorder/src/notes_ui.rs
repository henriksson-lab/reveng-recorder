//! The live "recording" note-taking window (Slint).
//!
//! Slint owns the main thread (its event loop requires it); the USB capture pipeline runs
//! on a worker. The window stamps each note on the shared master [`Clock`] the instant the
//! user presses Enter, shows it in a scrollback log, and forwards `(ts_ns, text)` to the
//! engine — which turns it into a `Manual` checkpoint anchored to the live frame. The
//! window stays up until the worker finishes (so it survives finalize), then the loop quits.

use crate::record::RecordSummary;
use crate::record_usb::NotesUi;
use anyhow::Result;
use reveng_core::clock::Clock;
use slint::{ComponentHandle, ModelRc, VecModel};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

slint::include_modules!();

/// Show the recording window and run `record` (the USB capture) on a worker thread until it
/// finishes or the user stops it. Returns the worker's [`RecordSummary`]. Must be called on
/// the main thread.
pub fn run_recording_window<F>(clock: Clock, record: F) -> Result<RecordSummary>
where
    F: FnOnce(NotesUi) -> Result<RecordSummary> + Send + 'static,
{
    let (note_tx, note_rx) = std::sync::mpsc::channel::<(i64, String)>();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let worker_done = Arc::new(AtomicBool::new(false));

    let wiring = NotesUi {
        note_rx,
        stop_flag: stop_flag.clone(),
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
    let notes_model: Rc<VecModel<NoteRow>> = Rc::new(VecModel::default());
    window.set_notes(ModelRc::from(notes_model.clone()));

    // Enter → stamp on the master clock, show in the log, forward to the engine.
    {
        let clock = clock.clone();
        let model = notes_model.clone();
        window.on_submit(move |text| {
            let text = text.trim().to_string();
            if text.is_empty() {
                return;
            }
            let ts = clock.now_ns();
            model.push(NoteRow {
                time: fmt_elapsed(ts).as_str().into(),
                text: text.as_str().into(),
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

    // From the UI thread: tick the elapsed clock and quit once the worker is done.
    let timer = slint::Timer::default();
    {
        let weak = window.as_weak();
        let clock = clock.clone();
        let worker_done = worker_done.clone();
        timer.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(250),
            move || {
                if worker_done.load(Ordering::Relaxed) {
                    let _ = slint::quit_event_loop();
                    return;
                }
                if let Some(w) = weak.upgrade() {
                    if w.get_recording() {
                        w.set_elapsed(fmt_elapsed(clock.now_ns()).as_str().into());
                    }
                }
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
