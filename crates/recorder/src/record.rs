//! Recording orchestration.
//!
//! The USB path needs Windows (USBPcap, hooks, screen capture). The PCIe **replay** path
//! is fully platform-neutral: it drives `ReplayPcieSource` through the source-agnostic
//! core, writing a real session (pcie.bin + pcie.idx + events.ndjson + meta.json) with
//! interval checkpoints resolved against the traffic index. This exercises the whole
//! record→session pipeline on any machine (DESIGN.md §4a, §7, §13 replay-source note).

use anyhow::Result;
use reveng_core::checkpoint::{Checkpoint, CheckpointConfig, CheckpointType};
use reveng_core::event::{SourceKind, TrafficAnchor, TrafficKind};
use reveng_core::session::{SessionRecord, SessionWriter};
use reveng_core::source::CaptureSource;
use reveng_pcicap::{PcieLog, ReplayPcieSource};
use std::path::Path;

pub struct RecordSummary {
    pub events: u64,
    pub checkpoints: u64,
}

/// Record a session from a replayed PCIe event stream.
pub fn run_pcie_replay(
    out: &Path,
    replay: &Path,
    cfg: &CheckpointConfig,
) -> Result<RecordSummary> {
    let mut session = SessionWriter::create(out)?;
    let mut log = PcieLog::create(session.pcie_bin(), session.pcie_idx())?;
    let mut source = ReplayPcieSource::from_path(replay)?;
    source.start()?;

    let mut next_id = 0u64;
    let mut new_ckpt = |ts_ns: i64,
                        kind: CheckpointType,
                        cause: &str,
                        anchor: Option<TrafficAnchor>|
     -> Checkpoint {
        let c = Checkpoint {
            id: next_id,
            ts_ns,
            kind,
            cause: cause.to_string(),
            anchor,
            screenshot_id: None,
            fg_process: None,
            fg_window: None,
            cursor: (0, 0),
            note: None,
        };
        next_id += 1;
        c
    };

    session.append_record(&SessionRecord::Checkpoint(new_ckpt(
        0,
        CheckpointType::SessionStart,
        "session_start",
        None,
    )))?;
    let mut checkpoints = 1u64;

    let mut events = 0u64;
    let mut bytes_since = 0u64;
    let mut last_ckpt_ts = 0i64;
    let mut last_index = 0u64;
    let mut have_last = false;
    let interval_ns = (cfg.interval_ms as i64).saturating_mul(1_000_000);

    while let Some(rec) = source.next()? {
        let ts = rec.ts_ns;
        let ev = match rec.kind {
            TrafficKind::Pcie(e) => e,
            TrafficKind::Usb(_) => continue, // replay stream is PCIe-only
        };
        let (index, offset) = log.append(&ev)?;
        events += 1;
        last_index = index;
        have_last = true;
        bytes_since = bytes_since.saturating_add(event_bytes(&ev));

        // Interval checkpoint: only when enough traffic has accumulated *and* the
        // interval has elapsed since the last checkpoint (DESIGN.md §7).
        if cfg.interval_ms > 0
            && bytes_since >= cfg.interval_bytes
            && ts - last_ckpt_ts >= interval_ns
        {
            let anchor = TrafficAnchor {
                source: SourceKind::Pcie,
                event_index: index,
                byte_offset: offset,
            };
            session.append_record(&SessionRecord::Checkpoint(new_ckpt(
                ts,
                CheckpointType::Interval,
                "interval",
                Some(anchor),
            )))?;
            checkpoints += 1;
            last_ckpt_ts = ts;
            bytes_since = 0;
        }
    }

    let stop_anchor = if have_last {
        Some(TrafficAnchor {
            source: SourceKind::Pcie,
            event_index: last_index,
            byte_offset: log.offset_of(last_index)?,
        })
    } else {
        None
    };
    let stop_ts = last_ckpt_ts.max(0);
    session.append_record(&SessionRecord::Checkpoint(new_ckpt(
        stop_ts,
        CheckpointType::SessionStop,
        "session_stop",
        stop_anchor,
    )))?;
    checkpoints += 1;

    source.stop()?;

    let meta = serde_json::json!({
        "tool": "reveng-rec",
        "version": env!("CARGO_PKG_VERSION"),
        "source": "pcie",
        "acquisition": "replay",
        "replay_file": replay.display().to_string(),
        "clock": "session-ns (replay timestamps)",
        "events": events,
        "checkpoints": checkpoints,
        "checkpoint_config": cfg,
    });
    session.write_meta(&meta)?;

    Ok(RecordSummary {
        events,
        checkpoints,
    })
}

/// A nominal byte count for a PCIe event, used to drive interval checkpoints.
fn event_bytes(ev: &reveng_core::event::PcieEvent) -> u64 {
    use reveng_core::event::PcieEvent::*;
    match *ev {
        Mmio { width, .. } => width as u64,
        Config { width, .. } => width as u64,
        Dma { len, .. } => len as u64,
        Irq { .. } => 4,
    }
}
