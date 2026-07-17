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

/// Record a session from a replayed PCIe event stream (portable).
pub fn run_pcie_replay(out: &Path, replay: &Path, cfg: &CheckpointConfig) -> Result<RecordSummary> {
    let source = ReplayPcieSource::from_path(replay)?;
    let extra = serde_json::json!({
        "acquisition": "replay",
        "replay_file": replay.display().to_string(),
        "clock": "session-ns (replay timestamps)",
    });
    record_pcie(out, source, cfg, extra)
}

/// Record a live session from the `reveng-pcidrv` driver-only backend (DESIGN.md §4a lighter
/// tier). Windows-only; opening `\\.\RevengPciCap` needs admin.
#[cfg(windows)]
pub fn run_pcie_live(
    out: &Path,
    target: reveng_pcicap::drv::Bdf,
    max_duration: Option<std::time::Duration>,
    trace_mmio: bool,
    trace_dma: bool,
    cfg: &CheckpointConfig,
) -> Result<RecordSummary> {
    let clock = reveng_core::clock::Clock::start();
    // A bounded run polls the ring for live interrupts / MMIO / DMA snapshots (M2/M3/M4 filter);
    // an unbounded run drains the finite config-space snapshot and stops (M1).
    let source = if max_duration.is_some() || trace_mmio || trace_dma {
        reveng_pcicap::drv::DrvPcieSource::new_live(target, clock, max_duration, trace_mmio, trace_dma)
    } else {
        reveng_pcicap::drv::DrvPcieSource::new(target, clock)
    };
    let extra = serde_json::json!({
        "acquisition": "pcidrv",
        "clock": "QPC-backed monotonic (session)",
        "trace_mmio": trace_mmio,
        "trace_dma": trace_dma,
        "target": format!(
            "{:04x}:{:02x}:{:02x}.{}",
            target.segment, target.bus, target.device, target.function
        ),
    });
    record_pcie(out, source, cfg, extra)
}

/// Record a live session of PCIe interrupts via the ETW NT-Kernel-Logger backend (DESIGN.md
/// §4a M2). Windows-only; the kernel logger needs admin. `vectors` (empty = all) filters ISRs
/// to a device's IDT vector(s); `max_duration` bounds the otherwise-unbounded stream.
#[cfg(windows)]
pub fn run_pcie_etw(
    out: &Path,
    vectors: Vec<u16>,
    max_duration: Option<std::time::Duration>,
    cfg: &CheckpointConfig,
) -> Result<RecordSummary> {
    let clock = reveng_core::clock::Clock::start();
    let opts = reveng_pcicap::etw::EtwIrqOpts {
        vectors: vectors.clone(),
        max_duration,
    };
    let source = reveng_pcicap::etw::EtwIrqSource::new(clock, opts);
    let extra = serde_json::json!({
        "acquisition": "etw-isr",
        "clock": "QPC-backed monotonic (session)",
        "irq_vectors": if vectors.is_empty() {
            serde_json::Value::String("all".into())
        } else {
            serde_json::json!(vectors)
        },
    });
    record_pcie(out, source, cfg, extra)
}

/// Shared PCIe record loop: drain a [`CaptureSource`] into `pcie.bin`/`pcie.idx`, emitting
/// session-start/stop plus traffic-interval checkpoints (§7). `extra_meta` fields are merged
/// into `meta.json` (acquisition/clock/source-specific).
fn record_pcie(
    out: &Path,
    mut source: impl CaptureSource,
    cfg: &CheckpointConfig,
    extra_meta: serde_json::Value,
) -> Result<RecordSummary> {
    let mut session = SessionWriter::create(out)?;
    let mut log = PcieLog::create(session.pcie_bin(), session.pcie_idx())?;
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
            anchors: Vec::new(),
            screenshot_id: None,
            mem_snapshot_id: None,
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
    let mut last_event_ts: Option<i64> = None;
    let interval_ns = (cfg.interval_ms as i64).saturating_mul(1_000_000);

    while let Some(rec) = source.next()? {
        let ts = rec.ts_ns;
        let ev = match rec.kind {
            TrafficKind::Pcie(e) => e,
            TrafficKind::Usb(_) => continue, // replay stream is PCIe-only
        };
        if last_event_ts.is_some_and(|previous| ts < previous) {
            anyhow::bail!("capture timestamps are not monotonic: {ts} followed {last_event_ts:?}");
        }
        let (index, offset) = log.append(&ev)?;
        events += 1;
        last_index = index;
        have_last = true;
        last_event_ts = Some(ts);
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
    let stop_ts = last_event_ts.unwrap_or(0).max(0);
    session.append_record(&SessionRecord::Checkpoint(new_ckpt(
        stop_ts,
        CheckpointType::SessionStop,
        "session_stop",
        stop_anchor,
    )))?;
    checkpoints += 1;

    source.stop()?;

    let mut meta = serde_json::json!({
        "tool": "reveng-rec",
        "version": env!("CARGO_PKG_VERSION"),
        "source": "pcie",
        "events": events,
        "checkpoints": checkpoints,
        "checkpoint_config": cfg,
    });
    if let (Some(obj), Some(extra)) = (meta.as_object_mut(), extra_meta.as_object()) {
        for (k, v) in extra {
            obj.insert(k.clone(), v.clone());
        }
    }
    session.write_meta(&meta)?;

    Ok(RecordSummary {
        events,
        checkpoints,
    })
}

/// A nominal byte count for a PCIe event, used to drive interval checkpoints and the live
/// throughput meter.
pub(crate) fn event_bytes(ev: &reveng_core::event::PcieEvent) -> u64 {
    use reveng_core::event::PcieEvent::*;
    match *ev {
        Mmio { width, .. } => width as u64,
        Config { width, .. } => width as u64,
        Dma { len, .. } => len as u64,
        Irq { .. } => 4,
    }
}
