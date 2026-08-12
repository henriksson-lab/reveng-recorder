//! The analyzer's **bus events**, and the sidecar file that keeps them.
//!
//! A capture carries two interleaved streams: packets, and events the host stack never sees
//! at all — bus reset, speed change, attach, line-state transitions, and the analyzer's own
//! start/stop. Packets go into `usb.pcapng`. Events have no representation in a USB 2.0
//! pcapng, so they go into a sidecar next to it.
//!
//! # Why they are worth keeping
//!
//! Discarding them costs two things that cannot be recovered from the packet file:
//!
//! 1. **Telling an idle bus from a mis-sampled one.** Setting the wrong capture speed
//!    produces zero packets and tens of thousands of line-state events — measured, 3 s of a
//!    Low-speed keyboard captured as Full gave 0 packets and 42112 events. Without the
//!    events the surviving file is indistinguishable from a clean recording of a quiet bus.
//! 2. **Detecting an analyzer-side gap.** [`CaptureStop(BufferFull)`](CAPTURE_STOP_BUFFER_FULL)
//!    is the analyzer saying it dropped data. Nothing in the packet stream shows this.
//!
//! # Format
//!
//! One JSON object per line — greppable by a person, readable by a decoder, and consistent
//! with the session's other sidecars (`events.ndjson`, `screenshots.ndjson`):
//!
//! ```text
//! {"ts_ns":6918950,"code":6,"name":"CaptureStart(Low)"}
//! ```
//!
//! # Evidence
//!
//! The code table is from Packetry's `src/event.rs` (`EventType::code`), the vendor's own
//! host tool. Several points are **[confirmed]** against this hardware: code 6 appeared once
//! at the head of a Low-speed capture and code 5 once at the head of a Full-speed one
//! (`CaptureStart(Low)` / `CaptureStart(Full)`); code 30 arrived at 1 kHz on a Low-speed bus
//! (`LsKeepalive`, one per frame); codes 12/18/19 dominated a mis-sampled capture
//! (`SE0`/`FsJ`/`FsK` line-state transitions); and code 25 (`BusReset`) landed within 1 ms of
//! a physical unplug, with five more during the re-enumeration that followed.
//!
//! ## Code 0 — undocumented, and emitted while nothing is attached
//!
//! **Packetry's table starts at 1 and its decoder silently discards anything it cannot name**
//! (`if let Some(event_type) = EventType::from_code(..)`), so code 0 has no published
//! meaning. It is nonetheless real, and frequent.
//!
//! Observed on this hardware: a capture spanning an unplug and replug produced **5821** code-0
//! events at a steady ~1.09 ms cadence, beginning 1.1 ms after the `BusReset` that marked the
//! unplug (15.366 s) and ending 16 ms before enumeration resumed (21.728 s). None occurred
//! while a device was attached. 6.362 s at that cadence predicts 5825 — within four of the
//! count. The natural reading is a per-frame heartbeat emitted while the port is empty, but
//! that is inference; what is established is *when* it appears, not what the gateware calls it.
//!
//! This is why [`event_name`] renders unknown codes as `Unknown(n)` instead of dropping them.
//! Following Packetry here would have discarded 13% of this capture's events and, with them,
//! the only positive evidence that the device was absent rather than merely quiet.

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::io::{BufRead, BufWriter, Write};
use std::path::{Path, PathBuf};

/// Sidecar filename inside a session directory.
pub const SIDECAR: &str = "bus_events.ndjson";

/// The analyzer stopped because its buffer overflowed — data was lost on the analyzer side,
/// which no amount of inspecting the packet stream would reveal.
pub const CAPTURE_STOP_BUFFER_FULL: u8 = 2;
/// A bus reset: the host re-enumerating whatever is downstream.
pub const BUS_RESET: u8 = 25;
/// Low-speed keepalive, one per 1 ms frame. Dominates a Low-speed capture's event count and
/// carries no information beyond "the bus is alive".
pub const LS_KEEPALIVE: u8 = 30;

/// Name for an event code, from Packetry's `EventType::code` table.
///
/// Unknown codes are rendered as `Unknown(n)` rather than dropped: a future gateware may add
/// events, and losing them silently is exactly the failure this module exists to prevent.
pub fn event_name(code: u8) -> String {
    let s = match code {
        1 => "CaptureStop(Requested)",
        2 => "CaptureStop(BufferFull)",
        3 => "CaptureStop(Error)",
        4 => "CaptureStart(High)",
        5 => "CaptureStart(Full)",
        6 => "CaptureStart(Low)",
        7 => "CaptureStart(Auto)",
        8 => "SpeedChange(High)",
        9 => "SpeedChange(Full)",
        10 => "SpeedChange(Low)",
        11 => "SpeedChange(Auto)",
        12 => "LineStateChange(SE0)",
        13 => "LineStateChange(ChirpJ)",
        14 => "LineStateChange(ChirpK)",
        15 => "LineStateChange(ChirpSE1)",
        16 => "LineStateChange(LsJ)",
        17 => "LineStateChange(LsK)",
        18 => "LineStateChange(FsJ)",
        19 => "LineStateChange(FsK)",
        20 => "LineStateChange(SE1)",
        21 => "VbusInvalid",
        22 => "VbusValid",
        23 => "LsAttach",
        24 => "FsAttach",
        25 => "BusReset",
        26 => "DeviceChirpValid",
        27 => "HostChirpValid",
        28 => "Suspend",
        29 => "Resume",
        30 => "LsKeepalive",
        other => return format!("Unknown({other})"),
    };
    s.to_string()
}

/// The sidecar path for a capture written to `pcapng_path`.
///
/// Inside a session that is `bus_events.ndjson` beside `usb.pcapng`; for a standalone capture
/// it lands beside the file under the same stem, the way `frames.idx` already does.
pub fn sidecar_path(pcapng_path: &Path) -> PathBuf {
    if pcapng_path.file_name().and_then(|n| n.to_str()) == Some("usb.pcapng") {
        pcapng_path.with_file_name(SIDECAR)
    } else {
        pcapng_path.with_extension("events.ndjson")
    }
}

/// Append-only writer for the sidecar.
pub struct EventLog {
    w: BufWriter<std::fs::File>,
}

impl EventLog {
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let f =
            std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
        Ok(Self {
            w: BufWriter::new(f),
        })
    }

    pub fn append(&mut self, ts_ns: i64, code: u8) -> std::io::Result<()> {
        writeln!(
            self.w,
            r#"{{"ts_ns":{ts_ns},"code":{code},"name":"{}"}}"#,
            event_name(code)
        )
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.w.flush()
    }
}

/// What a capture's events say about it, for `meta.json` and `verify`.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EventSummary {
    pub total: u64,
    /// Counts per event code, keyed by name so the summary reads without the table.
    pub by_name: BTreeMap<String, u64>,
    /// Analyzer buffer overflows — each one is data lost before it ever reached us.
    pub overflows: u64,
    pub bus_resets: u64,
    pub speed_changes: u64,
    /// Line-state transitions. A capture that is almost entirely these, with no packets, was
    /// sampled at the wrong speed.
    pub line_state_changes: u64,
}

/// Timestamps of every bus reset in a sidecar, in file order.
///
/// Needed by the wire integrity check: a reset returns every endpoint's data toggle to DATA0
/// (USB 2.0 §8.6.1), so a scan that cannot see resets reports the first packet on each
/// endpoint after one as a toggle violation. Measured — one replug produced 13 of them.
pub fn read_bus_resets(path: impl AsRef<Path>) -> Result<Vec<i64>> {
    let Ok(f) = std::fs::File::open(path.as_ref()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for line in std::io::BufReader::new(f).lines() {
        let line = line?;
        if !line.contains(r#""code":25,"#) {
            continue;
        }
        if let Some(ts) = line
            .split(r#""ts_ns":"#)
            .nth(1)
            .and_then(|t| t.split(&[',', '}'][..]).next())
            .and_then(|t| t.trim().parse::<i64>().ok())
        {
            out.push(ts);
        }
    }
    Ok(out)
}

/// Read a sidecar into a summary. Returns `Ok(None)` when there is no sidecar — a USBPcap
/// session, or a wire capture written before this existed.
pub fn read_summary(path: impl AsRef<Path>) -> Result<Option<EventSummary>> {
    let path = path.as_ref();
    let Ok(f) = std::fs::File::open(path) else {
        return Ok(None);
    };
    let mut s = EventSummary::default();
    for line in std::io::BufReader::new(f).lines() {
        let line = line?;
        let Some(code) = line
            .split("\"code\":")
            .nth(1)
            .and_then(|t| t.split(&[',', '}'][..]).next())
            .and_then(|t| t.trim().parse::<u8>().ok())
        else {
            continue;
        };
        s.total += 1;
        *s.by_name.entry(event_name(code)).or_default() += 1;
        match code {
            CAPTURE_STOP_BUFFER_FULL => s.overflows += 1,
            BUS_RESET => s.bus_resets += 1,
            8..=11 => s.speed_changes += 1,
            12..=20 => s.line_state_changes += 1,
            _ => {}
        }
    }
    Ok(Some(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four codes observed on this hardware must map to the names the observations
    /// implied — this is the check that the table was transcribed correctly.
    #[test]
    fn observed_codes_match_what_the_hardware_showed() {
        assert_eq!(event_name(6), "CaptureStart(Low)");
        assert_eq!(event_name(5), "CaptureStart(Full)");
        assert_eq!(event_name(30), "LsKeepalive");
        assert_eq!(event_name(12), "LineStateChange(SE0)");
        assert_eq!(event_name(18), "LineStateChange(FsJ)");
        assert_eq!(event_name(19), "LineStateChange(FsK)");
    }

    #[test]
    fn an_unknown_code_is_kept_not_dropped() {
        assert_eq!(event_name(200), "Unknown(200)");
    }

    #[test]
    fn round_trips_through_the_sidecar() {
        let p = std::env::temp_dir().join("reveng_evt_roundtrip.ndjson");
        let _ = std::fs::remove_file(&p);
        {
            let mut log = EventLog::create(&p).unwrap();
            log.append(1_000, 6).unwrap();
            log.append(2_000, LS_KEEPALIVE).unwrap();
            log.append(3_000, LS_KEEPALIVE).unwrap();
            log.append(4_000, BUS_RESET).unwrap();
            log.append(5_000, CAPTURE_STOP_BUFFER_FULL).unwrap();
            log.flush().unwrap();
        }
        let s = read_summary(&p).unwrap().unwrap();
        assert_eq!(s.total, 5);
        assert_eq!(s.by_name["LsKeepalive"], 2);
        assert_eq!(s.bus_resets, 1);
        assert_eq!(s.overflows, 1, "an analyzer-side gap must be visible");
        assert_eq!(s.line_state_changes, 0);
        let _ = std::fs::remove_file(&p);
    }

    /// The signature of a wrong capture speed: nothing but line-state transitions.
    #[test]
    fn a_mis_sampled_capture_shows_as_line_state_churn() {
        let p = std::env::temp_dir().join("reveng_evt_misampled.ndjson");
        let _ = std::fs::remove_file(&p);
        {
            let mut log = EventLog::create(&p).unwrap();
            log.append(0, 5).unwrap();
            for i in 0..100 {
                log.append(i, if i % 2 == 0 { 18 } else { 19 }).unwrap();
            }
            log.flush().unwrap();
        }
        let s = read_summary(&p).unwrap().unwrap();
        assert_eq!(s.line_state_changes, 100);
        assert_eq!(s.total, 101);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn no_sidecar_is_not_an_error() {
        assert!(
            read_summary(std::env::temp_dir().join("definitely_absent.ndjson"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn sidecar_sits_beside_its_capture() {
        assert_eq!(
            sidecar_path(Path::new("/s/usb.pcapng")),
            Path::new("/s/bus_events.ndjson")
        );
        assert_eq!(
            sidecar_path(Path::new("/tmp/kbd.pcapng")),
            Path::new("/tmp/kbd.events.ndjson")
        );
    }
}
