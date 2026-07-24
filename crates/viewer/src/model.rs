//! Session data model for the viewer (DESIGN.md §9). Kept separate from the egui UI so
//! the data plumbing — checkpoints, the frame window around a checkpoint, screenshot
//! resolution — is unit-testable without a display.

use anyhow::Result;
use reveng_core::checkpoint::{Checkpoint, CheckpointType};
use reveng_core::event::SourceKind;
use reveng_core::session::SessionReader;
use reveng_pcicap::PcieLog;
use reveng_usbcap::UsbReader;
use std::path::{Path, PathBuf};

/// Normalize a value track to `0.0..=1.0` for drawing (min→0, max→1); `None` stays `None`, and an
/// all-equal (or empty) track normalizes every present value to `0.5`. Pure — unit-tested.
pub fn normalize_track(track: &[Option<f64>]) -> Vec<Option<f32>> {
    let vals: Vec<f64> = track.iter().flatten().copied().collect();
    if vals.is_empty() {
        return track.iter().map(|_| None).collect();
    }
    let min = vals.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = vals.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let span = max - min;
    track
        .iter()
        .map(|o| o.map(|v| if span > 0.0 { ((v - min) / span) as f32 } else { 0.5 }))
        .collect()
}

/// One row in the traffic inspector.
pub struct InspectorRow {
    pub index: u64,
    pub header: String,
    pub hex: String,
}

enum Backend {
    Usb(UsbReader),
    Pcie(PcieLog),
    None,
}

pub struct SessionModel {
    root: PathBuf,
    pub source: &'static str,
    pub checkpoints: Vec<Checkpoint>,
    pub total_frames: u64,
    backend: Backend,
    /// Co-logged PCIe log (present when USB is primary but a `pcie.bin` exists too), used to
    /// resolve a checkpoint's secondary anchors (`Checkpoint.anchors`).
    secondary_pcie: Option<PcieLog>,
}

impl SessionModel {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let reader = SessionReader::open(&root)?;
        let root = reader.root().to_path_buf();
        let checkpoints = reader.checkpoints()?;

        let (backend, source) = if reader.usb_pcapng().exists() {
            let r = UsbReader::open(reader.usb_pcapng(), reader.frames_idx())?;
            (Backend::Usb(r), "usb")
        } else if reader.pcie_bin().exists() {
            let l = PcieLog::open(reader.pcie_bin(), reader.pcie_idx())?;
            (Backend::Pcie(l), "pcie")
        } else {
            (Backend::None, "none")
        };
        let total_frames = match &backend {
            Backend::Usb(r) => r.len(),
            Backend::Pcie(l) => l.len(),
            Backend::None => 0,
        };

        // Co-logged session: USB is primary, but PCIe events were recorded alongside. Open
        // the PCIe log too so secondary anchors can be resolved.
        let secondary_pcie = if matches!(backend, Backend::Usb(_)) && reader.pcie_bin().exists() {
            PcieLog::open(reader.pcie_bin(), reader.pcie_idx()).ok()
        } else {
            None
        };

        Ok(Self {
            root,
            source,
            checkpoints,
            total_frames,
            backend,
            secondary_pcie,
        })
    }

    /// Traffic index `i`'s timestamp (from whichever backend is primary).
    fn ts_at(&mut self, i: u64) -> Result<i64> {
        match &mut self.backend {
            Backend::Usb(r) => r.ts_at(i),
            Backend::Pcie(l) => l.ts_at(i),
            Backend::None => Ok(0),
        }
    }

    /// Primary + co-logged-PCIe densities bucketed over a *shared* time axis, for a two-tone
    /// timeline overlay showing each wire's busy regions. Secondary is empty unless co-logged.
    pub fn traffic_density_split(&mut self, buckets: usize) -> (Vec<u32>, Vec<u32>) {
        let total = self.total_frames;
        if total == 0 || buckets == 0 {
            return (Vec::new(), Vec::new());
        }
        // Shared span across both logs so the strips line up.
        let mut first = self.ts_at(0).unwrap_or(0);
        let mut last = self.ts_at(total - 1).unwrap_or(first);
        let sec_total = self.secondary_pcie.as_ref().map_or(0, |l| l.len());
        if sec_total > 0 {
            if let Some(l) = &mut self.secondary_pcie {
                first = first.min(l.ts_at(0).unwrap_or(first));
                last = last.max(l.ts_at(sec_total - 1).unwrap_or(last));
            }
        }
        let span = (last - first).max(1) as f64;
        let bucket = |ts: i64| {
            (((ts - first) as f64 / span).clamp(0.0, 1.0) * buckets as f64) as usize
        }; // yields 0..=buckets
        let bin = |b: usize| b.min(buckets - 1);

        let mut prim = vec![0u32; buckets];
        for i in 0..total {
            if let Ok(ts) = self.ts_at(i) {
                prim[bin(bucket(ts))] += 1;
            }
        }
        let mut sec = Vec::new();
        if sec_total > 0 {
            sec = vec![0u32; buckets];
            if let Some(l) = &mut self.secondary_pcie {
                for i in 0..sec_total {
                    if let Ok(ts) = l.ts_at(i) {
                        sec[bin(bucket(ts))] += 1;
                    }
                }
            }
        }
        (prim, sec)
    }

    /// Decoded secondary anchors — the co-logged PCIe events referenced by a checkpoint's
    /// `anchors` — so one checkpoint shows both wires (DESIGN.md §7 co-logging).
    pub fn secondary_rows(&mut self, ckpt: &Checkpoint) -> Result<Vec<InspectorRow>> {
        let Some(log) = &mut self.secondary_pcie else {
            return Ok(Vec::new());
        };
        let mut rows = Vec::new();
        for a in &ckpt.anchors {
            if a.source == SourceKind::Pcie {
                let ev = log.event_at(a.event_index)?;
                rows.push(InspectorRow {
                    index: a.event_index,
                    header: format!("pcie #{} {}", a.event_index, serde_json::to_string(&ev)?),
                    hex: String::new(),
                });
            }
        }
        Ok(rows)
    }

    /// A UIA value track: for each checkpoint, the named control's `range_value` from that
    /// checkpoint's `ui/<screenshot_id>.json`, or `None` if absent. Same source as
    /// `reveng-rec track --ui` — lets the timeline show a control's value (exposure/gain) curve.
    pub fn value_track(&self, control: &str) -> Vec<Option<f64>> {
        let needle = control.to_lowercase();
        let ui_dir = self.root.join("ui");
        self.checkpoints
            .iter()
            .map(|c| {
                let sid = c.screenshot_id?;
                let bytes = std::fs::read(ui_dir.join(format!("{sid:06}.json"))).ok()?;
                let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
                v.as_array()?.iter().find_map(|el| {
                    let name = el.get("name")?.as_str()?.to_lowercase();
                    name.contains(&needle)
                        .then(|| el.get("range_value").and_then(|x| x.as_f64()))
                        .flatten()
                })
            })
            .collect()
    }

    /// Absolute path to a checkpoint's screenshot, if it has one and the file exists.
    pub fn screenshot_path(&self, ckpt: &Checkpoint) -> Option<PathBuf> {
        let id = ckpt.screenshot_id?;
        let p = self.root.join("screenshots").join(format!("{id:06}.png"));
        p.exists().then_some(p)
    }

    /// The traffic rows in a ±`window` window around a checkpoint's anchor frame.
    pub fn frames_around(&mut self, ckpt: &Checkpoint, window: u64) -> Result<Vec<InspectorRow>> {
        let total = self.total_frames;
        if total == 0 {
            return Ok(Vec::new());
        }
        let center = match ckpt.anchor {
            Some(a) => a.event_index,
            None => return Ok(Vec::new()),
        };
        let start = center.saturating_sub(window);
        let end = center.saturating_add(window).min(total - 1);

        let mut rows = Vec::new();
        for i in start..=end {
            rows.push(self.row(i)?);
        }
        Ok(rows)
    }

    fn row(&mut self, i: u64) -> Result<InspectorRow> {
        match &mut self.backend {
            Backend::Usb(r) => {
                let f = r.frame_at(i)?;
                Ok(InspectorRow {
                    index: i,
                    header: format!(
                        "#{:<6} {:>10.3}ms  ep {} {:<3} {:<9} len {}",
                        i,
                        f.ts_ns as f64 / 1e6,
                        f.ep,
                        f.dir,
                        f.xfer,
                        f.len
                    ),
                    hex: f.hex,
                })
            }
            Backend::Pcie(l) => {
                let ev = l.event_at(i)?;
                Ok(InspectorRow {
                    index: i,
                    header: format!("#{i:<6} {}", serde_json::to_string(&ev)?),
                    hex: String::new(),
                })
            }
            Backend::None => Ok(InspectorRow {
                index: i,
                header: format!("#{i}"),
                hex: String::new(),
            }),
        }
    }
}

/// A stable display colour (RGB) for each checkpoint type, for the timeline track.
pub fn type_color(t: CheckpointType) -> [u8; 3] {
    match t {
        CheckpointType::Click => [66, 135, 245],       // blue
        CheckpointType::KeyDown => [46, 204, 113],      // green
        CheckpointType::Interval => [149, 165, 166],    // grey
        CheckpointType::Manual => [241, 196, 15],       // yellow
        CheckpointType::SessionStart => [155, 89, 182], // purple
        CheckpointType::SessionStop => [231, 76, 60],   // red
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reveng_core::event::{SourceKind, TrafficAnchor};
    use reveng_core::session::{SessionRecord, SessionWriter};
    use reveng_usbcap::UsbWriter;

    #[test]
    fn normalize_track_scales_and_preserves_gaps() {
        let t = vec![Some(10.0), None, Some(20.0), Some(30.0)];
        let n = normalize_track(&t);
        assert_eq!(n[0], Some(0.0), "min → 0");
        assert_eq!(n[1], None, "gap preserved");
        assert_eq!(n[2], Some(0.5), "midpoint");
        assert_eq!(n[3], Some(1.0), "max → 1");
    }

    #[test]
    fn normalize_track_all_equal_is_midline() {
        let n = normalize_track(&[Some(5.0), Some(5.0)]);
        assert_eq!(n, vec![Some(0.5), Some(0.5)], "flat track draws mid-height");
    }

    #[test]
    fn normalize_track_empty_or_all_none() {
        assert_eq!(normalize_track(&[None, None]), vec![None, None]);
        assert!(normalize_track(&[]).is_empty());
    }

    fn packet(ep: u8, payload: &[u8]) -> Vec<u8> {
        let mut h = vec![0u8; 27];
        h[0..2].copy_from_slice(&27u16.to_le_bytes());
        h[21] = ep;
        h[22] = 2;
        h[23..27].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        h.extend_from_slice(payload);
        h
    }

    #[test]
    fn model_loads_usb_session_and_windows_frames() {
        let dir = std::env::temp_dir().join("reveng_viewer_model_test");
        let _ = std::fs::remove_dir_all(&dir);
        let mut session = SessionWriter::create(&dir).unwrap();
        let mut usb = UsbWriter::create(session.usb_pcapng(), session.frames_idx()).unwrap();
        let mut offs = Vec::new();
        for i in 0..5u8 {
            let (_idx, off) = usb
                .append_packet((i as i64 + 1) * 1_000_000, &packet(0x81, &[i, i, i]))
                .unwrap();
            offs.push(off);
        }
        usb.flush().unwrap();
        session
            .append_record(&SessionRecord::Checkpoint(Checkpoint {
                id: 0,
                ts_ns: 2_500_000,
                kind: CheckpointType::Click,
                cause: "click".into(),
                anchor: Some(TrafficAnchor {
                    source: SourceKind::Usb,
                    event_index: 2,
                    byte_offset: offs[2],
                }),
                anchors: Vec::new(),
                screenshot_id: None,
                mem_snapshot_id: None,
                fg_process: None,
                fg_window: None,
                cursor: (0, 0),
                note: None,
            }))
            .unwrap();

        let mut m = SessionModel::open(&dir).unwrap();
        assert_eq!(m.source, "usb");
        assert_eq!(m.total_frames, 5);
        assert_eq!(m.checkpoints.len(), 1);
        let rows = m.frames_around(&m.checkpoints[0].clone(), 1).unwrap();
        // ±1 around frame 2 -> frames 1,2,3.
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].index, 1);
        assert_eq!(rows[1].index, 2);
        assert_eq!(rows[2].index, 3);
        assert!(rows[1].hex.contains("02 02 02"));

        // Density: 5 frames at ts 1..5 ms across 4 buckets → all counted, last bucket gets the
        // final (clamped) frame. No co-logged PCIe here, so the secondary strip is empty.
        let (d, sec) = m.traffic_density_split(4);
        assert_eq!(d.len(), 4);
        assert_eq!(d.iter().sum::<u32>(), 5);
        assert_eq!(d[3], 2);
        assert!(sec.is_empty());
        assert!(m.traffic_density_split(0).0.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn model_resolves_secondary_pcie_anchor() {
        use reveng_core::event::PcieEvent;

        let dir = std::env::temp_dir().join("reveng_viewer_secondary_test");
        let _ = std::fs::remove_dir_all(&dir);
        let mut session = SessionWriter::create(&dir).unwrap();

        // USB primary (one frame) + a co-logged PCIe event.
        let mut usb = UsbWriter::create(session.usb_pcapng(), session.frames_idx()).unwrap();
        usb.append_packet(1_000_000, &packet(0x81, &[9, 9, 9])).unwrap();
        usb.flush().unwrap();
        let mut pl = PcieLog::create(session.pcie_bin(), session.pcie_idx()).unwrap();
        pl.append(&PcieEvent::Irq { ts_ns: 500_000, vector: 129 }).unwrap();

        session
            .append_record(&SessionRecord::Checkpoint(Checkpoint {
                id: 0,
                ts_ns: 900_000,
                kind: CheckpointType::Manual,
                cause: "note".into(),
                anchor: Some(TrafficAnchor {
                    source: SourceKind::Usb,
                    event_index: 0,
                    byte_offset: 0,
                }),
                anchors: vec![TrafficAnchor {
                    source: SourceKind::Pcie,
                    event_index: 0,
                    byte_offset: 0,
                }],
                screenshot_id: None,
                mem_snapshot_id: None,
                fg_process: None,
                fg_window: None,
                cursor: (0, 0),
                note: Some("n".into()),
            }))
            .unwrap();

        let mut m = SessionModel::open(&dir).unwrap();
        assert_eq!(m.source, "usb"); // USB stays primary
        let ck = m.checkpoints[0].clone();
        let rows = m.secondary_rows(&ck).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].header.contains("irq") && rows[0].header.contains("129"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
