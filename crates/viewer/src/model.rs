//! Session data model for the viewer (DESIGN.md §9). Kept separate from the egui UI so
//! the data plumbing — checkpoints, the frame window around a checkpoint, screenshot
//! resolution — is unit-testable without a display.

use anyhow::Result;
use reveng_core::checkpoint::{Checkpoint, CheckpointType};
use reveng_core::session::SessionReader;
use reveng_pcicap::PcieLog;
use reveng_usbcap::UsbReader;
use std::path::{Path, PathBuf};

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

        Ok(Self {
            root,
            source,
            checkpoints,
            total_frames,
            backend,
        })
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
        let end = (center + window).min(total - 1);

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
                screenshot_id: None,
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

        let _ = std::fs::remove_dir_all(&dir);
    }
}
