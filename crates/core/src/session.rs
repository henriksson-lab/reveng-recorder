//! On-disk session layout (DESIGN.md §8).
//!
//! `events.ndjson` is the append-only, crash-safe source of truth for input events and
//! checkpoints. `usb.pcapng` / `pcie.bin` hold raw traffic; `*.idx` are the fixed-width
//! seek indexes; `index.sqlite` (added later) is a rebuildable query accelerator.

use crate::checkpoint::Checkpoint;
use crate::input::InputEvent;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

/// One line of `events.ndjson`. Tagged so input events and checkpoints can interleave
/// in one append-only log and be told apart on read.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "rec", rename_all = "snake_case")]
pub enum SessionRecord {
    Checkpoint(Checkpoint),
    Input(InputEvent),
}

pub struct SessionWriter {
    root: PathBuf,
    events: fs::File,
}

impl SessionWriter {
    /// Create the session directory (and `screenshots/`) and open `events.ndjson`.
    pub fn create(root: impl AsRef<Path>) -> anyhow::Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("screenshots"))?;
        let events = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("events.ndjson"))?;
        Ok(Self { root, events })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn screenshots_dir(&self) -> PathBuf {
        self.root.join("screenshots")
    }
    /// Per-screenshot spatial metadata log (one JSON line per PNG: id, capture rect, cursor,
    /// monitor, DPI). Lets later analysis map cursor / OCR boxes to pixels.
    pub fn screenshots_meta(&self) -> PathBuf {
        self.root.join("screenshots.ndjson")
    }
    /// Monitor layout captured at session start (`enumerate_displays`).
    pub fn displays_json(&self) -> PathBuf {
        self.root.join("displays.json")
    }
    /// OCR result cache: `ocr/<id:06>.json` per screenshot.
    pub fn ocr_dir(&self) -> PathBuf {
        self.root.join("ocr")
    }
    /// UI-Automation widget-tree snapshots: `ui/<id:06>.json` per checkpoint.
    pub fn ui_dir(&self) -> PathBuf {
        self.root.join("ui")
    }
    /// Directory holding process-memory snapshots (`memsnaps/<id:06>/`), created on first use.
    pub fn memsnaps_dir(&self) -> PathBuf {
        self.root.join("memsnaps")
    }
    pub fn usb_pcapng(&self) -> PathBuf {
        self.root.join("usb.pcapng")
    }
    pub fn frames_idx(&self) -> PathBuf {
        self.root.join("frames.idx")
    }
    pub fn pcie_bin(&self) -> PathBuf {
        self.root.join("pcie.bin")
    }
    pub fn pcie_idx(&self) -> PathBuf {
        self.root.join("pcie.idx")
    }

    /// Write `meta.json` (clock anchor, config, device info, versions).
    pub fn write_meta<T: Serialize>(&self, meta: &T) -> anyhow::Result<()> {
        fs::write(self.root.join("meta.json"), serde_json::to_string_pretty(meta)?)?;
        Ok(())
    }

    /// Append one raw serializable value as a JSON line.
    pub fn append_event<T: Serialize>(&mut self, ev: &T) -> anyhow::Result<()> {
        let line = serde_json::to_string(ev)?;
        self.events.write_all(line.as_bytes())?;
        self.events.write_all(b"\n")?;
        Ok(())
    }

    /// Append a tagged session record (checkpoint or input event).
    pub fn append_record(&mut self, rec: &SessionRecord) -> anyhow::Result<()> {
        self.append_event(rec)
    }
}

/// Reads an existing session directory (DESIGN.md §8a — the query side).
pub struct SessionReader {
    root: PathBuf,
}

impl SessionReader {
    pub fn open(root: impl AsRef<Path>) -> anyhow::Result<Self> {
        let root = root.as_ref().to_path_buf();
        if !root.is_dir() {
            anyhow::bail!("session directory not found: {}", root.display());
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn pcie_bin(&self) -> PathBuf {
        self.root.join("pcie.bin")
    }
    pub fn pcie_idx(&self) -> PathBuf {
        self.root.join("pcie.idx")
    }
    pub fn usb_pcapng(&self) -> PathBuf {
        self.root.join("usb.pcapng")
    }
    pub fn frames_idx(&self) -> PathBuf {
        self.root.join("frames.idx")
    }
    /// Directory holding process-memory snapshots (`memsnaps/<id:06>/`).
    pub fn memsnaps_dir(&self) -> PathBuf {
        self.root.join("memsnaps")
    }
    pub fn screenshots_dir(&self) -> PathBuf {
        self.root.join("screenshots")
    }
    pub fn screenshots_meta(&self) -> PathBuf {
        self.root.join("screenshots.ndjson")
    }
    pub fn displays_json(&self) -> PathBuf {
        self.root.join("displays.json")
    }
    pub fn ocr_dir(&self) -> PathBuf {
        self.root.join("ocr")
    }
    pub fn ui_dir(&self) -> PathBuf {
        self.root.join("ui")
    }

    pub fn meta(&self) -> anyhow::Result<serde_json::Value> {
        let s = fs::read_to_string(self.root.join("meta.json"))?;
        Ok(serde_json::from_str(&s)?)
    }

    /// All records from `events.ndjson`, in file order.
    pub fn records(&self) -> anyhow::Result<Vec<SessionRecord>> {
        let file = fs::File::open(self.root.join("events.ndjson"))?;
        let mut reader = std::io::BufReader::new(file);
        let mut out = Vec::new();
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            let terminated = line.ends_with('\n');
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<SessionRecord>(line) {
                Ok(record) => out.push(record),
                // A crash can leave only the final append partially written.  Preserve all
                // complete source-of-truth records and ignore that unterminated tail.
                Err(_) if !terminated => break,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(out)
    }

    /// Just the checkpoints (the timeline / manifest), in file order.
    pub fn checkpoints(&self) -> anyhow::Result<Vec<Checkpoint>> {
        Ok(self
            .records()?
            .into_iter()
            .filter_map(|r| match r {
                SessionRecord::Checkpoint(c) => Some(c),
                _ => None,
            })
            .collect())
    }

    pub fn checkpoint(&self, id: u64) -> anyhow::Result<Checkpoint> {
        self.checkpoints()?
            .into_iter()
            .find(|c| c.id == id)
            .ok_or_else(|| anyhow::anyhow!("no checkpoint with id {id}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{Checkpoint, CheckpointType};
    use crate::event::{SourceKind, TrafficAnchor};

    /// A live note is stored as a `Manual` checkpoint carrying the text + the anchor to the
    /// frame that was live when it was entered — the note-vs-wire correlation the feature
    /// exists for. Guard that it survives the `events.ndjson` round-trip.
    #[test]
    fn manual_note_round_trips_through_ndjson() {
        let c = Checkpoint {
            id: 7,
            ts_ns: 5_000_000_000,
            kind: CheckpointType::Manual,
            cause: "note".into(),
            anchor: Some(TrafficAnchor {
                source: SourceKind::Usb,
                event_index: 42,
                byte_offset: 0,
            }),
            anchors: Vec::new(),
            screenshot_id: None,
            mem_snapshot_id: None,
            fg_process: None,
            fg_window: None,
            cursor: (0, 0),
            note: Some("clicked connect".into()),
        };
        let line = serde_json::to_string(&SessionRecord::Checkpoint(c)).unwrap();
        assert!(line.contains(r#""rec":"checkpoint""#));
        assert!(line.contains(r#""kind":"manual""#));

        match serde_json::from_str::<SessionRecord>(&line).unwrap() {
            SessionRecord::Checkpoint(d) => {
                assert_eq!(d.kind, CheckpointType::Manual);
                assert_eq!(d.note.as_deref(), Some("clicked connect"));
                assert_eq!(d.anchor.unwrap().event_index, 42);
            }
            _ => panic!("expected a checkpoint record"),
        }
    }

    #[test]
    fn records_ignore_only_an_unterminated_crash_tail() {
        let dir = std::env::temp_dir().join(format!(
            "reveng_session_tail_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut writer = SessionWriter::create(&dir).unwrap();
        writer
            .append_record(&SessionRecord::Input(InputEvent {
                ts_ns: 1,
                kind: crate::input::InputKind::KeyDown,
                button: None,
                vk: Some(65),
                scancode: None,
                x: 0,
                y: 0,
                injected: false,
            }))
            .unwrap();
        drop(writer);
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("events.ndjson"))
            .unwrap();
        file.write_all(br#"{"rec":"checkpoint""#).unwrap();
        drop(file);

        assert_eq!(SessionReader::open(&dir).unwrap().records().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}
