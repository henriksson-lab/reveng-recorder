//! PCIe capture backend (DESIGN.md §4a).
//!
//! Two sources behind the one [`CaptureSource`] seam:
//! - [`ReplayPcieSource`] — reads a JSONL of [`PcieEvent`]s. Portable, zero kernel code;
//!   this is the source that lets storage/index/decode/viewer be built and validated
//!   before the hypervisor exists (see the build-order note in DESIGN.md §13).
//! - [`HvPcieSource`] — the real VT-x/EPT hypervisor-backed source (Windows only, stub).

pub mod log;
pub mod pci;

pub use log::{PcieIdxRecord, PcieLog};
pub use pci::{list_pci_devices, PciDevice};

use reveng_core::event::{PcieEvent, SourceKind, TrafficKind, TrafficRecord};
use reveng_core::source::CaptureSource;
use std::io::BufRead;

/// Replays PCIe events from a JSONL file (one [`PcieEvent`] per line).
pub struct ReplayPcieSource {
    events: std::vec::IntoIter<PcieEvent>,
}

impl ReplayPcieSource {
    /// Load events from a `.jsonl` file.
    pub fn from_path(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let file = std::fs::File::open(path)?;
        let mut events = Vec::new();
        for line in std::io::BufReader::new(file).lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            events.push(serde_json::from_str::<PcieEvent>(line)?);
        }
        Ok(Self {
            events: events.into_iter(),
        })
    }

    pub fn from_events(events: Vec<PcieEvent>) -> Self {
        Self {
            events: events.into_iter(),
        }
    }
}

impl CaptureSource for ReplayPcieSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Pcie
    }

    fn start(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn next(&mut self) -> anyhow::Result<Option<TrafficRecord>> {
        Ok(self.events.next().map(|ev| TrafficRecord {
            ts_ns: ev.ts_ns(),
            source: SourceKind::Pcie,
            kind: TrafficKind::Pcie(ev),
            payload: Vec::new(),
        }))
    }

    fn stop(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Hypervisor-backed PCIe source: EPT MMIO traps + config/interrupt capture, DMA by
/// descriptor-following (DESIGN.md §4a). Requires the `driver/reveng-hv` kernel driver
/// and VBS/HVCI off. Not yet implemented.
pub struct HvPcieSource;

impl CaptureSource for HvPcieSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Pcie
    }

    fn start(&mut self) -> anyhow::Result<()> {
        anyhow::bail!("hypervisor PCIe capture not yet implemented (see driver/reveng-hv)")
    }

    fn next(&mut self) -> anyhow::Result<Option<TrafficRecord>> {
        Ok(None)
    }

    fn stop(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reveng_core::event::Dir;

    #[test]
    fn replay_yields_records_in_order() {
        let evs = vec![
            PcieEvent::Mmio {
                ts_ns: 10,
                bar: 0,
                offset: 0x40,
                width: 4,
                value: 1,
                dir: Dir::Out,
            },
            PcieEvent::Irq {
                ts_ns: 20,
                vector: 3,
            },
        ];
        let mut src = ReplayPcieSource::from_events(evs);
        src.start().unwrap();
        assert_eq!(src.next().unwrap().unwrap().ts_ns, 10);
        assert_eq!(src.next().unwrap().unwrap().ts_ns, 20);
        assert!(src.next().unwrap().is_none());
    }
}
