//! The `CaptureSource` seam (DESIGN.md §3, §4a).
//!
//! Every acquisition backend — USB via USBPcap, PCIe via the hypervisor, or a replay
//! source for testing — implements this one trait. Nothing downstream (index, decode,
//! checkpoints, viewer) depends on which implementation is in use, which is what makes
//! postponing or swapping a source free.

use crate::event::{SourceKind, TrafficRecord};

pub trait CaptureSource {
    /// Which source this is.
    fn kind(&self) -> SourceKind;

    /// Begin capturing (spawn the sniffer, arm the hypervisor, open the replay file, …).
    fn start(&mut self) -> anyhow::Result<()>;

    /// Pull the next record, or `Ok(None)` at end of stream.
    ///
    /// Scaffold contract is pull-based for simplicity; the real recorder drives each
    /// source from a dedicated high-priority thread and forwards records over a channel
    /// (DESIGN.md §3 thread model).
    fn next(&mut self) -> anyhow::Result<Option<TrafficRecord>>;

    /// Stop capturing and release resources.
    fn stop(&mut self) -> anyhow::Result<()>;
}
