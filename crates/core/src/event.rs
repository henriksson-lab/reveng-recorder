//! Source-agnostic traffic event schema (DESIGN.md §4, §4a, §7).

use serde::{Deserialize, Serialize};

/// Which capture source produced a record. New sources are additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    Usb,
    Pcie,
}

/// Transfer direction, from the host's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Dir {
    In,
    Out,
}

/// The indexed part of a USB frame. Payload bytes live in `usb.pcapng`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbFrameHeader {
    pub bus: u16,
    pub device: u16,
    pub endpoint: u8,
    pub transfer: u8, // 0=iso 1=interrupt 2=control 3=bulk (USBPcap encoding)
    pub status: u32,
    pub data_length: u32,
}

/// A single PCIe capture event from the software-only backend (DESIGN.md §4a).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum PcieEvent {
    Mmio {
        ts_ns: i64,
        bar: u8,
        offset: u32,
        width: u8,
        value: u64,
        dir: Dir,
    },
    Dma {
        ts_ns: i64,
        dir: Dir,
        dev_addr: u64,
        len: u32,
    },
    Irq {
        ts_ns: i64,
        vector: u16,
    },
    Config {
        ts_ns: i64,
        offset: u16,
        width: u8,
        value: u32,
        dir: Dir,
    },
}

impl PcieEvent {
    pub fn ts_ns(&self) -> i64 {
        match *self {
            PcieEvent::Mmio { ts_ns, .. }
            | PcieEvent::Dma { ts_ns, .. }
            | PcieEvent::Irq { ts_ns, .. }
            | PcieEvent::Config { ts_ns, .. } => ts_ns,
        }
    }
}

/// Typed header for a traffic record, tagged by source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficKind {
    Usb(UsbFrameHeader),
    Pcie(PcieEvent),
}

/// One unit of device traffic on the unified timeline, from any [`super::CaptureSource`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrafficRecord {
    pub ts_ns: i64,
    pub source: SourceKind,
    pub kind: TrafficKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub payload: Vec<u8>,
}

/// Source-agnostic pointer from a checkpoint to the nearest preceding traffic event
/// (DESIGN.md §7). A PCIe source populates the identical fields against `pcie.idx`,
/// so adding a source is an addition, not a schema migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficAnchor {
    pub source: SourceKind,
    pub event_index: u64,
    /// Advisory offset into the raw log at record time. For USB, finalize may rewrite the
    /// pcapng (checkpoint-comment injection) and shift offsets; the authoritative offset is
    /// always re-derived from the index via `event_index`, so consumers should prefer that
    /// and treat this field as a hint only.
    pub byte_offset: u64,
}
