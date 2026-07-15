//! `reveng-core` — the platform-neutral foundation shared by every crate.
//!
//! Everything here is source-agnostic on purpose: USB and PCIe (and any future
//! [`CaptureSource`]) feed the *same* timeline, index, checkpoints, and session
//! format. See `DESIGN.md` §2 (clock), §7 (checkpoints), §8/§8.2 (storage & seek).

pub mod checkpoint;
pub mod clock;
pub mod event;
pub mod index;
pub mod input;
pub mod session;
pub mod source;
pub mod text;

pub use checkpoint::{Checkpoint, CheckpointConfig, CheckpointType, IntervalTracker};
pub use clock::Clock;
pub use event::{
    Dir, PcieEvent, SourceKind, TrafficAnchor, TrafficKind, TrafficRecord, UsbFrameHeader,
};
pub use index::{FixedRecord, IndexFile};
pub use input::{InputEvent, InputKind};
pub use session::{SessionReader, SessionRecord, SessionWriter};
pub use source::CaptureSource;
