//! The PCIe traffic log + seek index (DESIGN.md §4a, §8.2).
//!
//! `pcie.bin` stores one decoded [`PcieEvent`] as a JSON line (this *is* the on-demand
//! decoded form for PCIe — there is no pcapng equivalent). `pcie.idx` is the fixed-width
//! `{ts_ns, byte_offset}` seek index, mirroring the USB `frames.idx` design so seeking is
//! O(1) by index and O(log n) by time.

use reveng_core::event::PcieEvent;
use reveng_core::index::{FixedRecord, IndexFile};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// 16-byte PCIe index record: `{ts_ns, byte_offset}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcieIdxRecord {
    pub ts_ns: i64,
    pub byte_offset: u64,
}

impl FixedRecord for PcieIdxRecord {
    const SIZE: usize = 16;
    fn ts_ns(&self) -> i64 {
        self.ts_ns
    }
    fn write_to(&self, buf: &mut [u8]) {
        buf[0..8].copy_from_slice(&self.ts_ns.to_le_bytes());
        buf[8..16].copy_from_slice(&self.byte_offset.to_le_bytes());
    }
    fn read_from(buf: &[u8]) -> Self {
        PcieIdxRecord {
            ts_ns: i64::from_le_bytes(buf[0..8].try_into().unwrap()),
            byte_offset: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        }
    }
}

pub struct PcieLog {
    bin: File,
    idx: IndexFile<PcieIdxRecord>,
    write_offset: u64,
}

impl PcieLog {
    /// Create (truncating) a new log + index pair.
    pub fn create(bin_path: impl AsRef<Path>, idx_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let bin = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(bin_path)?;
        let idx = IndexFile::<PcieIdxRecord>::create(idx_path)?;
        Ok(Self {
            bin,
            idx,
            write_offset: 0,
        })
    }

    /// Open an existing log for reading (and appending).
    pub fn open(bin_path: impl AsRef<Path>, idx_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let bin = OpenOptions::new().read(true).write(true).open(bin_path)?;
        let write_offset = bin.metadata()?.len();
        let idx = IndexFile::<PcieIdxRecord>::open(idx_path)?;
        Ok(Self {
            bin,
            idx,
            write_offset,
        })
    }

    pub fn len(&self) -> u64 {
        self.idx.len()
    }
    pub fn is_empty(&self) -> bool {
        self.idx.is_empty()
    }

    /// Append one event; returns `(index, byte_offset)`.
    pub fn append(&mut self, ev: &PcieEvent) -> anyhow::Result<(u64, u64)> {
        let mut line = serde_json::to_string(ev)?;
        line.push('\n');
        self.bin.seek(SeekFrom::Start(self.write_offset))?;
        self.bin.write_all(line.as_bytes())?;
        let offset = self.write_offset;
        self.write_offset += line.len() as u64;
        let index = self.idx.append(&PcieIdxRecord {
            ts_ns: ev.ts_ns(),
            byte_offset: offset,
        })?;
        Ok((index, offset))
    }

    /// Read the event stored at a byte offset in `pcie.bin`.
    pub fn event_at_offset(&mut self, offset: u64) -> anyhow::Result<PcieEvent> {
        self.bin.seek(SeekFrom::Start(offset))?;
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = self.bin.read(&mut byte)?;
            if n == 0 || byte[0] == b'\n' {
                break;
            }
            buf.push(byte[0]);
        }
        Ok(serde_json::from_slice(&buf)?)
    }

    /// Read the event at index `i`.
    pub fn event_at(&mut self, i: u64) -> anyhow::Result<PcieEvent> {
        let rec = self.idx.get(i)?;
        self.event_at_offset(rec.byte_offset)
    }

    /// Largest event index whose `ts_ns <= target` (the checkpoint-anchor rule).
    pub fn index_le_ts(&mut self, target_ns: i64) -> anyhow::Result<Option<u64>> {
        Ok(self.idx.search_le_ts(target_ns)?)
    }

    /// The byte offset of event `i` (for a checkpoint anchor).
    pub fn offset_of(&mut self, i: u64) -> anyhow::Result<u64> {
        Ok(self.idx.get(i)?.byte_offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reveng_core::event::Dir;

    fn mmio(ts: i64, off: u32, val: u64) -> PcieEvent {
        PcieEvent::Mmio {
            ts_ns: ts,
            bar: 0,
            offset: off,
            width: 4,
            value: val,
            dir: Dir::Out,
        }
    }

    #[test]
    fn append_then_read_back() {
        let dir = std::env::temp_dir();
        let bin = dir.join("reveng_pcie_test.bin");
        let idx = dir.join("reveng_pcie_test.idx");
        let _ = std::fs::remove_file(&bin);
        let _ = std::fs::remove_file(&idx);

        {
            let mut log = PcieLog::create(&bin, &idx).unwrap();
            log.append(&mmio(10, 0x40, 1)).unwrap();
            log.append(&mmio(20, 0x44, 2)).unwrap();
            log.append(&mmio(30, 0x48, 3)).unwrap();
            assert_eq!(log.len(), 3);
        }

        let mut log = PcieLog::open(&bin, &idx).unwrap();
        assert_eq!(log.len(), 3);
        assert_eq!(log.event_at(1).unwrap(), mmio(20, 0x44, 2));
        assert_eq!(log.index_le_ts(25).unwrap(), Some(1));
        assert_eq!(log.index_le_ts(5).unwrap(), None);

        let _ = std::fs::remove_file(&bin);
        let _ = std::fs::remove_file(&idx);
    }
}
