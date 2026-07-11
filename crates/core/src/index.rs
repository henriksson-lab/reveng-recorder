//! Fixed-width, directly-addressable seek index (DESIGN.md §8.2).
//!
//! Record N lives at byte `N * SIZE`, so "seek to event N" is O(1) direct addressing
//! and "seek to time T" is a binary search over the monotonic `ts_ns` column. Each
//! capture source has its own record layout (USB vs PCIe) but shares this machinery.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::path::Path;

/// A fixed-width index record. `ts_ns` must be the sort key and monotonic across
/// appends so [`IndexFile::search_le_ts`] can binary-search it.
pub trait FixedRecord: Sized {
    const SIZE: usize;
    fn ts_ns(&self) -> i64;
    fn write_to(&self, buf: &mut [u8]);
    fn read_from(buf: &[u8]) -> Self;
}

pub struct IndexFile<R: FixedRecord> {
    file: File,
    len: u64,
    _marker: PhantomData<R>,
}

impl<R: FixedRecord> IndexFile<R> {
    /// Create (truncating) a new index file.
    pub fn create(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        Ok(Self {
            file,
            len: 0,
            _marker: PhantomData,
        })
    }

    /// Open an existing index file for read/append.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let bytes = file.metadata()?.len();
        Ok(Self {
            file,
            len: bytes / R::SIZE as u64,
            _marker: PhantomData,
        })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append a record; returns its index. Cheap and crash-safe — this runs on the
    /// hot recording path.
    pub fn append(&mut self, rec: &R) -> std::io::Result<u64> {
        let mut buf = vec![0u8; R::SIZE];
        rec.write_to(&mut buf);
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&buf)?;
        let idx = self.len;
        self.len += 1;
        Ok(idx)
    }

    /// Direct-address read of record N.
    pub fn get(&mut self, index: u64) -> std::io::Result<R> {
        let mut buf = vec![0u8; R::SIZE];
        self.file.seek(SeekFrom::Start(index * R::SIZE as u64))?;
        self.file.read_exact(&mut buf)?;
        Ok(R::read_from(&buf))
    }

    /// Largest index whose `ts_ns <= target` — the checkpoint-anchor rule (DESIGN.md §7).
    pub fn search_le_ts(&mut self, target_ns: i64) -> std::io::Result<Option<u64>> {
        if self.len == 0 {
            return Ok(None);
        }
        let (mut lo, mut hi) = (0u64, self.len - 1);
        let mut ans: Option<u64> = None;
        while lo <= hi {
            let mid = lo + (hi - lo) / 2;
            if self.get(mid)?.ts_ns() <= target_ns {
                ans = Some(mid);
                lo = mid + 1; // safe: mid <= hi < len <= u64::MAX
            } else {
                if mid == 0 {
                    break;
                }
                hi = mid - 1;
            }
        }
        Ok(ans)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rec {
        ts: i64,
        v: u32,
    }
    impl FixedRecord for Rec {
        const SIZE: usize = 12;
        fn ts_ns(&self) -> i64 {
            self.ts
        }
        fn write_to(&self, buf: &mut [u8]) {
            buf[0..8].copy_from_slice(&self.ts.to_le_bytes());
            buf[8..12].copy_from_slice(&self.v.to_le_bytes());
        }
        fn read_from(buf: &[u8]) -> Self {
            Rec {
                ts: i64::from_le_bytes(buf[0..8].try_into().unwrap()),
                v: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            }
        }
    }

    #[test]
    fn append_get_and_search() {
        let path = std::env::temp_dir().join("reveng_index_test.bin");
        let _ = std::fs::remove_file(&path);
        let mut idx = IndexFile::<Rec>::create(&path).unwrap();
        for (i, ts) in [10i64, 20, 30, 40].iter().enumerate() {
            let n = idx.append(&Rec {
                ts: *ts,
                v: i as u32,
            })
            .unwrap();
            assert_eq!(n, i as u64);
        }
        assert_eq!(idx.len(), 4);
        assert_eq!(idx.get(2).unwrap().v, 2);

        assert_eq!(idx.search_le_ts(5).unwrap(), None);
        assert_eq!(idx.search_le_ts(10).unwrap(), Some(0));
        assert_eq!(idx.search_le_ts(25).unwrap(), Some(1));
        assert_eq!(idx.search_le_ts(40).unwrap(), Some(3));
        assert_eq!(idx.search_le_ts(999).unwrap(), Some(3));

        let _ = std::fs::remove_file(&path);
    }
}
