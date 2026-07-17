//! Process memory snapshotting and before/after delta — the "decoded form" oracle.
//!
//! When there's no clean export, a program's **resident memory** is the decoded data:
//! floats as IEEE-754, arrays contiguous, strings as UTF-16. Snapshot the target before
//! and after a data acquisition, [`diff`] the two, and the changed/new regions point at
//! where the acquired data landed — pair that with the on-screen value ([`scan`]) and the
//! on-the-wire bytes (the checkpoint anchor) for the "wire → memory → screen" triple.
//!
//! The **format + analysis** ([`RegionMeta`], [`MemSnapshotMeta`], [`write_snapshot`],
//! [`LoadedSnapshot`], [`diff`], [`scan`]) is pure and cross-platform (so the diff is
//! unit-testable and exercisable from a synthetic fixture with zero OS calls). The
//! **capture** ([`MemSnapshotSource`]) is Windows-only; a stub bails elsewhere, matching
//! the rest of the live-capture stack.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

// ------------------------------------------------------------------------------------------
// Format
// ------------------------------------------------------------------------------------------

/// One committed memory region captured in a snapshot. `hash` is a fast content hash (FNV-1a,
/// not crypto) so [`diff`] can skip unchanged regions without a byte scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionMeta {
    pub base: u64,        // target virtual address of the region
    pub size: u64,        // uncompressed captured bytes (what diff/scan/read operate on)
    pub protect: u32,     // PAGE_* protection flags
    pub mem_type: u32,    // MEM_PRIVATE / MEM_MAPPED / MEM_IMAGE
    pub hash: String,     // fnv1a64 hex of the (uncompressed) captured bytes
    pub file_offset: u64, // byte offset of this region's stored bytes in regions.bin
    /// Bytes stored on disk for this region: `== size` uncompressed, else the deflate length.
    pub stored_len: u64,
}

/// Manifest for one snapshot (`memsnaps/<id:06>/manifest.json`); the bytes sit alongside in
/// `regions.bin`, each region at its `file_offset` for `stored_len` bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemSnapshotMeta {
    pub id: u64,
    pub ts_ns: i64,
    pub pid: u32,
    pub process: String,
    /// Uncompressed total across all regions (`sum(size)`).
    pub total_bytes: u64,
    /// Bytes actually written to `regions.bin` (`sum(stored_len)`) — the compressed size.
    #[serde(default)]
    pub stored_bytes: u64,
    /// Per-region codec: `"none"` or `"deflate"`.
    #[serde(default = "compression_none")]
    pub compression: String,
    pub regions: Vec<RegionMeta>,
}

fn compression_none() -> String {
    "none".to_string()
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Fold more bytes into a running FNV-1a hash (so a region can be hashed chunk-by-chunk).
fn fnv1a64_update(mut h: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Fast non-crypto content hash — only used to short-circuit "did this region change?".
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    fnv1a64_update(FNV_OFFSET, bytes)
}

/// Deflate a whole region to an owned buffer (used by the region-parallel compressor pool).
pub(crate) fn deflate(bytes: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write;
    let mut e = flate2::write::DeflateEncoder::new(
        Vec::with_capacity(bytes.len() / 2 + 16),
        flate2::Compression::default(),
    );
    e.write_all(bytes)?;
    Ok(e.finish()?)
}

/// Streams a snapshot to disk region-by-region and, within a region, chunk-by-chunk — so peak
/// memory is bounded by the caller's chunk buffer, not the region or the target's footprint. A
/// region is written as: `region_begin` → one or more `region_write(chunk)` → `region_end`.
/// With `compress`, each region is an independent deflate stream (`stored_len` = compressed
/// bytes); the manifest records both the uncompressed `size` and on-disk `stored_len`. This is
/// the single producer of the on-disk format (live capture + the fixture both go through it).
pub struct SnapshotWriter {
    out: Option<Out>, // Raw between regions; Deflate while a compressed region is open
    dir: PathBuf,
    id: u64,
    ts_ns: i64,
    pid: u32,
    process: String,
    compress: bool,
    regions: Vec<RegionMeta>,
    stored: u64, // current on-disk offset in regions.bin
    cur: Option<RegionState>,
}

enum Out {
    Raw(BufWriter<File>),
    Deflate(flate2::write::DeflateEncoder<BufWriter<File>>),
}

struct RegionState {
    base: u64,
    protect: u32,
    mem_type: u32,
    file_offset: u64,
    hash: u64,
    size: u64, // uncompressed bytes written so far
}

impl SnapshotWriter {
    pub fn create(
        dir: &Path,
        id: u64,
        ts_ns: i64,
        pid: u32,
        process: &str,
        compress: bool,
    ) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let blob = BufWriter::new(File::create(dir.join("regions.bin"))?);
        Ok(Self {
            out: Some(Out::Raw(blob)),
            dir: dir.to_path_buf(),
            id,
            ts_ns,
            pid,
            process: process.to_string(),
            compress,
            regions: Vec::new(),
            stored: 0,
            cur: None,
        })
    }

    /// Begin a region at the current on-disk offset. In compressed mode this wraps the writer in
    /// a fresh per-region deflate encoder. Call once, then `region_write` chunks, then `region_end`.
    pub fn region_begin(&mut self, base: u64, protect: u32, mem_type: u32) {
        if self.compress {
            if let Some(Out::Raw(w)) = self.out.take() {
                self.out = Some(Out::Deflate(flate2::write::DeflateEncoder::new(
                    w,
                    flate2::Compression::default(),
                )));
            }
        }
        self.cur = Some(RegionState {
            base,
            protect,
            mem_type,
            file_offset: self.stored,
            hash: FNV_OFFSET,
            size: 0,
        });
    }

    /// Append one chunk to the region currently open (bytes hashed + written/compressed here).
    pub fn region_write(&mut self, chunk: &[u8]) -> Result<()> {
        match self.out.as_mut() {
            Some(Out::Raw(w)) => w.write_all(chunk)?,
            Some(Out::Deflate(e)) => e.write_all(chunk)?,
            None => anyhow::bail!("region_write with no open writer"),
        }
        let st = self.cur.as_mut().expect("region_write outside a region");
        st.hash = fnv1a64_update(st.hash, chunk);
        st.size += chunk.len() as u64;
        Ok(())
    }

    /// Finalize the open region: flush its deflate stream (if any), record its metadata, and
    /// advance the on-disk offset. Empty regions (nothing written) are dropped.
    pub fn region_end(&mut self) -> Result<()> {
        let st = self.cur.take().expect("region_end outside a region");
        let stored_len = if self.compress {
            if let Some(Out::Deflate(mut e)) = self.out.take() {
                e.try_finish()?;
                let n = e.total_out();
                self.out = Some(Out::Raw(e.finish()?));
                n
            } else {
                0
            }
        } else {
            st.size // raw: on-disk == uncompressed
        };
        if st.size == 0 {
            return Ok(()); // skip empty region (also nothing was written to disk in raw mode)
        }
        self.stored += stored_len;
        self.regions.push(RegionMeta {
            base: st.base,
            size: st.size,
            protect: st.protect,
            mem_type: st.mem_type,
            hash: format!("{:016x}", st.hash),
            file_offset: st.file_offset,
            stored_len,
        });
        Ok(())
    }

    /// Append a region whose bytes are **already encoded** in the snapshot's codec (used by the
    /// region-parallel compressor: the pool deflates each region off-thread and this just writes
    /// the finished bytes + metadata). `size`/`hash` describe the uncompressed region; `stored`
    /// is what lands in `regions.bin`. Requires no region to be open (raw writer).
    pub fn push_encoded_region(
        &mut self,
        base: u64,
        protect: u32,
        mem_type: u32,
        size: u64,
        hash: u64,
        stored: &[u8],
    ) -> Result<()> {
        if size == 0 {
            return Ok(()); // skip empty region — write nothing, keep offsets aligned
        }
        let file_offset = self.stored;
        match self.out.as_mut() {
            Some(Out::Raw(w)) => w.write_all(stored)?,
            _ => anyhow::bail!("push_encoded_region requires the raw writer (a region is open)"),
        }
        self.stored += stored.len() as u64;
        self.regions.push(RegionMeta {
            base,
            size,
            protect,
            mem_type,
            hash: format!("{hash:016x}"),
            file_offset,
            stored_len: stored.len() as u64,
        });
        Ok(())
    }

    /// Convenience: write a whole in-memory region in one call (batch/fixture path).
    pub fn push_region(&mut self, base: u64, protect: u32, mem_type: u32, bytes: &[u8]) -> Result<()> {
        self.region_begin(base, protect, mem_type);
        if !bytes.is_empty() {
            self.region_write(bytes)?;
        }
        self.region_end()
    }

    /// Flush `regions.bin` and write `manifest.json`; returns the completed manifest.
    pub fn finish(mut self) -> Result<MemSnapshotMeta> {
        match self.out.take() {
            Some(Out::Raw(mut w)) => w.flush()?,
            Some(Out::Deflate(e)) => {
                e.finish()?; // no region left open, but be safe
            }
            None => {}
        }
        let total_bytes: u64 = self.regions.iter().map(|r| r.size).sum();
        let meta = MemSnapshotMeta {
            id: self.id,
            ts_ns: self.ts_ns,
            pid: self.pid,
            process: self.process,
            total_bytes,
            stored_bytes: self.stored,
            compression: if self.compress { "deflate".into() } else { "none".into() },
            regions: self.regions,
        };
        fs::write(self.dir.join("manifest.json"), serde_json::to_vec_pretty(&meta)?)?;
        Ok(meta)
    }
}

/// Batch convenience over [`SnapshotWriter`] — write a whole set of already-in-memory regions
/// (base, protect, mem_type, bytes). Used by the synthetic fixture and tests; the live capture
/// streams via [`SnapshotWriter`] directly so it never holds them all at once.
pub fn write_snapshot(
    dir: &Path,
    id: u64,
    ts_ns: i64,
    pid: u32,
    process: &str,
    compress: bool,
    regions: &[(u64, u32, u32, Vec<u8>)],
) -> Result<MemSnapshotMeta> {
    let mut w = SnapshotWriter::create(dir, id, ts_ns, pid, process, compress)?;
    for (base, protect, mem_type, bytes) in regions {
        w.push_region(*base, *protect, *mem_type, bytes)?;
    }
    w.finish()
}

/// A snapshot loaded off disk for analysis: the manifest plus each region's **uncompressed**
/// bytes (decompressed at load if the snapshot used deflate), keyed by `file_offset`. The whole
/// uncompressed image is held in RAM — the analysis side (`diff`/`scan`) scans everything.
pub struct LoadedSnapshot {
    pub meta: MemSnapshotMeta,
    regions: std::collections::HashMap<u64, Vec<u8>>, // file_offset → uncompressed bytes
}

impl LoadedSnapshot {
    pub fn load(dir: &Path) -> Result<Self> {
        let meta: MemSnapshotMeta =
            serde_json::from_slice(&fs::read(dir.join("manifest.json")).with_context(|| {
                format!("reading {}", dir.join("manifest.json").display())
            })?)?;
        let raw = fs::read(dir.join("regions.bin"))?;
        let deflate = meta.compression == "deflate";
        let mut regions = std::collections::HashMap::with_capacity(meta.regions.len());
        for r in &meta.regions {
            let start = usize::try_from(r.file_offset).context("region offset does not fit this platform")?;
            let stored_len = usize::try_from(r.stored_len).context("region stored length does not fit this platform")?;
            let expected_size = usize::try_from(r.size).context("region size does not fit this platform")?;
            let end = start.checked_add(stored_len).context("region offset overflow")?;
            let stored = raw
                .get(start..end)
                .context("region bytes are outside regions.bin")?;
            let bytes = if deflate { inflate(stored, expected_size)? } else { stored.to_vec() };
            if bytes.len() != expected_size {
                anyhow::bail!(
                    "region at offset {} has {} bytes, expected {}",
                    r.file_offset,
                    bytes.len(),
                    expected_size
                );
            }
            regions.insert(r.file_offset, bytes);
        }
        Ok(Self { meta, regions })
    }

    pub fn region_bytes(&self, r: &RegionMeta) -> &[u8] {
        self.regions.get(&r.file_offset).map(Vec::as_slice).unwrap_or(&[])
    }
}

/// Inflate one deflate-compressed region (`hint` = expected uncompressed size, for pre-alloc).
fn inflate(data: &[u8], hint: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    // Do not trust a manifest-provided size enough to reserve it all up front. The decoder's
    // `take` bound below still enforces the exact declared limit while capacity grows with data.
    let mut out = Vec::with_capacity(hint.min(16 * 1024 * 1024));
    let max_len = u64::try_from(hint)
        .ok()
        .and_then(|n| n.checked_add(1))
        .context("region size is too large to inflate")?;
    flate2::read::DeflateDecoder::new(data)
        .take(max_len)
        .read_to_end(&mut out)?;
    if out.len() > hint {
        anyhow::bail!("deflate region exceeds its declared size");
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------
// Diff — the delta
// ------------------------------------------------------------------------------------------

/// A run of bytes that differ within a region present in both snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ByteChange {
    pub abs_addr: u64, // target VA of the first differing byte (base + offset)
    pub offset: u64,   // offset within the region
    pub old: Vec<u8>,
    pub new: Vec<u8>,
}

/// How a region changed between snapshot A (before) and B (after).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RegionDelta {
    /// Same base+size, contents changed — the byte runs that differ.
    Changed { base: u64, size: u64, changes: Vec<ByteChange> },
    /// A region that only exists in B — a fresh allocation during the window. Prime suspect.
    New { base: u64, size: u64 },
    /// A region that existed in A but is gone in B.
    Freed { base: u64, size: u64 },
    /// Same base, different size (realloc/grow).
    Resized { base: u64, old_size: u64, new_size: u64 },
}

/// Diff two snapshots (A = before, B = after). Regions are aligned by base address; only
/// [`RegionDelta::New`] and [`RegionDelta::Changed`] carry acquired data, so callers usually
/// rank those first. Unchanged regions (equal hash) are skipped without a byte compare.
pub fn diff(a: &LoadedSnapshot, b: &LoadedSnapshot) -> Vec<RegionDelta> {
    use std::collections::BTreeMap;
    let a_by_base: BTreeMap<u64, &RegionMeta> =
        a.meta.regions.iter().map(|r| (r.base, r)).collect();
    let b_by_base: BTreeMap<u64, &RegionMeta> =
        b.meta.regions.iter().map(|r| (r.base, r)).collect();

    let mut out = Vec::new();
    for (base, rb) in &b_by_base {
        match a_by_base.get(base) {
            None => out.push(RegionDelta::New { base: *base, size: rb.size }),
            Some(ra) if ra.size != rb.size => out.push(RegionDelta::Resized {
                base: *base,
                old_size: ra.size,
                new_size: rb.size,
            }),
            Some(ra) if ra.hash != rb.hash => {
                let changes = byte_runs(*base, a.region_bytes(ra), b.region_bytes(rb));
                out.push(RegionDelta::Changed { base: *base, size: rb.size, changes });
            }
            Some(_) => {} // unchanged
        }
    }
    for (base, ra) in &a_by_base {
        if !b_by_base.contains_key(base) {
            out.push(RegionDelta::Freed { base: *base, size: ra.size });
        }
    }
    out
}

/// Coalesce differing bytes between two equal-length buffers into contiguous runs.
fn byte_runs(base: u64, old: &[u8], new: &[u8]) -> Vec<ByteChange> {
    let mut changes = Vec::new();
    let n = old.len().min(new.len());
    let mut i = 0;
    while i < n {
        if old[i] != new[i] {
            let start = i;
            while i < n && old[i] != new[i] {
                i += 1;
            }
            changes.push(ByteChange {
                abs_addr: base + start as u64,
                offset: start as u64,
                old: old[start..i].to_vec(),
                new: new[start..i].to_vec(),
            });
        } else {
            i += 1;
        }
    }
    changes
}

// ------------------------------------------------------------------------------------------
// Scan — seed with a known (on-screen) value
// ------------------------------------------------------------------------------------------

/// A location where a value's encoding was found in a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hit {
    pub abs_addr: u64,     // target VA (region base + offset)
    pub region_base: u64,
    pub offset: u64,
    pub encoding: String,  // "u32_le", "f64_le", "ascii", "utf16le", ...
}

/// Candidate byte encodings for a user-supplied value string. Integers yield the LE (and BE)
/// forms of every width they fit; a value with a `.` also yields f32/f64; every value yields
/// its ASCII and UTF-16LE string forms. This is deliberately broad — the whole point is to
/// find which representation the program actually holds.
pub fn encodings(value: &str) -> Vec<(String, Vec<u8>)> {
    let mut enc = Vec::new();
    let v = value.trim();

    if let Ok(i) = v.parse::<i64>() {
        let u = i as u64;
        if let Ok(b) = u8::try_from(i) {
            enc.push(("u8".into(), vec![b]));
        }
        if let Ok(b) = u16::try_from(i) {
            enc.push(("u16_le".into(), b.to_le_bytes().to_vec()));
            enc.push(("u16_be".into(), b.to_be_bytes().to_vec()));
        }
        if let Ok(b) = u32::try_from(i) {
            enc.push(("u32_le".into(), b.to_le_bytes().to_vec()));
            enc.push(("u32_be".into(), b.to_be_bytes().to_vec()));
        }
        enc.push(("u64_le".into(), u.to_le_bytes().to_vec()));
        enc.push(("u64_be".into(), u.to_be_bytes().to_vec()));
    }
    if let Ok(f) = v.parse::<f64>() {
        if v.contains('.') || v.contains('e') || v.contains('E') {
            enc.push(("f64_le".into(), f.to_le_bytes().to_vec()));
            enc.push(("f32_le".into(), (f as f32).to_le_bytes().to_vec()));
        }
    }
    // String forms (also covers the case where the number is stored as text).
    enc.push(("ascii".into(), v.as_bytes().to_vec()));
    let utf16: Vec<u8> = v.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    enc.push(("utf16le".into(), utf16));

    enc.retain(|(_, b)| !b.is_empty());
    enc
}

/// Find every occurrence of any of `value`'s encodings across the snapshot's regions.
pub fn scan(snap: &LoadedSnapshot, value: &str) -> Vec<Hit> {
    let encs = encodings(value);
    let mut hits = Vec::new();
    for r in &snap.meta.regions {
        let bytes = snap.region_bytes(r);
        for (label, needle) in &encs {
            for off in find_all(bytes, needle) {
                hits.push(Hit {
                    abs_addr: r.base + off as u64,
                    region_base: r.base,
                    offset: off as u64,
                    encoding: label.clone(),
                });
            }
        }
    }
    hits
}

/// All start offsets of `needle` in `hay` (overlapping).
fn find_all(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            out.push(i);
        }
        i += 1;
    }
    out
}

// ------------------------------------------------------------------------------------------
// Capture (Windows only)
// ------------------------------------------------------------------------------------------

/// A handle to a target process, opened once and reused per snapshot. Windows-only; on other
/// platforms `open`/`snapshot` bail (matching the rest of the live-capture stack).
pub struct MemSnapshotSource {
    #[cfg(windows)]
    proc: imp::ProcHandle,
    pid: u32,
    process: String,
}

impl MemSnapshotSource {
    /// Open the target by PID. Needs elevation + SeDebugPrivilege for cross-user/other targets.
    pub fn open(pid: u32) -> Result<Self> {
        #[cfg(windows)]
        {
            let proc = imp::open(pid)?;
            let process = imp::process_name(pid).unwrap_or_else(|_| "?".into());
            Ok(Self { proc, pid, process })
        }
        #[cfg(not(windows))]
        {
            let _ = pid;
            anyhow::bail!("memcap capture is Windows-only")
        }
    }

    /// Resolve a process by (first matching) image name, e.g. `Vendor.exe`.
    pub fn by_name(name: &str) -> Result<Self> {
        #[cfg(windows)]
        {
            let pid = imp::find_pid(name)
                .with_context(|| format!("no running process matching {name:?}"))?;
            Self::open(pid)
        }
        #[cfg(not(windows))]
        {
            let _ = name;
            anyhow::bail!("memcap capture is Windows-only")
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Walk committed private+writable regions, `ReadProcessMemory` each in fixed [`CHUNK`]-sized
    /// pieces, and **stream** them into the snapshot under `dir` (= `memsnaps/<id:06>/`). Peak
    /// memory is bounded by the chunk buffer regardless of region/target size; `compress` stores
    /// each region as deflate.
    pub fn snapshot(&self, id: u64, ts_ns: i64, dir: &Path, compress: bool) -> Result<MemSnapshotMeta> {
        #[cfg(windows)]
        {
            // Deflate is CPU-bound, so compress regions across a thread pool when we have cores.
            // Uncompressed capture is I/O-bound → the serial chunk-streaming path is fine.
            let threads = if compress { compress_threads() } else { 1 };
            if threads > 1 {
                return imp::snapshot_parallel(
                    &self.proc, dir, id, ts_ns, self.pid, &self.process, threads,
                );
            }
            let mut w = SnapshotWriter::create(dir, id, ts_ns, self.pid, &self.process, compress)?;
            imp::for_each_region(&self.proc, CHUNK, &mut w)?;
            w.finish()
        }
        #[cfg(not(windows))]
        {
            let _ = (id, ts_ns, dir, compress);
            anyhow::bail!("memcap capture is Windows-only")
        }
    }
}

/// Bytes read per `ReadProcessMemory` call — the upper bound on serial-path working memory.
pub const CHUNK: usize = 4 * 1024 * 1024;

/// Size of the compressor pool for `--mem-compress` (cores, clamped) — overridable with
/// `REVENG_MEM_THREADS` (e.g. `1` to force the serial path).
fn compress_threads() -> usize {
    if let Some(n) = std::env::var("REVENG_MEM_THREADS").ok().and_then(|v| v.parse::<usize>().ok()) {
        return n.max(1);
    }
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).clamp(1, 16)
}

#[cfg(windows)]
mod imp {
    use super::Result;
    use anyhow::Context;
    use std::path::Path;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READWRITE,
        PAGE_GUARD, PAGE_READWRITE, PAGE_WRITECOPY,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    /// Owns a process HANDLE and closes it on drop.
    pub struct ProcHandle(pub HANDLE);
    // A process HANDLE is a kernel object usable from any thread; the source is opened on the
    // capture thread and moved to the memcap worker, so it must cross the thread boundary.
    unsafe impl Send for ProcHandle {}
    impl Drop for ProcHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    pub fn open(pid: u32) -> Result<ProcHandle> {
        let h = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
            .with_context(|| format!("OpenProcess({pid}) — elevated? SeDebugPrivilege?"))?;
        Ok(ProcHandle(h))
    }

    /// The noise filter: decoded data lives in committed, private, writable pages. Skipping
    /// images/mapped files and read-only pages is what makes the later diff tractable.
    fn keep(mbi: &MEMORY_BASIC_INFORMATION) -> bool {
        let writable = PAGE_READWRITE.0 | PAGE_WRITECOPY.0 | PAGE_EXECUTE_READWRITE.0;
        mbi.State == MEM_COMMIT
            && mbi.Type == MEM_PRIVATE
            && (mbi.Protect.0 & writable) != 0
            && (mbi.Protect.0 & PAGE_GUARD.0) == 0
    }

    /// Enumerate keep-worthy regions and stream each into `w` in `chunk`-sized `ReadProcessMemory`
    /// reads, reusing one fixed buffer — so working memory is bounded by `chunk`, not the region.
    /// A region is opened only once its first chunk reads (so unreadable regions leave nothing).
    pub fn for_each_region(
        proc: &ProcHandle,
        chunk: usize,
        w: &mut super::SnapshotWriter,
    ) -> Result<()> {
        let mut addr: usize = 0;
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let sz = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
        let mut buf: Vec<u8> = vec![0u8; chunk];
        loop {
            let n = unsafe { VirtualQueryEx(proc.0, Some(addr as *const _), &mut mbi, sz) };
            if n == 0 {
                break; // walked past the top of the address space
            }
            let base = mbi.BaseAddress as usize;
            let region = mbi.RegionSize;
            if keep(&mbi) {
                let mut off = 0usize;
                let mut open = false;
                while off < region {
                    let want = (region - off).min(chunk);
                    let mut read: usize = 0;
                    let ok = unsafe {
                        ReadProcessMemory(
                            proc.0,
                            (base + off) as *const _,
                            buf.as_mut_ptr() as *mut _,
                            want,
                            Some(&mut read),
                        )
                    };
                    if ok.is_err() || read == 0 {
                        break; // unreadable (sub)region; keep whatever we already streamed
                    }
                    if !open {
                        w.region_begin(base as u64, mbi.Protect.0, mbi.Type.0);
                        open = true;
                    }
                    w.region_write(&buf[..read])?;
                    off += read;
                }
                if open {
                    w.region_end()?;
                }
            }
            match base.checked_add(region) {
                Some(next) if next > addr => addr = next,
                _ => break, // overflow / no progress
            }
        }
        Ok(())
    }

    /// Read each keep-worthy region fully (chunked reads appended into one owned buffer) and send
    /// it down `tx` for off-thread compression. The bounded `tx` applies backpressure so the
    /// reader can't race ahead of the compressor pool and load the whole target into memory.
    fn read_regions_into(
        proc: &ProcHandle,
        chunk: usize,
        tx: &std::sync::mpsc::SyncSender<(u64, u32, u32, Vec<u8>)>,
    ) -> Result<()> {
        let mut addr: usize = 0;
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let sz = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
        let mut buf: Vec<u8> = vec![0u8; chunk]; // scratch, reused across regions
        loop {
            let n = unsafe { VirtualQueryEx(proc.0, Some(addr as *const _), &mut mbi, sz) };
            if n == 0 {
                break;
            }
            let base = mbi.BaseAddress as usize;
            let region = mbi.RegionSize;
            if keep(&mbi) {
                let mut data: Vec<u8> = Vec::with_capacity(region);
                let mut off = 0usize;
                while off < region {
                    let want = (region - off).min(chunk);
                    let mut read: usize = 0;
                    let ok = unsafe {
                        ReadProcessMemory(
                            proc.0,
                            (base + off) as *const _,
                            buf.as_mut_ptr() as *mut _,
                            want,
                            Some(&mut read),
                        )
                    };
                    if ok.is_err() || read == 0 {
                        break;
                    }
                    data.extend_from_slice(&buf[..read]);
                    off += read;
                }
                if !data.is_empty()
                    && tx.send((base as u64, mbi.Protect.0, mbi.Type.0, data)).is_err()
                {
                    break; // collector/pool gone
                }
            }
            match base.checked_add(region) {
                Some(next) if next > addr => addr = next,
                _ => break,
            }
        }
        Ok(())
    }

    /// Region-parallel compressed snapshot: one reader thread streams regions into a bounded queue,
    /// a pool of `threads` compressors deflate them off-thread, and a collector writes the finished
    /// (independent) region blobs in completion order. Peak memory is bounded by the queue depth ×
    /// region size, not the target footprint.
    pub fn snapshot_parallel(
        proc: &ProcHandle,
        dir: &Path,
        id: u64,
        ts_ns: i64,
        pid: u32,
        process: &str,
        threads: usize,
    ) -> Result<super::MemSnapshotMeta> {
        use std::sync::mpsc::{channel, sync_channel};
        use std::sync::{Arc, Mutex};

        let mut w = super::SnapshotWriter::create(dir, id, ts_ns, pid, process, true)?;
        let (work_tx, work_rx) = sync_channel::<(u64, u32, u32, Vec<u8>)>(threads * 2);
        let work_rx = Arc::new(Mutex::new(work_rx));
        // (base, protect, mem_type, uncompressed_size, hash, compressed_bytes)
        type EncodedRegion = (u64, u32, u32, u64, u64, Vec<u8>);
        let (res_tx, res_rx) = channel::<std::result::Result<EncodedRegion, String>>();

        std::thread::scope(|s| -> Result<super::MemSnapshotMeta> {
            for _ in 0..threads {
                let rx = work_rx.clone();
                let tx = res_tx.clone();
                s.spawn(move || loop {
                    let job = { rx.lock().unwrap().recv() };
                    let Ok((base, protect, mt, bytes)) = job else { break };
                    let hash = super::fnv1a64(&bytes);
                    match super::deflate(&bytes) {
                        Ok(comp) => {
                            if tx
                                .send(Ok((base, protect, mt, bytes.len() as u64, hash, comp)))
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(Err(format!(
                                "compressing memory region at 0x{base:x}: {e:#}"
                            )));
                            break;
                        }
                    }
                });
            }
            drop(res_tx); // res_rx closes once every compressor clone is dropped

            let collector = s.spawn(move || -> Result<super::MemSnapshotMeta> {
                while let Ok(result) = res_rx.recv() {
                    let (base, protect, mt, size, hash, comp) =
                        result.map_err(anyhow::Error::msg)?;
                    w.push_encoded_region(base, protect, mt, size, hash, &comp)?;
                }
                w.finish()
            });

            read_regions_into(proc, super::CHUNK, &work_tx)?; // producer on this thread
            drop(work_tx); // pool drains and exits → res closes → collector finishes

            collector.join().map_err(|_| anyhow::anyhow!("memcap collector panicked"))?
        })
    }

    pub fn process_name(pid: u32) -> Result<String> {
        find_entry(|e| e.th32ProcessID == pid).map(|(_, name)| name)
    }

    pub fn find_pid(name: &str) -> Option<u32> {
        let want = name.to_ascii_lowercase();
        find_entry(|e| {
            let n = wsz_to_string(&e.szExeFile).to_ascii_lowercase();
            n == want
        })
        .ok()
        .map(|(pid, _)| pid)
    }

    fn find_entry(
        mut pred: impl FnMut(&PROCESSENTRY32W) -> bool,
    ) -> Result<(u32, String)> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
            let mut e = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            let guard = ProcHandle(snap);
            if Process32FirstW(guard.0, &mut e).is_ok() {
                loop {
                    if pred(&e) {
                        return Ok((e.th32ProcessID, wsz_to_string(&e.szExeFile)));
                    }
                    if Process32NextW(guard.0, &mut e).is_err() {
                        break;
                    }
                }
            }
        }
        anyhow::bail!("process not found")
    }

    fn wsz_to_string(w: &[u16]) -> String {
        let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
        String::from_utf16_lossy(&w[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(dir: &Path, id: u64, regions: &[(u64, Vec<u8>)]) -> LoadedSnapshot {
        mk_c(dir, id, regions, false)
    }
    fn mk_c(dir: &Path, id: u64, regions: &[(u64, Vec<u8>)], compress: bool) -> LoadedSnapshot {
        let regs: Vec<_> = regions
            .iter()
            .map(|(base, b)| (*base, PAGE_RW, MEM_PRIV, b.clone()))
            .collect();
        write_snapshot(dir, id, id as i64, 1234, "target.exe", compress, &regs).unwrap();
        LoadedSnapshot::load(dir).unwrap()
    }
    const PAGE_RW: u32 = 0x04;
    const MEM_PRIV: u32 = 0x20000;

    #[test]
    fn diff_flags_new_changed_freed() {
        let tmp = std::env::temp_dir().join("memcap_diff_test");
        let _ = fs::remove_dir_all(&tmp);
        let a = mk(&tmp.join("a"), 0, &[(0x1000, vec![0u8; 8]), (0x2000, vec![9u8; 4])]);
        // B: region 0x1000 changed at offset 4..6; 0x2000 freed; 0x3000 new.
        let b = mk(
            &tmp.join("b"),
            1,
            &[(0x1000, vec![0, 0, 0, 0, 1, 1, 0, 0]), (0x3000, vec![7u8; 16])],
        );
        let d = diff(&a, &b);
        assert!(d.contains(&RegionDelta::New { base: 0x3000, size: 16 }));
        assert!(d.contains(&RegionDelta::Freed { base: 0x2000, size: 4 }));
        let changed = d
            .iter()
            .find_map(|x| match x {
                RegionDelta::Changed { base: 0x1000, changes, .. } => Some(changes.clone()),
                _ => None,
            })
            .expect("0x1000 changed");
        assert_eq!(
            changed,
            vec![ByteChange { abs_addr: 0x1004, offset: 4, old: vec![0, 0], new: vec![1, 1] }]
        );
    }

    #[test]
    fn unchanged_region_is_skipped() {
        let tmp = std::env::temp_dir().join("memcap_same_test");
        let _ = fs::remove_dir_all(&tmp);
        let a = mk(&tmp.join("a"), 0, &[(0x1000, vec![5u8; 32])]);
        let b = mk(&tmp.join("b"), 1, &[(0x1000, vec![5u8; 32])]);
        assert!(diff(&a, &b).is_empty());
    }

    #[test]
    fn deflate_round_trips_and_shrinks() {
        let tmp = std::env::temp_dir().join("memcap_zip_test");
        let _ = fs::remove_dir_all(&tmp);
        // A highly-compressible region (repeated bytes) + a value to find after decompression.
        let mut r = vec![0u8; 4096];
        r[100..104].copy_from_slice(&4660u32.to_le_bytes());
        let raw = mk_c(&tmp.join("raw"), 0, &[(0x1000, r.clone())], false);
        let zip = mk_c(&tmp.join("zip"), 1, &[(0x1000, r.clone())], true);
        // Compressed on-disk size is much smaller, but the decoded bytes are identical.
        assert!(zip.meta.stored_bytes < raw.meta.stored_bytes);
        assert_eq!(zip.meta.compression, "deflate");
        assert_eq!(zip.region_bytes(&zip.meta.regions[0]), &r[..]);
        // diff of a compressed vs uncompressed capture of the same memory sees no change.
        assert!(diff(&raw, &zip).is_empty());
        // scan works through decompression.
        assert!(scan(&zip, "4660").iter().any(|h| h.abs_addr == 0x1064));
    }

    #[test]
    fn scan_finds_int_and_string_encodings() {
        let tmp = std::env::temp_dir().join("memcap_scan_test");
        let _ = fs::remove_dir_all(&tmp);
        // 0x1000 holds u32_le 4660 (0x1234) at off 2; 0x2000 holds ASCII "Acme" at off 0.
        let a = mk(
            &tmp.join("a"),
            0,
            &[
                (0x1000, vec![0xFF, 0xFF, 0x34, 0x12, 0x00, 0x00]),
                (0x2000, b"Acme HD".to_vec()),
            ],
        );
        let hits = scan(&a, "4660");
        assert!(hits
            .iter()
            .any(|h| h.encoding == "u32_le" && h.abs_addr == 0x1002));
        let s = scan(&a, "Acme");
        assert!(s.iter().any(|h| h.encoding == "ascii" && h.abs_addr == 0x2000));
    }

    #[test]
    fn inflate_rejects_data_larger_than_its_manifest_size() {
        let compressed = deflate(&[42u8; 32]).unwrap();
        assert!(inflate(&compressed, 31).is_err());
    }
}
