//! Build a synthetic session with two memory snapshots and a controlled before→after delta,
//! so `reveng-rec mem ls/regions/diff/scan/read` can be exercised without a live process.
//! Models "acquire data into a program": a static region that doesn't move, a heap region
//! that gains a decoded struct (ASCII name + u32 serial + f64 value), and a brand-new
//! allocation that appears only in the "after" snapshot.
//!
//! `cargo run -p reveng-memcap --example mksnaps -- <out_dir>`
use reveng_core::checkpoint::{Checkpoint, CheckpointType};
use reveng_core::session::{SessionRecord, SessionWriter};
use reveng_memcap::write_snapshot;

const PAGE_RW: u32 = 0x04; // PAGE_READWRITE
const MEM_PRIVATE: u32 = 0x20000;
const STATIC_BASE: u64 = 0x1_4000_0000;
const HEAP_BASE: u64 = 0x20_0000;
const NEW_BASE: u64 = 0x30_0000;

fn heap_after() -> Vec<u8> {
    let mut b = vec![0u8; 64];
    b[0..14].copy_from_slice(b"Acme HD Webcam"); // ASCII name at off 0
    b[16..20].copy_from_slice(&4660u32.to_le_bytes()); // u32 serial 0x1234 at off 16
    b[24..32].copy_from_slice(&42.5f64.to_le_bytes()); // f64 value at off 24
    b
}

fn main() -> anyhow::Result<()> {
    let out = std::env::args().nth(1).unwrap_or_else(|| "mem.session".into());
    let zip = std::env::args().nth(2).as_deref() == Some("zip");
    let mut session = SessionWriter::create(&out)?;
    let snaps = session.memsnaps_dir();
    let dir = |id: u64| snaps.join(format!("{id:06}"));

    let pid = 4321;
    let proc = "Vendor.exe";
    let static_region = vec![0xABu8; 128]; // unchanged across both snapshots

    // Snapshot 0 — BEFORE acquisition: heap region present but empty.
    write_snapshot(
        &dir(0),
        0,
        1_000_000,
        pid,
        proc,
        zip,
        &[
            (STATIC_BASE, PAGE_RW, MEM_PRIVATE, static_region.clone()),
            (HEAP_BASE, PAGE_RW, MEM_PRIVATE, vec![0u8; 64]),
        ],
    )?;

    // Snapshot 1 — AFTER acquisition: heap filled with the decoded struct + a new allocation.
    write_snapshot(
        &dir(1),
        1,
        5_000_000,
        pid,
        proc,
        zip,
        &[
            (STATIC_BASE, PAGE_RW, MEM_PRIVATE, static_region),
            (HEAP_BASE, PAGE_RW, MEM_PRIVATE, heap_after()),
            (NEW_BASE, PAGE_RW, MEM_PRIVATE, b"frame#1 payload....".to_vec()),
        ],
    )?;

    let mk = |id, ts, kind, note: Option<&str>, snap: Option<u64>| {
        SessionRecord::Checkpoint(Checkpoint {
            id,
            ts_ns: ts,
            kind,
            cause: "note".into(),
            anchor: None,
            anchors: Vec::new(),
            screenshot_id: None,
            mem_snapshot_id: snap,
            fg_process: Some("Vendor.exe".into()),
            fg_window: Some("Device Config".into()),
            cursor: (0, 0),
            note: note.map(str::to_string),
        })
    };
    session.append_record(&mk(0, 0, CheckpointType::SessionStart, None, None))?;
    session.append_record(&mk(1, 1_000_000, CheckpointType::Manual, Some("before acquire"), Some(0)))?;
    session.append_record(&mk(2, 5_000_000, CheckpointType::Manual, Some("after acquire"), Some(1)))?;
    session.append_record(&mk(3, 6_000_000, CheckpointType::SessionStop, None, None))?;

    session.write_meta(&serde_json::json!({
        "tool": "reveng-rec",
        "source": "memsnap-fixture",
        "acquisition": "synthetic",
    }))?;

    println!("wrote memory-snapshot session to {out}");
    Ok(())
}
