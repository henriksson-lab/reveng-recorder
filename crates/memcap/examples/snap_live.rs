//! Smoke-test the live capture path against a real process: snapshot it twice and diff.
//! `cargo run -p reveng-memcap --example snap_live -- <pid|process.exe> <out_dir>`
use reveng_memcap::{diff, LoadedSnapshot, MemSnapshotSource, RegionDelta};

fn main() -> anyhow::Result<()> {
    let target = std::env::args().nth(1).unwrap_or_else(|| "self".into());
    let out = std::env::args().nth(2).unwrap_or_else(|| "live.snaps".into());
    let dir = std::path::Path::new(&out);

    let src = if target == "self" {
        MemSnapshotSource::open(std::process::id())?
    } else if let Ok(pid) = target.parse::<u32>() {
        MemSnapshotSource::open(pid)?
    } else {
        MemSnapshotSource::by_name(&target)?
    };
    let compress = std::env::args().nth(3).as_deref() == Some("zip");
    println!("opened pid {} (compress={compress})", src.pid());

    let a = src.snapshot(0, 0, &dir.join("000000"), compress)?;
    println!(
        "snap 0: {} regions, {} uncompressed, {} on disk",
        a.regions.len(),
        a.total_bytes,
        a.stored_bytes
    );
    std::thread::sleep(std::time::Duration::from_millis(250));
    let b = src.snapshot(1, 1, &dir.join("000001"), compress)?;
    println!("snap 1: {} regions, {} bytes", b.regions.len(), b.total_bytes);

    let la = LoadedSnapshot::load(&dir.join("000000"))?;
    let lb = LoadedSnapshot::load(&dir.join("000001"))?;
    let d = diff(&la, &lb);
    let (mut new, mut changed, mut freed) = (0, 0, 0);
    for x in &d {
        match x {
            RegionDelta::New { .. } => new += 1,
            RegionDelta::Changed { .. } => changed += 1,
            RegionDelta::Freed { .. } => freed += 1,
            RegionDelta::Resized { .. } => {}
        }
    }
    println!("diff over 250ms: {new} new, {changed} changed, {freed} freed regions");
    if a.regions.is_empty() || a.total_bytes == 0 {
        anyhow::bail!("captured no memory — the read path is broken");
    }
    println!("OK: live capture read real committed memory");
    Ok(())
}
