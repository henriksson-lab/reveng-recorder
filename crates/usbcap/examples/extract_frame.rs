//! Reassemble one complete camera frame from a passively-captured bulk stream and write it raw.
//!
//! Usage: `extract_frame <session_dir> <out.raw> [frame_bytes]`  (default 8479744 = 3328×2548 RAW8)
//!
//! The image endpoint (bulk 0x81) delivers a frame as a run of 512 KB transfers ending in a
//! short transfer + zero-length packet. We accumulate payloads between ZLP boundaries and emit
//! the first run whose length matches `frame_bytes`.

use reveng_core::session::SessionReader;
use reveng_usbcap::UsbReader;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let session = args.next().expect("usage: extract_frame <session> <out.raw> [frame_bytes]");
    let out = args.next().expect("need out path");
    let frame_bytes: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(3328 * 2548);

    let s = SessionReader::open(&session)?;
    let mut r = UsbReader::open(s.usb_pcapng(), s.frames_idx())?;
    let n = r.len();

    let mut acc: Vec<u8> = Vec::with_capacity(frame_bytes + (1 << 20));
    let mut started = false;
    let mut boundaries = 0u64;
    let mut ep81 = 0u64;

    for i in 0..n {
        if r.endpoint_at(i)? != 0x81 {
            continue;
        }
        ep81 += 1;
        let p = r.payload_at(i)?;
        if p.is_empty() {
            // Zero-length packet = frame boundary.
            boundaries += 1;
            if started && acc.len() >= frame_bytes {
                std::fs::write(&out, &acc[..frame_bytes])?;
                println!(
                    "extracted frame: {frame_bytes} bytes -> {out}  (accumulated {} across a run)",
                    acc.len()
                );
                return Ok(());
            }
            acc.clear();
            started = true; // begin a fresh frame after the first boundary
            continue;
        }
        if started {
            acc.extend_from_slice(&p);
            // Safety: if we blew well past a frame with no boundary, cut anyway.
            if acc.len() >= frame_bytes * 2 {
                std::fs::write(&out, &acc[..frame_bytes])?;
                println!("extracted frame (no ZLP boundary): {frame_bytes} bytes -> {out}");
                return Ok(());
            }
        }
    }

    eprintln!(
        "no complete frame found: {ep81} bulk-0x81 transfers, {boundaries} ZLP boundaries, last run {} bytes (need {frame_bytes})",
        acc.len()
    );
    std::process::exit(1);
}
