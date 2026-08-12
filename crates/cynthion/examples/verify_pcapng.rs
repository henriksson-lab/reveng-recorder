//! Read back a Cynthion capture the way the analysis toolchain does, and print what the
//! shared [`UsbReader`] made of it.
//!
//! This is the P2 acceptance check: the same reader that serves `frames`, `payload`,
//! `grep`, `diff` and the viewer opens a wire session, works out from the file that it is
//! one, and decodes tokens, data and handshakes. If this prints sensible PIDs and endpoints
//! then every Tier A command does too, because they all go through here.
//!
//! ```sh
//! cargo run -p reveng-cynthion --example verify_pcapng -- out.pcapng
//! ```

use reveng_usbcap::UsbReader;

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: verify_pcapng <capture.pcapng>"))?;
    let data = std::fs::read(&path)?;
    let (lt, ns) = reveng_usbcap::pcapng::interface_info(&data)?;
    let pkts = reveng_usbcap::pcapng::packets(&data)?;
    let span =
        pkts.last().map(|p| p.ts_ns).unwrap_or(0) - pkts.first().map(|p| p.ts_ns).unwrap_or(0);
    println!(
        "link type {lt}, {ns} ns per unit, {} packets, span {:.3} ms",
        pkts.len(),
        span as f64 / 1e6
    );

    let idx = std::path::Path::new(&path).with_extension("idx");
    if !idx.exists() {
        println!(
            "no {} beside the capture — nothing to decode",
            idx.display()
        );
        return Ok(());
    }

    let mut r = UsbReader::open(&path, &idx)?;
    println!("format {:?}, {} frame(s)", r.format(), r.len());
    println!(
        "{:>6}  {:>12}  {:>6} {:>5} {:>4} {:>4}  payload",
        "i", "ts_ns", "pid", "ep", "dir", "crc"
    );
    for i in 0..r.len().min(12) {
        let f = r.frame_at(i)?;
        println!(
            "{:>6}  {:>12}  {:>6} {:>5} {:>4} {:>4}  {}",
            f.i,
            f.ts_ns,
            f.pid.unwrap_or("-"),
            f.ep,
            f.dir,
            match f.crc_ok {
                Some(true) => "ok",
                Some(false) => "BAD",
                None => "-",
            },
            f.hex
        );
    }

    // A wire capture's whole point is bus-level detail, so count what the host stack would
    // never have shown: retries, and any packet whose CRC failed.
    let (mut naks, mut bad_crc) = (0u64, 0u64);
    for i in 0..r.len() {
        if r.pid_at(i)? == Some(reveng_usbcap::wire::PID_NAK) {
            naks += 1;
        }
        if r.frame_at(i)?.crc_ok == Some(false) {
            bad_crc += 1;
        }
    }
    println!("{naks} NAK(s), {bad_crc} bad CRC(s)");
    Ok(())
}
