//! Capture from a Cynthion into a pcapng of raw USB 2.0 wire packets.
//!
//! Proves the whole path — transport, framing, timestamps, file format — with a file
//! Wireshark can open and dissect. No reassembly; the stored capture is what was on the bus.
//!
//! It writes through [`UsbWriter`], so a capture is a *session*: `usb.pcapng` plus the
//! `frames.idx` seek sidecar that every query command needs. Writing the pcapng alone would
//! produce a file Wireshark likes and `reveng-rec` cannot open.
//!
//! ```sh
//! cargo run -p reveng-cynthion --bin cynthion-capture -- --speed low --seconds 5 out.pcapng
//! ```
//!
//! Speed is explicit and defaults to nothing sensible on purpose: `Auto` misdetects, and
//! the failure looks exactly like a working capture of an idle bus.

use anyhow::{bail, Context, Result};
use reveng_core::clock::Clock;
use reveng_core::source::CaptureSource;
use reveng_cynthion::{CynthionSource, Speed};
use reveng_usbcap::UsbWriter;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value_of = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };

    let speed = match value_of("--speed").as_deref() {
        Some("low") => Speed::Low,
        Some("full") => Speed::Full,
        Some("high") => Speed::High,
        Some("auto") => Speed::Auto,
        Some(other) => bail!("unknown --speed {other}; expected low, full, high or auto"),
        None => bail!(
            "--speed is required (low|full|high|auto). Auto-detection misreports a \
             Low-speed device as Full, and the resulting capture contains bus events \
             and no packets while appearing to succeed."
        ),
    };
    let seconds: u64 = value_of("--seconds")
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let out = args
        .iter()
        .find(|a| !a.starts_with("--") && a.ends_with(".pcapng"))
        .cloned()
        .unwrap_or_else(|| "cynthion.pcapng".into());

    let clock = Clock::start();
    let mut source = CynthionSource::new(clock, speed);
    // Bus events sit beside the capture: they have no representation in a USB 2.0 pcapng,
    // and they are the only record of a reset, a speed change, or an analyzer overflow.
    let events_path = reveng_cynthion::events::sidecar_path(std::path::Path::new(&out));
    source
        .log_events_to(&events_path)
        .with_context(|| format!("creating {}", events_path.display()))?;
    source.start().context("starting the Cynthion capture")?;
    let stopper = source.stopper();

    // Stop from a timer; `next()` blocks, so the capture has to be ended from outside.
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(seconds));
        stopper.stop();
    });

    // The index sits beside the pcapng, exactly as a recorded session lays it out.
    let idx_path = std::path::Path::new(&out).with_extension("idx");
    let mut writer = UsbWriter::create_wire(&out, &idx_path, speed.link_type())
        .with_context(|| format!("creating {out}"))?;

    let mut packets = 0u64;
    let mut bytes = 0u64;
    while let Some(record) = source.next()? {
        writer.append_packet(record.ts_ns, &record.payload)?;
        packets += 1;
        bytes += record.payload.len() as u64;
    }
    writer.flush()?;
    source.stop().context("stopping the Cynthion capture")?;

    let events: u64 = source.event_counts.values().sum();
    println!(
        "wrote {out} + {}: {packets} packet(s), {bytes} byte(s); {events} bus event(s)",
        idx_path.display()
    );
    for (code, n) in &source.event_counts {
        println!("  event {code:>3}: {n}");
    }
    println!(
        "link type {} ({:?}), nanosecond timestamps",
        speed.link_type(),
        speed
    );

    if source.looks_like_speed_mismatch() {
        bail!(
            "captured {events} bus events and no packets — the analyzer saw signalling it \
             could not frame, which is what a wrong --speed looks like. Try another speed."
        );
    }
    Ok(())
}
