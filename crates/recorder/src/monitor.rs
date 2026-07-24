//! `monitor` — a live per-endpoint traffic dashboard with **no session written**. Attaches USBPcap
//! (like `record`) and prints a frames/s + bytes/s rate table each second with an `IDLE` flag, so
//! you can confirm the device is actually streaming *before* committing a real capture. This is the
//! fix for the #1 repeated waste: launching a capture that got 0 frames because nothing was flowing.

use anyhow::{Context, Result};
use reveng_core::clock::Clock;
use reveng_core::event::TrafficKind;
use reveng_core::source::CaptureSource;
use reveng_usbcap::{UsbCaptureSource, UsbSelection};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A point-in-time capture tally. `by_ep: ep -> (frames, bytes, transfer-type-code)`.
#[derive(Clone, Default)]
pub struct Snapshot {
    pub total_frames: u64,
    pub total_bytes: u64,
    pub by_ep: BTreeMap<u8, (u64, u64, u8)>,
}

fn xfer_name(code: u8) -> &'static str {
    match code {
        0 => "iso",
        1 => "intr",
        2 => "ctrl",
        3 => "bulk",
        _ => "?",
    }
}

/// Render the per-endpoint rate table from two snapshots `dt` seconds apart. Pure — unit-tested.
/// Flags `IDLE` when no new frames arrived in the interval (the "device isn't streaming" signal).
pub fn render_rates(prev: &Snapshot, now: &Snapshot, dt: f64) -> String {
    let dt = dt.max(1e-3);
    let mut out = String::new();
    let dframes = now.total_frames.saturating_sub(prev.total_frames);
    let dbytes = now.total_bytes.saturating_sub(prev.total_bytes);
    if dframes == 0 {
        out.push_str("IDLE — no traffic this interval\n");
    }
    out.push_str(&format!(
        "total: {:>8.0} frames/s  {:>10}/s   ({} frames, {} bytes cumulative)\n",
        dframes as f64 / dt,
        human(dbytes as f64 / dt),
        now.total_frames,
        now.total_bytes,
    ));
    for (ep, (f, b, xfer)) in &now.by_ep {
        let (pf, pb) = prev.by_ep.get(ep).map(|(f, b, _)| (*f, *b)).unwrap_or((0, 0));
        let (df, db) = (f.saturating_sub(pf), b.saturating_sub(pb));
        if df == 0 && db == 0 {
            continue; // skip endpoints with no activity this interval
        }
        out.push_str(&format!(
            "  ep 0x{ep:02x} {:<4} {:>8.0} frames/s  {:>10}/s\n",
            xfer_name(*xfer),
            df as f64 / dt,
            human(db as f64 / dt),
        ));
    }
    out
}

fn human(bytes_per_s: f64) -> String {
    const U: [&str; 4] = ["B", "KB", "MB", "GB"];
    let (mut v, mut i) = (bytes_per_s, 0);
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1}{}", U[i])
}

/// Resolve `--device-vidpid` (or all hubs) to USBPcap selections, without the full `record` arg set.
fn selections(vidpid: Option<&str>) -> Result<Vec<UsbSelection>> {
    let devs = reveng_usbcap::list_devices().context("enumerating USB devices (USBPcap installed?)")?;
    let mut hubs: BTreeMap<String, Vec<u16>> = BTreeMap::new();
    match vidpid {
        Some(want) => {
            let (wv, wp) = want.split_once(':').unwrap_or((want, ""));
            for d in &devs {
                if d.vid.eq_ignore_ascii_case(wv) && d.pid.eq_ignore_ascii_case(wp) && !d.usbpcap.is_empty() {
                    hubs.entry(d.usbpcap.clone()).or_default().push(d.address);
                }
            }
            if hubs.is_empty() {
                anyhow::bail!("device {want} not found on any USBPcap hub (plugged in? USBPcap attached this boot?)");
            }
        }
        None => {
            for d in &devs {
                if !d.usbpcap.is_empty() {
                    hubs.entry(d.usbpcap.clone()).or_default();
                }
            }
            if hubs.is_empty() {
                anyhow::bail!("no USBPcap control devices found (install USBPcap + reboot; run as admin)");
            }
        }
    }
    Ok(hubs
        .into_iter()
        .map(|(dev, addrs)| UsbSelection {
            usbpcap_device: Some(dev),
            vidpid: vidpid.map(|s| vec![s.to_string()]).unwrap_or_default(),
            serial: None,
            address: addrs,
            all_devices: vidpid.is_none(),
        })
        .collect())
}

pub fn run(vidpid: Option<&str>, max_seconds: Option<u64>) -> Result<()> {
    let clock = Clock::start();
    let sels = selections(vidpid)?;
    eprintln!(
        "monitoring {} hub(s){} — Ctrl+C to stop. NO session is written.",
        sels.len(),
        vidpid.map(|v| format!(" for {v}")).unwrap_or_default()
    );

    let tally = Arc::new(Mutex::new(Snapshot::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut killers = Vec::new();
    let mut threads = Vec::new();

    for sel in sels {
        let mut source = UsbCaptureSource::new(sel, clock.clone());
        source.start().context("USBPcap start failed (admin? driver attached this boot?)")?;
        killers.push(source.killer());
        let tally = tally.clone();
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match source.next() {
                    Ok(Some(rec)) => {
                        let ep = match &rec.kind {
                            TrafficKind::Usb(h) => h.endpoint,
                            _ => 0,
                        };
                        let xfer = match &rec.kind {
                            TrafficKind::Usb(h) => h.transfer,
                            _ => 0xff,
                        };
                        let n = rec.payload.len() as u64;
                        let mut t = tally.lock().unwrap();
                        t.total_frames += 1;
                        t.total_bytes += n;
                        let e = t.by_ep.entry(ep).or_insert((0, 0, xfer));
                        e.0 += 1;
                        e.1 += n;
                        e.2 = xfer;
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
            let _ = source.stop();
        }));
    }

    let start = Instant::now();
    let mut prev = tally.lock().unwrap().clone();
    let mut last = Instant::now();
    let result = (|| -> Result<()> {
        loop {
            std::thread::sleep(Duration::from_millis(1000));
            let now = tally.lock().unwrap().clone();
            let dt = last.elapsed().as_secs_f64();
            last = Instant::now();
            print!("\n{}", render_rates(&prev, &now, dt));
            prev = now;
            if max_seconds.is_some_and(|s| start.elapsed() >= Duration::from_secs(s)) {
                break;
            }
        }
        Ok(())
    })();

    stop.store(true, Ordering::Relaxed);
    for k in &killers {
        k.kill();
    }
    for t in threads {
        let _ = t.join();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(frames: u64, bytes: u64, eps: &[(u8, u64, u64, u8)]) -> Snapshot {
        Snapshot {
            total_frames: frames,
            total_bytes: bytes,
            by_ep: eps.iter().map(|(e, f, b, x)| (*e, (*f, *b, *x))).collect(),
        }
    }

    #[test]
    fn idle_flagged_when_no_new_frames() {
        let a = snap(10, 1000, &[(0x81, 10, 1000, 3)]);
        let out = render_rates(&a, &a, 1.0);
        assert!(out.contains("IDLE"), "no new frames must flag IDLE: {out}");
    }

    #[test]
    fn per_endpoint_rates_computed() {
        let a = snap(0, 0, &[]);
        let b = snap(100, 1_048_576, &[(0x81, 100, 1_048_576, 3)]); // 1 MiB in 1s on bulk ep
        let out = render_rates(&a, &b, 1.0);
        assert!(!out.contains("IDLE"));
        assert!(out.contains("ep 0x81 bulk"), "endpoint line: {out}");
        assert!(out.contains("1.0MB/s"), "byte rate: {out}");
        assert!(out.contains("100 frames/s"), "frame rate: {out}");
    }

    #[test]
    fn quiet_endpoints_omitted() {
        let a = snap(50, 500, &[(0x81, 50, 500, 3), (0x02, 0, 0, 3)]);
        let b = snap(60, 600, &[(0x81, 60, 600, 3), (0x02, 0, 0, 3)]);
        let out = render_rates(&a, &b, 1.0);
        assert!(out.contains("ep 0x81"));
        assert!(!out.contains("ep 0x02"), "an endpoint with no activity is omitted: {out}");
    }
}
