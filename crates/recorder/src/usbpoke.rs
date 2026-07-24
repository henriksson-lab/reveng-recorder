//! `usb-poke` — interactive/scripted control transfers + queued bulk reads against a **live** USB
//! device (via `nusb`, cross-platform). The "device oracle": issue arbitrary vendor requests,
//! probe determinism, replay a captured `ctrl --json` stream, and bring up streaming — without
//! writing a throwaway binary each time.
//!
//! Commands (one per line, from stdin REPL or `--script`; `#` comments allowed):
//! ```text
//!   out <bReq> <wVal> <wIdx> [hexdata]   vendor control OUT (host→device)
//!   in  <bReq> <wVal> <wIdx> <len>       vendor control IN  (device→host), prints hex
//!   stream <ep> [nframes] [framebytes]   queued bulk read (16 in flight); default 1 frame
//!   replay <file.jsonl>                  byte-exact replay of a `ctrl --json` capture
//!   reset                                USB device reset (Linux/macOS; no-op on Windows)
//!   probe                                descriptor/endpoint dump
//!   quit
//! ```
//! Numbers accept `0x..` or bare hex. Values are vendor/device requests (the camera-style default).

use anyhow::{bail, Context, Result};
use futures_lite::future::block_on;
use nusb::transfer::{ControlIn, ControlOut, ControlType, Recipient, RequestBuffer};
use nusb::{Device, Interface};
use std::io::BufRead;
use std::path::Path;

fn hx(s: &str) -> Result<u16> {
    u16::from_str_radix(s.trim_start_matches("0x"), 16).with_context(|| format!("bad hex: {s}"))
}
fn hx8(s: &str) -> Result<u8> {
    u8::from_str_radix(s.trim_start_matches("0x"), 16).with_context(|| format!("bad hex: {s}"))
}
fn hexbytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or(0)).collect()
}
fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Open `VID:PID`, claim interface 0. Shared by the REPL, `--check`, and `--doctor` flows.
fn open_device(vidpid: &str) -> Result<(Device, Interface)> {
    let (vid, pid) = vidpid
        .split_once(':')
        .context("--vidpid must be VID:PID, e.g. 1234:abcd")?;
    let (vid, pid) = (
        u16::from_str_radix(vid.trim_start_matches("0x"), 16)?,
        u16::from_str_radix(pid.trim_start_matches("0x"), 16)?,
    );
    let di = nusb::list_devices()?
        .find(|d| d.vendor_id() == vid && d.product_id() == pid)
        .with_context(|| format!("device {vid:04x}:{pid:04x} not found"))?;
    let dev = di.open().context("open failed (in use? permissions?)")?;
    let iface = dev
        .detach_and_claim_interface(0)
        .context("claim interface 0 failed")?;
    let _ = iface.set_alt_setting(0);
    Ok((dev, iface))
}

pub fn run(vidpid: &str, script: Option<&Path>) -> Result<()> {
    let (dev, iface) = open_device(vidpid)?;
    eprintln!("opened {vidpid}, interface 0 claimed. Type commands ('quit' to exit).");

    match script {
        Some(f) => {
            let text = std::fs::read_to_string(f)?;
            for line in text.lines() {
                if !exec(&dev, &iface, line)? {
                    break;
                }
            }
        }
        None => {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let line = line?;
                if !exec(&dev, &iface, &line)? {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Execute one command line. Returns `Ok(false)` to stop (quit).
fn exec(dev: &Device, iface: &Interface, line: &str) -> Result<bool> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(true);
    }
    let t: Vec<&str> = line.split_whitespace().collect();
    let r = (|| -> Result<()> {
        match t[0] {
            "quit" | "exit" | "q" => return Ok(()),
            "out" => {
                let (req, v, i) = (hx8(t[1])?, hx(t[2])?, hx(t[3])?);
                let data = t.get(4).map(|s| hexbytes(s)).unwrap_or_default();
                block_on(iface.control_out(ControlOut {
                    control_type: ControlType::Vendor,
                    recipient: Recipient::Device,
                    request: req,
                    value: v,
                    index: i,
                    data: &data,
                }))
                .into_result()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("out ok");
            }
            "in" => {
                let (req, v, i, len) = (hx8(t[1])?, hx(t[2])?, hx(t[3])?, t[4].parse::<u16>()?);
                let d = block_on(iface.control_in(ControlIn {
                    control_type: ControlType::Vendor,
                    recipient: Recipient::Device,
                    request: req,
                    value: v,
                    index: i,
                    length: len,
                }))
                .into_result()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("in -> {}", hexs(&d));
            }
            "stream" => {
                let ep = hx8(t[1])?;
                let nframes: usize = t.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
                let framebytes: usize =
                    t.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
                stream(iface, ep, nframes, framebytes)?;
            }
            "replay" => {
                let path = t.get(1).context("replay needs a file")?;
                replay(iface, path)?;
            }
            "reset" => {
                dev.reset().map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("reset ok");
            }
            "probe" => {
                for c in dev.configurations() {
                    for intf in c.interfaces() {
                        for alt in intf.alt_settings() {
                            for e in alt.endpoints() {
                                println!(
                                    "  cfg{} if{} alt{} ep0x{:02x} {:?} mps={}",
                                    c.configuration_value(),
                                    intf.interface_number(),
                                    alt.alternate_setting(),
                                    e.address(),
                                    e.transfer_type(),
                                    e.max_packet_size()
                                );
                            }
                        }
                    }
                }
            }
            other => bail!("unknown command '{other}' (out|in|stream|replay|reset|probe|quit)"),
        }
        Ok(())
    })();
    if let Err(e) = r {
        println!("error: {e}");
    }
    Ok(!matches!(t[0], "quit" | "exit" | "q"))
}

/// Queued bulk read (16 requests outstanding — FX3-style DMA needs sustained IN tokens),
/// accumulating `nframes` frames of `framebytes` each (0 = report raw completions).
fn stream(iface: &Interface, ep: u8, nframes: usize, framebytes: usize) -> Result<()> {
    use std::sync::mpsc::{channel, RecvTimeoutError};
    use std::time::{Duration, Instant};
    let ifc = iface.clone();
    let (tx, rx) = channel::<std::result::Result<Vec<u8>, String>>();
    std::thread::spawn(move || {
        let mut q = ifc.bulk_in_queue(ep);
        for _ in 0..16 {
            q.submit(RequestBuffer::new(512 * 1024));
        }
        loop {
            let c = block_on(q.next_complete());
            let msg = c.status.map(|_| c.data.clone()).map_err(|e| e.to_string());
            let stop = msg.is_err();
            if tx.send(msg).is_err() || stop {
                return;
            }
            q.submit(RequestBuffer::new(512 * 1024));
        }
    });
    let mut frame = Vec::new();
    let mut got_frames = 0usize;
    let mut total = 0u64;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline && got_frames < nframes {
        match rx.recv_timeout(Duration::from_millis(1000)) {
            Ok(Ok(d)) => {
                total += d.len() as u64;
                if framebytes == 0 {
                    println!("  completion: {} bytes", d.len());
                    got_frames += 1;
                } else {
                    frame.extend_from_slice(&d);
                    if frame.len() >= framebytes {
                        let (mn, mx) = (*frame[..framebytes].iter().min().unwrap(), *frame[..framebytes].iter().max().unwrap());
                        println!("  frame {got_frames}: {framebytes} bytes (min={mn} max={mx})");
                        frame.drain(..framebytes);
                        got_frames += 1;
                    }
                }
            }
            Ok(Err(e)) => {
                println!("  stream error: {e}");
                break;
            }
            Err(RecvTimeoutError::Timeout) => println!("  …silent ({total} B so far)"),
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    println!("stream: {got_frames} frame(s), {total} bytes total");
    Ok(())
}

/// Byte-exact replay of a `ctrl --json` capture (issues each control transfer verbatim).
fn replay(iface: &Interface, path: &str) -> Result<()> {
    let text = std::fs::read_to_string(path)?;
    let (mut ok, mut err) = (0u32, 0u32);
    for line in text.lines() {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let get = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("");
        let req = hx8(get("bRequest")).unwrap_or(0);
        let val = hx(get("wValue")).unwrap_or(0);
        let idx = hx(get("wIndex")).unwrap_or(0);
        let dir = get("dir");
        let data = hexbytes(get("data"));
        let wlen = v.get("wLength").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
        let r = if dir == "out" {
            block_on(iface.control_out(ControlOut {
                control_type: ControlType::Vendor,
                recipient: Recipient::Device,
                request: req,
                value: val,
                index: idx,
                data: &data,
            }))
            .into_result()
            .map(|_| ())
        } else {
            block_on(iface.control_in(ControlIn {
                control_type: ControlType::Vendor,
                recipient: Recipient::Device,
                request: req,
                value: val,
                index: idx,
                length: wlen,
            }))
            .into_result()
            .map(|_| ())
        };
        if r.is_ok() {
            ok += 1;
        } else {
            err += 1;
        }
    }
    println!("replay: {ok} ok, {err} errors");
    Ok(())
}

/// How a live IN response compares to the captured bytes.
#[derive(Debug, PartialEq, Eq)]
enum InCmp {
    Match,
    LenDiff { cap: usize, live: usize },
    ByteDiff { positions: Vec<usize> },
}

/// Compare a captured IN response to the live one (pure — the heart of the determinism check).
fn compare_in(cap: &[u8], live: &[u8]) -> InCmp {
    if cap.len() != live.len() {
        return InCmp::LenDiff { cap: cap.len(), live: live.len() };
    }
    let positions: Vec<usize> = cap
        .iter()
        .zip(live)
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(i, _)| i)
        .collect();
    if positions.is_empty() {
        InCmp::Match
    } else {
        InCmp::ByteDiff { positions }
    }
}

/// `--check` — replay a `ctrl --json` capture against the live device and flag every IN response
/// that differs from the captured bytes. Automates "is this field deterministic? does auth
/// reproduce?": all-match ⇒ deterministic protocol; divergences pinpoint nonces/challenge bytes.
pub fn check(vidpid: &str, path: &Path) -> Result<()> {
    let (_dev, iface) = open_device(vidpid)?;
    let text = std::fs::read_to_string(path)?;
    let (mut ins, mut matched, mut diverged, mut errors) = (0u32, 0u32, 0u32, 0u32);
    for line in text.lines() {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let get = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("");
        let (req, val, idx) = (
            hx8(get("bRequest")).unwrap_or(0),
            hx(get("wValue")).unwrap_or(0),
            hx(get("wIndex")).unwrap_or(0),
        );
        let data = hexbytes(get("data"));
        if get("dir") == "out" {
            let r = block_on(iface.control_out(ControlOut {
                control_type: ControlType::Vendor,
                recipient: Recipient::Device,
                request: req,
                value: val,
                index: idx,
                data: &data,
            }))
            .into_result();
            if r.is_err() {
                errors += 1;
            }
            continue;
        }
        // IN — reissue and compare to the captured response.
        ins += 1;
        let wlen = v.get("wLength").and_then(|x| x.as_u64()).unwrap_or(data.len() as u64) as u16;
        let live = match block_on(iface.control_in(ControlIn {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: req,
            value: val,
            index: idx,
            length: wlen,
        }))
        .into_result()
        {
            Ok(d) => d,
            Err(e) => {
                println!("  IN req0x{req:02x} val0x{val:04x} idx0x{idx:04x}: transfer error: {e}");
                errors += 1;
                continue;
            }
        };
        match compare_in(&data, &live) {
            InCmp::Match => matched += 1,
            InCmp::LenDiff { cap, live } => {
                diverged += 1;
                println!("  IN req0x{req:02x} idx0x{idx:04x}: LENGTH {cap} → {live}");
            }
            InCmp::ByteDiff { positions } => {
                diverged += 1;
                println!(
                    "  IN req0x{req:02x} idx0x{idx:04x}: {} byte(s) differ at {:?}",
                    positions.len(),
                    &positions[..positions.len().min(8)]
                );
                println!("    captured: {}", hexs(&data));
                println!("    live:     {}", hexs(&live));
            }
        }
    }
    println!(
        "\ncheck: {ins} IN transfer(s) — {matched} deterministic (byte-identical), {diverged} diverged, {errors} error(s)"
    );
    if diverged == 0 && ins > 0 {
        println!("→ protocol is DETERMINISTIC across these transfers (any auth/nonce reproduces byte-for-byte).");
    } else if diverged > 0 {
        println!("→ diverging transfers carry live state (nonce/challenge/sensor readout) — not fixed bytes.");
    }
    Ok(())
}

/// `--doctor` — automated streaming bring-up diagnosis. Encodes the wedged-device/queued-reads
/// decision tree: open (± reset) → one bulk read (classify NAK-timeout vs STALL vs data) → a queued
/// read (16 in flight) → print the diagnosis and the fix.
pub fn doctor(vidpid: &str, ep: u8, do_reset: bool) -> Result<()> {
    use std::sync::mpsc::channel;
    use std::time::{Duration, Instant};

    let (dev, iface) = open_device(vidpid)?;
    println!("doctor: opened {vidpid}, ep 0x{ep:02x}");
    if do_reset {
        match dev.reset() {
            Ok(_) => println!("  reset: ok (clean device state)"),
            Err(e) => println!("  reset: failed ({e}) — continuing"),
        }
    }

    // Step 1 — a single bulk read with a short deadline. Classify the outcome.
    println!("step 1: single bulk read (3s)…");
    let single = {
        let ifc = iface.clone();
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let mut q = ifc.bulk_in_queue(ep);
            q.submit(RequestBuffer::new(512 * 1024));
            let c = block_on(q.next_complete());
            let _ = tx.send(c.status.map(|_| c.data.len()).map_err(|e| e.to_string()));
        });
        rx.recv_timeout(Duration::from_secs(3))
    };
    let single_diag = match &single {
        Ok(Ok(n)) => Diag::Data(*n),
        Ok(Err(e)) if e.to_lowercase().contains("stall") => Diag::Stall,
        Ok(Err(e)) => Diag::Error(e.clone()),
        Err(_) => Diag::NakTimeout,
    };
    println!("  → {}", single_diag.describe());

    // Step 2 — a queued read (16 in flight) for 5s: does sustained IN pressure unblock it?
    println!("step 2: queued read, 16 in flight (5s)…");
    let ifc = iface.clone();
    let (tx, rx) = channel::<std::result::Result<usize, String>>();
    std::thread::spawn(move || {
        let mut q = ifc.bulk_in_queue(ep);
        for _ in 0..16 {
            q.submit(RequestBuffer::new(512 * 1024));
        }
        loop {
            let c = block_on(q.next_complete());
            let msg = c.status.map(|_| c.data.len()).map_err(|e| e.to_string());
            let stop = msg.is_err();
            if tx.send(msg).is_err() || stop {
                return;
            }
            q.submit(RequestBuffer::new(512 * 1024));
        }
    });
    let (mut total, mut completions) = (0u64, 0u32);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Ok(n)) => {
                total += n as u64;
                completions += 1;
            }
            Ok(Err(e)) => {
                println!("  queued read error: {e}");
                break;
            }
            Err(_) => {}
        }
    }
    println!("  → {completions} completion(s), {total} bytes in 5s");

    println!("\ndiagnosis:");
    match (&single_diag, completions > 0) {
        (Diag::Data(_), _) | (_, true) => {
            println!("  ✓ endpoint PRODUCES data. If a single read stalled but the queue flowed,");
            println!("    the device needs sustained IN tokens — use a 16-deep bulk_in_queue in the driver.");
        }
        (Diag::Stall, false) => {
            println!("  ✗ endpoint STALLs and the queue is dry — send the stream-start control write");
            println!("    first (e.g. the 0x0003 start), or clear_halt, then retry.");
        }
        (Diag::NakTimeout, false) => {
            println!("  ✗ endpoint NAKs/idles and the queue stays dry — device isn't producing.");
            println!("    It likely needs its init sequence (try --init / replay a capture) or a replug;");
            println!("    an aborted prior attempt can wedge FX3 until reset/replug.");
        }
        (Diag::Error(e), false) => println!("  ✗ transfer error: {e} (permissions? wrong endpoint?)"),
    }
    Ok(())
}

enum Diag {
    Data(usize),
    Stall,
    NakTimeout,
    Error(String),
}
impl Diag {
    fn describe(&self) -> String {
        match self {
            Diag::Data(n) => format!("DATA: {n} bytes (endpoint is streaming)"),
            Diag::Stall => "STALL: endpoint halted (needs start command / clear_halt)".into(),
            Diag::NakTimeout => "NAK/timeout: no data within deadline (device not producing)".into(),
            Diag::Error(e) => format!("error: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_responses_match() {
        assert_eq!(compare_in(&[1, 2, 3], &[1, 2, 3]), InCmp::Match);
    }

    #[test]
    fn length_divergence_flagged() {
        assert_eq!(compare_in(&[1, 2], &[1, 2, 3]), InCmp::LenDiff { cap: 2, live: 3 });
    }

    #[test]
    fn byte_divergence_positions() {
        // A nonce/challenge changes some bytes but not length — the auth-red-herring signature.
        assert_eq!(
            compare_in(&[0xaa, 0xbb, 0xcc, 0xdd], &[0xaa, 0x00, 0xcc, 0x11]),
            InCmp::ByteDiff { positions: vec![1, 3] }
        );
    }
}
