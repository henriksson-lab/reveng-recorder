//! Query commands — the LLM-facing surface over a recorded session (DESIGN.md §8a.1).
//!
//! Works over both traffic backends behind one seam:
//! - **USB**: decoded frames from `usb.pcapng` + `frames.idx` (via `UsbReader`).
//! - **PCIe**: decoded events from `pcie.bin` + `pcie.idx` (via `PcieLog`).
//!
//! The session is classified by which raw log it holds, so every command below is
//! source-agnostic — exactly the property DESIGN.md §7/§8 calls for.

use anyhow::{Context, Result};
use reveng_core::event::PcieEvent;
use reveng_core::session::SessionReader;
use reveng_pcicap::PcieLog;
use reveng_usbcap::UsbReader;
use std::io::Write;
use std::path::Path;

/// How to render raw payload bytes for `payload`.
#[derive(Copy, Clone)]
pub enum PayloadFmt {
    Hex,
    Bin,
    Base64,
    Json,
}

/// A session's traffic log, of whichever source produced it.
enum Log {
    Usb(UsbReader),
    Pcie(PcieLog),
}

impl Log {
    fn open(s: &SessionReader) -> Result<Log> {
        if s.usb_pcapng().exists() {
            Ok(Log::Usb(UsbReader::open(s.usb_pcapng(), s.frames_idx())?))
        } else if s.pcie_bin().exists() {
            Ok(Log::Pcie(
                PcieLog::open(s.pcie_bin(), s.pcie_idx())
                    .context("opening pcie.bin/pcie.idx")?,
            ))
        } else {
            anyhow::bail!("session has no traffic log (usb.pcapng or pcie.bin)")
        }
    }

    fn len(&self) -> u64 {
        match self {
            Log::Usb(r) => r.len(),
            Log::Pcie(l) => l.len(),
        }
    }

    /// One event/frame as a JSON value carrying its stable index `i`.
    fn event_json(&mut self, i: u64) -> Result<serde_json::Value> {
        match self {
            Log::Usb(r) => Ok(serde_json::to_value(r.frame_at(i)?)?),
            Log::Pcie(l) => Ok(serde_json::json!({"i": i, "event": l.event_at(i)?})),
        }
    }

    /// Endpoint (USB) or BAR (PCIe/Mmio) filter match. For USB this reads only the index
    /// record, avoiding a full frame decode per candidate.
    fn matches_filter(&mut self, i: u64, filter: u8) -> Result<bool> {
        Ok(match self {
            Log::Usb(r) => r.endpoint_at(i)? == filter,
            Log::Pcie(l) => matches!(l.event_at(i)?, PcieEvent::Mmio { bar, .. } if bar == filter),
        })
    }

    /// Raw payload bytes for one index (USB payload; PCIe has none — empty).
    fn payload_bytes(&mut self, i: u64) -> Result<Vec<u8>> {
        match self {
            Log::Usb(r) => r.payload_at(i),
            Log::Pcie(_) => Ok(Vec::new()),
        }
    }
}

fn open_log(session: &SessionReader) -> Result<Log> {
    Log::open(session)
}

/// `ls` — the manifest: one line per checkpoint.
pub fn ls(session_dir: &Path, json: bool) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let out = std::io::stdout();
    let mut w = out.lock();
    for c in s.checkpoints()? {
        let anchor_idx = c.anchor.map(|a| a.event_index);
        if json {
            let line = serde_json::json!({
                "checkpoint": c.id,
                "ts_ns": c.ts_ns,
                "type": c.kind,
                "cause": c.cause,
                "anchor_index": anchor_idx,
                "screenshot": c.screenshot_id,
            });
            writeln!(w, "{line}")?;
        } else {
            writeln!(
                w,
                "#{:<4} t={:>12}ns  {:<14} {:<16} anchor={}",
                c.id,
                c.ts_ns,
                format!("{:?}", c.kind),
                c.cause,
                anchor_idx.map(|i| i.to_string()).unwrap_or_else(|| "-".into()),
            )?;
        }
    }
    Ok(())
}

/// `show` — a checkpoint card, including the anchored traffic event.
pub fn show(session_dir: &Path, id: u64) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let c = s.checkpoint(id)?;
    let anchored = match c.anchor {
        Some(a) => {
            let mut log = open_log(&s)?;
            Some(log.event_json(a.event_index)?)
        }
        None => None,
    };
    let card = serde_json::json!({
        "checkpoint": c.id,
        "ts_ns": c.ts_ns,
        "type": c.kind,
        "cause": c.cause,
        "cursor": c.cursor,
        "fg_process": c.fg_process,
        "fg_window": c.fg_window,
        "screenshot_id": c.screenshot_id,
        "anchor": c.anchor,
        "anchor_event": anchored,
        "note": c.note,
    });
    println!("{}", serde_json::to_string_pretty(&card)?);
    Ok(())
}

/// `frames` — events near a checkpoint (`--around`) or by `--range a:b`.
pub fn frames(
    session_dir: &Path,
    around: Option<u64>,
    window: u64,
    range: Option<&str>,
    filter: Option<u8>,
) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let mut log = open_log(&s)?;
    let total = log.len();
    if total == 0 {
        return Ok(());
    }

    let (start, end) = if let Some(r) = range {
        parse_range(r)?
    } else if let Some(ckpt) = around {
        let c = s.checkpoint(ckpt)?;
        let center = c
            .anchor
            .map(|a| a.event_index)
            .context("checkpoint has no traffic anchor")?;
        (center.saturating_sub(window), center + window)
    } else {
        (0, total - 1)
    };
    let end = end.min(total - 1);

    let out = std::io::stdout();
    let mut w = out.lock();
    for i in start..=end {
        if let Some(f) = filter {
            if !log.matches_filter(i, f)? {
                continue;
            }
        }
        writeln!(w, "{}", log.event_json(i)?)?;
    }
    Ok(())
}

/// `stream` — reassembled logical messages on an endpoint (USB, DESIGN.md §8b). Without
/// `--logical` it is the raw per-endpoint frame view. PCIe falls back to filtered events.
pub fn stream(session_dir: &Path, ep: Option<u8>, logical: bool) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let mut log = open_log(&s)?;
    let total = log.len();
    if total == 0 {
        return Ok(());
    }
    // Non-logical, or non-USB: just the filtered frames.
    if !logical || matches!(log, Log::Pcie(_)) {
        return frames(session_dir, None, 0, Some(&format!("0:{}", total - 1)), ep);
    }

    // Logical reassembly (USB): concatenate consecutive frames sharing (endpoint, dir)
    // into one message. Raw frames stay available; this is a view, never a mutation (§8b).
    // Note: a message accumulates until the endpoint changes, so a very long single-endpoint
    // stream yields one large in-memory message — use `--range` to bound huge captures.
    let Log::Usb(reader) = &mut log else { unreachable!() };
    let out = std::io::stdout();
    let mut w = out.lock();

    let mut cur: Option<(u8, i64, u64, Vec<u8>)> = None; // (endpoint, first_ts, first_i, payload)
    let flush = |m: &(u8, i64, u64, Vec<u8>), w: &mut dyn Write| -> Result<()> {
        use base64::Engine;
        let (endpoint, ts, first_i, payload) = m;
        let dir = if endpoint & 0x80 != 0 { "in" } else { "out" };
        let line = serde_json::json!({
            "first_i": first_i,
            "ts_ns": ts,
            "ep": format!("0x{:02x}", endpoint),
            "dir": dir,
            "len": payload.len(),
            "b64": base64::engine::general_purpose::STANDARD.encode(payload),
        });
        writeln!(w, "{line}")?;
        Ok(())
    };

    for i in 0..total {
        let f = reader.frame_at(i)?;
        if let Some(sel) = ep {
            if f.endpoint != sel {
                continue;
            }
        }
        match &mut cur {
            Some((endpoint, _, _, payload)) if *endpoint == f.endpoint => {
                payload.extend_from_slice(&f.payload);
            }
            _ => {
                if let Some(prev) = cur.take() {
                    flush(&prev, &mut w)?;
                }
                cur = Some((f.endpoint, f.ts_ns, f.i, f.payload));
            }
        }
    }
    if let Some(prev) = cur {
        flush(&prev, &mut w)?;
    }
    Ok(())
}

/// `payload` — raw bytes of one frame, rendered per `fmt`.
pub fn payload(session_dir: &Path, frame: u64, fmt: PayloadFmt) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let mut log = open_log(&s)?;
    match (&mut log, fmt) {
        // PCIe has no raw payload; show the decoded event.
        (Log::Pcie(l), _) => {
            println!("{}", serde_json::to_string_pretty(&l.event_at(frame)?)?);
            Ok(())
        }
        (_, PayloadFmt::Json) => {
            println!("{}", serde_json::to_string_pretty(&log.event_json(frame)?)?);
            Ok(())
        }
        (_, PayloadFmt::Bin) => {
            let bytes = log.payload_bytes(frame)?;
            std::io::stdout().write_all(&bytes)?;
            Ok(())
        }
        (_, PayloadFmt::Hex) => {
            let bytes = log.payload_bytes(frame)?;
            let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
            println!("{}", hex.join(" "));
            Ok(())
        }
        (_, PayloadFmt::Base64) => {
            use base64::Engine;
            let bytes = log.payload_bytes(frame)?;
            println!("{}", base64::engine::general_purpose::STANDARD.encode(&bytes));
            Ok(())
        }
    }
}

/// `diff` — events between two checkpoints' anchors.
pub fn diff(session_dir: &Path, a: u64, b: u64) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let ca = s.checkpoint(a)?;
    let cb = s.checkpoint(b)?;
    let ia = ca.anchor.map(|x| x.event_index).context("checkpoint a has no anchor")?;
    let ib = cb.anchor.map(|x| x.event_index).context("checkpoint b has no anchor")?;
    let (lo, hi) = if ia <= ib { (ia, ib) } else { (ib, ia) };
    frames(session_dir, None, 0, Some(&format!("{lo}:{hi}")), None)
}

/// `grep` — USB: frames whose payload contains a hex byte pattern; PCIe: events whose
/// JSON line contains a substring.
pub fn grep(session_dir: &Path, pattern: &str) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let mut log = open_log(&s)?;
    let out = std::io::stdout();
    let mut w = out.lock();

    match &mut log {
        Log::Usb(reader) => {
            let needle = parse_hex_pattern(pattern)
                .context("USB grep pattern must be hex bytes, e.g. `12 01` or `1201`")?;
            let total = reader.len();
            for i in 0..total {
                // Scan raw payload cheaply; only fully decode the frames that match.
                if contains_subslice(&reader.payload_at(i)?, &needle) {
                    writeln!(w, "{}", serde_json::to_value(reader.frame_at(i)?)?)?;
                }
            }
        }
        Log::Pcie(_) => {
            use std::io::BufRead;
            let file = std::fs::File::open(s.pcie_bin())?;
            let needle = pattern.to_ascii_lowercase();
            for (i, line) in std::io::BufReader::new(file).lines().enumerate() {
                let line = line?;
                if line.to_ascii_lowercase().contains(&needle) {
                    writeln!(
                        w,
                        "{}",
                        serde_json::json!({"i": i, "event": serde_json::from_str::<PcieEvent>(&line)?})
                    )?;
                }
            }
        }
    }
    Ok(())
}

/// `reindex` — rebuild the fixed-width seek index from the raw truth (DESIGN.md §8).
pub fn reindex(session_dir: &Path) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    if s.usb_pcapng().exists() {
        reindex_usb(&s)
    } else if s.pcie_bin().exists() {
        reindex_pcie(&s)
    } else {
        anyhow::bail!("session has no traffic log to reindex")
    }
}

fn reindex_usb(s: &SessionReader) -> Result<()> {
    use reveng_core::index::IndexFile;
    use reveng_usbcap::parse::parse_packet_header;
    use reveng_usbcap::pcapng;
    use reveng_usbcap::UsbIdxRecord;

    let data = std::fs::read(s.usb_pcapng())?;
    let mut idx = IndexFile::<UsbIdxRecord>::create(s.frames_idx())?;
    let mut n = 0u64;
    for p in pcapng::packets(&data)? {
        let h = parse_packet_header(p.data);
        let (endpoint, xfer, status, data_length) = h
            .map(|h| (h.endpoint, h.transfer, h.status, h.data_length))
            .unwrap_or((0, 0xff, 0, 0));
        let dir = if endpoint & 0x80 != 0 { 1 } else { 0 };
        idx.append(&UsbIdxRecord {
            ts_ns: p.ts_ns,
            byte_offset: p.offset as u64,
            endpoint,
            dir,
            xfer,
            status: (status & 0xff) as u8,
            data_length,
        })?;
        n += 1;
    }
    println!("reindexed {n} USB frames -> {}", s.frames_idx().display());
    Ok(())
}

fn reindex_pcie(s: &SessionReader) -> Result<()> {
    use reveng_core::index::IndexFile;
    use reveng_pcicap::PcieIdxRecord;
    use std::io::BufRead;

    let bin = std::fs::File::open(s.pcie_bin())?;
    let mut idx = IndexFile::<PcieIdxRecord>::create(s.pcie_idx())?;
    let mut offset = 0u64;
    let mut n = 0u64;
    for line in std::io::BufReader::new(bin).lines() {
        let line = line?;
        let ev: PcieEvent = serde_json::from_str(&line)?;
        idx.append(&PcieIdxRecord {
            ts_ns: ev.ts_ns(),
            byte_offset: offset,
        })?;
        offset += line.len() as u64 + 1; // + '\n'
        n += 1;
    }
    println!("reindexed {n} PCIe events -> {}", s.pcie_idx().display());
    Ok(())
}

/// `decode` — run a candidate decoder over the frames and stream its output.
///
/// Contract (DESIGN.md §8b): the decoder reads frames as JSONL on stdin (one object per
/// line, with a stable `i`/`first_i` and a base64 payload for USB) and emits annotated
/// JSONL on stdout. This is the imperative path; `--ksy` (Kaitai) is not yet wired.
pub fn decode(
    session_dir: &Path,
    with: Option<&str>,
    ksy: Option<&Path>,
    filter: Option<u8>,
) -> Result<()> {
    use std::process::{Command, Stdio};

    if ksy.is_some() {
        anyhow::bail!("--ksy (Kaitai Struct) decoding not yet implemented; use --with <command>");
    }
    let cmd = with.context("decode needs --with <command> (or --ksy <file>)")?;
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let (prog, prog_args) = parts.split_first().context("--with is empty")?;

    let s = SessionReader::open(session_dir)?;
    let mut log = open_log(&s)?;
    let total = log.len();

    let mut frames = Vec::with_capacity(total as usize);
    for i in 0..total {
        if let Some(f) = filter {
            if !log.matches_filter(i, f)? {
                continue;
            }
        }
        frames.push(log.event_json(i)?.to_string());
    }

    let mut child = Command::new(prog)
        .args(prog_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to launch decoder `{cmd}`"))?;

    let mut stdin = child.stdin.take().context("decoder stdin unavailable")?;
    let writer = std::thread::spawn(move || {
        for line in &frames {
            if writeln!(stdin, "{line}").is_err() {
                break;
            }
        }
    });

    let stdout = child.stdout.take().context("decoder stdout unavailable")?;
    let out = std::io::stdout();
    let mut w = out.lock();
    use std::io::BufRead;
    for line in std::io::BufReader::new(stdout).lines() {
        writeln!(w, "{}", line?)?;
    }
    let _ = writer.join();
    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("decoder exited with {status}");
    }
    Ok(())
}

fn parse_range(r: &str) -> Result<(u64, u64)> {
    let (a, b) = r
        .split_once(':')
        .context("range must be A:B, e.g. 100:160")?;
    Ok((a.trim().parse()?, b.trim().parse()?))
}

/// Parse a hex byte pattern like `12 01` / `1201` / `0x12,0x01` into bytes.
fn parse_hex_pattern(p: &str) -> Result<Vec<u8>> {
    let cleaned: String = p
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if cleaned.is_empty() || cleaned.len() % 2 != 0 {
        anyhow::bail!("hex pattern must be an even number of hex digits");
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(Into::into))
        .collect()
}

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}
