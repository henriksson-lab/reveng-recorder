//! Query commands — the LLM-facing surface over a recorded session (DESIGN.md §8a.1).
//!
//! Implemented for the PCIe log (`pcie.bin`/`pcie.idx`), which the replay recorder
//! produces on any machine. USB pcapng reading is added with the USB capture path.

use anyhow::{Context, Result};
use reveng_core::event::PcieEvent;
use reveng_core::session::SessionReader;
use reveng_pcicap::PcieLog;
use std::io::{BufRead, Write};
use std::path::Path;

fn open_log(session: &SessionReader) -> Result<PcieLog> {
    PcieLog::open(session.pcie_bin(), session.pcie_idx())
        .context("this session has no PCIe log (pcie.bin/pcie.idx)")
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

/// `show` — a checkpoint card, including the anchored PCIe event.
pub fn show(session_dir: &Path, id: u64) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let c = s.checkpoint(id)?;
    let anchored = match c.anchor {
        Some(a) => {
            let mut log = open_log(&s)?;
            Some(log.event_at(a.event_index)?)
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
    bar_filter: Option<u8>,
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
        let ev = log.event_at(i)?;
        if let Some(bar) = bar_filter {
            if !matches_bar(&ev, bar) {
                continue;
            }
        }
        writeln!(w, "{}", serde_json::json!({"i": i, "event": ev}))?;
    }
    Ok(())
}

/// `payload` — one event by index.
pub fn payload(session_dir: &Path, frame: u64) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let mut log = open_log(&s)?;
    let ev = log.event_at(frame)?;
    println!("{}", serde_json::to_string_pretty(&ev)?);
    Ok(())
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

/// `grep` — events whose JSON contains a substring (hex or text).
pub fn grep(session_dir: &Path, pattern: &str) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let file = std::fs::File::open(s.pcie_bin())?;
    let needle = pattern.to_ascii_lowercase();
    let out = std::io::stdout();
    let mut w = out.lock();
    for (i, line) in std::io::BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.to_ascii_lowercase().contains(&needle) {
            writeln!(w, "{}", serde_json::json!({"i": i, "event": serde_json::from_str::<PcieEvent>(&line)?}))?;
        }
    }
    Ok(())
}

/// `reindex` — rebuild `pcie.idx` from `pcie.bin` (the raw truth).
pub fn reindex(session_dir: &Path) -> Result<()> {
    use reveng_core::index::IndexFile;
    use reveng_pcicap::PcieIdxRecord;

    let s = SessionReader::open(session_dir)?;
    let bin = std::fs::File::open(s.pcie_bin())?;
    let mut idx = IndexFile::<PcieIdxRecord>::create(s.pcie_idx())?;
    let mut offset = 0u64;
    let mut n = 0u64;
    let reader = std::io::BufReader::new(bin);
    for line in reader.lines() {
        let line = line?;
        let ev: PcieEvent = serde_json::from_str(&line)?;
        idx.append(&PcieIdxRecord {
            ts_ns: ev.ts_ns(),
            byte_offset: offset,
        })?;
        offset += line.len() as u64 + 1; // + '\n'
        n += 1;
    }
    println!("reindexed {n} events -> {}", s.pcie_idx().display());
    Ok(())
}

/// `decode` — run a candidate decoder over the events and stream its output.
///
/// Contract (DESIGN.md §8b): the decoder is any program that reads frames as JSONL on
/// stdin (`{"i":<index>, ...event...}` per line) and emits annotated JSONL on stdout.
/// This is the imperative decoder path; `--ksy` (Kaitai) is not yet wired.
pub fn decode(
    session_dir: &Path,
    with: Option<&str>,
    ksy: Option<&Path>,
    bar_filter: Option<u8>,
) -> Result<()> {
    use std::process::{Command, Stdio};

    if ksy.is_some() {
        anyhow::bail!("--ksy (Kaitai Struct) decoding not yet implemented; use --with <command>");
    }
    // `--with` is a command line: first token is the program, the rest are args, so
    // `--with "python3 decoder.py"` works.
    let cmd = with.context("decode needs --with <command> (or --ksy <file>)")?;
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let (prog, prog_args) = parts.split_first().context("--with is empty")?;

    let s = SessionReader::open(session_dir)?;
    let mut log = open_log(&s)?;
    let total = log.len();

    // Collect the frames to feed (JSONL, one object per line).
    let mut frames = Vec::with_capacity(total as usize);
    for i in 0..total {
        let ev = log.event_at(i)?;
        if let Some(bar) = bar_filter {
            if !matches_bar(&ev, bar) {
                continue;
            }
        }
        frames.push(serde_json::json!({"i": i, "event": ev}).to_string());
    }

    let mut child = Command::new(prog)
        .args(prog_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to launch decoder `{cmd}`"))?;

    // Write frames on a thread so a large stream can't deadlock against the child's
    // stdout buffer.
    let mut stdin = child.stdin.take().context("decoder stdin unavailable")?;
    let writer = std::thread::spawn(move || {
        for line in &frames {
            if writeln!(stdin, "{line}").is_err() {
                break;
            }
        }
        // stdin dropped here -> EOF to the child
    });

    let stdout = child.stdout.take().context("decoder stdout unavailable")?;
    let out = std::io::stdout();
    let mut w = out.lock();
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

fn matches_bar(ev: &PcieEvent, bar: u8) -> bool {
    matches!(ev, PcieEvent::Mmio { bar: b, .. } if *b == bar)
}
