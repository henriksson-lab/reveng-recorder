//! Query commands — the LLM-facing surface over a recorded session (DESIGN.md §8a.1).
//!
//! Works over both traffic backends behind one seam:
//! - **USB**: decoded frames from `usb.pcapng` + `frames.idx` (via `UsbReader`).
//! - **PCIe**: decoded events from `pcie.bin` + `pcie.idx` (via `PcieLog`).
//!
//! The session is classified by which raw log it holds, so every command below is
//! source-agnostic — exactly the property DESIGN.md §7/§8 calls for.

use anyhow::{Context, Result};
use reveng_core::event::{PcieEvent, SourceKind};
use reveng_core::session::SessionReader;
use reveng_pcicap::PcieLog;
use reveng_usbcap::reader::{Setup, CTRL_STAGE_COMPLETE, CTRL_STAGE_SETUP};
use reveng_usbcap::UsbReader;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

/// How to render raw payload bytes for `payload`.
#[derive(Copy, Clone)]
pub enum PayloadFmt {
    /// xxd-style hex + ASCII gutter.
    Hex,
    Bin,
    Base64,
    Json,
    /// UTF-8 (lossy) text.
    Text,
    /// Auto: text if the payload classifies as texty, else hex.
    Auto,
}

/// xxd-style hex dump: `offset  hex bytes  |ascii gutter|`.
fn hexdump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (row, chunk) in bytes.chunks(16).enumerate() {
        let mut hex = String::new();
        let mut asc = String::new();
        for (j, &b) in chunk.iter().enumerate() {
            if j == 8 {
                hex.push(' ');
            }
            hex.push_str(&format!("{b:02x} "));
            asc.push(if (0x20..=0x7e).contains(&b) { b as char } else { '.' });
        }
        out.push_str(&format!("{:08x}  {hex:<49}|{asc}|\n", row * 16));
    }
    out
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

    /// Open a specific source's log — needed for co-logged (USB + PCIe) sessions where an
    /// anchor names which wire it points into.
    fn open_source(s: &SessionReader, source: SourceKind) -> Result<Log> {
        match source {
            SourceKind::Usb => Ok(Log::Usb(UsbReader::open(s.usb_pcapng(), s.frames_idx())?)),
            SourceKind::Pcie => Ok(Log::Pcie(
                PcieLog::open(s.pcie_bin(), s.pcie_idx()).context("opening pcie.bin/pcie.idx")?,
            )),
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
        // Co-logged PCIe anchor, if this is a USB + PCIe session.
        let pcie_idx = c
            .anchors
            .iter()
            .find(|a| a.source == SourceKind::Pcie)
            .map(|a| a.event_index);
        if json {
            let line = serde_json::json!({
                "checkpoint": c.id,
                "ts_ns": c.ts_ns,
                "type": c.kind,
                "cause": c.cause,
                "anchor_index": anchor_idx,
                "pcie_anchor_index": pcie_idx,
                "screenshot": c.screenshot_id,
                "note": c.note,
            });
            writeln!(w, "{line}")?;
        } else {
            let pcie = pcie_idx.map(|i| format!(" pcie={i}")).unwrap_or_default();
            let note = c
                .note
                .as_deref()
                .map(|n| format!("  note=\"{n}\""))
                .unwrap_or_default();
            writeln!(
                w,
                "#{:<4} t={:>12}ns  {:<14} {:<16} anchor={}{}{}",
                c.id,
                c.ts_ns,
                format!("{:?}", c.kind),
                c.cause,
                anchor_idx.map(|i| i.to_string()).unwrap_or_else(|| "-".into()),
                pcie,
                note,
            )?;
        }
    }
    Ok(())
}

/// `notes` — the user notes typed during recording (Manual checkpoints), each as a JSON
/// line with its elapsed time and the traffic frame live when it was entered. This is the
/// "when did I say what, and what was on the wire then" view an agent correlates against.
pub fn notes(session_dir: &Path) -> Result<()> {
    use reveng_core::checkpoint::CheckpointType;
    let s = SessionReader::open(session_dir)?;
    let out = std::io::stdout();
    let mut w = out.lock();
    for c in s.checkpoints()? {
        if c.kind != CheckpointType::Manual {
            continue;
        }
        let Some(note) = c.note.as_deref() else {
            continue;
        };
        let line = serde_json::json!({
            "checkpoint": c.id,
            "ts_ns": c.ts_ns,
            "elapsed": fmt_elapsed(c.ts_ns),
            "anchor_index": c.anchor.map(|a| a.event_index),
            "note": note,
        });
        writeln!(w, "{line}")?;
    }
    Ok(())
}

/// Session-relative `ns` → `mm:ss.mmm`.
fn fmt_elapsed(ns: i64) -> String {
    let secs = (ns / 1_000_000_000).max(0);
    let ms = (ns / 1_000_000).max(0) % 1000;
    format!("{:02}:{:02}.{:03}", secs / 60, secs % 60, ms)
}

// ---- process-memory snapshots: the decoded-form oracle (reveng-memcap) -------------------

fn snap_dir(s: &SessionReader, id: u64) -> std::path::PathBuf {
    s.memsnaps_dir().join(format!("{id:06}"))
}

fn load_meta(dir: &Path) -> Result<reveng_memcap::MemSnapshotMeta> {
    let raw = std::fs::read(dir.join("manifest.json"))
        .with_context(|| format!("no memory snapshot at {}", dir.display()))?;
    Ok(serde_json::from_slice(&raw)?)
}

fn hex_inline(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

fn parse_addr(s: &str) -> Result<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Ok(u64::from_str_radix(h, 16)?)
    } else {
        Ok(s.parse()?)
    }
}

/// `mem ls` — snapshots taken during the session, each with the timeline context (elapsed +
/// the traffic frame live when it was taken) so you know what to diff against what.
pub fn mem_ls(session_dir: &Path) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let out = std::io::stdout();
    let mut w = out.lock();
    for c in s.checkpoints()? {
        let Some(mid) = c.mem_snapshot_id else { continue };
        let meta = load_meta(&snap_dir(&s, mid)).ok();
        let line = serde_json::json!({
            "snapshot": mid,
            "checkpoint": c.id,
            "ts_ns": c.ts_ns,
            "elapsed": fmt_elapsed(c.ts_ns),
            "pid": meta.as_ref().map(|m| m.pid),
            "process": meta.as_ref().map(|m| m.process.clone()),
            "total_bytes": meta.as_ref().map(|m| m.total_bytes),
            "stored_bytes": meta.as_ref().map(|m| m.stored_bytes),
            "compression": meta.as_ref().map(|m| m.compression.clone()),
            "regions": meta.as_ref().map(|m| m.regions.len()),
            "anchor_index": c.anchor.map(|a| a.event_index),
            "note": c.note,
        });
        writeln!(w, "{line}")?;
    }
    Ok(())
}

/// `mem regions` — the region table of one snapshot.
pub fn mem_regions(session_dir: &Path, id: u64) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let meta = load_meta(&snap_dir(&s, id))?;
    let out = std::io::stdout();
    let mut w = out.lock();
    for r in &meta.regions {
        let line = serde_json::json!({
            "base": format!("0x{:x}", r.base),
            "size": r.size,
            "stored_len": r.stored_len,
            "protect": format!("0x{:x}", r.protect),
            "mem_type": format!("0x{:x}", r.mem_type),
            "hash": r.hash,
        });
        writeln!(w, "{line}")?;
    }
    Ok(())
}

/// `mem diff a b` — the before→after delta. New and Changed regions carry the acquired data,
/// so they're ranked first; each changed byte-run shows old vs new (truncated to `max`).
pub fn mem_diff(session_dir: &Path, a: u64, b: u64, max: usize) -> Result<()> {
    use reveng_memcap::RegionDelta;
    let s = SessionReader::open(session_dir)?;
    let la = reveng_memcap::LoadedSnapshot::load(&snap_dir(&s, a))?;
    let lb = reveng_memcap::LoadedSnapshot::load(&snap_dir(&s, b))?;
    let mut deltas = reveng_memcap::diff(&la, &lb);
    let rank = |d: &RegionDelta| match d {
        RegionDelta::New { .. } => 0,
        RegionDelta::Changed { .. } => 1,
        RegionDelta::Resized { .. } => 2,
        RegionDelta::Freed { .. } => 3,
    };
    deltas.sort_by_key(|d| (rank(d), delta_base(d)));

    let out = std::io::stdout();
    let mut w = out.lock();
    for d in &deltas {
        let line = match d {
            RegionDelta::New { base, size } => serde_json::json!({
                "kind": "new", "base": format!("0x{base:x}"), "size": size }),
            RegionDelta::Freed { base, size } => serde_json::json!({
                "kind": "freed", "base": format!("0x{base:x}"), "size": size }),
            RegionDelta::Resized { base, old_size, new_size } => serde_json::json!({
                "kind": "resized", "base": format!("0x{base:x}"),
                "old_size": old_size, "new_size": new_size }),
            RegionDelta::Changed { base, size, changes } => {
                let cs: Vec<_> = changes
                    .iter()
                    .map(|c| {
                        let n = c.old.len().min(c.new.len());
                        serde_json::json!({
                            "addr": format!("0x{:x}", c.abs_addr),
                            "offset": c.offset,
                            "len": n,
                            "old": hex_inline(&c.old[..n.min(max)]),
                            "new": hex_inline(&c.new[..n.min(max)]),
                            "truncated": n > max,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "kind": "changed", "base": format!("0x{base:x}"), "size": size,
                    "changed_runs": cs.len(), "changes": cs })
            }
        };
        writeln!(w, "{line}")?;
    }
    Ok(())
}

fn delta_base(d: &reveng_memcap::RegionDelta) -> u64 {
    use reveng_memcap::RegionDelta::*;
    match d {
        New { base, .. } | Freed { base, .. } | Resized { base, .. } | Changed { base, .. } => *base,
    }
}

/// `mem scan id <value>` — find every encoding of a known (on-screen) value in a snapshot.
/// The seed that turns a noisy diff into a precise pointer.
pub fn mem_scan(session_dir: &Path, id: u64, value: &str) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let snap = reveng_memcap::LoadedSnapshot::load(&snap_dir(&s, id))?;
    let out = std::io::stdout();
    let mut w = out.lock();
    for h in reveng_memcap::scan(&snap, value) {
        let line = serde_json::json!({
            "addr": format!("0x{:x}", h.abs_addr),
            "encoding": h.encoding,
            "region_base": format!("0x{:x}", h.region_base),
            "offset": h.offset,
        });
        writeln!(w, "{line}")?;
    }
    Ok(())
}

/// `mem read id <addr> <len>` — hex/auto-render a slice of a snapshot at a target address.
pub fn mem_read(session_dir: &Path, id: u64, addr: &str, len: u64) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let snap = reveng_memcap::LoadedSnapshot::load(&snap_dir(&s, id))?;
    let addr = parse_addr(addr)?;
    let Some(r) = snap
        .meta
        .regions
        .iter()
        .find(|r| addr.checked_sub(r.base).is_some_and(|offset| offset < r.size))
    else {
        anyhow::bail!("address 0x{addr:x} is not inside any captured region");
    };
    let bytes = snap.region_bytes(r);
    let start = usize::try_from(addr - r.base).context("address offset does not fit this platform")?;
    let requested = usize::try_from(len).unwrap_or(usize::MAX);
    let end = start.saturating_add(requested).min(bytes.len());
    let slice = &bytes[start..end];
    if reveng_core::text::is_texty(slice) {
        print!("{}", String::from_utf8_lossy(slice));
    } else {
        print!("{}", hexdump(slice));
    }
    Ok(())
}

/// `show` — a checkpoint card, including the anchored traffic event.
pub fn show(session_dir: &Path, id: u64) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let c = s.checkpoint(id)?;
    // Resolve the primary anchor against its own source's log.
    let anchored = match &c.anchor {
        Some(a) => Log::open_source(&s, a.source)
            .and_then(|mut log| log.event_json(a.event_index))
            .ok(),
        None => None,
    };
    // Secondary anchors (co-logged sources, e.g. the PCIe event when USB + PCIe are recorded
    // together), each decoded from its own log — one checkpoint, both wires.
    let extra: Vec<serde_json::Value> = c
        .anchors
        .iter()
        .map(|a| {
            let event = Log::open_source(&s, a.source)
                .and_then(|mut log| log.event_json(a.event_index))
                .ok();
            serde_json::json!({ "anchor": a, "event": event })
        })
        .collect();

    let mut card = serde_json::json!({
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
    if !extra.is_empty() {
        card["extra_anchors"] = serde_json::Value::Array(extra);
    }
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
    fmt: PayloadFmt,
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
        (center.saturating_sub(window), center.saturating_add(window))
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
        // Render per --format. `text` (and the payload-ish formats) collapse the per-frame
        // hex/ascii/base64 firehose into one scannable line — essential for a bulk endpoint
        // where the default JSON is thousands of chars per frame.
        let line = match &mut log {
            Log::Usb(r) => {
                let uf = r.frame_at(i)?;
                match fmt {
                    PayloadFmt::Json => serde_json::to_string(&uf)?,
                    PayloadFmt::Hex => usb_hex_block(&uf),
                    PayloadFmt::Base64 => format!("#{} {}", uf.i, uf.b64),
                    _ => usb_text_line(&uf),
                }
            }
            Log::Pcie(l) => serde_json::json!({"i": i, "event": l.event_at(i)?}).to_string(),
        };
        writeln!(w, "{line}")?;
    }
    Ok(())
}

/// One compact scannable line for a USB frame (`--format text`): identity + a short payload
/// preview, and — for control transfers — the decoded SETUP command instead of raw bytes.
fn usb_text_line(f: &reveng_usbcap::UsbFrame) -> String {
    let mut s = format!(
        "#{:<6} t={:>9.3}s {} {:<3} {:<9} len={}",
        f.i,
        f.ts_ns as f64 / 1e9,
        f.ep,
        f.dir.to_uppercase(),
        f.xfer,
        f.len
    );
    if let Some(setup) = &f.setup {
        s += &format!(
            "  {}/{} req={} val={} idx={} wlen={}",
            setup.req_type, setup.recipient, setup.b_request, setup.w_value, setup.w_index,
            setup.w_length
        );
    }
    if !f.payload.is_empty() {
        let preview: Vec<String> = f.payload.iter().take(24).map(|b| format!("{b:02x}")).collect();
        let ell = if f.payload.len() > 24 { " …" } else { "" };
        s += &format!("  {}{}", preview.join(" "), ell);
    }
    s
}

/// A USB frame as a header line + xxd-style payload dump (`--format hex`).
fn usb_hex_block(f: &reveng_usbcap::UsbFrame) -> String {
    let mut s = format!(
        "#{} t={:.3}s {} {} {} len={}\n",
        f.i,
        f.ts_ns as f64 / 1e9,
        f.ep,
        f.dir,
        f.xfer,
        f.len
    );
    s.push_str(&hexdump(&f.payload));
    s
}

/// One fully-paired control transfer (SETUP joined with its completion), ready to emit.
struct CtrlCmd {
    i: u64,
    ts_ns: i64,
    setup: Setup,
    /// OUT data written by the host, or IN data returned by the device.
    data: Vec<u8>,
    /// Completion status, if the completion stage was seen within the range.
    status: Option<u32>,
}

fn emit_ctrl(w: &mut dyn Write, c: &CtrlCmd, json: bool) -> Result<()> {
    let data_hex: String = c.data.iter().map(|b| format!("{b:02x}")).collect();
    if json {
        let v = serde_json::json!({
            "i": c.i,
            "ts_ns": c.ts_ns,
            "dir": c.setup.dir,
            "req_type": c.setup.req_type,
            "recipient": c.setup.recipient,
            "bmRequestType": c.setup.bm_request_type,
            "bRequest": c.setup.b_request,
            "wValue": c.setup.w_value,
            "wIndex": c.setup.w_index,
            "wLength": c.setup.w_length,
            "data": data_hex,
            "status": c.status,
        });
        writeln!(w, "{v}")?;
        return Ok(());
    }
    let dir = c.setup.dir.to_ascii_uppercase();
    let status = match c.status {
        None => "?".to_string(),
        Some(0) => "ok".to_string(),
        Some(x) => format!("ERR 0x{x:08x}"),
    };
    // Cap the inline data so a long OUT/IN blob doesn't wrap the line; full bytes are in `data=`
    // via --json or the `payload` command.
    let shown = if data_hex.len() > 64 {
        format!("{}… ({} B)", &data_hex[..64], c.data.len())
    } else {
        data_hex
    };
    let data_field = if c.data.is_empty() {
        String::new()
    } else {
        format!("  data={shown}")
    };
    writeln!(
        w,
        "#{:<6} t={:>9.3}s  {:<3} {}/{}  req={} val={} idx={} wlen={}{}  {}",
        c.i,
        c.ts_ns as f64 / 1e9,
        dir,
        c.setup.req_type,
        c.setup.recipient,
        c.setup.b_request,
        c.setup.w_value,
        c.setup.w_index,
        c.setup.w_length,
        data_field,
        status,
    )?;
    Ok(())
}

/// `ctrl` — the control-transfer command log. Iterates control (EP0) frames, pairs each SETUP
/// with its completion by IRP id, and prints one line per request: direction, type/recipient,
/// `bRequest`/`wValue`/`wIndex`, the data payload, and completion status. This is the command
/// layer of a vendor USB protocol — for a Cypress-based camera it's the whole control surface.
pub fn ctrl(
    session_dir: &Path,
    around: Option<u64>,
    window: u64,
    range: Option<&str>,
    req_type: Option<&str>,
    json: bool,
) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    if !s.usb_pcapng().exists() {
        anyhow::bail!("`ctrl` is a USB view; this session has no usb.pcapng");
    }
    let mut reader = UsbReader::open(s.usb_pcapng(), s.frames_idx())?;
    let total = reader.len();
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
        (center.saturating_sub(window), center.saturating_add(window))
    } else {
        (0, total - 1)
    };
    let end = end.min(total - 1);
    let cmds = collect_ctrl(&mut reader, start, end, req_type)?;
    let out = std::io::stdout();
    let mut w = out.lock();
    for c in &cmds {
        emit_ctrl(&mut w, c, json)?;
    }
    Ok(())
}

/// Collect the paired control-transfer commands in `start..=end` (ordered by SETUP index),
/// filtered to `req_type` (standard|class|vendor) when given. Shared by `ctrl` and `ctrl-diff`.
fn collect_ctrl(
    reader: &mut UsbReader,
    start: u64,
    end: u64,
    req_type: Option<&str>,
) -> Result<Vec<CtrlCmd>> {
    let type_filter = req_type.map(|t| t.to_ascii_lowercase());
    let want = |c: &CtrlCmd| type_filter.as_deref().is_none_or(|t| c.setup.req_type == t);
    let mut pending: HashMap<u64, CtrlCmd> = HashMap::new();
    let mut done: Vec<CtrlCmd> = Vec::new();
    for i in start..=end {
        if reader.xfer_at(i)? != reveng_usbcap::XFER_CONTROL {
            continue;
        }
        let f = reader.frame_at(i)?;
        match f.stage_raw {
            Some(CTRL_STAGE_SETUP) => {
                if let Some(setup) = f.setup {
                    let data = if setup.dir == "out" && f.payload.len() > 8 {
                        f.payload[8..].to_vec()
                    } else {
                        Vec::new()
                    };
                    pending.insert(f.irp_id, CtrlCmd { i, ts_ns: f.ts_ns, setup, data, status: None });
                }
            }
            Some(stage) => {
                if let Some(p) = pending.get_mut(&f.irp_id) {
                    if p.setup.dir == "in" && !f.payload.is_empty() {
                        p.data.extend_from_slice(&f.payload);
                    }
                    if stage == CTRL_STAGE_COMPLETE {
                        let mut c = pending.remove(&f.irp_id).unwrap();
                        c.status = Some(f.status);
                        if want(&c) {
                            done.push(c);
                        }
                    }
                }
            }
            None => {}
        }
    }
    done.extend(pending.into_values().filter(|c| want(c)));
    done.sort_by_key(|c| c.i);
    Ok(done)
}

/// All control commands for a whole session (for `ctrl-diff`).
fn collect_ctrl_session(session_dir: &Path, req_type: Option<&str>) -> Result<Vec<CtrlCmd>> {
    let s = SessionReader::open(session_dir)?;
    if !s.usb_pcapng().exists() {
        anyhow::bail!("{}: not a USB session (no usb.pcapng)", session_dir.display());
    }
    let mut reader = UsbReader::open(s.usb_pcapng(), s.frames_idx())?;
    let total = reader.len();
    if total == 0 {
        return Ok(Vec::new());
    }
    collect_ctrl(&mut reader, 0, total - 1, req_type)
}

/// A command's alignment identity: `(bRequest, wValue, wIndex, dir)` — not data/status/timing.
fn ctrl_key(c: &CtrlCmd) -> String {
    format!("{} {} {} {}", c.setup.b_request, c.setup.w_value, c.setup.w_index, c.setup.dir)
}

/// Compact one-line rendering of a command (for diffs).
fn ctrl_oneline(c: &CtrlCmd) -> String {
    let data: String = c.data.iter().take(24).map(|b| format!("{b:02x}")).collect();
    let ell = if c.data.len() > 24 { "…" } else { "" };
    let d = if c.data.is_empty() { String::new() } else { format!(" data={data}{ell}") };
    format!(
        "{} {}/{} req={} val={} idx={} wlen={}{}",
        c.setup.dir.to_uppercase(),
        c.setup.req_type,
        c.setup.recipient,
        c.setup.b_request,
        c.setup.w_value,
        c.setup.w_index,
        c.setup.w_length,
        d
    )
}

enum DiffOp {
    Same(usize, usize),
    Del(usize),
    Add(usize),
}

/// LCS alignment of two key sequences → a diff op list.
fn lcs_diff(a: &[String], b: &[String]) -> Vec<DiffOp> {
    let (n, m) = (a.len(), b.len());
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0usize, 0usize);
    let mut ops = Vec::new();
    while i < n && j < m {
        if a[i] == b[j] {
            ops.push(DiffOp::Same(i, j));
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            ops.push(DiffOp::Del(i));
            i += 1;
        } else {
            ops.push(DiffOp::Add(j));
            j += 1;
        }
    }
    while i < n {
        ops.push(DiffOp::Del(i));
        i += 1;
    }
    while j < m {
        ops.push(DiffOp::Add(j));
        j += 1;
    }
    ops
}

fn flush_same(w: &mut dyn Write, run: &mut u32) -> Result<()> {
    if *run > 0 {
        writeln!(w, "  … {run} identical")?;
        *run = 0;
    }
    Ok(())
}

/// `ctrl-diff <A> <B>` — align two sessions' control-command streams (by request/value/index/dir)
/// and show what differs: `-` only in A, `+` only in B, `~` same command but different data.
/// Answers "what did the working run do that mine didn't?".
pub fn ctrl_diff(a_dir: &Path, b_dir: &Path, req_type: Option<&str>) -> Result<()> {
    let a = collect_ctrl_session(a_dir, req_type)?;
    let b = collect_ctrl_session(b_dir, req_type)?;
    let ka: Vec<String> = a.iter().map(ctrl_key).collect();
    let kb: Vec<String> = b.iter().map(ctrl_key).collect();
    let ops = lcs_diff(&ka, &kb);

    let out = std::io::stdout();
    let mut w = out.lock();
    writeln!(w, "--- A {}  ({} commands)", a_dir.display(), a.len())?;
    writeln!(w, "+++ B {}  ({} commands)", b_dir.display(), b.len())?;
    let (mut dels, mut adds, mut chg, mut same_run) = (0u32, 0u32, 0u32, 0u32);
    for op in &ops {
        match *op {
            DiffOp::Same(ia, ib) => {
                if a[ia].data != b[ib].data {
                    flush_same(&mut w, &mut same_run)?;
                    writeln!(w, "~ A {}", ctrl_oneline(&a[ia]))?;
                    writeln!(w, "~ B {}", ctrl_oneline(&b[ib]))?;
                    chg += 1;
                } else {
                    same_run += 1;
                }
            }
            DiffOp::Del(ia) => {
                flush_same(&mut w, &mut same_run)?;
                writeln!(w, "- {}", ctrl_oneline(&a[ia]))?;
                dels += 1;
            }
            DiffOp::Add(ib) => {
                flush_same(&mut w, &mut same_run)?;
                writeln!(w, "+ {}", ctrl_oneline(&b[ib]))?;
                adds += 1;
            }
        }
    }
    flush_same(&mut w, &mut same_run)?;
    writeln!(w, "\n{dels} only-in-A, {adds} only-in-B, {chg} changed-data")?;
    Ok(())
}

/// Group a command list into bursts separated by inter-command gaps > `gap_ns` (one burst ≈ one
/// parameter-change transaction).
fn group_bursts(cmds: &[CtrlCmd], gap_ns: i64) -> Vec<std::ops::Range<usize>> {
    let mut bursts = Vec::new();
    let mut start = 0usize;
    for i in 1..cmds.len() {
        if cmds[i].ts_ns - cmds[i - 1].ts_ns > gap_ns {
            bursts.push(start..i);
            start = i;
        }
    }
    if !cmds.is_empty() {
        bursts.push(start..cmds.len());
    }
    bursts
}

fn wval_lo(c: &CtrlCmd) -> u8 {
    u16::from_str_radix(c.setup.w_value.trim_start_matches("0x"), 16).unwrap_or(0) as u8
}

/// `sweep-correlate` — pair a known list of driven values with the control-transfer bursts they
/// produced (the last N bursts in the session), and pivot to a `value, <byte per register>` table
/// (and CSV) ready for `solve`. The analysis half of `sweep`; also usable on any capture where you
/// know the values that were set, in order.
pub fn sweep_correlate(
    session_dir: &Path,
    values: &[f64],
    req_type: Option<&str>,
    field: &str,
    out_csv: Option<&Path>,
) -> Result<()> {
    let cmds = collect_ctrl_session(session_dir, req_type)?;
    let bursts = group_bursts(&cmds, 500_000_000); // 0.5s gap between transactions
    let n = values.len();
    if bursts.len() < n {
        anyhow::bail!("found only {} bursts for {n} values — widen the gap or check the capture", bursts.len());
    }
    let tail = &bursts[bursts.len() - n..]; // the driven sweep is the last N bursts

    // Registers = unique (bRequest, wIndex) across the tail, in first-seen order.
    let mut regs: Vec<(String, String)> = Vec::new();
    for r in tail {
        for c in &cmds[r.clone()] {
            let key = (c.setup.b_request.clone(), c.setup.w_index.clone());
            if !regs.contains(&key) {
                regs.push(key);
            }
        }
    }
    let byte_of = |c: &CtrlCmd| -> u8 {
        if field == "data" {
            c.data.first().copied().unwrap_or(0)
        } else {
            wval_lo(c)
        }
    };

    let out = std::io::stdout();
    let mut w = out.lock();
    // Header
    write!(w, "{:>14}", "value")?;
    for (req, idx) in &regs {
        write!(w, "  {req}@{idx}")?;
    }
    writeln!(w)?;
    // Rows + optional CSV
    let mut csv = String::from("value");
    for (req, idx) in &regs {
        csv += &format!(",{req}@{idx}");
    }
    csv.push('\n');
    for (val, r) in values.iter().zip(tail) {
        let mut row: std::collections::HashMap<(String, String), u8> = Default::default();
        for c in &cmds[r.clone()] {
            row.insert((c.setup.b_request.clone(), c.setup.w_index.clone()), byte_of(c));
        }
        write!(w, "{val:>14}")?;
        csv += &format!("{val}");
        for reg in &regs {
            match row.get(reg) {
                Some(b) => {
                    write!(w, "  0x{b:02x}    ")?;
                    csv += &format!(",{b}");
                }
                None => {
                    write!(w, "  --      ")?;
                    csv += ",";
                }
            }
        }
        writeln!(w)?;
        csv.push('\n');
    }
    if let Some(p) = out_csv {
        std::fs::write(p, &csv)?;
        writeln!(w, "\nwrote {} — feed to `reveng-rec solve {} --var 0 --bytes 1{}`",
            p.display(), p.display(),
            (2..=regs.len()).map(|i| format!(",{i}")).collect::<String>())?;
    }
    Ok(())
}

/// Fold the control-write history into a register map: `(bRequest, wIndex) -> (last byte, ts)`,
/// considering only commands at-or-before `up_to_ts` (`cmds` are in capture = time order). The
/// "byte" is the low byte of `wValue` (covers both plain OUT register writes and the
/// obfuscated-IN-carries-the-write style). Folding by timestamp — not the checkpoint's traffic
/// `event_index`, which USB sessions often leave unset — makes this work on every session.
fn register_map(cmds: &[CtrlCmd], up_to_ts: i64) -> std::collections::BTreeMap<(String, String), (u8, i64)> {
    let mut m = std::collections::BTreeMap::new();
    for c in cmds {
        if c.ts_ns > up_to_ts {
            break;
        }
        m.insert((c.setup.b_request.clone(), c.setup.w_index.clone()), (wval_lo(c), c.ts_ns));
    }
    m
}

/// A checkpoint's timestamp (ns), the fold cutoff for its register state.
fn checkpoint_ts(s: &SessionReader, ckpt: u64) -> Result<i64> {
    Ok(s.checkpoint(ckpt)?.ts_ns)
}

/// The folded register map `(bRequest, wIndex) -> (last byte, ts)` for a session as of a checkpoint
/// (or end of session). Shared by `reg-state`/`reg-diff`/`track` and `annotate`.
pub(crate) fn folded_registers(
    session_dir: &Path,
    at_ckpt: Option<u64>,
    req_type: Option<&str>,
) -> Result<std::collections::BTreeMap<(String, String), (u8, i64)>> {
    let s = SessionReader::open(session_dir)?;
    let cmds = collect_ctrl_session(session_dir, req_type)?;
    let up_to = match at_ckpt {
        Some(ck) => checkpoint_ts(&s, ck)?,
        None => i64::MAX,
    };
    Ok(register_map(&cmds, up_to))
}

/// `reg-state` — the device's register map (last write per `(bRequest,wIndex)`) as of a checkpoint
/// (or end of session). The semantic device state, reconstructed from the control-write history.
pub fn reg_state(session_dir: &Path, at_ckpt: Option<u64>, req_type: Option<&str>) -> Result<()> {
    let m = folded_registers(session_dir, at_ckpt, req_type)?;
    let out = std::io::stdout();
    let mut w = out.lock();
    writeln!(w, "register state ({} registers){}:", m.len(),
        at_ckpt.map(|c| format!(" as of checkpoint {c}")).unwrap_or_default())?;
    for ((req, idx), (val, ts)) in &m {
        writeln!(w, "  {req} {idx} = 0x{val:02x}   (last t={:.3}s)", *ts as f64 / 1e9)?;
    }
    Ok(())
}

/// `reg-diff` — registers that changed between two checkpoints (semantic layer above `ctrl-diff`:
/// "clicking X changed registers A and B", not a wall of raw transfers).
pub fn reg_diff(session_dir: &Path, a: u64, b: u64, req_type: Option<&str>) -> Result<()> {
    let ma = folded_registers(session_dir, Some(a), req_type)?;
    let mb = folded_registers(session_dir, Some(b), req_type)?;
    let out = std::io::stdout();
    let mut w = out.lock();
    writeln!(w, "register changes between checkpoint {a} and {b}:")?;
    let mut keys: Vec<&(String, String)> = ma.keys().chain(mb.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut changes = 0u32;
    for k in keys {
        let va = ma.get(k).map(|x| x.0);
        let vb = mb.get(k).map(|x| x.0);
        if va != vb {
            let fmt = |v: Option<u8>| v.map(|x| format!("0x{x:02x}")).unwrap_or_else(|| "--".into());
            writeln!(w, "  {} {}:  {} -> {}", k.0, k.1, fmt(va), fmt(vb))?;
            changes += 1;
        }
    }
    writeln!(w, "\n{changes} register(s) changed")?;
    Ok(())
}

/// `track` — a value's time-series across the session: a UIA control's value (from `ui/<id>.json`)
/// or a register's last-written byte at each checkpoint. Replaces per-checkpoint extraction loops.
pub fn track(session_dir: &Path, ui_name: Option<&str>, reg: Option<&str>, json: bool) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let checkpoints = s.checkpoints()?;
    let out = std::io::stdout();
    let mut w = out.lock();

    let mut emit = |id: u64, ts: i64, val: String| -> Result<()> {
        if json {
            writeln!(w, "{}", serde_json::json!({"checkpoint": id, "ts_ns": ts, "value": val}))
                .map_err(Into::into)
        } else {
            writeln!(w, "  ckpt {id:<4} t={:>9.3}s   {val}", ts as f64 / 1e9).map_err(Into::into)
        }
    };

    match (ui_name, reg) {
        (Some(name), _) => {
            let needle = name.to_lowercase();
            for c in &checkpoints {
                let Some(sid) = c.screenshot_id else { continue };
                let Ok(bytes) = std::fs::read(s.ui_dir().join(format!("{sid:06}.json"))) else {
                    continue;
                };
                let els: Vec<reveng_winui::UiElement> = serde_json::from_slice(&bytes).unwrap_or_default();
                if let Some(el) = els.iter().find(|e| {
                    e.name.to_lowercase().contains(&needle)
                        && (e.range_value.is_some() || e.value.is_some())
                }) {
                    let v = el
                        .range_value
                        .map(|r| r.to_string())
                        .or_else(|| el.value.clone())
                        .unwrap_or_default();
                    emit(c.id, c.ts_ns, v)?;
                }
            }
        }
        (None, Some(r)) => {
            let (req, idx) = r.split_once(':').context("--reg must be REQ:IDX, e.g. 0x40:0x1000")?;
            let key = (req.trim().to_string(), idx.trim().to_string());
            let cmds = collect_ctrl_session(session_dir, None)?;
            for c in &checkpoints {
                if let Some((val, _)) = register_map(&cmds, c.ts_ns).get(&key) {
                    emit(c.id, c.ts_ns, format!("0x{val:02x}"))?;
                }
            }
        }
        (None, None) => anyhow::bail!("give --ui <control-name> or --reg <bRequest:wIndex>"),
    }
    Ok(())
}

/// `verify` — capture-integrity health check for a USB session. Answers "is this capture
/// complete?" so time isn't wasted chasing missing data that was really a dropped packet.
/// Reports the endpoint histogram, control SETUP↔completion pairing (unpaired = likely drops),
/// non-zero statuses, and timestamp ordering. Exits non-zero if integrity problems are found.
pub fn verify(session_dir: &Path) -> Result<()> {
    use std::collections::{BTreeMap, HashSet};
    let s = SessionReader::open(session_dir)?;
    let out = std::io::stdout();
    let mut w = out.lock();
    if !s.usb_pcapng().exists() {
        writeln!(w, "{}: not a USB session (verify currently covers USB)", session_dir.display())?;
        return Ok(());
    }
    let mut reader = UsbReader::open(s.usb_pcapng(), s.frames_idx())?;
    let total = reader.len();
    writeln!(w, "session {} — {total} USB frames", session_dir.display())?;
    if total == 0 {
        return Ok(());
    }

    let xname = |x: u8| match x {
        0 => "iso",
        1 => "interrupt",
        2 => "control",
        3 => "bulk",
        _ => "?",
    };
    let mut hist: BTreeMap<(u8, u8), (u64, u64)> = BTreeMap::new();
    let (mut prev_ts, mut backwards) = (i64::MIN, 0u64);
    let (mut setups, mut completes, mut errs) = (0u64, 0u64, 0u64);
    let mut pending: HashSet<u64> = HashSet::new();
    for i in 0..total {
        let (ep, xf) = (reader.endpoint_at(i)?, reader.xfer_at(i)?);
        let e = hist.entry((ep, xf)).or_default();
        e.0 += 1;
        e.1 += reader.len_at(i)? as u64;
        let ts = reader.ts_at(i)?;
        if ts < prev_ts {
            backwards += 1;
        }
        prev_ts = ts;
        if xf == reveng_usbcap::XFER_CONTROL {
            let f = reader.frame_at(i)?;
            match f.stage_raw {
                Some(CTRL_STAGE_SETUP) => {
                    setups += 1;
                    pending.insert(f.irp_id);
                }
                Some(CTRL_STAGE_COMPLETE) => {
                    completes += 1;
                    pending.remove(&f.irp_id);
                    if f.status != 0 {
                        errs += 1;
                    }
                }
                _ => {}
            }
        }
    }
    let unpaired = pending.len() as u64;

    writeln!(w, "\nendpoints  (ep dir xfer  frames  bytes):")?;
    for ((ep, xf), (cnt, by)) in &hist {
        let dir = if ep & 0x80 != 0 { "IN " } else { "OUT" };
        writeln!(w, "  0x{ep:02x} {dir} {:<9} {cnt:>8}  {by}", xname(*xf))?;
    }
    writeln!(
        w,
        "\ncontrol: {setups} SETUP, {completes} complete, {unpaired} unpaired, {errs} non-zero status"
    )?;
    writeln!(w, "timeline: {backwards} out-of-order timestamp(s)")?;
    writeln!(
        w,
        "note: USBPcap buffer-overflow drops aren't recorded in the pcapng; unpaired SETUPs are the\n      best proxy for lost control transfers (and gaps in a bulk stream for lost data)."
    )?;

    let mut issues = Vec::new();
    if unpaired > 0 {
        issues.push(format!(
            "{unpaired} SETUP(s) with no completion — likely dropped/truncated control transfers"
        ));
    }
    if backwards > 0 {
        issues.push(format!("{backwards} frame(s) earlier than the previous — ordering/clock anomaly"));
    }
    writeln!(w)?;
    if issues.is_empty() {
        writeln!(w, "OK — no capture-integrity problems detected.")?;
        if errs > 0 {
            writeln!(w, "({errs} control transfer(s) returned a non-zero status — may be normal, e.g. capability probes.)")?;
        }
    } else {
        for it in &issues {
            writeln!(w, "⚠ {it}")?;
        }
        drop(w);
        std::process::exit(1);
    }
    Ok(())
}

/// Per-screenshot capture geometry, read back from `screenshots.ndjson`.
struct ShotGeom {
    origin_x: i32,
    origin_y: i32,
    cursor_x: i32,
    cursor_y: i32,
}

/// Load `screenshots.ndjson` into a map: screenshot id → capture geometry.
fn load_shot_geom(session: &SessionReader) -> HashMap<u64, ShotGeom> {
    let mut out = HashMap::new();
    let Ok(text) = std::fs::read_to_string(session.screenshots_meta()) else {
        return out;
    };
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let get = |k: &str| v.get(k).and_then(|x| x.as_i64());
        if let Some(id) = v.get("id").and_then(|x| x.as_u64()) {
            out.insert(
                id,
                ShotGeom {
                    origin_x: get("origin_x").unwrap_or(0) as i32,
                    origin_y: get("origin_y").unwrap_or(0) as i32,
                    cursor_x: get("cursor_x").unwrap_or(0) as i32,
                    cursor_y: get("cursor_y").unwrap_or(0) as i32,
                },
            );
        }
    }
    out
}

/// `ocr` — recognize on-screen text (Windows.Media.Ocr) in one or all screenshots, and emit each
/// word with its pixel box, ordered by distance to the cursor at capture time. Results are cached
/// under `ocr/<id>.json` so re-analysis of a large session is instant.
///
/// The cursor→pixel mapping uses `screenshots.ndjson` geometry (cursor − capture origin); for
/// older sessions without it, the checkpoint cursor is used with a zero origin.
pub fn ocr(
    session_dir: &Path,
    target: Option<u64>,
    all: bool,
    json: bool,
    refresh: bool,
) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let shots_dir = s.screenshots_dir();
    let geom = load_shot_geom(&s);

    // Which screenshots to process.
    let ids: Vec<u64> = if all {
        let mut v: Vec<u64> = std::fs::read_dir(&shots_dir)
            .with_context(|| format!("no screenshots dir at {}", shots_dir.display()))?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                e.path()
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse::<u64>().ok())
            })
            .collect();
        v.sort_unstable();
        v
    } else {
        vec![target.context("give a screenshot id, or --all")?]
    };

    std::fs::create_dir_all(s.ocr_dir()).ok();
    let out = std::io::stdout();
    let mut w = out.lock();

    for id in ids {
        // Cursor position in image pixels (word distances are measured from here).
        let (cursor_px, cursor_py) = match geom.get(&id) {
            Some(g) => (g.cursor_x - g.origin_x, g.cursor_y - g.origin_y),
            None => s
                .checkpoint(id)
                .ok()
                .map(|c| c.cursor)
                .unwrap_or((0, 0)),
        };

        // Cache: ocr/<id>.json. Reuse unless --refresh.
        let cache = s.ocr_dir().join(format!("{id:06}.json"));
        let result: reveng_winocr::Ocr = if !refresh && cache.exists() {
            serde_json::from_slice(&std::fs::read(&cache)?)?
        } else {
            let png_path = shots_dir.join(format!("{id:06}.png"));
            let png = std::fs::read(&png_path)
                .with_context(|| format!("no screenshot {}", png_path.display()))?;
            let r = reveng_winocr::ocr_png(&png)
                .with_context(|| format!("OCR of screenshot {id} failed"))?;
            let _ = std::fs::write(&cache, serde_json::to_vec(&r)?);
            r
        };

        // Order words by distance from their center to the cursor.
        let dist = |wd: &reveng_winocr::Word| -> f64 {
            let (cx, cy) = wd.center();
            (((cx - cursor_px as f32).powi(2) + (cy - cursor_py as f32).powi(2)) as f64).sqrt()
        };
        let mut words = result.words.clone();
        words.sort_by(|a, b| dist(a).total_cmp(&dist(b)));

        if json {
            let arr: Vec<serde_json::Value> = words
                .iter()
                .map(|wd| {
                    serde_json::json!({
                        "text": wd.text,
                        "x": wd.x, "y": wd.y, "w": wd.w, "h": wd.h,
                        "dist": dist(wd).round(),
                    })
                })
                .collect();
            let line = serde_json::json!({
                "id": id,
                "cursor_px": [cursor_px, cursor_py],
                "n_words": words.len(),
                "words": arr,
            });
            writeln!(w, "{line}")?;
        } else {
            writeln!(
                w,
                "# screenshot {id} — {} words, cursor at pixel ({cursor_px},{cursor_py})",
                words.len()
            )?;
            for wd in &words {
                writeln!(
                    w,
                    "  d={:>5}  ({:>4},{:>4}) {:>3}x{:<3}  {:?}",
                    dist(wd).round() as i64,
                    wd.x.round() as i64,
                    wd.y.round() as i64,
                    wd.w.round() as i64,
                    wd.h.round() as i64,
                    wd.text,
                )?;
            }
        }
    }
    Ok(())
}

/// `ui` — read the UI-Automation widget snapshot captured at a checkpoint: typed controls
/// (Button/CheckBox/RadioButton/Slider/Edit/ComboBox…) with their screen rects and live
/// state/value, ordered by distance to the cursor. This is the structured screen-side oracle:
/// it names exactly which widget a click hit and what its value was (e.g. an exposure slider's
/// number), so a UI change can be correlated with the wire bytes at the same checkpoint.
pub fn ui(
    session_dir: &Path,
    target: Option<u64>,
    all: bool,
    json: bool,
    interactive_only: bool,
) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let ui_dir = s.ui_dir();
    let geom = load_shot_geom(&s);

    let ids: Vec<u64> = if all {
        let mut v: Vec<u64> = std::fs::read_dir(&ui_dir)
            .with_context(|| format!("no UI snapshots at {}", ui_dir.display()))?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                e.path()
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse::<u64>().ok())
            })
            .collect();
        v.sort_unstable();
        v
    } else {
        vec![target.context("give a checkpoint id, or --all")?]
    };

    let out = std::io::stdout();
    let mut w = out.lock();

    for id in ids {
        let path = ui_dir.join(format!("{id:06}.json"));
        let Ok(bytes) = std::fs::read(&path) else {
            if !all {
                anyhow::bail!("no UI snapshot for checkpoint {id} at {}", path.display());
            }
            continue;
        };
        let mut els: Vec<reveng_winui::UiElement> = serde_json::from_slice(&bytes)?;

        // Cursor in absolute screen coords (UIA rects are absolute too, so distance is direct).
        let (cx, cy) = match geom.get(&id) {
            Some(g) => (g.cursor_x, g.cursor_y),
            None => s.checkpoint(id).ok().map(|c| c.cursor).unwrap_or((0, 0)),
        };
        let dist = |e: &reveng_winui::UiElement| -> f64 {
            let (ex, ey) = ((e.x + e.w / 2) as f64, (e.y + e.h / 2) as f64);
            ((ex - cx as f64).powi(2) + (ey - cy as f64).powi(2)).sqrt()
        };
        if interactive_only {
            els.retain(|e| e.is_interactive());
        }
        els.sort_by(|a, b| dist(a).total_cmp(&dist(b)));

        if json {
            for e in &els {
                let mut v = serde_json::to_value(e)?;
                v["dist"] = serde_json::json!(dist(e).round());
                v["checkpoint"] = serde_json::json!(id);
                writeln!(w, "{v}")?;
            }
        } else {
            writeln!(
                w,
                "# checkpoint {id} — {} controls, cursor at screen ({cx},{cy})",
                els.len()
            )?;
            for e in &els {
                let mut state = String::new();
                if let Some(t) = &e.toggle {
                    state += &format!(" toggle={t}");
                }
                if let Some(sel) = e.selected {
                    state += &format!(" selected={sel}");
                }
                if let Some(val) = &e.value {
                    state += &format!(" value={val:?}");
                }
                if let Some(rv) = e.range_value {
                    state += &format!(" range={rv}");
                }
                writeln!(
                    w,
                    "  d={:>5}  {:<11} {:<26}{}",
                    dist(e).round() as i64,
                    e.role,
                    truncate_label(&e.name, 26),
                    state,
                )?;
            }
        }
    }
    Ok(())
}

fn truncate_label(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}

/// `stream` — reassembled logical messages on an endpoint (USB, DESIGN.md §8b). Without
/// `--logical` it is the raw per-endpoint frame view. PCIe falls back to filtered events.
pub fn stream(session_dir: &Path, ep: Option<u8>, logical: bool, text: bool) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let mut log = open_log(&s)?;
    let total = log.len();
    if total == 0 {
        return Ok(());
    }
    // Text reassembly (USB): concatenate the endpoint and split on newlines — the natural
    // shape for CDC-ACM serial / NMEA / AT-command / debug-log endpoints.
    if text {
        if let Log::Usb(reader) = &mut log {
            return stream_text(reader, total, ep);
        }
    }
    // Non-logical, or non-USB: just the filtered frames.
    if !logical || matches!(log, Log::Pcie(_)) {
        return frames(session_dir, None, 0, Some(&format!("0:{}", total - 1)), ep, PayloadFmt::Json);
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

/// Text reassembly for a USB endpoint: concatenate frames per endpoint and emit one record
/// per newline-delimited line (trailing `\r` trimmed). Partial trailing data is flushed.
fn stream_text(reader: &mut UsbReader, total: u64, ep: Option<u8>) -> Result<()> {
    use std::collections::BTreeMap;
    let out = std::io::stdout();
    let mut w = out.lock();
    let emit = |w: &mut dyn Write, endpoint: u8, line: &[u8]| -> Result<()> {
        let dir = if endpoint & 0x80 != 0 { "in" } else { "out" };
        let text = String::from_utf8_lossy(line);
        let line = serde_json::json!({
            "ep": format!("0x{:02x}", endpoint),
            "dir": dir,
            "text": text.trim_end_matches('\r'),
        });
        writeln!(w, "{line}")?;
        Ok(())
    };
    let mut buf: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
    for i in 0..total {
        let f = reader.frame_at(i)?;
        if let Some(sel) = ep {
            if f.endpoint != sel {
                continue;
            }
        }
        let b = buf.entry(f.endpoint).or_default();
        b.extend_from_slice(&f.payload);
        while let Some(pos) = b.iter().position(|&c| c == b'\n') {
            let line: Vec<u8> = b.drain(..=pos).collect();
            emit(&mut w, f.endpoint, &line[..line.len() - 1])?;
        }
    }
    for (endpoint, b) in buf {
        if !b.is_empty() {
            emit(&mut w, endpoint, &b)?;
        }
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
            print!("{}", hexdump(&bytes));
            Ok(())
        }
        (_, PayloadFmt::Base64) => {
            use base64::Engine;
            let bytes = log.payload_bytes(frame)?;
            println!("{}", base64::engine::general_purpose::STANDARD.encode(&bytes));
            Ok(())
        }
        (_, PayloadFmt::Text) => {
            let bytes = log.payload_bytes(frame)?;
            print!("{}", String::from_utf8_lossy(&bytes));
            Ok(())
        }
        // Auto: text endpoints (serial/logs) render as text; binary as hex+ASCII.
        (_, PayloadFmt::Auto) => {
            let bytes = log.payload_bytes(frame)?;
            if reveng_core::text::is_texty(&bytes) {
                print!("{}", String::from_utf8_lossy(&bytes));
            } else {
                print!("{}", hexdump(&bytes));
            }
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
    frames(session_dir, None, 0, Some(&format!("{lo}:{hi}")), None, PayloadFmt::Json)
}

/// `grep` — USB: frames whose payload contains a hex byte pattern; PCIe: events whose
/// JSON line contains a substring.
pub fn grep(session_dir: &Path, pattern: &str, text: bool) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    let mut log = open_log(&s)?;
    let out = std::io::stdout();
    let mut w = out.lock();

    match &mut log {
        Log::Usb(reader) => {
            let total = reader.len();
            if text {
                // Text substring over the (UTF-8 lossy) payload.
                for i in 0..total {
                    let payload = reader.payload_at(i)?;
                    if String::from_utf8_lossy(&payload).contains(pattern) {
                        writeln!(w, "{}", serde_json::to_value(reader.frame_at(i)?)?)?;
                    }
                }
            } else {
                let needle = parse_hex_pattern(pattern)
                    .context("USB grep pattern must be hex bytes, e.g. `12 01` or `1201`")?;
                for i in 0..total {
                    // Scan raw payload cheaply; only fully decode the frames that match.
                    if contains_subslice(&reader.payload_at(i)?, &needle) {
                        writeln!(w, "{}", serde_json::to_value(reader.frame_at(i)?)?)?;
                    }
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
    let log = open_log(&s)?;
    let total = log.len();

    let mut child = Command::new(prog)
        .args(prog_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to launch decoder `{cmd}`"))?;

    let mut stdin = child.stdin.take().context("decoder stdin unavailable")?;
    let writer = std::thread::spawn(move || -> Result<()> {
        let mut log = log;
        for i in 0..total {
            if let Some(f) = filter {
                if !log.matches_filter(i, f)? {
                    continue;
                }
            }
            let line = log.event_json(i)?;
            if let Err(e) = writeln!(stdin, "{line}") {
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    break;
                }
                return Err(e.into());
            }
        }
        Ok(())
    });

    let stdout = child.stdout.take().context("decoder stdout unavailable")?;
    let out = std::io::stdout();
    let mut w = out.lock();
    use std::io::BufRead;
    let output_result = (|| -> Result<()> {
        for line in std::io::BufReader::new(stdout).lines() {
            writeln!(w, "{}", line?)?;
        }
        Ok(())
    })();
    if output_result.is_err() {
        let _ = child.kill();
    }
    let input_result = writer
        .join()
        .map_err(|_| anyhow::anyhow!("decoder input writer thread panicked"))?;
    let status = child.wait()?;
    output_result?;
    input_result?;
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
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
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
