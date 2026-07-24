//! `frame-extract` / `frame-decode` — reassemble a "logical frame" from a bulk endpoint in a
//! capture, and turn RAW pixel data into a viewable image. Validates a camera/scanner frame format
//! without writing a driver.

use anyhow::{bail, Context, Result};
use reveng_core::session::SessionReader;
use reveng_usbcap::UsbReader;
use std::path::Path;

/// Reassemble one frame of `frame_bytes` from bulk endpoint `ep` (skipping zero-length packets,
/// accumulating until a full frame). Warns if the capture was snaplen-truncated (reassembly would
/// be wrong — recapture losslessly).
pub fn extract(session_dir: &Path, ep: u8, frame_bytes: usize, out: &Path) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    if !s.usb_pcapng().exists() {
        bail!("{}: not a USB session", session_dir.display());
    }
    let mut r = UsbReader::open(s.usb_pcapng(), s.frames_idx())?;
    let n = r.len();
    let mut acc: Vec<u8> = Vec::with_capacity(frame_bytes + (1 << 20));
    let (mut seen, mut truncated) = (0u64, false);
    for i in 0..n {
        if r.endpoint_at(i)? != ep {
            continue;
        }
        seen += 1;
        let reported = r.len_at(i)? as usize;
        let p = r.payload_at(i)?;
        if reported > 0 && p.len() < reported {
            truncated = true; // snaplen cut this transfer — data is incomplete
        }
        if p.is_empty() {
            continue; // ZLP
        }
        acc.extend_from_slice(&p);
        if acc.len() >= frame_bytes {
            break;
        }
    }
    if truncated {
        eprintln!(
            "⚠ this capture snaplen-truncated bulk transfers — the reassembled frame is INCOMPLETE.\n  Recapture with `record` at full snaplen (no --usb-snaplen / --auto-truncate)."
        );
    }
    if acc.len() < frame_bytes {
        bail!(
            "only {} of {frame_bytes} bytes on ep 0x{ep:02x} ({seen} transfers). Wrong endpoint, \
             wrong frame size, or a truncated/short capture.",
            acc.len()
        );
    }
    acc.truncate(frame_bytes);
    std::fs::write(out, &acc)?;
    println!("wrote {frame_bytes} bytes -> {}", out.display());
    Ok(())
}

/// `frame-guess` — infer a bulk endpoint's frame format from the capture alone. Segments the stream
/// two ways — short-packet boundaries and inter-frame time gaps (cross-checking, since a lossy
/// capture fools the first) — measures bytes-per-frame, derives fps, and factors the more
/// self-consistent size into candidate `W×H×bpp` near common aspect ratios. Replaces the arithmetic
/// by hand. Needs a clean (non-truncated, low-loss) capture to resolve a real multi-URB frame.
pub fn guess(session_dir: &Path, ep: u8) -> Result<()> {
    let s = SessionReader::open(session_dir)?;
    if !s.usb_pcapng().exists() {
        bail!("{}: not a USB session", session_dir.display());
    }
    let mut r = UsbReader::open(s.usb_pcapng(), s.frames_idx())?;
    let n = r.len();

    // Per-transfer (ts, reported_len) for this endpoint. Segmentation uses the *reported* on-wire
    // transfer size, not the captured payload length — so `frame-guess` is correct even when the
    // capture was snaplen-truncated (only `frame-extract`, which needs the actual bytes, isn't).
    let mut xfers: Vec<(i64, usize)> = Vec::new();
    for i in 0..n {
        if r.endpoint_at(i)? != ep {
            continue;
        }
        xfers.push((r.ts_at(i)?, r.len_at(i)? as usize));
    }
    if xfers.is_empty() {
        bail!("no transfers on ep 0x{ep:02x} — wrong endpoint? (`frames` lists endpoints)");
    }

    // The DMA/URB chunk size is the dominant (max) transfer length; a shorter transfer ends a frame.
    let chunk = xfers.iter().map(|x| x.1).max().unwrap_or(0);
    println!("ep 0x{ep:02x}: {} transfers, URB chunk {} bytes", xfers.len(), chunk);

    // Estimate 1 — short-packet boundaries. Correct on a clean capture, but a lossy capture
    // (dropped packets) sprays spurious short transfers and over-segments.
    let (sp_frames, _) = segment_short_packet(&xfers, chunk);
    // Estimate 2 — time-gap boundaries. Real frames are separated by a sensor-readout gap much
    // larger than intra-frame URB spacing; robust to dropped packets.
    let (tg_frames, tg_starts) = segment_time_gap(&xfers);

    let sp = modal(&sp_frames);
    let tg = modal(&tg_frames);
    if let Some((sz, votes, n)) = sp {
        println!("short-packet segmentation: {n} frame(s), modal {sz} bytes ({votes}/{n} agree)");
    }
    if let Some((sz, votes, n)) = tg {
        println!("time-gap segmentation:     {n} frame(s), modal {sz} bytes ({votes}/{n} agree)");
    }

    // Frame period from the time-gap starts (the physically meaningful cadence).
    if tg_starts.len() >= 2 {
        let mut gaps: Vec<i64> = tg_starts.windows(2).map(|w| w[1] - w[0]).collect();
        gaps.sort_unstable();
        let med = gaps[gaps.len() / 2] as f64 / 1e9;
        if med > 0.0 {
            println!("median frame period: {:.1} ms  (~{:.1} fps)", med * 1e3, 1.0 / med);
        }
    }

    // Factor the more self-consistent estimate (higher agreement fraction), preferring the larger
    // frame when they tie — a real frame is many URBs, not a single chunk.
    let frac = |m: &Option<(usize, u32, usize)>| m.map(|(_, v, n)| v as f64 / n as f64).unwrap_or(0.0);
    let pick = match (sp, tg) {
        (Some(a), Some(b)) => {
            if (frac(&sp) - frac(&tg)).abs() < 0.05 {
                if a.0 >= b.0 { a.0 } else { b.0 }
            } else if frac(&sp) > frac(&tg) {
                a.0
            } else {
                b.0
            }
        }
        (Some(a), None) => a.0,
        (None, Some(b)) => b.0,
        (None, None) => bail!("could not segment any frames on ep 0x{ep:02x}"),
    };
    if pick == chunk {
        println!("\n⚠ modal frame == one URB chunk — likely dropped packets or the true frame spans\n  multiple URBs that the capture merged. Candidates below are for {pick} bytes; treat with care.");
    }

    let cands = factor_candidates(pick);
    let best = pick;
    if cands.is_empty() {
        println!("\nno clean W×H×bpp near a common aspect ratio for {best} bytes.");
        println!("Sensor frames often carry extra readout lines — try `frame-extract --frame-bytes {best}`");
        println!("then `frame-decode` sweeping a few heights around a 4:3/16:9 fit.");
        return Ok(());
    }
    println!("\ncandidate formats (feed the winner to `frame-extract --frame-bytes {best}` + `frame-decode`):");
    println!("  {:>5} x {:<5}  {:<7} {:<6} {}", "W", "H", "pix", "ratio", "note");
    for c in cands.iter().take(10) {
        let mult = if c.w % 16 == 0 { "W%16=0" } else if c.w % 8 == 0 { "W%8=0" } else { "" };
        println!("  {:>5} x {:<5}  {:<7} {:<6} {} {}", c.w, c.h, c.pix, c.ratio, mult,
            if (c.ar - c.ideal).abs() < 1e-6 { "exact" } else { "≈" });
    }
    Ok(())
}

/// Segment by short-packet boundaries: a transfer shorter than the URB chunk ends a frame.
/// Returns (frame byte-sizes, frame start timestamps).
fn segment_short_packet(xfers: &[(i64, usize)], chunk: usize) -> (Vec<usize>, Vec<i64>) {
    let (mut frames, mut starts, mut acc, mut in_frame) = (Vec::new(), Vec::new(), 0usize, false);
    for &(ts, rep) in xfers {
        if !in_frame && rep > 0 {
            starts.push(ts);
            in_frame = true;
        }
        acc += rep;
        if rep < chunk {
            if acc > 0 {
                frames.push(acc);
            }
            acc = 0;
            in_frame = false;
        }
    }
    (frames, starts)
}

/// Segment by inter-transfer time gaps: a gap much larger than the median (the sensor-readout gap
/// between frames) ends a frame. Robust when dropped packets confuse short-packet detection.
fn segment_time_gap(xfers: &[(i64, usize)]) -> (Vec<usize>, Vec<i64>) {
    if xfers.len() < 3 {
        let total: usize = xfers.iter().map(|x| x.1).sum();
        return (vec![total], xfers.first().map(|x| vec![x.0]).unwrap_or_default());
    }
    let mut gaps: Vec<i64> = xfers.windows(2).map(|w| w[1].0 - w[0].0).collect();
    let mut sorted = gaps.clone();
    sorted.sort_unstable();
    let median = sorted[sorted.len() / 2].max(1);
    let threshold = median * 4; // an inter-frame gap is several× the intra-frame URB spacing
    gaps.push(0); // no gap after the last transfer

    let (mut frames, mut starts, mut acc, mut in_frame) = (Vec::new(), Vec::new(), 0usize, false);
    for (i, &(ts, rep)) in xfers.iter().enumerate() {
        if !in_frame && rep > 0 {
            starts.push(ts);
            in_frame = true;
        }
        acc += rep;
        if gaps[i] > threshold {
            if acc > 0 {
                frames.push(acc);
            }
            acc = 0;
            in_frame = false;
        }
    }
    if acc > 0 {
        frames.push(acc);
    }
    (frames, starts)
}

/// Modal frame size and its agreement: `(size, votes, total_frames)`.
fn modal(frames: &[usize]) -> Option<(usize, u32, usize)> {
    if frames.is_empty() {
        return None;
    }
    let mut counts: std::collections::BTreeMap<usize, u32> = Default::default();
    for &f in frames {
        *counts.entry(f).or_default() += 1;
    }
    counts.iter().max_by_key(|(_, c)| **c).map(|(k, c)| (*k, *c, frames.len()))
}

struct Cand {
    w: usize,
    h: usize,
    bpp: usize,
    pix: &'static str,
    ar: f64,
    ideal: f64,
    ratio: &'static str,
    err: f64,
}

/// Factor `nbytes` into `W×H×bpp` whose aspect ratio is within tolerance of a common ratio.
fn factor_candidates(nbytes: usize) -> Vec<Cand> {
    const RATIOS: [(f64, &str); 6] = [
        (4.0 / 3.0, "4:3"),
        (3.0 / 2.0, "3:2"),
        (16.0 / 9.0, "16:9"),
        (16.0 / 10.0, "16:10"),
        (5.0 / 4.0, "5:4"),
        (1.0, "1:1"),
    ];
    let mut out: Vec<Cand> = Vec::new();
    for (bpp, pix) in [(1usize, "raw8"), (2, "raw16")] {
        if nbytes % bpp != 0 {
            continue;
        }
        let px = nbytes / bpp;
        for w in 320..=8192usize {
            if px % w != 0 {
                continue;
            }
            let h = px / w;
            if !(200..=8192).contains(&h) {
                continue;
            }
            let ar = w as f64 / h as f64;
            if let Some((ideal, ratio, err)) = RATIOS
                .iter()
                .map(|(r, n)| (*r, *n, (ar - r).abs() / r))
                .filter(|(_, _, e)| *e < 0.05)
                .min_by(|a, b| a.2.total_cmp(&b.2))
            {
                out.push(Cand { w, h, bpp, pix, ar, ideal, ratio, err });
            }
        }
    }
    // Best first: closest to a standard ratio, then raw8 over raw16, then 16-aligned width.
    out.sort_by(|a, b| {
        a.err
            .total_cmp(&b.err)
            .then(a.bpp.cmp(&b.bpp))
            .then((b.w % 16 == 0).cmp(&(a.w % 16 == 0)))
    });
    out
}

#[derive(Clone, Copy)]
enum Bayer {
    Rggb,
    Grbg,
    Gbrg,
    Bggr,
}
impl Bayer {
    const ALL: [(Bayer, &'static str); 4] = [
        (Bayer::Rggb, "rggb"),
        (Bayer::Grbg, "grbg"),
        (Bayer::Gbrg, "gbrg"),
        (Bayer::Bggr, "bggr"),
    ];
}

/// Half-res debayer: each 2×2 block → one RGB pixel.
fn debayer_half(raw: &[u8], width: usize, height: usize, phase: Bayer) -> (u32, u32, Vec<u8>) {
    let (ow, oh) = (width / 2, height / 2);
    let mut out = vec![0u8; ow * oh * 3];
    let at = |x: usize, y: usize| raw[y * width + x] as u32;
    for by in 0..oh {
        for bx in 0..ow {
            let (x, y) = (bx * 2, by * 2);
            let (p00, p01, p10, p11) = (at(x, y), at(x + 1, y), at(x, y + 1), at(x + 1, y + 1));
            let (r, g, b) = match phase {
                Bayer::Rggb => (p00, (p01 + p10) / 2, p11),
                Bayer::Bggr => (p11, (p01 + p10) / 2, p00),
                Bayer::Grbg => (p01, (p00 + p11) / 2, p10),
                Bayer::Gbrg => (p10, (p00 + p11) / 2, p01),
            };
            let o = (by * ow + bx) * 3;
            out[o] = r as u8;
            out[o + 1] = g as u8;
            out[o + 2] = b as u8;
        }
    }
    (ow as u32, oh as u32, out)
}

/// Decode a RAW frame into PNG(s). `pix`: `raw8` (8-bit) or `raw16le` (16-bit LE, shown as 8-bit).
/// With `bayer`, also emits the 4 debayered phases so the correct one is obvious on a lit scene.
pub fn decode(
    raw_path: &Path,
    width: usize,
    height: usize,
    pix: &str,
    bayer: bool,
    out_prefix: &str,
) -> Result<()> {
    let data = std::fs::read(raw_path).with_context(|| format!("reading {}", raw_path.display()))?;
    let gray: Vec<u8> = match pix {
        "raw8" => {
            anyhow::ensure!(data.len() >= width * height, "raw8 needs {} bytes, got {}", width * height, data.len());
            data[..width * height].to_vec()
        }
        "raw16le" | "raw16" => {
            anyhow::ensure!(data.len() >= width * height * 2, "raw16 needs {} bytes, got {}", width * height * 2, data.len());
            data.chunks_exact(2).take(width * height).map(|c| (u16::from_le_bytes([c[0], c[1]]) >> 8) as u8).collect()
        }
        other => bail!("unknown --pix '{other}' (raw8 | raw16le)"),
    };
    let img = image::GrayImage::from_raw(width as u32, height as u32, gray.clone())
        .context("frame size mismatch")?;
    let gpath = format!("{out_prefix}_gray.png");
    img.save(&gpath)?;
    println!("wrote {gpath} ({width}x{height} grayscale)");
    if bayer {
        for (ph, name) in Bayer::ALL {
            let (w, h, rgb) = debayer_half(&gray, width, height, ph);
            let img = image::RgbImage::from_raw(w, h, rgb).context("rgb size mismatch")?;
            let p = format!("{out_prefix}_{name}.png");
            img.save(&p)?;
            println!("wrote {p} ({w}x{h} debayered {name})");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factors_known_camera_frame() {
        // An example full-sensor frame: 3328 x 2548 RAW8 = 8,479,744 bytes. Must appear as a candidate.
        let c = factor_candidates(3328 * 2548);
        assert!(
            c.iter().any(|x| x.w == 3328 && x.h == 2548 && x.bpp == 1),
            "3328x2548 raw8 not among candidates: {:?}",
            c.iter().map(|x| (x.w, x.h, x.bpp)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn factors_clean_16_9() {
        // 1280x720 RAW8 is an exact 16:9 candidate (note 921600 also factors as 960x960 1:1, so
        // several exact-ratio candidates tie — frame-guess ranks, the human/scene picks).
        let c = factor_candidates(1280 * 720);
        let hit = c.iter().find(|x| x.w == 1280 && x.h == 720 && x.bpp == 1).expect("1280x720 present");
        assert!(hit.err < 1e-9, "16:9 should be an exact match");
        assert_eq!(hit.ratio, "16:9");
    }

    #[test]
    fn time_gap_segments_on_readout_gap() {
        // 3 URBs per frame, then a big inter-frame gap. ts in ns, 1ms intra, 100ms inter.
        let mk = |t: i64| (t, 100usize);
        let xf = vec![
            mk(0), mk(1_000_000), mk(2_000_000),        // frame 1
            mk(102_000_000), mk(103_000_000), mk(104_000_000), // frame 2 after 100ms gap
        ];
        let (frames, starts) = segment_time_gap(&xf);
        assert_eq!(frames, vec![300, 300], "two 3-URB frames of 300 bytes");
        assert_eq!(starts, vec![0, 102_000_000]);
    }

    #[test]
    fn short_packet_ends_frame() {
        let xf = vec![(0, 100), (1, 100), (2, 40), (3, 100), (4, 100), (5, 40)];
        let (frames, _) = segment_short_packet(&xf, 100);
        assert_eq!(frames, vec![240, 240]);
    }
}
