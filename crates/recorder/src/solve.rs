//! `solve` — brute-force the fixed transform behind an obfuscated register field. Given a CSV of
//! `(known variable, wire bytes…)` pairs (e.g. from a `sweep`), search per-byte XOR keys, 16-bit
//! byte pairings, and inversion for the transform whose result is most linear in the variable
//! (|Pearson r| → 1) — then report the fitted formula. Generalizes the one-off decode that cracked
//! a camera's obfuscated exposure encoding (a per-byte XOR key + a linear scale).

use anyhow::{Context, Result};
use std::path::Path;

fn pearson(xs: &[f64], ys: &[f64]) -> f64 {
    let n = xs.len() as f64;
    if n < 2.0 {
        return 0.0;
    }
    let (mx, my) = (xs.iter().sum::<f64>() / n, ys.iter().sum::<f64>() / n);
    let (mut sxy, mut sxx, mut syy) = (0.0, 0.0, 0.0);
    for (&x, &y) in xs.iter().zip(ys) {
        sxy += (x - mx) * (y - my);
        sxx += (x - mx).powi(2);
        syy += (y - my).powi(2);
    }
    if sxx == 0.0 || syy == 0.0 {
        0.0
    } else {
        sxy / (sxx.sqrt() * syy.sqrt())
    }
}

/// Parse a byte from hex (`1f`, `0x1F`) or decimal.
fn parse_byte(s: &str) -> Option<u8> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x") {
        return u8::from_str_radix(h, 16).ok();
    }
    if s.len() == 2 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(v) = u8::from_str_radix(s, 16) {
            return Some(v);
        }
    }
    s.parse::<u8>().ok()
}

struct Cand {
    r: f64,
    desc: String,
    var_form: &'static str,
    slope: f64,
    intercept: f64,
}

pub fn run(
    csv: &Path,
    var_col: usize,
    byte_cols: &[usize],
    filter: Option<(usize, String)>,
) -> Result<()> {
    let text = std::fs::read_to_string(csv).with_context(|| format!("reading {}", csv.display()))?;
    let mut vars: Vec<f64> = Vec::new();
    let mut rows: Vec<Vec<u8>> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if let Some((c, v)) = &filter {
            if f.get(*c).map(|x| x != v).unwrap_or(true) {
                continue;
            }
        }
        let Some(var) = f.get(var_col).and_then(|s| s.parse::<f64>().ok()) else {
            continue; // header / non-numeric row
        };
        let bytes: Option<Vec<u8>> = byte_cols
            .iter()
            .map(|&c| f.get(c).and_then(|s| parse_byte(s)))
            .collect();
        if let Some(b) = bytes {
            vars.push(var);
            rows.push(b);
        }
    }
    let nrows = vars.len();
    anyhow::ensure!(nrows >= 3, "need >=3 usable rows, got {nrows}");
    let nb = byte_cols.len();
    eprintln!("solve: {nrows} rows, {nb} byte columns {byte_cols:?}, var col {var_col}");

    // Try the variable as-is and under simple nonlinear reparametrisations, so a field that's
    // linear in 1/var (e.g. an analog-gain register) or ln(var) is found too. Best form wins.
    let var_forms: Vec<(&'static str, Vec<f64>)> = vec![
        ("var", vars.clone()),
        ("1/var", vars.iter().map(|&v| if v != 0.0 { 1.0 / v } else { f64::NAN }).collect()),
        ("ln var", vars.iter().map(|&v| if v > 0.0 { v.ln() } else { f64::NAN }).collect()),
    ];
    let var_forms: Vec<(&'static str, Vec<f64>)> = var_forms
        .into_iter()
        .filter(|(_, xs)| xs.iter().all(|x| x.is_finite()))
        .collect();

    // Best (|r|, var-form, slope, intercept) for `value = slope·f(var) + intercept`.
    let fit = |ys: &[f64]| -> (f64, &'static str, f64, f64) {
        let mut best = (0.0f64, "var", 0.0, 0.0);
        for (name, xs) in &var_forms {
            let r = pearson(xs, ys).abs();
            if r > best.0 {
                let n = xs.len() as f64;
                let (mx, my) = (xs.iter().sum::<f64>() / n, ys.iter().sum::<f64>() / n);
                let (mut sxy, mut sxx) = (0.0, 0.0);
                for (&x, &y) in xs.iter().zip(ys) {
                    sxy += (x - mx) * (y - my);
                    sxx += (x - mx).powi(2);
                }
                let slope = if sxx == 0.0 { 0.0 } else { sxy / sxx };
                best = (r, name, slope, my - slope * mx);
            }
        }
        best
    };

    let byte = |row: usize, bi: usize| rows[row][bi] as i64;
    let mut best: Vec<Cand> = Vec::new();
    let mut push = |r: f64, desc: String, var_form: &'static str, slope: f64, intercept: f64| {
        if r > 0.9 {
            best.push(Cand { r, desc, var_form, slope, intercept });
        }
    };

    // Single byte, XOR key.
    for bi in 0..nb {
        for k in 0u16..256 {
            let ys: Vec<f64> = (0..nrows).map(|r| (byte(r, bi) ^ k as i64) as f64).collect();
            let (r, vf, s, ic) = fit(&ys);
            push(r, format!("col{}^0x{:02x}", byte_cols[bi], k), vf, s, ic);
        }
    }
    // 16-bit big-endian pair, independent XOR keys, optional 16-bit invert.
    for h in 0..nb {
        for l in 0..nb {
            if h == l {
                continue;
            }
            for kh in 0u16..256 {
                for kl in 0u16..256 {
                    let raw: Vec<i64> = (0..nrows)
                        .map(|r| ((byte(r, h) ^ kh as i64) << 8) | (byte(r, l) ^ kl as i64))
                        .collect();
                    for &inv in &[false, true] {
                        let ys: Vec<f64> = raw
                            .iter()
                            .map(|&v| if inv { (0xffff - v) as f64 } else { v as f64 })
                            .collect();
                        let (r, vf, s, ic) = fit(&ys);
                        if r > 0.985 {
                            let d = format!(
                                "(col{}^{:02x}:col{}^{:02x}){}",
                                byte_cols[h], kh, byte_cols[l], kl,
                                if inv { " inv16" } else { "" }
                            );
                            push(r, d, vf, s, ic);
                        }
                    }
                }
            }
        }
    }

    best.sort_by(|a, b| b.r.total_cmp(&a.r));
    best.dedup_by(|a, b| (a.r - b.r).abs() < 1e-9 && a.desc.split('^').next() == b.desc.split('^').next());
    println!("Top transforms (value = transform(bytes), by |Pearson r| vs the variable):\n");
    for c in best.iter().take(12) {
        let extra = if c.var_form == "var" && c.slope != 0.0 {
            format!("  (1/slope = {:.3})", 1.0 / c.slope)
        } else {
            String::new()
        };
        println!(
            "|r|={:.5}  {:<28}  value ≈ {:.5}·({}) + {:.2}{extra}",
            c.r, c.desc, c.slope, c.var_form, c.intercept
        );
    }
    if best.is_empty() {
        println!("(no transform reached |r|>0.9 — try more/cleaner data points or a nonlinear variable, e.g. 1/x)");
    }
    Ok(())
}
