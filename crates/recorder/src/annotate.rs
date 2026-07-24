//! `annotate` — apply a device **spec** to a capture, decoding raw control transfers into meaning.
//!
//! A spec (TOML) names requests and registers and describes how to combine registers into
//! high-level fields (deobfuscation XOR + a linear or reciprocal transform). `annotate` folds the
//! capture's control-write history into a register map (reusing [`crate::query::folded_registers`])
//! and applies the spec — turning `PROTOCOL.md` prose into a *reusable, executable* decoder. The
//! `solve` command's output feeds the `[[fields]]` transform parameters.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

#[derive(Deserialize, Default)]
pub struct Spec {
    #[serde(default)]
    pub device: DeviceMeta,
    /// `bRequest` hex → human name, e.g. `"0x40" = "vendor_command"`.
    #[serde(default)]
    pub requests: BTreeMap<String, String>,
    /// `"bRequest:wIndex"` → register name, e.g. `"0x40:0x1000" = "exposure_hi"`.
    #[serde(default)]
    pub registers: BTreeMap<String, String>,
    /// High-level fields decoded from one or more registers.
    #[serde(default)]
    pub fields: Vec<Field>,
}

impl Spec {
    /// Layer `other` on top of `self`: a later spec's `device` name/vidpid, request and register
    /// names override; its fields are appended. This is what makes a shared sensor-knowledge base
    /// (common register names) reusable *under* a per-device spec — the R9 "database feeds R6" goal.
    fn merge(&mut self, other: Spec) {
        if !other.device.name.is_empty() {
            self.device.name = other.device.name;
        }
        if !other.device.vidpid.is_empty() {
            self.device.vidpid = other.device.vidpid;
        }
        self.requests.extend(other.requests);
        self.registers.extend(other.registers);
        self.fields.extend(other.fields);
    }
}

#[derive(Deserialize, Default)]
pub struct DeviceMeta {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub vidpid: String,
}

#[derive(Deserialize)]
pub struct Field {
    pub name: String,
    #[serde(default)]
    pub unit: String,
    /// Registers (`"req:idx"`) combined most-significant-first (see `combine`).
    pub regs: Vec<String>,
    /// XOR mask applied to each register byte before combining (deobfuscation).
    #[serde(default)]
    pub xor: Option<u8>,
    /// Byte order concatenating regs into the raw integer: `"be"` (default) or `"le"`.
    #[serde(default = "be")]
    pub combine: String,
    /// Raw→value transform: `"linear"` (`raw*scale + offset`) or `"reciprocal"` (`num/(den - raw)`).
    #[serde(default = "linear")]
    pub form: String,
    #[serde(default = "one")]
    pub scale: f64,
    #[serde(default)]
    pub offset: f64,
    #[serde(default)]
    pub num: f64,
    #[serde(default = "one")]
    pub den: f64,
}

fn be() -> String {
    "be".into()
}
fn linear() -> String {
    "linear".into()
}
fn one() -> f64 {
    1.0
}

/// Apply a field's deobfuscation + transform to the current register map. Returns `(raw, value)`,
/// or `None` if any of the field's registers hasn't been written yet in this capture.
fn compute(field: &Field, regs: &BTreeMap<(String, String), (u8, i64)>) -> Option<(u64, f64)> {
    let mut bytes = Vec::with_capacity(field.regs.len());
    for key in &field.regs {
        let (req, idx) = key.split_once(':')?;
        let (b, _) = regs.get(&(req.trim().to_string(), idx.trim().to_string()))?;
        bytes.push(field.xor.map(|m| b ^ m).unwrap_or(*b));
    }
    if field.combine == "le" {
        bytes.reverse();
    }
    let raw = bytes.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64);
    let value = match field.form.as_str() {
        "reciprocal" => field.num / (field.den - raw as f64),
        _ => raw as f64 * field.scale + field.offset,
    };
    Some((raw, value))
}

/// Load and layer one or more spec files (later files override names / append fields).
fn load_specs(spec_paths: &[std::path::PathBuf]) -> Result<Spec> {
    let mut spec = Spec::default();
    for p in spec_paths {
        let one: Spec = toml::from_str(
            &std::fs::read_to_string(p).with_context(|| format!("reading spec {}", p.display()))?,
        )
        .with_context(|| format!("parsing spec {}", p.display()))?;
        spec.merge(one);
    }
    Ok(spec)
}

pub fn annotate(
    session_dir: &Path,
    spec_paths: &[std::path::PathBuf],
    at_ckpt: Option<u64>,
    req_type: Option<&str>,
    log: bool,
) -> Result<()> {
    let spec = load_specs(spec_paths)?;

    // Vendor requests are the default target for a device spec; let the spec/flag override.
    let regs = crate::query::folded_registers(session_dir, at_ckpt, req_type.or(Some("vendor")))?;

    let out = std::io::stdout();
    let mut w = out.lock();
    let mut title = if spec.device.name.is_empty() {
        "device".to_string()
    } else {
        spec.device.name.clone()
    };
    if !spec.device.vidpid.is_empty() {
        title = format!("{title} [{}]", spec.device.vidpid);
    }
    writeln!(
        w,
        "{title} decoded from {}{}:",
        session_dir.display(),
        at_ckpt.map(|c| format!(" as of checkpoint {c}")).unwrap_or_default()
    )?;

    if spec.fields.is_empty() {
        writeln!(w, "  (spec defines no [[fields]])")?;
    }
    for f in &spec.fields {
        match compute(f, &regs) {
            Some((raw, val)) => {
                let unit = if f.unit.is_empty() { String::new() } else { format!(" {}", f.unit) };
                writeln!(w, "  {:<18} = {:>12.4}{unit}   (raw 0x{raw:x})", f.name, val)?;
            }
            None => writeln!(w, "  {:<18} = <registers not yet written in this capture>", f.name)?,
        }
    }

    if log {
        writeln!(w, "\nlabeled register state ({} registers):", regs.len())?;
        for ((req, idx), (v, ts)) in &regs {
            let rname = spec.registers.get(&format!("{req}:{idx}")).map(String::as_str).unwrap_or("");
            let reqname = spec.requests.get(req).map(String::as_str).unwrap_or("");
            writeln!(
                w,
                "  {req} {idx} = 0x{v:02x}   {reqname:<16} {rname:<20} (t={:.3}s)",
                *ts as f64 / 1e9
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regmap(pairs: &[(&str, &str, u8)]) -> BTreeMap<(String, String), (u8, i64)> {
        pairs
            .iter()
            .map(|(req, idx, v)| ((req.to_string(), idx.to_string()), (*v, 0)))
            .collect()
    }

    // Neutral synthetic constants (not tied to any specific device): XOR key 0x5A, request 0x40,
    // registers 0x1000/0x1002 (linear field) and 0x2000/0x2002 (reciprocal field).
    fn field(form: &str, regs: &[&str], scale: f64, num: f64, den: f64) -> Field {
        Field {
            name: "f".into(),
            unit: String::new(),
            regs: regs.iter().map(|s| s.to_string()).collect(),
            xor: Some(0x5A),
            combine: "be".into(),
            form: form.into(),
            scale,
            offset: 0.0,
            num,
            den,
        }
    }

    #[test]
    fn linear_field_deobfuscates_and_scales() {
        // Two obfuscated register bytes (0x48, 0x6E) XOR 0x5A → 0x12, 0x34 → big-endian raw 0x1234
        // (4660); linear scale 10.0 → 46600.
        let regs = regmap(&[("0x40", "0x1000", 0x48), ("0x40", "0x1002", 0x6E)]);
        let f = field("linear", &["0x40:0x1000", "0x40:0x1002"], 10.0, 0.0, 1.0);
        let (raw, val) = compute(&f, &regs).unwrap();
        assert_eq!(raw, 4660, "deobfuscated big-endian value");
        assert!((val - 46600.0).abs() < 0.01, "linear value = {val}");
    }

    #[test]
    fn reciprocal_field_form() {
        // Obfuscated (0x5A, 0x66) XOR 0x5A → 0x00, 0x3C → raw 60; reciprocal 1000/(100-60) = 25.
        let regs = regmap(&[("0x40", "0x2000", 0x5A), ("0x40", "0x2002", 0x66)]);
        let f = field("reciprocal", &["0x40:0x2000", "0x40:0x2002"], 1.0, 1000.0, 100.0);
        let (raw, val) = compute(&f, &regs).unwrap();
        assert_eq!(raw, 60);
        assert!((val - 25.0).abs() < 0.01, "reciprocal value = {val}");
    }

    #[test]
    fn later_spec_overrides_and_appends() {
        let base: Spec = toml::from_str(
            r#"
            [device]
            name = "generic sensor"
            [requests]
            "0x40" = "register_write"
            "0x41" = "unknown_channel"
            [registers]
            "0x51:0x3012" = "coarse_integration_time"
            "#,
        )
        .unwrap();
        let device: Spec = toml::from_str(
            r#"
            [device]
            name = "Example Device"
            [requests]
            "0x41" = "vendor_channel"
            [[fields]]
            name = "exposure"
            regs = ["0x41:0x1000"]
            "#,
        )
        .unwrap();
        let mut merged = base;
        merged.merge(device);
        assert_eq!(merged.device.name, "Example Device", "later device name wins");
        assert_eq!(merged.requests.get("0x41").unwrap(), "vendor_channel", "later overrides");
        assert_eq!(merged.requests.get("0x40").unwrap(), "register_write", "base kept");
        assert!(merged.registers.contains_key("0x51:0x3012"), "base register kept");
        assert_eq!(merged.fields.len(), 1, "device fields appended");
    }

    #[test]
    fn missing_register_yields_none() {
        let regs = regmap(&[("0x40", "0x1000", 0x48)]); // 0x1002 absent
        let f = field("linear", &["0x40:0x1000", "0x40:0x1002"], 10.0, 0.0, 1.0);
        assert!(compute(&f, &regs).is_none());
    }
}
