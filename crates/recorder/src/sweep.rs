//! `sweep` — one-command single-variable capture. Records USB while driving a UIA control across a
//! list of values (with settling pauses), then correlates each value with the control-transfer
//! burst it produced (via `query::sweep_correlate`) and writes a `value → bytes` CSV ready for
//! `solve`. Turns "decode a protocol field" into a button press.
//!
//! The recorder runs as a self-elevating subprocess (needs admin for USBPcap); this process only
//! drives the UI (no admin). Windows-only for the driving step (UIA). Correlation is ordinal — the
//! driven values are matched to the last N transaction bursts — so `sweep` is the only device
//! activity that should be happening during the run.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::time::Duration;

#[allow(clippy::too_many_arguments)]
pub fn run(
    device_vidpid: &str,
    window: &str,
    control: &str,
    values: &[f64],
    pause_s: f64,
    out: PathBuf,
    req_type: Option<&str>,
    field: &str,
) -> Result<()> {
    let startup = 12u64;
    let dur = startup + (values.len() as f64 * (pause_s + 1.0)).ceil() as u64 + 15;

    let exe = std::env::current_exe()?;
    let mut child = std::process::Command::new(&exe)
        .args([
            "record",
            "--source",
            "usb",
            "--device-vidpid",
            device_vidpid,
            "--headless",
            "--drop-bulk",
            "--usb-snaplen",
            "4096",
            "--max-seconds",
            &dur.to_string(),
            "--out",
        ])
        .arg(&out)
        .spawn()
        .context("failed to launch the recorder subprocess")?;

    eprintln!("recording ~{dur}s to {}; waiting {startup}s for capture startup…", out.display());
    std::thread::sleep(Duration::from_secs(startup));

    eprintln!("driving {control:?} in {window:?} through {} values:", values.len());
    for v in values {
        match reveng_winui::set_range(window, control, *v)? {
            Some(actual) => eprintln!("  set {control} = {v}  (readback {actual})"),
            None => eprintln!("  WARN: no Slider/Spinner named {control:?} in a {window:?} window"),
        }
        std::thread::sleep(Duration::from_secs_f64(pause_s));
    }

    eprintln!("sweep done; waiting for the recording to finish…");
    let _ = child.wait();

    eprintln!("\ncorrelating values with control-transfer bursts:\n");
    let csv = out.join("sweep_pairs.csv");
    crate::query::sweep_correlate(&out, values, req_type, field, Some(&csv))
}
