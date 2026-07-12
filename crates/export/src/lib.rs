//! Export / Wireshark handoff (DESIGN.md §10).

use std::path::Path;

/// Write a new pcapng containing frames `[start_frame, end_frame]` (inclusive), sliced
/// from `src_pcapng`. Used by "export slice around checkpoint" (DESIGN.md §10).
pub fn slice_pcapng(
    src_pcapng: &Path,
    start_frame: u64,
    end_frame: u64,
    out: &Path,
) -> anyhow::Result<()> {
    let data = std::fs::read(src_pcapng)?;
    let sliced = reveng_usbcap::pcapng::slice(&data, start_frame, end_frame)?;
    std::fs::write(out, sliced)?;
    Ok(())
}

/// Launch Wireshark on `pcapng`, jumping to `frame_number` (Wireshark's `-g`, which is a
/// 1-based packet number). Does not wait — Wireshark keeps running after we return.
pub fn open_in_wireshark(pcapng: &Path, frame_number: u64) -> anyhow::Result<()> {
    use std::process::Command;

    // Try `wireshark` on PATH first, then the default install locations.
    let candidates = [
        "wireshark".to_string(),
        r"C:\Program Files\Wireshark\Wireshark.exe".to_string(),
        r"C:\Program Files (x86)\Wireshark\Wireshark.exe".to_string(),
    ];
    let mut last_err = None;
    for exe in candidates {
        match Command::new(&exe)
            .arg("-r")
            .arg(pcapng)
            .arg("-g")
            .arg(frame_number.max(1).to_string())
            .spawn()
        {
            Ok(_child) => return Ok(()),
            Err(e) => last_err = Some((exe, e)),
        }
    }
    match last_err {
        Some((exe, e)) => anyhow::bail!(
            "could not launch Wireshark (tried `{exe}` and default install paths): {e}"
        ),
        None => anyhow::bail!("could not launch Wireshark"),
    }
}
