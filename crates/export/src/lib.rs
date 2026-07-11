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

/// Launch Wireshark on `pcapng`, jumping to `frame_number` (`-g`).
pub fn open_in_wireshark(_pcapng: &Path, _frame_number: u64) -> anyhow::Result<()> {
    // TODO: spawn `wireshark.exe -r <pcapng> -g <frame_number>`.
    anyhow::bail!("Wireshark handoff not yet implemented")
}
