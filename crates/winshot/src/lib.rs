//! Event-triggered screenshots (DESIGN.md §6).

use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub enum Scope {
    CursorMonitor,
    All,
    ForegroundWindow,
}

/// Grab a screenshot and write it (PNG) to `out`. Windows-only.
///
/// GDI `BitBlt` by default; DXGI Desktop Duplication is the opt-in high-rate path.
pub fn capture_to(_out: &Path, _scope: Scope) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        // TODO: BitBlt from the screen DC (or DXGI), encode PNG on a worker thread.
        anyhow::bail!("screen capture not yet implemented")
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("screen capture requires Windows")
    }
}
