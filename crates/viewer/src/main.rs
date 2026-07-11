//! `reveng-viewer` — egui timeline + screenshot pane + USB inspector (DESIGN.md §9).
//!
//! GUI is not yet implemented in this scaffold; this validates that a session path can
//! be opened and reports what the viewer will present.

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "reveng-viewer", version, about = "Session timeline / inspector (GUI TBD)")]
struct Cli {
    /// Session directory to open.
    session: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if !cli.session.is_dir() {
        anyhow::bail!("session directory not found: {}", cli.session.display());
    }
    eprintln!(
        "reveng-viewer: would open {} (timeline + screenshots + USB inspector) — GUI not yet implemented",
        cli.session.display()
    );
    Ok(())
}
