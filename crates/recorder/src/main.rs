//! `reveng-rec` — record reverse-engineering sessions and query them.
//!
//! This is the surface an LLM/agent drives (DESIGN.md §8a.1, §11). Handlers are stubs
//! in this scaffold; the flag set is complete so `--help` documents the intended tool.

mod query;
mod record;

use clap::{Parser, Subcommand, ValueEnum};
use reveng_core::checkpoint::CheckpointConfig;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "reveng-rec", version, about = "Reverse-engineering recorder + query tool")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Record a session (USB or PCIe traffic + input + screenshots).
    Record(RecordArgs),
    /// Enumerate USB devices (for picking a capture target).
    Devices {
        #[arg(long, value_enum, default_value_t = OutFormat::Text)]
        format: OutFormat,
    },
    /// Enumerate PCI(e) devices (BDF, VID:PID, BARs, class).
    PciDevices {
        #[arg(long, value_enum, default_value_t = OutFormat::Text)]
        format: OutFormat,
    },
    /// List checkpoints (the manifest — read this first).
    Ls { session: PathBuf },
    /// Show one checkpoint's full card.
    Show { session: PathBuf, checkpoint: u64 },
    /// Decoded traffic frames near a checkpoint or by range.
    Frames {
        session: PathBuf,
        #[arg(long)]
        around: Option<u64>,
        #[arg(long, short = 'w', default_value_t = 20)]
        window: u64,
        #[arg(long)]
        range: Option<String>, // "10400:10460"
        #[arg(long)]
        ep: Option<String>,
        #[arg(long, value_enum, default_value_t = OutFormat::Json)]
        format: OutFormat,
    },
    /// Reassembled logical messages on an endpoint.
    Stream {
        session: PathBuf,
        #[arg(long)]
        ep: String,
        #[arg(long)]
        logical: bool,
    },
    /// Raw payload bytes of one frame.
    Payload {
        session: PathBuf,
        frame: u64,
        #[arg(long, value_enum, default_value_t = OutFormat::Hex)]
        format: OutFormat,
    },
    /// Frames that differ between two checkpoints.
    Diff { session: PathBuf, a: u64, b: u64 },
    /// Run a candidate decoder over frames and render its output.
    Decode {
        session: PathBuf,
        /// Imperative decoder command (reads/writes JSONL), e.g. "python3 decode.py".
        #[arg(long)]
        with: Option<String>,
        /// Declarative Kaitai Struct definition (not yet wired).
        #[arg(long)]
        ksy: Option<PathBuf>,
        #[arg(long)]
        ep: Option<String>,
    },
    /// Find frames whose payload contains a byte pattern.
    Grep { session: PathBuf, pattern: String },
    /// Rebuild index.sqlite / *.idx from the raw truth.
    Reindex { session: PathBuf },
    /// Export a pcapng slice / open Wireshark at a frame.
    Export {
        session: PathBuf,
        #[arg(long)]
        checkpoint: Option<u64>,
        #[arg(long)]
        range: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        wireshark: bool,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum OutFormat {
    Json,
    Text,
    Hex,
    Base64,
    Bin,
}

#[derive(Copy, Clone, ValueEnum)]
enum Source {
    Usb,
    Pcie,
}

#[derive(Copy, Clone, ValueEnum)]
enum ScreenshotOn {
    Mousedown,
    Mouseup,
    Both,
    None,
}

#[derive(Copy, Clone, ValueEnum)]
enum ScreenshotScope {
    CursorMonitor,
    All,
    ForegroundWindow,
}

#[derive(Copy, Clone, ValueEnum)]
enum ScreenshotFormat {
    Png,
    WebpLossless,
}

#[derive(Copy, Clone, ValueEnum)]
enum DmaMode {
    Descriptor,
    Iommu,
    Off,
}

#[derive(Copy, Clone, ValueEnum)]
enum MmioTraceMode {
    Always,
    AroundCheckpoints,
}

#[derive(Parser)]
struct RecordArgs {
    /// Capture source.
    #[arg(long, value_enum, default_value_t = Source::Usb)]
    source: Source,

    /// Replay a PCIe event JSONL instead of live capture (works on any platform).
    #[arg(long)]
    replay: Option<PathBuf>,

    // ---- USB device selection (§11.1) ----
    #[arg(long)]
    usbpcap_device: Option<String>,
    #[arg(long)]
    device_vidpid: Vec<String>,
    #[arg(long)]
    device_serial: Option<String>,
    #[arg(long)]
    device_address: Vec<u16>,
    #[arg(long)]
    all_devices: bool,
    #[arg(long)]
    endpoints: Option<String>,

    // ---- PCIe selection (§4a) ----
    #[arg(long)]
    pci_vidpid: Option<String>,
    #[arg(long)]
    pci_bdf: Option<String>,
    #[arg(long)]
    mmio_ranges: Option<String>,
    #[arg(long)]
    trace_dma: bool,
    #[arg(long, value_enum, default_value_t = DmaMode::Descriptor)]
    dma_mode: DmaMode,
    #[arg(long, value_enum, default_value_t = MmioTraceMode::Always)]
    mmio_trace_mode: MmioTraceMode,

    // ---- Checkpoint control (§11.2) ----
    #[arg(long)]
    checkpoint_on_any_key: bool,
    #[arg(long)]
    checkpoint_keys: Option<String>,
    #[arg(long)]
    no_checkpoint_keys: bool,
    #[arg(long)]
    checkpoint_key_combos: Option<String>,
    #[arg(long)]
    checkpoint_mouse_buttons: Option<String>,
    #[arg(long)]
    checkpoint_on_mouseup: bool,
    #[arg(long)]
    checkpoint_on_wheel: bool,
    #[arg(long)]
    no_checkpoint_clicks: bool,
    #[arg(long, default_value_t = 1000)]
    interval_checkpoint_ms: u64,
    #[arg(long, default_value_t = 4096)]
    interval_bytes: u64,
    #[arg(long)]
    manual_checkpoint_hotkey: Option<String>,

    // ---- Screenshots & control (§11.3) ----
    #[arg(long, value_enum, default_value_t = ScreenshotOn::Mousedown)]
    screenshot_on: ScreenshotOn,
    #[arg(long)]
    no_screenshot_on_keys: bool,
    #[arg(long, value_enum, default_value_t = ScreenshotScope::CursorMonitor)]
    screenshot_scope: ScreenshotScope,
    #[arg(long, default_value_t = 150)]
    screenshot_min_interval_ms: u64,
    #[arg(long, value_enum, default_value_t = ScreenshotFormat::Png)]
    screenshot_format: ScreenshotFormat,

    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long)]
    stop_hotkey: Option<String>,
    #[arg(long, default_value_t = 0)]
    rotate_mb: u64,

    #[arg(long)]
    config: Option<PathBuf>,
}

fn main() {
    if let Err(e) = run() {
        // A closed downstream pipe (e.g. `... | head`) is not an error for a CLI.
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::BrokenPipe {
                std::process::exit(0);
            }
        }
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Record(args) => run_record(args),
        Cmd::Devices { .. } => not_impl("devices (requires Windows + USBPcap)"),
        Cmd::PciDevices { .. } => not_impl("pci-devices (requires Windows)"),
        Cmd::Ls { session } => query::ls(&session, false),
        Cmd::Show { session, checkpoint } => query::show(&session, checkpoint),
        Cmd::Frames {
            session,
            around,
            window,
            range,
            ep,
            format: _,
        } => query::frames(&session, around, window, range.as_deref(), parse_bar(ep.as_deref())),
        Cmd::Stream { session, ep, .. } => {
            query::frames(&session, None, 0, None, parse_bar(Some(&ep)))
        }
        Cmd::Payload { session, frame, .. } => query::payload(&session, frame),
        Cmd::Diff { session, a, b } => query::diff(&session, a, b),
        Cmd::Decode {
            session,
            with,
            ksy,
            ep,
        } => query::decode(&session, with.as_deref(), ksy.as_deref(), parse_bar(ep.as_deref())),
        // note: Decode.with is a command string (see below)
        Cmd::Grep { session, pattern } => query::grep(&session, &pattern),
        Cmd::Reindex { session } => query::reindex(&session),
        Cmd::Export { .. } => not_impl("export (pcapng slice / Wireshark)"),
    }
}

fn run_record(args: RecordArgs) -> anyhow::Result<()> {
    let mut cfg = CheckpointConfig::default();
    cfg.on_any_key = args.checkpoint_on_any_key;
    if let Some(k) = &args.checkpoint_keys {
        cfg.special_keys = split_csv(k);
    }
    if args.no_checkpoint_keys {
        cfg.special_keys.clear();
        cfg.on_any_key = false;
    }
    if let Some(k) = &args.checkpoint_key_combos {
        cfg.key_combos = split_csv(k);
    }
    if let Some(m) = &args.checkpoint_mouse_buttons {
        cfg.mouse_buttons = split_csv(m);
    }
    if args.no_checkpoint_clicks {
        cfg.mouse_buttons.clear();
    }
    cfg.on_mouseup = args.checkpoint_on_mouseup;
    cfg.on_wheel = args.checkpoint_on_wheel;
    cfg.interval_ms = args.interval_checkpoint_ms;
    cfg.interval_bytes = args.interval_bytes;

    match args.source {
        Source::Pcie => {
            let replay = args.replay.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "live PCIe capture needs the hypervisor driver (Windows); use --replay <events.jsonl> here"
                )
            })?;
            let out = args.out.clone().unwrap_or_else(|| default_out(replay));
            let summary = record::run_pcie_replay(&out, replay, &cfg)?;
            eprintln!(
                "recorded {} events, {} checkpoints -> {}",
                summary.events,
                summary.checkpoints,
                out.display()
            );
            Ok(())
        }
        Source::Usb => anyhow::bail!(
            "USB capture requires Windows + USBPcap (not available on this machine)"
        ),
    }
}

/// Default session dir for a replay: `<replay>.session`.
fn default_out(replay: &std::path::Path) -> PathBuf {
    let mut p = replay.to_path_buf();
    p.set_extension("session");
    p
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

/// Interpret `--ep` as a PCIe BAR number (`0`, `0x1`, …) for filtering.
fn parse_bar(ep: Option<&str>) -> Option<u8> {
    let e = ep?.trim();
    let v = if let Some(h) = e.strip_prefix("0x").or_else(|| e.strip_prefix("0X")) {
        u8::from_str_radix(h, 16).ok()?
    } else {
        e.parse().ok()?
    };
    Some(v)
}

fn not_impl(what: &str) -> anyhow::Result<()> {
    anyhow::bail!("`{what}` not yet implemented on this platform (scaffold)")
}
