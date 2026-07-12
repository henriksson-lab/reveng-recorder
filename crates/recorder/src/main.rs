//! `reveng-rec` — record reverse-engineering sessions and query them.
//!
//! This is the surface an LLM/agent drives (DESIGN.md §8a.1, §11). Handlers are stubs
//! in this scaffold; the flag set is complete so `--help` documents the intended tool.

mod elevate;
mod query;
mod record;
mod record_usb;

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
    /// Install reveng-pcidrv as an upper filter on a PCI device and restart it (M2 interrupts).
    PciAttach {
        /// Target device, `SSSS:BB:DD.F` (e.g. 0000:0d:00.0).
        #[arg(long)]
        pci_bdf: String,
    },
    /// Remove reveng-pcidrv's upper filter from a PCI device and restart it.
    PciDetach {
        #[arg(long)]
        pci_bdf: String,
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

/// Which live PCIe backend to drive (DESIGN.md §4a). `drv` = the reveng-pcidrv config-space
/// driver (M1); `etw` = the NT Kernel Logger ISR consumer (M2 interrupts, no driver).
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum PciBackend {
    Drv,
    Etw,
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
    /// Live PCIe backend: `drv` (config-space driver, M1) or `etw` (interrupt/ISR capture, M2).
    #[arg(long, value_enum, default_value_t = PciBackend::Drv)]
    pci_backend: PciBackend,
    /// ETW-only: restrict IRQ capture to these IDT vectors (comma-separated, hex `0x81` or
    /// decimal). Empty = capture every ISR (histogram offline to find the device's vector).
    #[arg(long)]
    irq_vectors: Option<String>,
    #[arg(long)]
    pci_vidpid: Option<String>,
    #[arg(long)]
    pci_bdf: Option<String>,
    /// M3: periodically snapshot the attached filter's MMIO BARs and emit register-change events
    /// (needs `pci-attach` first; drv backend). Read-only register-state diff, not per-access.
    #[arg(long)]
    trace_mmio: bool,
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

    /// Stop automatically after this many seconds (for automation; default: run until the
    /// stop hotkey Ctrl+Alt+Pause).
    #[arg(long)]
    max_seconds: Option<u64>,

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
        Cmd::Devices { format } => run_devices(format),
        Cmd::PciDevices { format } => run_pci_devices(format),
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
        Cmd::Stream {
            session,
            ep,
            logical,
        } => query::stream(&session, parse_bar(Some(&ep)), logical),
        Cmd::Payload {
            session,
            frame,
            format,
        } => query::payload(&session, frame, payload_fmt(format)),
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
        Cmd::Export {
            session,
            checkpoint,
            range,
            out,
            wireshark,
        } => run_export(&session, checkpoint, range.as_deref(), out, wireshark),
        Cmd::PciAttach { pci_bdf } => run_pci_filter(&pci_bdf, true),
        Cmd::PciDetach { pci_bdf } => run_pci_filter(&pci_bdf, false),
    }
}

/// Install or remove the reveng-pcidrv upper filter on a PCI device (M2). Needs admin; the
/// SetClassInstaller restart re-enumerates the device so PnP (un)loads our filter.
fn run_pci_filter(bdf: &str, attach: bool) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        if !elevate::is_elevated() && std::env::var_os("REVENG_NO_ELEVATE").is_none() {
            eprintln!("filter (un)install needs administrator rights — requesting elevation…");
            let forward: Vec<String> = std::env::args().skip(1).collect();
            let code = elevate::relaunch_elevated(&forward)?;
            std::process::exit(code as i32);
        }
        let t = parse_bdf(bdf)?;
        if attach {
            reveng_pcicap::filter::attach(t.bus, t.device, t.function)?;
            eprintln!(
                "attached reveng-pcidrv as upper filter on {bdf} and restarted it — capture IRQs \
                 with `record --source pcie` (ReadFile drains the ISR ring)"
            );
        } else {
            reveng_pcicap::filter::detach(t.bus, t.device, t.function)?;
            eprintln!("removed reveng-pcidrv filter from {bdf} and restarted it");
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (bdf, attach);
        anyhow::bail!("PCI filter (un)install requires Windows")
    }
}

/// Export a pcapng slice around a checkpoint / range, or open Wireshark at that frame
/// (DESIGN.md §10). USB-only — PCIe has no pcapng.
fn run_export(
    session: &std::path::Path,
    checkpoint: Option<u64>,
    range: Option<&str>,
    out: Option<PathBuf>,
    wireshark: bool,
) -> anyhow::Result<()> {
    use reveng_core::session::SessionReader;

    /// Frames of context to include on each side of a single-checkpoint export.
    const CONTEXT: u64 = 25;

    let s = SessionReader::open(session)?;
    let pcapng = s.usb_pcapng();
    if !pcapng.exists() {
        anyhow::bail!("export requires a USB session (usb.pcapng); PCIe sessions have no pcapng");
    }

    // Resolve the target frame range (and the primary frame, for the Wireshark jump).
    let (start, end, primary) = if let Some(ckpt) = checkpoint {
        let c = s.checkpoint(ckpt)?;
        let anchor = c
            .anchor
            .map(|a| a.event_index)
            .ok_or_else(|| anyhow::anyhow!("checkpoint {ckpt} has no traffic anchor"))?;
        (anchor.saturating_sub(CONTEXT), anchor + CONTEXT, anchor)
    } else if let Some(r) = range {
        let (a, b) = r
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("range must be A:B, e.g. 100:160"))?;
        let a: u64 = a.trim().parse()?;
        let b: u64 = b.trim().parse()?;
        (a.min(b), a.max(b), a.min(b))
    } else if wireshark {
        (0, 0, 0) // open the whole capture at packet 1
    } else {
        anyhow::bail!("export needs --checkpoint <n> or --range <a:b> (or --wireshark)");
    };

    if wireshark {
        // Wireshark packet numbers are 1-based; our frame indices are 0-based.
        reveng_export::open_in_wireshark(&pcapng, primary + 1)?;
        eprintln!("opened Wireshark on {} at packet {}", pcapng.display(), primary + 1);
        return Ok(());
    }

    let out = out.unwrap_or_else(|| session.join(format!("export_{start}_{end}.pcapng")));
    reveng_export::slice_pcapng(&pcapng, start, end, &out)?;
    eprintln!("exported frames {start}..={end} -> {}", out.display());
    Ok(())
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
            if let Some(replay) = args.replay.as_ref() {
                let out = args.out.clone().unwrap_or_else(|| default_out(replay));
                let summary = record::run_pcie_replay(&out, replay, &cfg)?;
                eprintln!(
                    "recorded {} PCIe events, {} checkpoints -> {}",
                    summary.events,
                    summary.checkpoints,
                    out.display()
                );
                return Ok(());
            }
            // Live capture (§4a lighter tier). Both backends open kernel facilities that need
            // admin — self-elevate like the USB path.
            #[cfg(windows)]
            {
                if !elevate::is_elevated() && std::env::var_os("REVENG_NO_ELEVATE").is_none() {
                    eprintln!("PCIe capture needs administrator rights — requesting elevation…");
                    let forward: Vec<String> = std::env::args().skip(1).collect();
                    let code = elevate::relaunch_elevated(&forward)?;
                    std::process::exit(code as i32);
                }
                let out = args.out.clone().unwrap_or_else(default_session_dir);
                let summary = match args.pci_backend {
                    PciBackend::Drv => {
                        let target = resolve_pci_target(&args)?;
                        let max = args.max_seconds.map(std::time::Duration::from_secs);
                        record::run_pcie_live(
                            &out, target, max, args.trace_mmio, args.trace_dma, &cfg,
                        )?
                    }
                    PciBackend::Etw => {
                        let vectors = parse_irq_vectors(args.irq_vectors.as_deref())?;
                        let max = args.max_seconds.map(std::time::Duration::from_secs);
                        record::run_pcie_etw(&out, vectors, max, &cfg)?
                    }
                };
                eprintln!(
                    "recorded {} PCIe events, {} checkpoints -> {}",
                    summary.events,
                    summary.checkpoints,
                    out.display()
                );
                Ok(())
            }
            #[cfg(not(windows))]
            {
                anyhow::bail!(
                    "live PCIe capture requires Windows + the reveng-pcidrv driver; use --replay <events.jsonl> here"
                )
            }
        }
        Source::Usb => {
            // Passive USB capture opens \\.\USBPcapN, which needs admin. If we're not elevated,
            // relaunch ourselves through UAC (a consent/password prompt) rather than making the
            // user open an elevated shell. `REVENG_NO_ELEVATE` opts out.
            #[cfg(windows)]
            {
                if !elevate::is_elevated() && std::env::var_os("REVENG_NO_ELEVATE").is_none() {
                    eprintln!("USB capture needs administrator rights — requesting elevation…");
                    let forward: Vec<String> = std::env::args().skip(1).collect();
                    let code = elevate::relaunch_elevated(&forward)?;
                    std::process::exit(code as i32);
                }
            }

            let out = args.out.clone().unwrap_or_else(default_session_dir);
            let opts = build_usb_opts(&args, cfg)?;
            let summary = record_usb::run_usb_capture(&out, opts)?;
            eprintln!(
                "recorded {} USB frames, {} checkpoints -> {}",
                summary.events,
                summary.checkpoints,
                out.display()
            );
            Ok(())
        }
    }
}

/// Assemble the live-USB recording options from CLI args, resolving VID:PID → address via
/// device enumeration when only a VID:PID was given (DESIGN.md §11.1).
fn build_usb_opts(
    args: &RecordArgs,
    cfg: CheckpointConfig,
) -> anyhow::Result<record_usb::UsbRecordOpts> {
    use reveng_usbcap::UsbSelection;

    let mut address = args.device_address.clone();
    let mut usbpcap_device = args.usbpcap_device.clone();

    // Enumerate at most once, only if we actually need it (VID:PID resolution or
    // control-device auto-pick), and reuse the result for both.
    let need_resolve = address.is_empty() && !args.device_vidpid.is_empty();
    let need_autopick = usbpcap_device.is_none();
    if need_resolve || need_autopick {
        if let Ok(devs) = reveng_usbcap::list_devices() {
            if need_resolve {
                for want in &args.device_vidpid {
                    let (wv, wp) = want.split_once(':').unwrap_or((want.as_str(), ""));
                    for d in &devs {
                        if d.vid.eq_ignore_ascii_case(wv) && d.pid.eq_ignore_ascii_case(wp) {
                            address.push(d.address);
                            // Prefer the matched device's own control device — correct even
                            // when several root hubs are present.
                            if usbpcap_device.is_none() && !d.usbpcap.is_empty() {
                                usbpcap_device = Some(d.usbpcap.clone());
                            }
                        }
                    }
                }
            }
            // Fall back to auto-picking when there's exactly one live root-hub filter.
            if usbpcap_device.is_none() {
                let hubs: std::collections::BTreeSet<_> = devs
                    .iter()
                    .map(|d| d.usbpcap.clone())
                    .filter(|s| !s.is_empty())
                    .collect();
                if hubs.len() == 1 {
                    usbpcap_device = hubs.into_iter().next();
                }
            }
        }
    }

    let selection = UsbSelection {
        usbpcap_device,
        vidpid: args.device_vidpid.clone(),
        serial: args.device_serial.clone(),
        address,
        all_devices: args.all_devices,
    };

    Ok(record_usb::UsbRecordOpts {
        selection,
        cfg,
        screenshot_on: match args.screenshot_on {
            ScreenshotOn::Mousedown => record_usb::ScreenshotWhen::Mousedown,
            ScreenshotOn::Mouseup => record_usb::ScreenshotWhen::Mouseup,
            ScreenshotOn::Both => record_usb::ScreenshotWhen::Both,
            ScreenshotOn::None => record_usb::ScreenshotWhen::None,
        },
        screenshot_on_keys: !args.no_screenshot_on_keys,
        scope: match args.screenshot_scope {
            ScreenshotScope::CursorMonitor => reveng_winshot::Scope::CursorMonitor,
            ScreenshotScope::All => reveng_winshot::Scope::All,
            ScreenshotScope::ForegroundWindow => reveng_winshot::Scope::ForegroundWindow,
        },
        min_interval_ms: args.screenshot_min_interval_ms,
        stop_vk: 0x13, // VK_PAUSE (Ctrl+Alt+Pause)
        max_duration: args.max_seconds.map(std::time::Duration::from_secs),
    })
}

/// Resolve the live PCIe capture target (BDF) from `--pci-bdf` or `--pci-vidpid`.
#[cfg(windows)]
fn resolve_pci_target(args: &RecordArgs) -> anyhow::Result<reveng_pcicap::drv::Bdf> {
    if let Some(bdf) = &args.pci_bdf {
        return parse_bdf(bdf);
    }
    if let Some(vidpid) = &args.pci_vidpid {
        let (wv, wp) = vidpid
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("--pci-vidpid must be VID:PID (hex)"))?;
        for d in reveng_pcicap::list_pci_devices()? {
            if d.vid.eq_ignore_ascii_case(wv) && d.pid.eq_ignore_ascii_case(wp) {
                return parse_bdf(&d.bdf);
            }
        }
        anyhow::bail!("no PCI device matching {vidpid}");
    }
    anyhow::bail!("live PCIe capture needs --pci-bdf <seg:bus:dev.func> or --pci-vidpid <vid:pid>")
}

/// Parse `SSSS:BB:DD.F` — segment/bus/device hex, function decimal (e.g. `0000:03:00.0`).
#[cfg(windows)]
fn parse_bdf(s: &str) -> anyhow::Result<reveng_pcicap::drv::Bdf> {
    let err = || anyhow::anyhow!("bad BDF '{s}', expected SSSS:BB:DD.F (e.g. 0000:03:00.0)");
    let (seg, rest) = s.split_once(':').ok_or_else(err)?;
    let (bus, rest) = rest.split_once(':').ok_or_else(err)?;
    let (dev, func) = rest.split_once('.').ok_or_else(err)?;
    Ok(reveng_pcicap::drv::Bdf {
        segment: u16::from_str_radix(seg.trim_start_matches("0x"), 16).map_err(|_| err())?,
        bus: u8::from_str_radix(bus, 16).map_err(|_| err())?,
        device: u8::from_str_radix(dev, 16).map_err(|_| err())?,
        function: func.parse().map_err(|_| err())?,
    })
}

/// Parse `--irq-vectors` (comma-separated IDT vectors, hex `0x81` or decimal). None/empty → [].
#[cfg(windows)]
fn parse_irq_vectors(s: Option<&str>) -> anyhow::Result<Vec<u16>> {
    let Some(s) = s else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for tok in s.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        let v = if let Some(hex) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
            u16::from_str_radix(hex, 16)
        } else {
            tok.parse::<u16>()
        }
        .map_err(|_| anyhow::anyhow!("bad --irq-vectors entry '{tok}' (use hex 0x81 or decimal)"))?;
        out.push(v);
    }
    Ok(out)
}

/// Default session directory: `./session_<unix_secs>`.
fn default_session_dir() -> PathBuf {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    PathBuf::from(format!("session_{secs}"))
}

/// `devices` — enumerate the USB tree for picking a capture target (DESIGN.md §11.1).
fn run_devices(format: OutFormat) -> anyhow::Result<()> {
    let devs = reveng_usbcap::list_devices()?;
    match format {
        OutFormat::Json => {
            for d in &devs {
                println!("{}", serde_json::to_string(d)?);
            }
        }
        _ => {
            if devs.is_empty() {
                eprintln!("(no USB devices reported by USBPcapCMD)");
            }
            for d in &devs {
                println!(
                    "{}  bus {} addr {}  {}:{}  {}",
                    d.usbpcap, d.bus, d.address, d.vid, d.pid, d.product
                );
            }
        }
    }
    Ok(())
}

/// `pci-devices` — enumerate PCI(e) devices for picking a PCIe capture target (§4a/§11).
fn run_pci_devices(format: OutFormat) -> anyhow::Result<()> {
    let devs = reveng_pcicap::list_pci_devices()?;
    match format {
        OutFormat::Json => {
            for d in &devs {
                println!("{}", serde_json::to_string(d)?);
            }
        }
        _ => {
            for d in &devs {
                println!(
                    "{}  {}:{}  class {}  {}",
                    d.bdf,
                    if d.vid.is_empty() { "----" } else { &d.vid },
                    if d.pid.is_empty() { "----" } else { &d.pid },
                    if d.class.is_empty() { "------" } else { &d.class },
                    d.description
                );
            }
        }
    }
    Ok(())
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

/// Map the CLI's output format onto the payload renderer.
fn payload_fmt(f: OutFormat) -> query::PayloadFmt {
    match f {
        OutFormat::Hex => query::PayloadFmt::Hex,
        OutFormat::Bin => query::PayloadFmt::Bin,
        OutFormat::Base64 => query::PayloadFmt::Base64,
        OutFormat::Json | OutFormat::Text => query::PayloadFmt::Json,
    }
}
