//! `reveng-rec` — record reverse-engineering sessions and query them.
//!
//! This is the surface an LLM/agent drives (DESIGN.md §8a.1, §11). Handlers are stubs
//! in this scaffold; the flag set is complete so `--help` documents the intended tool.

mod elevate;
mod hv;
#[cfg(windows)]
mod notes_ui;
mod query;
mod record;
mod record_usb;

use clap::{Parser, Subcommand, ValueEnum};
use reveng_core::checkpoint::CheckpointConfig;
use reveng_core::clock::Clock;
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
    /// List notes typed during recording (elapsed time + anchored frame + text).
    Notes { session: PathBuf },
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
        /// Reassemble as text: concatenate the endpoint and split on newlines (serial/logs).
        #[arg(long)]
        text: bool,
    },
    /// Raw payload bytes of one frame.
    Payload {
        session: PathBuf,
        frame: u64,
        #[arg(long, value_enum, default_value_t = OutFormat::Auto)]
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
    /// Find frames whose payload contains a byte pattern (or text substring with --text).
    Grep {
        session: PathBuf,
        pattern: String,
        /// Match the pattern as a text substring instead of hex bytes.
        #[arg(long)]
        text: bool,
    },
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
    /// Probe VT-x capability via the reveng-hv driver (hypervisor tier bring-up; read-only).
    HvProbe,
    /// VMXON+VMXOFF on every CPU via reveng-hv (no VMLAUNCH yet) — proves VMX entry works.
    HvVmxtest,
    /// H1 hyperjack self-test: VMLAUNCH on CPU 0, verify via CPUID backdoor, then devirtualize.
    HvSelftest,
    /// Read reveng-hv's diagnostic record (last devirtualize reason/RIP, secondary-ctls status).
    HvDiag,
    /// Process-memory snapshots + before/after delta (the decoded-form oracle).
    Mem {
        #[command(subcommand)]
        cmd: MemCmd,
    },
}

/// `mem` subcommands over a session's `memsnaps/`. See `reveng-memcap`.
#[derive(Subcommand)]
enum MemCmd {
    /// List snapshots taken (id, elapsed, pid, size, anchored frame).
    Ls { session: PathBuf },
    /// Region table for one snapshot.
    Regions { session: PathBuf, id: u64 },
    /// Before→after delta between two snapshots (new/changed/freed regions).
    Diff {
        session: PathBuf,
        a: u64,
        b: u64,
        /// Max bytes shown per changed run.
        #[arg(long, default_value_t = 32)]
        max: usize,
    },
    /// Find a value's encodings in a snapshot (seed with the on-screen number/string).
    Scan { session: PathBuf, id: u64, value: String },
    /// Hex/auto-render a slice of a snapshot at a target address (hex `0x…` or decimal).
    Read {
        session: PathBuf,
        id: u64,
        addr: String,
        len: u64,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum OutFormat {
    Json,
    Text,
    Hex,
    Base64,
    Bin,
    /// Text if the payload classifies as texty, else hex (payload default).
    Auto,
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

    /// Run the recording window without opening a USB capture (input + screenshots + notes
    /// only). Lets you exercise the UI, or take a note/input-only recording, with no USB
    /// device / no USBPcap / no admin.
    #[arg(long)]
    no_capture: bool,

    // ---- USB data-volume reduction (default lossless; opt-in) ----
    /// Driver snaplen: bytes captured per USB transfer (0 = unlimited, lossless). A small cap
    /// (e.g. 256) truncates bulk/isoc firehoses (camera/audio) in the kernel while keeping
    /// control/interrupt intact; the index still records the original on-wire length.
    #[arg(long, default_value_t = 0)]
    usb_snaplen: u32,
    /// Driver kernel buffer size in bytes (0 = default). Larger tolerates bursts.
    #[arg(long, default_value_t = 0)]
    usb_bufsize: u32,
    /// Drop isochronous transfers (camera/audio streaming payload) before writing.
    #[arg(long)]
    drop_isoc: bool,
    /// Drop bulk transfers before writing.
    #[arg(long)]
    drop_bulk: bool,
    /// Opt-in adaptive reduction: keep everything lossless except apply a header-only snaplen
    /// (256 B if unset) and drop isochronous transfers — for high-bandwidth devices (cameras).
    #[arg(long)]
    auto_truncate: bool,

    /// Also capture PCIe concurrently with USB, co-logged into the same session — both wires on
    /// one timeline, each checkpoint anchored to both. Uses the PCIe selection flags
    /// (`--pci-backend drv`, `--pci-bdf`/`--pci-vidpid`, `--trace-mmio`/`--trace-dma`), or
    /// `--pcie-replay <file>` for a portable replayed PCIe stream.
    #[arg(long)]
    with_pcie: bool,
    /// Co-log a replayed PCIe event JSONL (with `--with-pcie`) instead of a live PCIe device.
    #[arg(long)]
    pcie_replay: Option<PathBuf>,

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

    /// Stop once total captured traffic (USB + PCIe) reaches this many bytes (size budget).
    #[arg(long)]
    max_bytes: Option<u64>,

    /// Arm manual process-memory snapshots against this PID: the recording window shows a
    /// Snapshot button; each press dumps the target's committed memory and emits a checkpoint
    /// carrying `mem_snapshot_id`. Query later with `reveng-rec mem diff/scan/ls`. Needs admin +
    /// SeDebugPrivilege (auto-enabled). The decoded-form oracle for when there's no clean export.
    #[arg(long)]
    mem_pid: Option<u32>,

    /// Like `--mem-pid` but resolves the target by image name (first match, e.g. `Vendor.exe`).
    #[arg(long)]
    mem_process: Option<String>,

    /// Compress each memory snapshot on disk (deflate). Smaller `regions.bin`; slight CPU cost.
    #[arg(long)]
    mem_compress: bool,

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
        Cmd::Notes { session } => query::notes(&session),
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
            text,
        } => query::stream(&session, parse_bar(Some(&ep)), logical, text),
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
        Cmd::Grep {
            session,
            pattern,
            text,
        } => query::grep(&session, &pattern, text),
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
        Cmd::HvProbe => run_hv_op(hv::probe),
        Cmd::HvVmxtest => run_hv_op(hv::vmxtest),
        Cmd::HvSelftest => run_hv_op(hv::selftest),
        Cmd::HvDiag => run_hv_op(hv::diag),
        Cmd::Mem { cmd } => match cmd {
            MemCmd::Ls { session } => query::mem_ls(&session),
            MemCmd::Regions { session, id } => query::mem_regions(&session, id),
            MemCmd::Diff { session, a, b, max } => query::mem_diff(&session, a, b, max),
            MemCmd::Scan { session, id, value } => query::mem_scan(&session, id, &value),
            MemCmd::Read { session, id, addr, len } => query::mem_read(&session, id, &addr, len),
        },
    }
}

/// Run a reveng-hv control op, self-elevating first (the control device needs admin).
#[allow(unused_variables)]
fn run_hv_op(op: fn() -> anyhow::Result<()>) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        if !elevate::is_elevated() && std::env::var_os("REVENG_NO_ELEVATE").is_none() {
            eprintln!("reveng-hv control needs administrator rights — requesting elevation…");
            let forward: Vec<String> = std::env::args().skip(1).collect();
            let code = elevate::relaunch_elevated(&forward)?;
            std::process::exit(code as i32);
        }
        op()
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("reveng-hv control requires Windows")
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
            // Interactive drv/replay → the full input-driven engine (clicks→checkpoint+screenshot,
            // notes, window) with PCIe as the primary traffic source — the same model as USB, so a
            // PCIe-only session behaves identically. ETW, headless automation, and non-Windows keep
            // the portable minimal loop (`record.rs`), which is cross-platform and captures no input.
            #[cfg(windows)]
            {
                let headless = args.max_seconds.is_some()
                    || std::env::var_os("REVENG_NO_NOTES_UI").is_some();
                // drv/etw/replay all stop cleanly now, so all can drive the input engine.
                if !headless {
                    return run_pcie_engine_session(&args, cfg.clone());
                }
            }

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
            // Launched with no device specified (and interactive)? Show a checkbox picker of USB +
            // PCIe devices, then relaunch with the chosen ones as explicit args (elevated if
            // needed) — the relaunched process has explicit devices and skips the picker.
            #[cfg(windows)]
            {
                let bare = args.usbpcap_device.is_none()
                    && args.device_vidpid.is_empty()
                    && args.device_address.is_empty()
                    && !args.all_devices
                    && !args.no_capture
                    && !args.with_pcie
                    && args.pcie_replay.is_none();
                let interactive = args.max_seconds.is_none()
                    && std::env::var_os("REVENG_NO_NOTES_UI").is_none()
                    && std::env::var_os("REVENG_NO_PICKER").is_none();
                if bare && interactive {
                    if let Some(code) = run_device_picker_and_relaunch()? {
                        std::process::exit(code);
                    }
                    // (no devices to pick → fall through to the window-only path)
                }
            }

            let out = args.out.clone().unwrap_or_else(default_session_dir);
            let opts = build_usb_opts(&args, cfg)?;

            // A live PCIe co-capture (drv backend, not replay) also opens a kernel device that
            // needs admin.
            let pcie_live = args.with_pcie && args.pcie_replay.is_none();

            // USBPcap + the PCIe driver open kernel devices that need admin. Only elevate when we
            // actually have something live to open — a window-only run (no matching device, or
            // --no-capture) with no live PCIe needs no admin. If not elevated, relaunch through
            // UAC rather than making the user open an elevated shell. `REVENG_NO_ELEVATE` opts out.
            #[cfg(windows)]
            {
                if (!opts.selections.is_empty() || pcie_live)
                    && !elevate::is_elevated()
                    && std::env::var_os("REVENG_NO_ELEVATE").is_none()
                {
                    eprintln!("capture needs administrator rights — requesting elevation…");
                    let forward: Vec<String> = std::env::args().skip(1).collect();
                    let code = elevate::relaunch_elevated(&forward)?;
                    std::process::exit(code as i32);
                }
            }

            if opts.selections.is_empty() && !args.no_capture {
                eprintln!(
                    "no matching USB device/hub found — recording input + screenshots + notes only"
                );
            } else if opts.selections.len() > 1 {
                eprintln!("capturing {} USB hubs in parallel", opts.selections.len());
            }

            let clock = Clock::start();
            let pcie = build_pcie_capture(&args, &clock)?;
            if pcie.is_some() {
                eprintln!("co-logging PCIe into the same session");
            }
            run_engine_session(&out, opts, pcie, clock)
        }
    }
}

/// Run the shared input-driven recording engine (clicks→checkpoint+screenshot, keyboard, notes)
/// over whatever traffic sources `opts`/`pcie` carry — USB, PCIe, both, or neither. Interactive
/// runs get the Slint window; headless (`--max-seconds`/`REVENG_NO_NOTES_UI`) runs windowless.
fn run_engine_session(
    out: &std::path::Path,
    opts: record_usb::UsbRecordOpts,
    pcie: Option<record_usb::PcieCapture>,
    clock: Clock,
) -> anyhow::Result<()> {
    let usb_active = !opts.selections.is_empty();
    let pcie_active = pcie.is_some();
    let mem_active = opts.mem_pid.is_some() || opts.mem_process.is_some();
    let headless =
        opts.max_duration.is_some() || std::env::var_os("REVENG_NO_NOTES_UI").is_some();

    let summary = if headless {
        record_usb::run_usb_capture(clock, out, opts, None, pcie)?
    } else {
        #[cfg(windows)]
        {
            let worker_clock = clock.clone();
            let out2 = out.to_path_buf();
            // Live MMIO/DMA toggles reach the window only for the drv backend (both handles set).
            let trace = pcie.as_ref().and_then(|p| match (&p.trace_mmio, &p.trace_dma) {
                (Some(m), Some(d)) => Some((m.clone(), d.clone())),
                _ => None,
            });
            notes_ui::run_recording_window(clock, out.to_path_buf(), usb_active, pcie_active, mem_active, trace, move |ui| {
                record_usb::run_usb_capture(worker_clock, &out2, opts, Some(ui), pcie)
            })?
        }
        #[cfg(not(windows))]
        {
            record_usb::run_usb_capture(clock, out, opts, None, pcie)?
        }
    };
    if usb_active {
        eprintln!(
            "recorded {} USB frames, {} checkpoints -> {}",
            summary.events,
            summary.checkpoints,
            out.display()
        );
    } else if pcie_active {
        eprintln!("recorded PCIe session, {} checkpoints -> {}", summary.checkpoints, out.display());
    } else {
        eprintln!(
            "recorded {} checkpoints (input + notes only) -> {}",
            summary.checkpoints,
            out.display()
        );
    }
    Ok(())
}

/// State of the `RevengPciCap` (reveng-pcidrv) service that backs live PCIe capture.
#[cfg(windows)]
enum DrvStatus {
    Running,
    Stopped,
    NotInstalled,
}

/// Run `sc <args>` without flashing a console window (for the GUI path).
#[cfg(windows)]
fn sc(args: &[&str]) -> std::io::Result<std::process::Output> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    std::process::Command::new("sc")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
}

/// Query the reveng-pcidrv service state (read-only; works unelevated).
#[cfg(windows)]
fn drv_status() -> DrvStatus {
    match sc(&["query", "RevengPciCap"]) {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("RUNNING") {
                DrvStatus::Running
            } else if s.contains("STOP") {
                DrvStatus::Stopped // STOPPED / STOP_PENDING
            } else {
                DrvStatus::NotInstalled // e.g. 1060 "service does not exist"
            }
        }
        Err(_) => DrvStatus::NotInstalled,
    }
}

/// Start the reveng-pcidrv service if it's registered but stopped (needs admin). No-op if
/// already running; a failure is returned so the caller can fall back gracefully.
#[cfg(windows)]
fn ensure_drv_running() -> anyhow::Result<()> {
    if matches!(drv_status(), DrvStatus::Running) {
        return Ok(());
    }
    if matches!(drv_status(), DrvStatus::NotInstalled) {
        anyhow::bail!("reveng-pcidrv (RevengPciCap) is not installed");
    }
    eprintln!("loading reveng-pcidrv (starting the RevengPciCap service)…");
    let o = sc(&["start", "RevengPciCap"])?;
    let s = String::from_utf8_lossy(&o.stdout);
    if s.contains("RUNNING") || s.contains("START_PENDING") {
        Ok(())
    } else {
        anyhow::bail!("could not start RevengPciCap: {}", s.trim())
    }
}

/// Enumerate USB + PCIe devices, show the picker, and relaunch with the chosen devices as
/// explicit args (elevated if not already). Returns `Some(exit_code)` when the picker ran (the
/// caller should exit with it), or `None` when there was nothing to pick (fall through to the
/// window-only path). Opt out with `REVENG_NO_PICKER`.
#[cfg(windows)]
fn run_device_picker_and_relaunch() -> anyhow::Result<Option<i32>> {
    let usb: Vec<(String, String)> = reveng_usbcap::list_devices()
        .unwrap_or_default()
        .iter()
        .filter(|d| !d.usbpcap.is_empty())
        .map(|d| {
            (
                format!("{}:{} {}  (bus {} addr {})", d.vid, d.pid, d.product, d.bus, d.address),
                format!("{}:{}", d.vid, d.pid),
            )
        })
        .collect();
    let pci: Vec<(String, String)> = reveng_pcicap::list_pci_devices()
        .unwrap_or_default()
        .iter()
        .filter(|d| !d.vid.is_empty())
        .map(|d| (format!("{}  {}:{}  {}", d.bdf, d.vid, d.pid, d.description), d.bdf.clone()))
        .collect();

    if usb.is_empty() && pci.is_empty() {
        return Ok(None); // nothing to pick — caller records input + notes only
    }

    // If there are no USB capture devices, tell the user why — most often USBPcap isn't installed
    // (or it is, but the post-install reboot is still pending).
    let usb_note = if !usb.is_empty() {
        ""
    } else if usbpcap_installed() {
        "USBPcap is installed but no capture devices are attached yet — reboot to enable USB capture."
    } else {
        "USBPcap driver not installed — USB capture unavailable. Install it (PowerShell: \
         scripts/get-usbpcap.ps1, or https://desowin.org/usbpcap/), reboot, then relaunch."
    };
    // PCIe capture needs the reveng-pcidrv (RevengPciCap) service. If it's registered but stopped
    // the recorder will start it when recording begins; if not installed, guide the user.
    let pci_note = if pci.is_empty() {
        ""
    } else {
        match drv_status() {
            DrvStatus::Running => "",
            DrvStatus::Stopped => {
                "reveng-pcidrv is installed but not loaded — it will be started (admin) when recording begins."
            }
            DrvStatus::NotInstalled => {
                "reveng-pcidrv driver not loaded — PCIe capture needs it (build + test-sign per driver/reveng-pcidrv/README.md)."
            }
        }
    };

    let choice = match notes_ui::run_device_picker(usb, pci, usb_note, pci_note)? {
        Some(c) => c,
        None => return Ok(Some(0)), // user closed the picker
    };

    // Preserve any other flags the user passed; append the chosen devices.
    let mut fwd: Vec<String> = std::env::args().skip(1).collect();
    if choice.usb_vidpids.is_empty() && choice.pci_bdf.is_none() {
        fwd.push("--no-capture".into());
    } else {
        for vp in &choice.usb_vidpids {
            fwd.push("--device-vidpid".into());
            fwd.push(vp.clone());
        }
        if let Some(bdf) = &choice.pci_bdf {
            fwd.push("--with-pcie".into());
            fwd.push("--pci-bdf".into());
            fwd.push(bdf.clone());
        }
    }

    // Relaunch with explicit devices (elevated if we aren't already) → the child skips the picker.
    if !elevate::is_elevated() && std::env::var_os("REVENG_NO_ELEVATE").is_none() {
        Ok(Some(elevate::relaunch_elevated(&fwd)? as i32))
    } else {
        let exe = std::env::current_exe()?;
        let status = std::process::Command::new(exe).args(&fwd).status()?;
        Ok(Some(status.code().unwrap_or(1)))
    }
}

/// Is the USBPcap kernel driver installed? Detected by the presence of `USBPcap.sys` in the
/// system drivers directory — true whether or not the post-install reboot has happened yet.
#[cfg(windows)]
fn usbpcap_installed() -> bool {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    std::path::Path::new(&sysroot)
        .join("System32")
        .join("drivers")
        .join("USBPcap.sys")
        .exists()
}

/// Assemble the live-USB recording options from CLI args.
fn build_usb_opts(
    args: &RecordArgs,
    cfg: CheckpointConfig,
) -> anyhow::Result<record_usb::UsbRecordOpts> {
    let mut snaplen = args.usb_snaplen;
    let mut drop_transfers = Vec::new();
    if args.drop_isoc {
        drop_transfers.push(reveng_usbcap::XFER_ISO);
    }
    if args.drop_bulk {
        drop_transfers.push(reveng_usbcap::XFER_BULK);
    }
    // Adaptive preset: header-only cap + drop isoc, opt-in (default stays lossless).
    if args.auto_truncate {
        if snaplen == 0 {
            snaplen = 256;
        }
        if !drop_transfers.contains(&reveng_usbcap::XFER_ISO) {
            drop_transfers.push(reveng_usbcap::XFER_ISO);
        }
        eprintln!("--auto-truncate: snaplen {snaplen} B + dropping isoc (control/interrupt kept full)");
    }

    Ok(record_usb::UsbRecordOpts {
        selections: build_usb_selections(args)?,
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
        snaplen,
        buffer: args.usb_bufsize,
        drop_transfers,
        endpoints: parse_endpoints(args.endpoints.as_deref()),
        max_bytes: args.max_bytes,
        mem_pid: args.mem_pid,
        mem_process: args.mem_process.clone(),
        mem_compress: args.mem_compress,
    })
}

/// Parse `--endpoints` (comma-separated endpoint numbers, hex `0x81` or decimal) into a
/// direction-agnostic (`0x0F`-masked) allow-list. `None`/empty = capture all endpoints.
fn parse_endpoints(s: Option<&str>) -> Option<Vec<u8>> {
    let list: Vec<u8> = split_csv(s?)
        .iter()
        .filter_map(|t| {
            let v = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                u8::from_str_radix(h, 16).ok()
            } else {
                t.parse::<u8>().ok()
            }?;
            Some(v & 0x0F)
        })
        .collect();
    (!list.is_empty()).then_some(list)
}

/// Resolve the CLI device selection into one [`UsbSelection`] per USBPcap control device
/// (root hub) to capture in parallel (DESIGN.md §11.1). Devices are grouped by their hub so
/// a match spanning several root hubs opens several sources. Returns empty for `--no-capture`
/// or when nothing matches — the recorder then runs window-only (input + notes, no capture).
fn build_usb_selections(args: &RecordArgs) -> anyhow::Result<Vec<reveng_usbcap::UsbSelection>> {
    use reveng_usbcap::UsbSelection;
    use std::collections::{BTreeMap, BTreeSet};

    if args.no_capture {
        return Ok(Vec::new());
    }

    /// Accumulated request for one control device.
    #[derive(Default)]
    struct Hub {
        addresses: BTreeSet<u16>,
        all: bool,
    }
    let mut hubs: BTreeMap<String, Hub> = BTreeMap::new();

    // Explicit control device: honor --device-address on it, else capture the whole hub.
    if let Some(dev) = &args.usbpcap_device {
        let h = hubs.entry(dev.clone()).or_default();
        for a in &args.device_address {
            h.addresses.insert(*a);
        }
        if args.all_devices || (args.device_address.is_empty() && args.device_vidpid.is_empty()) {
            h.all = true;
        }
    }

    // Enumerate once when we must resolve VID:PID → (hub, address), honor --all-devices, or
    // auto-pick a lone hub.
    let need_enum = !args.device_vidpid.is_empty() || args.all_devices || hubs.is_empty();
    if need_enum {
        if let Ok(devs) = reveng_usbcap::list_devices() {
            for want in &args.device_vidpid {
                let (wv, wp) = want.split_once(':').unwrap_or((want.as_str(), ""));
                for d in &devs {
                    if d.vid.eq_ignore_ascii_case(wv)
                        && d.pid.eq_ignore_ascii_case(wp)
                        && !d.usbpcap.is_empty()
                    {
                        hubs.entry(d.usbpcap.clone()).or_default().addresses.insert(d.address);
                    }
                }
            }
            if args.all_devices {
                for d in &devs {
                    if !d.usbpcap.is_empty() {
                        hubs.entry(d.usbpcap.clone()).or_default().all = true;
                    }
                }
            }
            // Nothing requested → auto-pick the single hub if there's exactly one.
            if hubs.is_empty() {
                let set: BTreeSet<_> = devs
                    .iter()
                    .map(|d| d.usbpcap.clone())
                    .filter(|s| !s.is_empty())
                    .collect();
                if set.len() == 1 {
                    hubs.entry(set.into_iter().next().unwrap()).or_default().all = true;
                }
            }
        }
    }

    Ok(hubs
        .into_iter()
        .map(|(dev, h)| UsbSelection {
            usbpcap_device: Some(dev),
            vidpid: args.device_vidpid.clone(),
            serial: args.device_serial.clone(),
            address: h.addresses.into_iter().collect(),
            all_devices: h.all,
        })
        .collect())
}

/// The optional concurrent PCIe capture to co-log alongside USB (`--with-pcie`). `None` unless
/// requested; otherwise built from `--pcie-replay` or the live `drv` backend.
fn build_pcie_capture(
    args: &RecordArgs,
    clock: &Clock,
) -> anyhow::Result<Option<record_usb::PcieCapture>> {
    if !args.with_pcie {
        return Ok(None);
    }
    make_pcie_capture(args.pcie_replay.as_deref(), args, clock)
}

/// Build a started [`record_usb::PcieCapture`] from a replay file (`replay = Some`, works
/// anywhere) or the live `drv` backend (`replay = None`, Windows + reveng-pcidrv), sharing
/// `clock`. Shared by `--with-pcie` co-logging and the PCIe-only engine path. Returns `None` if
/// the source fails to `start()` (fault-tolerant — the session records without it).
fn make_pcie_capture(
    replay: Option<&std::path::Path>,
    args: &RecordArgs,
    clock: &Clock,
) -> anyhow::Result<Option<record_usb::PcieCapture>> {
    use reveng_core::source::CaptureSource;

    if let Some(replay) = replay {
        let mut source = reveng_pcicap::ReplayPcieSource::from_path(replay)?;
        if let Err(e) = source.start() {
            eprintln!("PCIe capture disabled (replay start failed): {e}");
            return Ok(None);
        }
        return Ok(Some(record_usb::PcieCapture {
            source: Box::new(source),
            stop: Box::new(|| {}),
            meta: serde_json::json!({
                "acquisition": "replay",
                "replay_file": replay.display().to_string(),
            }),
            trace_mmio: None,
            trace_dma: None,
        }));
    }

    // Live PCIe device (Windows + reveng-pcidrv), stamped on the shared session clock.
    #[cfg(windows)]
    {
        match args.pci_backend {
            PciBackend::Drv => {
                // Load the driver if it's registered but not running (we're elevated here). If it
                // can't be loaded, the open below fails and we fall back (record without PCIe).
                if let Err(e) = ensure_drv_running() {
                    eprintln!("reveng-pcidrv not available: {e}");
                }
                let target = resolve_pci_target(args)?;
                let mut source = reveng_pcicap::drv::DrvPcieSource::new_live(
                    target,
                    clock.clone(),
                    None, // unbounded — the session drives stop
                    args.trace_mmio,
                    args.trace_dma,
                );
                if let Err(e) = source.start() {
                    eprintln!("PCIe capture disabled (driver start failed): {e}");
                    return Ok(None);
                }
                let killer = source.killer();
                let (trace_mmio, trace_dma) = source.trace_handles();
                let stop: Box<dyn Fn() + Send + Sync> = Box::new(move || {
                    if let Some(k) = &killer {
                        k.kill();
                    }
                });
                Ok(Some(record_usb::PcieCapture {
                    source: Box::new(source),
                    stop,
                    meta: serde_json::json!({
                        "acquisition": "pcidrv",
                        "trace_mmio": args.trace_mmio,
                        "trace_dma": args.trace_dma,
                        "target": format!(
                            "{:04x}:{:02x}:{:02x}.{}",
                            target.segment, target.bus, target.device, target.function
                        ),
                    }),
                    trace_mmio: Some(trace_mmio),
                    trace_dma: Some(trace_dma),
                }))
            }
            PciBackend::Etw => {
                let vectors = parse_irq_vectors(args.irq_vectors.as_deref())?;
                let mut source = reveng_pcicap::etw::EtwIrqSource::new(
                    clock.clone(),
                    reveng_pcicap::etw::EtwIrqOpts {
                        vectors,
                        max_duration: None, // the session drives stop
                    },
                );
                if let Err(e) = source.start() {
                    eprintln!("PCIe capture disabled (etw start failed): {e}");
                    return Ok(None);
                }
                let flag = source.stop_handle();
                let stop: Box<dyn Fn() + Send + Sync> =
                    Box::new(move || flag.store(true, std::sync::atomic::Ordering::Relaxed));
                Ok(Some(record_usb::PcieCapture {
                    source: Box::new(source),
                    stop,
                    meta: serde_json::json!({
                        "acquisition": "etw-isr",
                        "irq_vectors": args.irq_vectors.clone().unwrap_or_else(|| "all".into()),
                    }),
                    trace_mmio: None,
                    trace_dma: None,
                }))
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (args, clock);
        anyhow::bail!("live PCIe requires Windows; use a replay file on other platforms")
    }
}

/// PCIe-only interactive recording through the shared input-driven engine: clicks form
/// checkpoints + screenshots and anchor to PCIe events, exactly like the USB path. Live `drv`
/// needs admin (replay doesn't); no USB sources are opened.
#[cfg(windows)]
fn run_pcie_engine_session(args: &RecordArgs, cfg: CheckpointConfig) -> anyhow::Result<()> {
    let live = args.replay.is_none();
    if live && !elevate::is_elevated() && std::env::var_os("REVENG_NO_ELEVATE").is_none() {
        eprintln!("PCIe capture needs administrator rights — requesting elevation…");
        let forward: Vec<String> = std::env::args().skip(1).collect();
        let code = elevate::relaunch_elevated(&forward)?;
        std::process::exit(code as i32);
    }

    let out = args.out.clone().unwrap_or_else(|| {
        args.replay
            .as_deref()
            .map(default_out)
            .unwrap_or_else(default_session_dir)
    });
    let clock = Clock::start();
    let pcie = make_pcie_capture(args.replay.as_deref(), args, &clock)?;
    if pcie.is_none() {
        anyhow::bail!("no PCIe source available (start failed)");
    }
    // PCIe is the only traffic source: reuse the checkpoint/screenshot config, no USB selections.
    let mut opts = build_usb_opts(args, cfg)?;
    opts.selections.clear();
    run_engine_session(&out, opts, pcie, clock)
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
        OutFormat::Text => query::PayloadFmt::Text,
        OutFormat::Auto => query::PayloadFmt::Auto,
        OutFormat::Json => query::PayloadFmt::Json,
    }
}
