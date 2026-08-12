//! Read a Cynthion's own account of itself: descriptors, interfaces, endpoints, strings.
//!
//! Everything here is a **standard, read-only** USB request. Nothing is written to the
//! board, so this is safe to run against an unknown unit — which is the point: the
//! device is the ground truth for its own interface layout, and that is a better source
//! than a remembered protocol or a vendor package we would rather not depend on.
//!
//! ```sh
//! cargo run -p reveng-cynthion --bin cynthion-probe
//! cargo run -p reveng-cynthion --bin cynthion-probe -- 1d50:615b
//! ```

use anyhow::{Context, Result};
use futures_lite::future::block_on;
use nusb::transfer::{ControlIn, ControlType, Recipient};

/// Great Scott Gadgets ship under the OpenMoko shared vendor id.
const DEFAULT_VID: u16 = 0x1d50;

const DESC_DEVICE: u8 = 0x01;
const DESC_CONFIG: u8 = 0x02;
const DESC_STRING: u8 = 0x03;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let scan_vendor = args.iter().any(|a| a == "--scan-vendor");
    let try_capture = args.iter().any(|a| a == "--try-capture");
    let set_state = args
        .iter()
        .position(|a| a == "--set-state")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<u16>().ok());
    let capture_secs = args.iter().position(|a| a == "--capture").map(|i| {
        args.get(i + 1)
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(3)
    });
    // A VID:PID always contains a colon, which also keeps `--set-state`'s numeric
    // argument from being mistaken for a device filter.
    // Speed field value: 0 High, 1 Full, 2 Low, 3 Auto.
    let speed = args
        .iter()
        .position(|a| a == "--speed")
        .and_then(|i| args.get(i + 1))
        .map(|v| match v.as_str() {
            "high" => 0u8,
            "full" => 1,
            "low" => 2,
            _ => 3,
        })
        .unwrap_or(3);
    let filter = args.iter().find(|a| a.contains(':')).cloned();
    if scan_vendor {
        return scan(filter.as_deref());
    }
    if try_capture {
        return try_capture_states(filter.as_deref());
    }
    if let Some(value) = set_state {
        return set_state_explicit(filter.as_deref(), value);
    }
    if let Some(secs) = capture_secs {
        return capture_raw(filter.as_deref(), secs, speed);
    }
    let (want_vid, want_pid) = match filter.as_deref() {
        Some(s) => {
            let (v, p) = s.split_once(':').context("expected VID:PID in hex")?;
            (
                u16::from_str_radix(v.trim_start_matches("0x"), 16)?,
                Some(u16::from_str_radix(p.trim_start_matches("0x"), 16)?),
            )
        }
        None => (DEFAULT_VID, None),
    };

    let mut found = 0usize;
    for info in nusb::list_devices()? {
        if info.vendor_id() != want_vid {
            continue;
        }
        if let Some(pid) = want_pid {
            if info.product_id() != pid {
                continue;
            }
        }
        found += 1;
        println!(
            "=== {:04x}:{:04x}  bus {} addr {}",
            info.vendor_id(),
            info.product_id(),
            info.bus_number(),
            info.device_address()
        );
        for (label, value) in [
            ("manufacturer", info.manufacturer_string()),
            ("product", info.product_string()),
            ("serial", info.serial_number()),
        ] {
            if let Some(value) = value {
                println!("  {label:<13}{value}");
            }
        }

        match info.open() {
            Ok(device) => {
                // Control transfers go through a claimed interface, not the device:
                // `Device::control_in_blocking` exists only on Linux/macOS, so routing
                // through the interface is what keeps this probe working on Windows too.
                let iface = device.claim_interface(0).ok();
                report_device(&device, iface.as_ref())?;
            }
            Err(e) => println!("  (cannot open: {e})"),
        }
        println!();
    }

    if found == 0 {
        println!("no device matching {want_vid:04x}:* found on USB");
    }
    Ok(())
}

fn report_device(device: &nusb::Device, iface: Option<&nusb::Interface>) -> Result<()> {
    // The parsed view first: what nusb resolves from the active configuration.
    for cfg in device.configurations() {
        println!("  config {}", cfg.configuration_value());
        for iface in cfg.interfaces() {
            for alt in iface.alt_settings() {
                println!(
                    "    interface {} alt {}  class {:02x}/{:02x}/{:02x}  endpoints {}",
                    alt.interface_number(),
                    alt.alternate_setting(),
                    alt.class(),
                    alt.subclass(),
                    alt.protocol(),
                    alt.num_endpoints()
                );
                for ep in alt.endpoints() {
                    println!(
                        "      ep 0x{:02x}  {:?} {:?}  max packet {}  interval {}",
                        ep.address(),
                        ep.direction(),
                        ep.transfer_type(),
                        ep.max_packet_size(),
                        ep.interval()
                    );
                }
            }
        }
    }

    // Then the raw bytes, because the parsed view drops vendor-specific descriptors —
    // exactly where a board is most likely to say something about its own protocol.
    let Some(iface) = iface else {
        println!("  (interface 0 not claimable; skipping raw descriptors)");
        return Ok(());
    };

    if let Ok(bytes) = get_descriptor(iface, DESC_DEVICE, 0, 18) {
        println!("  device descriptor : {}", hex(&bytes));
    }
    if let Ok(head) = get_descriptor(iface, DESC_CONFIG, 0, 9) {
        let total = u16::from_le_bytes([head[2], head[3]]) as usize;
        if let Ok(full) = get_descriptor(iface, DESC_CONFIG, 0, total) {
            println!("  config descriptor ({total} bytes):");
            for chunk in descriptors(&full) {
                println!("    {}", hex(chunk));
            }
        }
    }

    // String descriptors are cheap and often name an interface's role. Index 0 is the
    // supported-language list, so start at 1 and stop at the first gap.
    let mut strings = Vec::new();
    for index in 1..=8u8 {
        match get_descriptor(iface, DESC_STRING, index, 255) {
            Ok(bytes) if bytes.len() > 2 => strings.push((index, decode_utf16(&bytes))),
            _ => break,
        }
    }
    if !strings.is_empty() {
        println!("  strings:");
        for (index, text) in strings {
            println!("    [{index}] {text}");
        }
    }
    Ok(())
}

/// Enumerate which vendor **IN** requests the board answers, on each interface.
///
/// Read-only by construction: every transfer is device-to-host, so nothing is written
/// and no capture state is set. A request the firmware does not implement STALLs, so
/// "answered" versus "stalled" maps the API surface without needing the vendor's own
/// tooling — the board is the authority on what it accepts.
///
/// This is a discovery aid, not a substitute for a documented protocol. Treat what it
/// finds as a starting point to be confirmed, and record the confirmation.
fn scan(filter: Option<&str>) -> Result<()> {
    let (vid, pid) = match filter {
        Some(s) => {
            let (v, p) = s.split_once(':').context("expected VID:PID in hex")?;
            (
                u16::from_str_radix(v.trim_start_matches("0x"), 16)?,
                Some(u16::from_str_radix(p.trim_start_matches("0x"), 16)?),
            )
        }
        None => (DEFAULT_VID, None),
    };

    let info = nusb::list_devices()?
        .find(|d| d.vendor_id() == vid && pid.is_none_or(|p| d.product_id() == p))
        .context("no matching device on USB")?;
    let device = info.open().context("opening device")?;

    println!(
        "scanning vendor IN requests on {:04x}:{:04x} (read-only)",
        info.vendor_id(),
        info.product_id()
    );

    for iface_num in [0u8, 1] {
        let Ok(iface) = device.claim_interface(iface_num) else {
            println!("  interface {iface_num}: not claimable, skipped");
            continue;
        };
        for (label, recipient) in [
            ("device", Recipient::Device),
            ("interface", Recipient::Interface),
        ] {
            let mut hits = Vec::new();
            for request in 0u8..=0xff {
                let mut buf = [0u8; 64];
                let control = nusb::transfer::Control {
                    control_type: ControlType::Vendor,
                    recipient,
                    request,
                    value: 0,
                    index: iface_num as u16,
                };
                if let Ok(n) = iface.control_in_blocking(
                    control,
                    &mut buf,
                    std::time::Duration::from_millis(50),
                ) {
                    hits.push((request, buf[..n].to_vec()));
                }
            }
            if hits.is_empty() {
                println!("  interface {iface_num} / recipient {label}: no requests answered");
            } else {
                println!(
                    "  interface {iface_num} / recipient {label}: {} answered",
                    hits.len()
                );
                for (request, data) in hits {
                    println!(
                        "    bRequest 0x{request:02x} -> {} bytes  {}",
                        data.len(),
                        hex(&data)
                    );
                }
            }
        }
    }
    Ok(())
}

/// Vendor requests, recipient Interface, `wIndex` = interface number.
/// Reads answer one byte; writes carry their value in `wValue` with no data stage.
const REQ_GET_STATE: u8 = 0;
const REQ_SET_STATE: u8 = 1;
const REQ_GET_SPEEDS: u8 = 2;
const REQ_GET_PROTOCOL_MINOR: u8 = 4;

/// Kept as the write request for the helpers below.
const REQ_STATE: u8 = REQ_SET_STATE;
const ANALYZER_INTERFACE: u8 = 0;
const EP_CAPTURE: u8 = 0x81;
const CAPTURE_MAX_PACKET: usize = 512;

/// Write candidate values to the state register, read each back, and see whether the
/// capture endpoint starts producing data.
///
/// **Self-restoring**: the register is set back to 0 on every exit path, so the board is
/// left as it was found. Reversible by design — and if it is ever not, a replug clears
/// it, since this register is volatile state and not a flash write.
///
/// A quiet endpoint is *not* evidence the value was wrong: with nothing plugged into the
/// TARGET port there is no bus traffic to capture. Read this as mapping the control
/// interface, not as validating capture.
fn try_capture_states(filter: Option<&str>) -> Result<()> {
    let (vid, pid) = parse_filter(filter)?;
    let info = nusb::list_devices()?
        .find(|d| d.vendor_id() == vid && pid.is_none_or(|p| d.product_id() == p))
        .context("no matching device on USB")?;
    let device = info.open().context("opening device")?;
    let iface = device
        .claim_interface(ANALYZER_INTERFACE)
        .context("claiming the analyzer interface")?;

    let restore = |iface: &nusb::Interface| {
        let _ = write_state(iface, 0);
    };

    println!("state before: {:?}", read_state(&iface));
    for value in 1u16..=4 {
        match write_state(&iface, value) {
            Ok(()) => {
                let readback = read_state(&iface);
                let bytes = drain(&iface, std::time::Duration::from_millis(400));
                println!(
                    "  wValue {value}: accepted, state reads {readback:?}, {bytes} capture byte(s)"
                );
            }
            Err(e) => println!("  wValue {value}: rejected ({e})"),
        }
        restore(&iface);
    }
    restore(&iface);
    println!("state after restore: {:?}", read_state(&iface));
    Ok(())
}

/// Set the state register and report the outcome, errors included.
///
/// Exists because the sweep above hid a failing restore behind `let _ =` and left the
/// board enabled — a silent write failure is exactly the thing worth surfacing.
fn set_state_explicit(filter: Option<&str>, value: u16) -> Result<()> {
    let (vid, pid) = parse_filter(filter)?;
    let info = nusb::list_devices()?
        .find(|d| d.vendor_id() == vid && pid.is_none_or(|p| d.product_id() == p))
        .context("no matching device on USB")?;
    let device = info.open().context("opening device")?;
    let iface = device
        .claim_interface(ANALYZER_INTERFACE)
        .context("claiming the analyzer interface")?;

    println!("state before : {:?}", read_state(&iface));
    match write_state(&iface, value) {
        Ok(()) => println!("write {value}   : ok"),
        Err(e) => println!("write {value}   : FAILED — {e}"),
    }
    println!("state after  : {:?}", read_state(&iface));
    Ok(())
}

/// Enable capture, collect whatever arrives on the capture endpoint, disable, and dump
/// the raw bytes. The point is the *framing*: what the board wraps around each wire
/// packet before handing it over.
///
/// Always disables on the way out, and reports whether that succeeded — a silently
/// failed restore is how an earlier run left the board enabled.
fn capture_raw(filter: Option<&str>, secs: u64, speed: u8) -> Result<()> {
    use nusb::transfer::RequestBuffer;

    let (vid, pid) = parse_filter(filter)?;
    let info = nusb::list_devices()?
        .find(|d| d.vendor_id() == vid && pid.is_none_or(|p| d.product_id() == p))
        .context("no matching device on USB")?;
    let device = info.open().context("opening device")?;
    let iface = device
        .claim_interface(ANALYZER_INTERFACE)
        .context("claiming the analyzer interface")?;

    // The first control transfer after a claim always fails; spend it deliberately.
    let _ = read_state(&iface);

    // Tolerate finding the board already enabled. A capture left running — say by a
    // process killed before it could stop — refuses further state writes until its
    // buffer is drained, so insisting on the enable here would make the one action that
    // can recover it impossible.
    println!(
        "state {:?}  supported-speeds mask {:?}  protocol minor {:?}",
        read_state(&iface),
        read_byte(&iface, REQ_GET_SPEEDS).map(|m| format!("{m:#06b}")),
        read_byte(&iface, REQ_GET_PROTOCOL_MINOR),
    );

    // Enable, with the speed in bits 1-2. Every VBUS/power bit left clear so the board
    // only listens. Auto-detect is not always right: a Low-speed device can be reported
    // as Full, and then the analyzer samples at the wrong rate and yields raw line-state
    // transitions instead of framed packets.
    let want = 1u8 | (speed << 1);
    match read_state(&iface) {
        Some(s) if s & 1 != 0 => println!("capture already enabled (state {s:#04x}); draining"),
        _ => {
            write_state(&iface, want as u16).context("enabling capture")?;
            println!(
                "capture enabled with state {want:#04x} (reads {:?})",
                read_state(&iface)
            );
        }
    }

    // Queue several buffers so a burst is not lost between submissions.
    let mut queue = iface.bulk_in_queue(EP_CAPTURE);
    for _ in 0..64 {
        queue.submit(RequestBuffer::new(CAPTURE_MAX_PACKET));
    }

    // Terminating by construction: let transfers sit for the window, then cancel and
    // drain. `next_complete()` blocks with no timeout, so waiting on it before the
    // endpoint has produced anything parks forever — cancellation is what guarantees
    // every outstanding transfer completes and the drain finishes.
    std::thread::sleep(std::time::Duration::from_secs(secs));
    queue.cancel_all();

    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut total = 0usize;
    while queue.pending() > 0 {
        let completion = block_on(queue.next_complete());
        if completion.status.is_ok() && !completion.data.is_empty() {
            total += completion.data.len();
            if chunks.len() < 24 {
                chunks.push(completion.data.clone());
            }
        }
    }

    match write_state(&iface, 0) {
        Ok(()) => println!("capture disabled (state reads {:?})", read_state(&iface)),
        Err(e) => println!("WARNING: could not disable capture — {e}"),
    }

    println!("\n{total} byte(s) in {} transfer(s)", chunks.len());
    decode_stream(&chunks.concat());
    Ok(())
}

/// Decode the analyzer stream and summarise it.
///
/// Framing: every record is a 4-byte header. Byte 0 == `0xFF` marks an **event**, with
/// byte 1 the event code; otherwise bytes 0..2 are a big-endian **packet length**. Bytes
/// 2..4 are always a big-endian clock-cycle delta since the previous record. A packet's
/// bytes follow, plus one padding byte when its length is odd.
fn decode_stream(data: &[u8]) {
    let mut i = 0usize;
    let mut clk: u64 = 0;
    let mut events = 0usize;
    let mut packets = 0usize;
    let mut event_counts: std::collections::BTreeMap<u8, usize> = Default::default();
    let mut shown = 0usize;

    while i + 4 <= data.len() {
        let delta = u16::from_be_bytes([data[i + 2], data[i + 3]]) as u64;
        clk += delta;
        let ns = clk_to_ns(clk);

        if data[i] == 0xFF {
            let code = data[i + 1];
            events += 1;
            *event_counts.entry(code).or_default() += 1;
            if shown < 12 {
                println!("  {ns:>12} ns  event  {}", event_name(code));
                shown += 1;
            }
            i += 4;
        } else {
            let len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
            if i + 4 + len > data.len() {
                break;
            }
            let bytes = &data[i + 4..i + 4 + len];
            packets += 1;
            if shown < 12 {
                println!("  {ns:>12} ns  packet {len:>4} bytes  {}", hex(bytes));
                shown += 1;
            }
            i += 4 + len + (len % 2);
        }
    }

    println!("\n  {packets} packet(s), {events} event(s)");
    if !event_counts.is_empty() {
        println!("  event histogram:");
        for (code, n) in event_counts {
            println!("    {:<28} {n:>6}", event_name(code));
        }
    }
}

/// The analyzer's clock is 60 MHz: three cycles are exactly 50 ns, so counting in
/// whole cycles avoids the rounding drift of a per-cycle constant.
fn clk_to_ns(cycles: u64) -> u64 {
    const REMAINDER: [u64; 3] = [0, 16, 33];
    (cycles / 3) * 50 + REMAINDER[(cycles % 3) as usize]
}

fn event_name(code: u8) -> String {
    let name = match code {
        1 => "CaptureStop(Requested)",
        2 => "CaptureStop(BufferFull)",
        3 => "CaptureStop(Error)",
        4 => "CaptureStart(High)",
        5 => "CaptureStart(Full)",
        6 => "CaptureStart(Low)",
        7 => "CaptureStart(Auto)",
        8 => "SpeedChange(High)",
        9 => "SpeedChange(Full)",
        10 => "SpeedChange(Low)",
        11 => "SpeedChange(Auto)",
        12 => "LineState(SE0)",
        13 => "LineState(ChirpJ)",
        14 => "LineState(ChirpK)",
        15 => "LineState(ChirpSE1)",
        16 => "LineState(LsJ)",
        17 => "LineState(LsK)",
        18 => "LineState(FsJ)",
        19 => "LineState(FsK)",
        20 => "LineState(SE1)",
        21 => "VbusInvalid",
        22 => "VbusValid",
        23 => "LsAttach",
        24 => "FsAttach",
        25 => "BusReset",
        26 => "DeviceChirpValid",
        27 => "HostChirpValid",
        28 => "Suspend",
        29 => "Resume",
        30 => "LsKeepalive",
        _ => return format!("unknown({code})"),
    };
    name.to_string()
}

fn read_state(iface: &nusb::Interface) -> Option<u8> {
    let mut buf = [0u8; 1];
    let control = nusb::transfer::Control {
        control_type: ControlType::Vendor,
        recipient: Recipient::Interface,
        request: REQ_GET_STATE,
        value: 0,
        index: ANALYZER_INTERFACE as u16,
    };
    iface
        .control_in_blocking(control, &mut buf, std::time::Duration::from_millis(200))
        .ok()
        .filter(|n| *n == 1)
        .map(|_| buf[0])
}

/// Read a one-byte vendor register.
fn read_byte(iface: &nusb::Interface, request: u8) -> Option<u8> {
    let mut buf = [0u8; 64];
    let control = nusb::transfer::Control {
        control_type: ControlType::Vendor,
        recipient: Recipient::Interface,
        request,
        value: 0,
        index: ANALYZER_INTERFACE as u16,
    };
    iface
        .control_in_blocking(control, &mut buf, std::time::Duration::from_millis(200))
        .ok()
        .filter(|n| *n == 1)
        .map(|_| buf[0])
}

fn write_state(iface: &nusb::Interface, value: u16) -> Result<()> {
    let control = nusb::transfer::Control {
        control_type: ControlType::Vendor,
        recipient: Recipient::Interface,
        request: REQ_STATE,
        value,
        index: ANALYZER_INTERFACE as u16,
    };
    iface
        .control_out_blocking(control, &[], std::time::Duration::from_millis(200))
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Read whatever the capture endpoint offers within the window; 0 is a normal answer.
///
/// nusb has no blocking bulk read, so the wait is bounded by submitting, sleeping, then
/// cancelling: cancellation completes the outstanding transfers, so draining them cannot
/// block. That avoids abandoning a thread parked forever on a silent endpoint.
fn drain(iface: &nusb::Interface, window: std::time::Duration) -> usize {
    use nusb::transfer::RequestBuffer;

    let mut queue = iface.bulk_in_queue(EP_CAPTURE);
    for _ in 0..4 {
        queue.submit(RequestBuffer::new(512));
    }
    std::thread::sleep(window);
    queue.cancel_all();

    let mut total = 0usize;
    while queue.pending() > 0 {
        let completion = block_on(queue.next_complete());
        if completion.status.is_ok() {
            total += completion.data.len();
        }
    }
    total
}

fn parse_filter(filter: Option<&str>) -> Result<(u16, Option<u16>)> {
    Ok(match filter {
        Some(s) => {
            let (v, p) = s.split_once(':').context("expected VID:PID in hex")?;
            (
                u16::from_str_radix(v.trim_start_matches("0x"), 16)?,
                Some(u16::from_str_radix(p.trim_start_matches("0x"), 16)?),
            )
        }
        None => (DEFAULT_VID, None),
    })
}

fn get_descriptor(iface: &nusb::Interface, kind: u8, index: u8, len: usize) -> Result<Vec<u8>> {
    let data = block_on(iface.control_in(ControlIn {
        control_type: ControlType::Standard,
        recipient: Recipient::Device,
        request: 0x06, // GET_DESCRIPTOR
        value: ((kind as u16) << 8) | index as u16,
        // Language id, and only meaningful for string descriptors: 0x0409 = en-US.
        index: if kind == DESC_STRING { 0x0409 } else { 0 },
        length: len as u16,
    }))
    .into_result()
    .map_err(|e| anyhow::anyhow!("GET_DESCRIPTOR {kind:#04x}/{index}: {e}"))?;
    Ok(data)
}

/// Split a configuration descriptor into its constituent descriptors by walking the
/// `bLength` chain, so vendor-specific ones survive rather than being skipped.
fn descriptors(buf: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 2 <= buf.len() {
        let len = buf[i] as usize;
        if len < 2 || i + len > buf.len() {
            break;
        }
        out.push(&buf[i..i + len]);
        i += len;
    }
    out
}

fn decode_utf16(desc: &[u8]) -> String {
    let units: Vec<u16> = desc[2..]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}
