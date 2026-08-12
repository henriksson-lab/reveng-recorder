# reveng-recorder — Design

A tool for reverse-engineering devices by **correlating bus traffic with what the user was doing
on screen**. It records traffic, global mouse/keyboard input, and event-triggered screenshots into
a single time-synchronized session, then lets you seek through the traffic using clicks and key
events as natural checkpoints.

- **Platform:** Windows-first (x64). Traffic capture and the whole read side are cross-platform
  with the analyzer backend; the correlation half (input hooks, screenshots, UIA, OCR, viewer) is
  Windows-only, which is what `--traffic-only` (§4.4) switches off cleanly.
- **Stack:** Rust. Recorder is a CLI/service binary; viewer is an [egui](https://github.com/emilk/egui) desktop app.
- **USB capture, two backends:** [USBPcap](https://desowin.org/usbpcap/) (free kernel driver, no
  extra hardware, Windows, whole transfers) or a [Cynthion](https://greatscottgadgets.com/cynthion/)
  hardware analyzer (any OS, no driver, raw wire packets) — §4 and §4.1.
- **Wireshark:** raw capture stays Wireshark-openable; viewer can hand off to Wireshark at a specific frame.

> **Reading this doc.** It is the cross-crate contract and the *why*: decisions that span crates,
> and the measurements behind them. Mechanism lives in the code's own doc comments, which cannot
> drift from what they describe — prefer those for "how does X work". If the two disagree, the
> code is right and this file has a bug.

---

## 1. The workflow it enables

1. Start `reveng-rec`, pick the USBPcap root hub + (optionally) filter to the target device.
2. Drive the vendor software normally — click buttons, type, etc.
3. Every mouse-button press (and selected special keys) drops a **checkpoint** and grabs a
   **screenshot**. Long stretches of continuous USB traffic also get periodic checkpoints.
4. Stop with a global hotkey. The session is written to disk (USB as `.pcapng`, events as an
   append-only log, screenshots as files, plus rebuildable seek indexes).
5. Open the session in the **viewer**: a timeline of checkpoints. Jump between clicks, see the
   screenshot at that instant, and inspect the USB frames in a window around it. Export a slice
   or open it in Wireshark at that frame.

The core idea: **"what did clicking *this* button send on the wire?"** becomes a two-click answer.

---

## 2. Master clock (the thing everything hangs off)

All three data sources produce timestamps from different clocks. We normalize to one monotonic
timeline: **QueryPerformanceCounter (QPC)**, expressed as nanoseconds since session start.

At startup we record an **anchor** into `meta.json`:

```
qpc_freq = QueryPerformanceFrequency()
qpc0     = QueryPerformanceCounter()               // t=0 of the session
ft0      = GetSystemTimePreciseAsFileTime()         // wall clock at t=0 (100ns units)
```

- **Input events** → call QPC in the hook: `ts_ns = (qpc - qpc0) * 1e9 / qpc_freq`.
- **Screenshots** → QPC at the moment of grab.
- **USB frames** → USBPcap stamps each pcap record with system wall-clock time. Convert into the
  QPC timeline via the FILETIME anchor: `ts_ns = (usb_filetime - ft0) * 100`.

> **Caveat:** USB frame timestamps come from the driver's system-time clock, not QPC, so there
> can be a few ms of skew relative to input events. That is well within tolerance for *seeking to
> a click*; the raw pcap timestamps are preserved untouched for anyone who needs bus-accurate
> timing. Hardware-analyzer-grade timing is explicitly out of scope for the USBPcap backend.

---

## 3. Architecture

```
                          ┌──────────────────────────────────────────────┐
                          │                 recorder                     │
  \\.\USBPcapN  ─IOCTL─┐  │                                              │
  (kernel driver)      ├──▶  reader thread ──▶ pcapng writer (usb.pcapng)│
  Cynthion  ─nusb──────┘  │        │           frames.idx (ts,offset,…)  │
  (wire packets)          │        └──▶ bytes_since_ckpt (atomic) ──┐    │
                          │                                          │    │
  WH_MOUSE_LL   ─┐        │  input thread ──▶ InputEvent channel ──┐ │    │
  WH_KEYBOARD_LL ┘ hooks  │  (msg loop)          [off in           │ │    │
                          │                       --traffic-only]  ▼ ▼    │
                          │                          checkpoint engine    │
                          │                          - click → ckpt+shot  │
                          │                          - special key → ckpt │
                          │                          - interval timer     │
                          │                          - typed note → ckpt  │
                          │                                │   │          │
                          │                     screenshot ▼   ▼ session   │
                          │                     worker (GDI)   writer      │
                          │                     [off in        events.ndjson
                          │                      --traffic-only]           │
                          │                  screenshots/*.png             │
                          └──────────────────────────────────────────────┘
                                              │
                                       session directory
                                              │
                          ┌───────────────────▼───────────────────┐
                          │            viewer (egui)               │
                          │  timeline · screenshot pane · USB hex  │
                          │  seek/step · export slice · → Wireshark│
                          └────────────────────────────────────────┘
```

Both USB backends are `CaptureSource`s feeding the same reader thread, so everything right of it
is backend-agnostic. What differs is the *abstraction level* of what arrives — see §4.1.

### Thread model (recorder)

| Thread | Job | Constraint |
|---|---|---|
| **traffic reader** (one per source) | drain the `CaptureSource`, write through to `usb.pcapng`, derive the index record, bump `bytes_since_ckpt` | Highest priority. Must never block — the USBPcap kernel buffer and the analyzer's own buffer both drop if we stall. |
| **input** | owns the LL hooks + `GetMessage` loop; timestamps events and pushes to a channel | Hook callback does *only* timestamp+enqueue. LL hooks are dropped/removed by Windows if a callback exceeds `LowLevelHooksTimeout` (~300 ms). |
| **checkpoint engine** | consumes input events, interval timer, and traffic counter; emits `Checkpoint`s; resolves nearest USB frame; requests screenshots | — |
| **screenshot worker** | on request, grabs + encodes PNG off the hot path | Bounded queue; coalesces bursts (see §6). |
| **session writer** | serializes `events.ndjson` and the `*.idx` sidecars | Single writer = simple ordering. |
| **control** | global stop hotkey, Ctrl+C, clean flush/finalize | — |

Channels: `crossbeam-channel`. Shutdown via a `CancellationToken`-style atomic + channel close.

### Rust crate/module layout

```
reveng-recorder/
  crates/
    core/        # shared types, clock anchor, session schema, ndjson IO, CaptureSource trait
    usbcap/      # USBPcap CaptureSource (IOCTL), pcapng writer w/ comments, frames.idx;
                 #   `wire` (USB 2.0 packet decode + CRC), `reassemble` (wire → transfers)
    cynthion/    # Cynthion analyzer CaptureSource over nusb + the bus-event sidecar (§4.1)
    pcicap/      # PCIe CaptureSource: talks to reveng-hv, emits Mmio/Dma/Irq/Config events (§4a)
    winput/      # LL mouse/keyboard hooks, InputEvent
    winshot/     # screen capture (GDI) + PNG encode
    memcap/      # process-memory snapshot capture (Windows) + before/after diff/scan (portable) (§6a)
    recorder/    # bin: orchestration, checkpoint engine, control/hotkey, the query CLI
    viewer/      # bin: egui app — timeline, inspector, seek, export
    export/      # pcapng slicing + Wireshark handoff (shared by viewer)
  driver/
    reveng-hv/   # kernel-mode: thin VT-x/EPT hypervisor + PCI/IRQ driver (PCIe capture only)
```

All acquisition backends implement one `CaptureSource` trait (emit timestamped events onto the
shared timeline). USB and PCIe differ only in acquisition; the two *USB* backends differ in
acquisition **and** in the abstraction level of what they record, which is why §4.1 exists.
`memcap` is the exception — not a traffic backend but a manual-trigger **checkpoint attachment**
(like screenshots): it hangs a decoded-memory snapshot off a checkpoint rather than streaming
events. See §6a.

Key deps: `windows` (windows-rs) for hooks/capture/clock, `nusb` (the analyzer, and `usb-poke`),
`serde`/`serde_json`, `image` (PNG), `eframe`/`egui` for the viewer, `slint` for the recording
window, `clap` for the CLI.

---

## 4. USB capture (USBPcap backend)

- **Talks to `\\.\USBPcapN` directly over its IOCTL interface** (`usbcap::ioctl`) rather than
  shelling out to `USBPcapCMD.exe`; the subprocess path survives only as a fallback behind
  `REVENG_USBPCAP_CLI=1`. Requires **Administrator** (kernel driver), and `record` self-elevates.
- **Device selection:** enumerate with SetupAPI/CfgMgr (`usbcap::devs`), present the tree, and
  filter to the target device address. Filtering at the source dramatically cuts volume
  (isochronous/bulk devices can be very chatty). See §11.1.
- **Parsing:** each record is a `USBPCAP_BUFFER_PACKET_HEADER` (irpId, status, function, info,
  bus, device, endpoint, transfer type, dataLength) + payload. The reader parses the fixed header
  only (cheap) to build the index; payloads are written straight to disk.
- **Storage — we own the pcapng writer.** Instead of dumping USBPcap's raw pcap verbatim, we
  re-emit frames into a **pcapng** with `LINKTYPE_USBPCAP` (249):
  - Preserves original per-frame timestamps.
  - Lets us inject **per-packet Comment options** at checkpoint frames
    (`"CHECKPOINT #12 — click @ (842,391) in Vendor.exe"`). Those show up natively in Wireshark,
    so checkpoints are visible even outside our viewer.
  - Fully Wireshark-openable.
- **Frame index** — `frames.idx`, a fixed-width sidecar of 24-byte `UsbIdxRecord`s
  (ts, byte_offset, endpoint, dir, xfer, status, data_length), giving O(1) get by index and
  binary search by time. `byte_offset` is the frame's block offset in `usb.pcapng`, so a payload
  read is one seek. Field *meanings* differ per backend — see the table in §4.1.

### 4.1. USB capture (hardware-analyzer backend)

A Cynthion taps the bus itself rather than the host's driver stack, so capture needs no kernel
driver and works on Linux, macOS and Windows alike. What it records is one level lower: **wire
packets** — tokens, DATA, handshakes and SOF — not whole transfers.

```sh
reveng-rec record --usb-backend cynthion --cynthion-speed low --traffic-only
```

- **The backends are mutually exclusive**, which settles by construction the hazard of a USBPcap
  source and a Cynthion source double-reporting one device into one `usb.pcapng`.
- **`--cynthion-speed` is required** and has no default. Auto-detect misreports a Low-speed device
  as Full, and the capture then contains bus events and no packets while appearing to succeed.
- **No elevation.** The analyzer is a plain USB device opened through `nusb`, so the UAC
  self-elevation is skipped — unlike USBPcap, whose kernel driver needs it.
- **Device selection does not apply.** There is no hub to enumerate: the analyzer records whatever
  is physically routed through it, so `--device-*` warns and the picker is skipped.
- **Packet-level filtering is refused.** `--drop-isoc` / `--drop-bulk` / `--endpoints` would drop
  tokens and handshakes, and a transfer missing those will not reassemble — a capture that looks
  merely sparse rather than broken. **SOF is the exception** and is dropped by default (counted,
  never silently): it belongs to no transaction, and at high speed one arrives every 125 µs.
  `--keep-sof` retains them for bus-timing work.
- **The reader thread must know the format.** Running the USBPcap header parser over a wire packet
  reads the PID byte and CRC as an endpoint and a length. It does not fail — it produces
  mis-filtered packets and a dashboard full of endpoints that were never on the bus.

- **Storage** is the same `usb.pcapng` + `frames.idx` pair, under a `LINKTYPE_USB_2_0*` link
  type that also records the **capture speed** (a wire packet's meaning depends on the bit rate
  it was sampled at, and nothing in the bytes recovers it). Timestamps are nanoseconds
  (`if_tsresol = 9`); sub-microsecond bus timing is the reason to use such hardware at all.
- **The link type is how a session says which backend wrote it.** `UsbReader::open` reads it out
  of the interface block and picks a `CaptureFormat`, so every consumer of the reader — `frames`,
  `payload`, `grep`, `diff`, `decode`, `stream`, the viewer, `export` — works on either kind of
  session without knowing which it has.
- **Index derivation differs, and some fields change meaning** (`usbcap::wire`):

  | field | USBPcap | wire |
  |---|---|---|
  | `endpoint` | from the record header | from the transaction's **token**, carried forward |
  | `dir` | endpoint bit 7 | the transaction's direction, from the token PID |
  | `xfer` | the URB's transfer type | control on EP0/after SETUP, else **unknown** — bulk, interrupt and iso are indistinguishable on the wire without the descriptors |
  | `status` | `USBD_STATUS` | the **PID**; a wire capture has no host status, and the outcome of a transaction is its final handshake |
  | `data_length` | the URB's reported length | the DATA field, CRC excluded |

- **Only a token carries an address and endpoint.** The DATA and handshake packets after it
  identify themselves by nothing, so indexing is a small state machine. A capture that starts
  mid-transaction attributes its first packets to address 0 endpoint 0.
- **Reassembly is a read-side view** (§8b), so the stored packets stay exactly as captured.
  Commands built on host-transfer semantics that have no wire equivalent yet say so rather than
  degrading quietly: `verify` prints which of its checks do not apply, and `frame-guess` refuses
  outright — its whole model is the URB chunk, which on the wire is just `wMaxPacketSize`.

### 4.2. Control reassembly (`usbcap::reassemble`)

`ctrl`, `ctrl-diff`, `sweep`, `reg-state` and `annotate` all reason about control transfers, so
wire packets are rebuilt into them behind `collect_ctrl`. Three things make this more than a
filter over DATA packets:

- **There is no IRP id to pair on.** The transfer ends at its *status stage*, recognised by a
  token whose direction is opposite the SETUP's — uniformly, including for a zero-length request
  that has no data stage at all.
- **A NAK is a retry, not an outcome.** On an OUT transaction the host re-sends identical DATA
  after a NAK, so data is held until its handshake and committed only on ACK. Counting every
  DATA packet would duplicate the payload of every retried transfer. The NAK count is kept and
  reported — it is real information a host-stack capture cannot show.
- **The outcome is a handshake, not a status code.** ACK/STALL/incomplete are carried in their
  own field; rendering them as a `USBD_STATUS`-shaped `ERR 0x…` would be a lie in a familiar
  format.

The same NAK rule applies outside control transfers. `DataStream` yields only **acknowledged**
DATA payloads, and `frame-extract` uses it on a wire session — concatenating every DATA packet on
a bulk endpoint would duplicate every retried one, producing a frame of exactly the right length
that is silently wrong.

**Split transactions are out of scope** — a low/full-speed device behind a high-speed hub has its
traffic wrapped in SPLIT tokens, which are not modelled. Deferred until a target needs it rather
than guessed at.

### 4.3. What `verify` checks, per backend

USBPcap's failure mode is the kernel buffer overflowing and dropping whole transfers, caught by
SETUPs left unpaired. A wire capture cannot lose a transfer that way; it can mis-sample, corrupt
or lose individual packets. So `verify` asks different questions of each, and the endpoint
histogram takes its direction from the index rather than bit 7 of the endpoint (which on the wire
is not a direction bit at all, and previously labelled every wire frame OUT).

Wire checks: undecodable packets, CRC failures, DATA with no handshake, data-toggle anomalies,
incomplete control transfers. The toggle check only advances on ACK, so a legitimate
retransmission after a NAK is not flagged.

**The toggle check needs the bus events, not just the packets.** A bus reset returns every
endpoint's toggle to DATA0 (USB 2.0 §8.6.1) and a SETUP restarts its endpoint's sequence — so
resets are merged into the scan by timestamp from the sidecar. Without that, one replug reported
**13 toggle anomalies**, every one a false positive; with it, zero on the same capture. This is
the reason `check_wire_integrity` takes a `StreamItem` rather than a plain packet iterator.

**An empty wire capture is never reported as OK.** Setting the wrong capture speed produces
exactly one: measured, 3 s of a Low-speed keyboard captured as Full gave **0 packets and 42112
bus events**. The analyzer emits line-state events rather than malformed packets, so the failure
is not visible as framing garbage — and since the events are not stored in the pcapng, the file
that survives is indistinguishable from a clean recording of an idle bus.

**Bus events go to a sidecar**, `bus_events.ndjson` beside `usb.pcapng` (`<stem>.events.ndjson`
for a standalone capture). They have no representation in a USB 2.0 pcapng, and pcapng custom
blocks would need a registered enterprise number while remaining invisible in Wireshark anyway —
so they live where the session's other sidecars live, in a form a person can grep and a decoder
can read:

```text
{"ts_ns":2772400,"code":6,"name":"CaptureStart(Low)"}
{"ts_ns":3577633,"code":30,"name":"LsKeepalive"}
```

The code table is Packetry's `EventType::code`; six entries are confirmed against this hardware.
Keeping them buys two things nothing in the packet file can provide:

- **Telling an idle bus from a mis-sampled one.** Measured on the same keyboard, 4 s each:
  correct speed → 2174 packets and 4011 events, *none* of them line-state changes. Wrong speed →
  0 packets and 56448 events, 56447 of them line-state churn. `verify` now names the cause and
  exits 1, instead of shrugging at two empty files that looked identical.
- **Detecting an analyzer-side gap.** `CaptureStop(BufferFull)` is the analyzer saying it dropped
  data before it ever reached us. `verify` reports it as an integrity failure.

A summary is folded into `meta.json` (`bus_events`: totals, per-name counts, resets, speed
changes, line-state changes, overflows) so the headline questions are answerable without opening
the sidecar.

### 4.4. `--traffic-only` — the remote-target mode

With a hardware analyzer the capture host is usually **not** the machine being driven. Every
host-side correlation feature then records the wrong computer: the operator's own keystrokes,
their desktop, their foreground window — faithfully, and while looking like it is capturing the
target. `--traffic-only` turns all of it off:

| | normal | `--traffic-only` |
|---|---|---|
| bus traffic | ✓ | ✓ |
| notes | ✓ | ✓ |
| input hooks (`winput`) | ✓ | **not installed** |
| screenshots (`winshot`) | ✓ | **worker not spawned** |
| UI-Automation / OCR | ✓ | **not spawned** |
| `displays.json` | ✓ | not written |
| foreground-window context | ✓ | not read |
| checkpoint triggers | clicks, keys, interval, bytes, notes | interval, bytes, notes |

**Notes stay.** They were the single most valuable correlation signal in the Lumenera work
("usb is in", "starting software", "inserting uv tray"), and they matter *more* when the operator
is driving a second machine — nothing else on this host knows what is happening over there.

It is **independent of `--headless`**: that decides whether there is a window, this decides what
gets recorded. A `--traffic-only` run still shows the window, and its consent banner changes to
say traffic and notes only. Suppressing the banner would be the wrong move — the point is that
this mode captures less, so it should claim less. `meta.json` records `traffic_only` so a later
reader does not assume a session contains input events just because the schema has room for them.

Two implementation notes that cost a debugging session each: shadowing a channel sender does not
drop it (the original lives to end of scope, so the worker's `recv()` never returns and the join
hangs), and the input channel being closed from the start is *not* end-of-run — without a special
case, every traffic-only session finished the instant it began.

### 4.5. Host access to the analyzer, per OS

The Cynthion needs no kernel driver — `nusb` talks to it directly — but each OS still gates who
may open a USB device.

- **Linux** — needs a udev rule, or `root`. Ship-and-copy: `scripts/70-reveng-cynthion.rules`
  into `/etc/udev/rules.d/`, then `udevadm control --reload-rules && udevadm trigger`, then
  replug. It uses `TAG+="uaccess"` (the device goes to whoever is logged in at the seat) rather
  than `MODE="0666"`, which would let every account on the machine open a device capable of
  passively recording another machine's USB traffic; a `plugdev` group form is commented in the
  file for systems without logind. Without any rule, opening the interface fails with a
  permission error **that looks like a missing device** — the first thing to check when Linux
  enumeration appears to find nothing.
- **macOS** — nothing special. No driver, no entitlement, no elevation.
- **Windows** — the interface must be bound to WinUSB. numanager's `winusb_access` is the
  existing pattern for doing that from code (generated INF + self-signed catalog + `newdev`,
  behind an approval gate). Note that **capture itself needs no Administrator** — unlike the
  USBPcap backend, whose kernel driver does, so the UAC self-elevation should be skipped for a
  Cynthion-only run.

---

## 4a. PCIe capture (software-only backend)

USB and PCIe are both **capture sources** feeding the same timeline/checkpoint/decode machinery —
only the acquisition differs. But **there is no USBPcap for PCIe**: a PCIe device talks to the host
over several independent channels and the CPU isn't in the path for most of them. Target scope
(chosen): **MMIO/BAR registers, DMA, and config/interrupts — software-only, no raw TLPs** (TLPs are
hardware-analyzer-only and out of scope).

### Acquisition: a thin hypervisor + cooperating kernel driver

```
    crates/pcicap/          # CaptureSource for PCIe; talks to the kernel component
    driver/reveng-hv/       # kernel-mode: thin VT-x hypervisor (EPT) + PCI/IRQ driver
```

The kernel component puts the running Windows into VMX-root ("hyperjacks" the live OS, the standard
research pattern — cf. SimpleVisor/hvpp/Bareflank) and uses **EPT** to trap access to the target
device's memory. Events are pushed to user-mode `pcicap` over a lock-free ring buffer and land in
the session exactly like USB frames.

- **MMIO / BAR registers** — the primary, highest-fidelity software source. Mark the device's BAR
  pages *not-present* in EPT; every CPU register access to those pages causes an EPT violation
  (VM-exit). The handler logs `{bar, offset, width, value, dir}`, then executes the access **exactly
  once** and resumes.
  - **Read-side-effect registers** (read-to-clear, FIFO pops) make "trap → emulate → re-arm" the
    only safe pattern — the real access must happen once and only once. This is the delicate core.
  - **Perf is the constraint:** a VM-exit per register touch can be thousands/sec and can slow or
    even time-out a busy device. Mitigations (config): trap only chosen register ranges
    (`--mmio-ranges`), and/or enable tracing only **around checkpoints** rather than continuously.
- **DMA** — the device writing/reading system RAM does **not** go through the CPU or EPT, so it is
  invisible by default. Software-only DMA is therefore **descriptor-following, best-effort — not a
  guaranteed complete wire capture:**
  1. From the captured MMIO we learn descriptor-ring base addresses and doorbell writes.
  2. On a doorbell/ring-update (an MMIO event we already trap), we read the descriptor ring from RAM
     and snapshot the referenced buffers; interrupts mark completions.
  3. Optional advanced mode: full DMA trapping via the **IOMMU (VT-d)** — mark the device's DMA
     pages to fault. Complete but high-cost and can perturb timing; off by default (`--dma-mode`).
- **Config space + interrupts** — config reads/writes go through I/O ports `0xCF8/0xCFC` or MMCONFIG,
  both trappable (I/O bitmap / EPT); the driver also reads config space directly at attach. MSI/MSI-X
  interrupts are captured by hooking the device ISR / trapping vector delivery, logged as events with
  the same timestamps.

### Lighter tier (no hypervisor)

For an MMIO-only first cut, hook the HAL register accessors (`READ/WRITE_REGISTER_*`, `MmMapIoSpace`)
via a kernel driver or **Windows DTrace** (`fbt` provider). Captures the driver's *intended* register
access (not DMA), far less risk than a hypervisor. Good for bring-up; upgrade to EPT for completeness.

### Storage, timeline, and what's reused

- **Kernel timestamps** at trap time via `KeQueryPerformanceCounter` — the *same* QPC used everywhere
  else, so PCIe events are on the unified timeline with **tighter** correlation than USB (no
  wall-clock skew; stamped at the instant of access).
- **No pcapng / no Wireshark** — there is no PCIe-MMIO link type or dissector. PCIe events go to a
  binary log `pcie.bin` + a fixed-width `pcie.idx` (identical seek design to §8.2), decoded to text
  on demand. Everything downstream is unchanged: checkpoints, screenshots, the seek index, the
  decode harness (register maps are *more* natural to decode than raw USB — offset+width+value), and
  the `(action, screenshot, bytes)` oracle all apply as-is.

```rust
enum PcieEvent {
    Mmio  { ts_ns: i64, bar: u8, offset: u32, width: u8, value: u64, dir: Dir },
    Dma   { ts_ns: i64, dir: Dir, dev_addr: u64, len: u32, data_ref: BlobRef },
    Irq   { ts_ns: i64, vector: u16 },
    Config{ ts_ns: i64, offset: u16, width: u8, value: u32, dir: Dir },
}
```

### PCIe-specific CLI (composes with §11)

```
reveng-rec pci-devices --format json            # enumerate PCI(e) devices: BDF, VID:PID, BARs, class
reveng-rec record --pci-vidpid 1234:abcd \      # or --pci-bdf 0000:03:00.0
    --mmio-ranges bar0:0x40-0x80 \              # trap only these register windows (perf)
    --trace-dma --dma-mode descriptor \         # descriptor (default) | iommu | off
    --mmio-trace-mode around-checkpoints        # always | around-checkpoints
```

### Honest caveats

- **VBS / HVCI / Hyper-V:** if Virtualization-Based Security or Hyper-V is active, Windows is already
  the root partition and a custom hypervisor conflicts — VBS/HVCI must be off (or the design must
  become a Hyper-V extension, out of scope). Detected at startup with a clear error.
- **Signing + stability:** the kernel driver needs test-signing or a signed cert; a bug is a BSOD.
  This is deep systems work, isolated in `driver/reveng-hv/` behind the `CaptureSource` seam.
- **DMA is best-effort** in software-only mode (descriptor-following), not a complete bus capture;
  IOMMU mode is the fuller-but-costly option. Raw TLPs remain hardware-only and out of scope.

---

## 5. Input capture

Global low-level hooks on a dedicated thread that runs a message loop:

- `WH_MOUSE_LL` → button down/up (L/R/M/X1/X2), wheel, position. Moves are **not** logged by
  default (huge volume, low value); optionally sampled at a low rate.
- `WH_KEYBOARD_LL` → key down/up, virtual-key + scancode, extended/injected flags.

The callback does the minimum: read QPC, build an `InputEvent`, push to the channel, return.
No screenshotting, no disk IO in the callback — that's what gets a hook killed.

```rust
struct InputEvent {
    ts_ns: i64,
    kind:  InputKind,      // MouseDown/Up, Wheel, KeyDown/Up
    button: Option<Button>,
    vk: Option<u16>, scancode: Option<u16>,
    x: i32, y: i32,        // screen coords
    injected: bool,
}
```

**Context enrichment** (done off the hook, when a checkpoint fires, not per-event):
`GetForegroundWindow` → window title; `GetWindowThreadProcessId` → process name. Knowing *which
app/window* had focus when a packet went out is often the whole game in RE.

---

## 6. Screenshots (event-triggered)

- **Trigger:** every mouse **button-down** by default. Optional: also on button-**up** (to capture
  the *result* of a click), and on selected special keys (Enter, Esc, F-keys).
- **Capture path:** GDI `BitBlt` from the screen DC by default — simple, reliable, ~10–30 ms for a
  4K grab, and screenshots are event-driven so we don't need a streaming path. DXGI Desktop
  Duplication is available as an opt-in for lower-latency/high-rate capture.
- **Scope:** the monitor under the cursor by default (that's where the action is); configurable to
  all monitors or just the foreground window's rectangle (smaller files).
- **Encoding:** PNG (lossless — UI text/edges matter) on the worker thread. WebP-lossless optional
  to shrink volume.
- **Burst control:** a min-interval (default 150 ms) between shots, and a bounded encode queue.
  On a drag or rapid-fire clicking we **coalesce** and record a `"screenshot_skipped"` note on the
  checkpoint rather than blocking the pipeline or ballooning disk. Nothing that skips a shot is
  silent — the checkpoint still exists, it just points at the nearest available frame.

```
screenshot(id PK, ts_ns, path, monitor_idx, width, height, trigger_checkpoint)
```

---

## 6a. Process-memory snapshots (the decoded-form oracle)

Some protocols never expose a clean export: the bytes on the wire (or in a file) are compressed,
chunked, or checksummed, and the vendor app is the only thing that decodes them. But once the app
*has* parsed them, its **resident memory holds the decoded form** — floats as IEEE-754, strings as
UTF-16, arrays laid out contiguously. Snapshotting the target process's memory **before and after a
data acquisition** and diffing the two points straight at where the acquired data landed, already
decoded. This is a third leg of the oracle (§8b): pair a changed memory address with the on-screen
value that produced it (`scan`) and the on-the-wire bytes at that instant (the checkpoint `anchor`) —
the **wire → memory → screen** triple.

It has the same shape as screenshots (§6): a heavy capture done on a worker, stored as side files,
referenced by an id on the checkpoint. It is **not** a `CaptureSource` (it isn't a streamed traffic
backend) — it's a **manual-trigger checkpoint attachment**, Windows-only (`crates/memcap`,
`cfg`-gated like `winput`/`winshot`; the format + diff/scan analysis is cross-platform).

**Capturing.** `reveng-rec record --mem-pid <PID>` (or `--mem-process <name.exe>`) arms it; the
recording window then shows a **📸 Snapshot** button. Each press dumps the target's committed,
private, writable memory on a worker thread and emits a `Manual` checkpoint carrying a
`mem_snapshot_id` — anchored to the traffic frame live at that instant, exactly as a click carries
`screenshot_id`. Needs Administrator + `SeDebugPrivilege` (auto-enabled in `elevate.rs`) to open a
cross-user target. It is a genuine full memory reader — same authorized-machine posture as the rest
of the tool (§12).

**Capture is streamed and bounded.** The address space is walked region by region and each region is
read in fixed **4 MiB chunks** (`VirtualQueryEx` + `ReadProcessMemory`), streamed straight to disk —
so peak capture memory is bounded by the chunk, not the region or the whole target footprint.
`--mem-compress` stores each region as an independent **deflate** stream (pure-Rust `flate2`); regions
are deflated on a **bounded region-parallel thread pool** so compression overlaps capture, the queue
bound providing backpressure. The read side (`diff`/`scan`) loads a snapshot's uncompressed image into RAM.

**Storage** (side files, not in `events.ndjson` — the same pattern as `screenshots/`):

```
memsnaps/
  000000/
    manifest.json   # MemSnapshotMeta
    regions.bin     # each region's bytes at file_offset for stored_len bytes (deflate if compressed)
  000001/ ...
```

```rust
struct MemSnapshotMeta {
    id: u64, ts_ns: i64, pid: u32, process: String,
    total_bytes: u64,     // uncompressed sum(size)
    stored_bytes: u64,    // on-disk sum(stored_len) — the compressed size when --mem-compress
    compression: String,  // "none" | "deflate"
    regions: Vec<RegionMeta>,
}
struct RegionMeta {
    base: u64, size: u64,           // target VA, uncompressed length
    protect: u32, mem_type: u32,    // PAGE_* flags, MEM_PRIVATE/MAPPED/IMAGE
    hash: String,                   // fnv1a64 of the uncompressed bytes (diff skips unchanged regions)
    file_offset: u64, stored_len: u64,   // where/how many bytes in regions.bin
}
```

**Querying** (the agent/LLM surface; composes with §8a.1):

```
reveng-rec mem ls   <session>                    # snapshots on the timeline: elapsed, pid, size, compression, anchored frame
reveng-rec mem regions <session> <id>            # region table (base, size, protect, hash)
reveng-rec mem diff <session> <a> <b>            # before→after delta: New/Changed/Freed/Resized regions
reveng-rec mem scan <session> <id> <value>       # find a value's encodings (u8/u16/u32/u64 LE+BE, f32/f64, ASCII, UTF-16LE)
reveng-rec mem read <session> <id> <addr> <len>  # hex/auto-render a slice at a target VA
```

`mem diff` ranks **New** and **Changed** regions first — they're what carry freshly-acquired data —
and `--max` caps the bytes shown per changed run. `mem scan` is seeded with the value you can read
straight off the screenshot, turning a noisy diff into a precise pointer.

**Workflow (RE-loop style, §8b).** Arm on the vendor app, click **📸 Snapshot** just before and just
after acquiring a reading, then:

```
reveng-rec mem diff  dev.session 0 1              # what memory changed across the acquisition
reveng-rec mem scan  dev.session 1 "42.5"         # where the on-screen value 42.5 lives (→ an f64 at 0x…)
reveng-rec mem read  dev.session 1 0x1f2a40 64    # dump that struct; recover neighbouring fields
```

Cross-reference the changed address with the checkpoint's USB/PCIe `anchor` (§7): the same click that
changed memory is anchored to the bytes that arrived on the wire, so you learn the on-wire encoding
*and* its decoded in-memory form in one shot.

---

## 7. Checkpoints — the seek anchors

A checkpoint is a marker on the unified timeline that also stores **where in the traffic stream** it
lands, so the viewer can jump straight there.

```rust
enum CheckpointType { Click, KeyDown, Interval, Manual, SessionStart, SessionStop }

struct Checkpoint {
    id: u64,
    ts_ns: i64,
    kind: CheckpointType,
    cause: String,               // "LButtonDown", "VK_RETURN", "interval", ...
    // Nearest preceding traffic event, kept SOURCE-AGNOSTIC so PCIe (or any future
    // CaptureSource) populates the identical fields against its own index — adding a
    // source is an addition, not a schema migration. See §4a / build-order note in §13.
    anchor: Option<TrafficAnchor>,
    screenshot_id: Option<u64>,
    mem_snapshot_id: Option<u64>,// process-memory snapshot at this checkpoint (§6a), if triggered
    fg_process: Option<String>,  // context snapshot
    fg_window: Option<String>,
    cursor: (i32, i32),
    note: Option<String>,        // user-editable in the viewer
}

struct TrafficAnchor {
    source: SourceId,   // Usb | Pcie | ...  (which CaptureSource / index this refers to)
    event_index: u64,   // frame index (USB) or event index (PCIe) with ts <= checkpoint.ts_ns
    byte_offset: u64,   // offset into that source's log (usb.pcapng / pcie.bin)
}
```

**Three ways a checkpoint is born:**

1. **Mouse click** — any button-down. Fires a screenshot too.
2. **Special key** — a configurable set: Enter, Esc, Tab, Backspace, Delete, F1–F12,
   Ctrl/Alt-modified combos. (Ordinary typed characters are logged as input events but don't each
   become a checkpoint — too noisy.)
3. **Interval, only during continuous traffic** — a timer ticks every `interval_ms` (default
   1000 ms). It emits a checkpoint **only if** `bytes_since_ckpt >= threshold` (default 4 KB).
   Any real checkpoint (click/key) resets the counter, so intervals only appear inside sustained
   transfers with no user action — exactly the "long streaming with nothing to anchor to" case.

**Resolving the USB anchor:** when a checkpoint fires at `ts_ns`, the engine looks up the USB
frame with the greatest `ts_ns <= checkpoint.ts_ns` (the index is monotonic, so this is a cheap
tail lookup) and stores its `frame_index` + `byte_offset`. That pairing is what makes seeking
O(1) in the viewer, and it's also what we use to inject the Wireshark packet comment.

---

## 8. On-disk session format

```
session_2026-07-11_1030/
  meta.json          # clock anchor, backend + capture speed, config, tool/OS versions, monitor
                     #   layout, traffic_only, folded bus-event summary
  usb.pcapng         # traffic truth — Wireshark-openable, checkpoint comments injected
  frames.idx         # fixed-width binary seek index, one 24-byte record per frame — DERIVED
  events.ndjson      # append-only truth: every InputEvent + Checkpoint, in ts order
  bus_events.ndjson  # analyzer bus events (§4.1) — wire captures only
  screenshots/       # absent under --traffic-only
    000001.png ...
  displays.json      #   "
  ui/                #   " UI-Automation widget snapshots
  memsnaps/          # process-memory snapshots (§6a), when armed — side files like screenshots/
    000000/{manifest.json, regions.bin} ...
```

- **Sources of truth:** `usb.pcapng` (traffic) and `events.ndjson` (input/checkpoints). Both are
  append-only and flushed — crash-safe. If the recorder dies mid-session, the data is intact.
- **`*.idx` are derived** and fully rebuildable from the truth files with
  `reveng-rec reindex <session>`, which keeps the hot recording path free of anything
  transactional.

> A relational `index.sqlite` was specified here for the viewer and decoded-field tables. It was
> never built — `frames.idx` plus in-memory scanning proved sufficient at the sizes reached, and
> `rusqlite` is not a dependency. Two code comments still mention it aspirationally.

### 8.2 Seeking at scale

None of the *container* formats are self-seekable — `usb.pcapng` is a stream of variable-length
blocks and `events.ndjson` must be scanned line by line. Seeking is provided entirely by the
**index layer**:

- **`frames.idx` — fixed-width binary sidecar, the primary seek structure.** One record per
  frame, appended cheaply on the hot recording path (crash-safe, no transactions):

  ```
  struct FrameIdxRecord {   // 24 bytes, frame_index is implicit = record position
      ts_ns:       i64,     // monotonic → binary-searchable
      byte_offset: u64,     // offset of the frame's block in usb.pcapng
      endpoint:    u8, dir: u8, xfer: u8, status: u8,
      data_length: u32,
  }
  ```

  - **Seek to frame N** = read 24 bytes at `N * 24` — *direct addressing*, no search.
  - **Seek to time T** = binary search over the monotonic `ts_ns` column — O(log n).
  - The file is `mmap`'d, so both are memory-speed. At 20M frames it's ~480 MB.

- **Checkpoints and screenshots need no index.** They number in the hundreds or thousands
  regardless of capture size, so scanning `events.ndjson` is trivial — which is why the
  relational index above never became necessary.

**Reading a traffic window is independent of session size:** one index lookup → one `fseek` into the
pcapng at `byte_offset` → sequential read of K frames. Nothing parses the capture from the start.

**Scale check.** A worst-case bulk-streaming session (~10 MB/s for 10 min) ≈ 6 GB pcapng / ~20M
frames. `frames.idx` ≈ 480 MB, mmap'd; any seek is O(1) direct-address or O(log n) binary search.
Decoded text is **never** persisted as a monolithic `usb.jsonl` (it would exceed the capture and
can't be line-addressed) — it is generated on demand for the requested window only.

**Very large / long sessions (optional):** the pcapng may be **rotated into segments**
(`usb.000.pcapng`, `usb.001.pcapng`, …); `frames.idx` then stores `(segment_id, byte_offset)` and
seeking is unchanged. This bounds any single file and lets analysis start while recording continues.

### 8.1 What's LLM-readable, and what isn't

An LLM/agent is a first-class consumer of a session (see the README). But of the files above, only
the text ones are directly consumable:

| File | Format | LLM reads it? |
|---|---|---|
| `events.ndjson` | UTF-8, one JSON object per line | ✅ read / `grep` directly |
| `meta.json` | small JSON | ✅ |
| `screenshots/*.png` | binary PNG | ✅ **via vision** (image Read) |
| `usb.pcapng` | binary pcapng | ❌ binary, and large |
| `frames.idx` | fixed-width binary | ❌ not directly — needs the query CLI |

The main signal (`usb.pcapng`) is precisely the part an LLM can't read. **The rule: an agent never
*reads* a session, it *queries* it** — checkpoints are the index, screenshots go in via vision, USB
frames are served as bounded decoded **text** on demand. The pcapng is never loaded into context.

---

## 8a. LLM-facing representation

Two mechanisms make a session consumable by an agent without ever touching the binary pcapng.

**1. Decoded text mirror of USB frames.** Any frame can be rendered as a one-line JSON form,
**generated on demand for the requested window** (not persisted as a monolithic file — see §8.2).
Binary capture becomes greppable text:

```jsonl
{"i":10432,"ts_ms":15230.44,"dev":5,"ep":"0x81","dir":"in","xfer":"bulk","len":64,"status":0,"hex":"12 01 00 02 09 02 20 00","ascii":"...... ."}
```

For control transfers the setup packet is decoded (`bmRequestType`/`bRequest`/`wValue`/`wIndex`/
`wLength`) into named fields; other transfer types carry `hex` + `ascii`.

**2. Checkpoint cards + a manifest.** The **manifest** is the entry point — one compact line per
checkpoint, small enough to load whole even for long sessions:

```jsonl
{"checkpoint":12,"ts_ms":15200,"type":"click","summary":"click @ (842,391) in Vendor.exe; 3 bulk-OUT frames follow","screenshot":"screenshots/000012.png","frames":[10432,10450]}
```

A **checkpoint card** is the unit that binds all three streams for one moment:

```json
{
  "checkpoint": 12, "ts_ms": 15200.0, "type": "click",
  "cause": "LButtonDown @ (842,391)",
  "context": {"process": "Vendor.exe", "window": "Device Config"},
  "screenshot": "screenshots/000012.png",
  "usb_window": { "before": [ /* decoded frames */ ], "after": [ /* decoded frames */ ] }
}
```

**Agent loop:** read manifest → pick the checkpoint of interest → `show` its card → `Read` the
referenced screenshot (vision) → pull/`diff`/`grep` frames as needed. Context stays bounded because
only slices are ever materialized.

### 8a.1 Query CLI (the agent's interface)

```
reveng-rec ls                        # manifest — one line per checkpoint (read FIRST; co-logged sessions also show pcie=<idx>)
reveng-rec notes                     # just the live notes typed while recording (JSONL: elapsed + anchored frame + text)
reveng-rec show <ckpt>               # full checkpoint card (JSON); co-logged sessions add extra_anchors (PCIe event decoded)
reveng-rec frames --around <ckpt> -w 20   # decoded frames near a checkpoint
reveng-rec frames --range 10400:10460
reveng-rec diff <ckptA> <ckptB>      # frames that differ between two checkpoints
reveng-rec payload <frame> --format hex   # raw payload bytes of one frame
reveng-rec grep <hexpattern>         # frames whose payload contains a byte pattern
reveng-rec mem ls|regions|diff|scan|read  # process-memory snapshots taken during recording (§6a)
```

**Text vs binary.** `payload` defaults to `--format auto`: endpoints that classify as text
(`reveng_core::text::is_texty`, printable-ratio ≥ 0.85 — CDC-ACM serial, NMEA, AT commands, debug
logs) render as text; binary renders as an `xxd`-style hex + ASCII gutter. `stream --text`
reassembles an endpoint by newlines (the serial shape) instead of the binary logical framing, and
`grep --text` matches a UTF-8 substring instead of a hex byte pattern.

Output is bounded, decoded text (add `--format json|text|hex|auto`). These commands are backed by
`frames.idx` + byte-offset seeks into `usb.pcapng`, so they're O(1)-ish and never stream the whole
capture. The viewer and the CLI share the same `export`/decode code path.

---

## 8b. Iterative binary decoding — the core RE loop

Most captured traffic is **opaque proprietary binary**. The expected mode is: an LLM writes a
candidate decoder, runs it over the capture, checks the result, and refines. **The model does not
read bytes to decode them — its *code* does.** The framework's job is to feed that code clean bytes,
run it, and provide ground truth to check against.

**Division of labor**

| The framework provides | The LLM (or human) provides |
|---|---|
| Raw bytes with stable frame IDs | A hypothesis / candidate decoder |
| Logical message reassembly | Interpretation of decoded fields |
| A decoder harness (run + render) | Iteration until fields match reality |
| Ground truth: action + screenshot per checkpoint | — |

### Raw byte access

The pcapng is the untouched raw truth — the LLM's code can parse it with any pcap library (scapy,
pyshark, `pcap-file` in Rust, …). For direct feeding into a decoder without touching pcapng, the CLI
serves bytes with stable IDs:

```
reveng-rec frames --ep 0x02 --format base64      # decoder-consumable JSONL, one frame per line
reveng-rec payload <frame> --format bin           # raw bytes to stdout
```

Frame index `i` is stable for the life of the session, so a decoder's output always maps back to a
specific frame (and therefore to a checkpoint, screenshot, and moment).

### Logical message reassembly

USBPcap frames are URB/IRP fragments, not protocol messages. The `usbcap` decoder reassembles them
into **logical transfers per endpoint** (concatenating multi-packet bulk transfers; grouping
control setup/data/status stages) so a decoder sees message boundaries, not transport fragments:

```
reveng-rec stream --ep 0x02 --logical            # reassembled logical messages on the OUT endpoint
```

Raw frames remain available; reassembly is a view, never a mutation of the truth.

### Decoder harness

A decoder is **language-agnostic**: a program that reads frames as JSONL (base64 payload) on stdin
and emits annotated JSONL on stdout. The harness runs it and renders the result (CLI text or in the
viewer):

```
reveng-rec decode --with ./mydecoder.py --ep 0x02      # run a candidate decoder, show its output
reveng-rec decode --ksy ./proto.ksy   --ep 0x02        # or a declarative Kaitai Struct definition
```

Two decoder flavors, both optional and layered on top of the always-present raw bytes:
- **Imperative** — any script honoring the stdin/stdout JSONL contract (fastest for an LLM to author).
- **Declarative** — a [Kaitai Struct](https://kaitai.io) `.ksy` file, which is self-documenting and
  reusable outside this tool. In-tree Rust decoders (a `Decoder` trait) are also supported for
  performance.

Saved decoders live in the session (`decoders/`); re-running makes the viewer and CLI render semantic
fields alongside the raw hex. Decoding is **additive** — raw bytes are never overwritten, so a wrong
decoder is free to throw away.

### Decode-assist analytics

Primitives so the LLM doesn't reimplement common structure-hunting over a class of frames:

```
reveng-rec bytes --ep 0x02 --stats     # per-byte-position constancy / entropy across all frames
reveng-rec diff <ckptA> <ckptB>        # which bytes changed between two actions
reveng-rec track --ep 0x02 --offset 4  # value at byte 4 across checkpoints (vs. the screenshots)
```

Constant vs. variable byte positions, candidate length fields, and CRC/checksum guesses fall out of
these — the scaffolding for a hypothesis.

### The oracle (why this beats a plain sniffer)

Every checkpoint binds bytes to **what the user did** and **what the screen showed**. A session is a
labeled dataset of `(action, screenshot, bytes)` triples. A hypothesized field is *verifiable*: "the
slider read 50 in the screenshot at checkpoint 12 → byte 4 is `0x32`; at checkpoint 15 it read 80 →
byte 4 is `0x50`." That correlation is what makes the decode loop converge instead of guess.

---

## 9. Viewer (egui desktop app)

- **Timeline** — checkpoints color-coded by type (click / key / interval / manual / note), with
  traffic density overlaid so busy regions are visible. Click a marker or `←/→` to step; the
  screenshot pane and traffic inspector move together.
- **Inspector** — frames in a window around the checkpoint, decoded header plus hex/ASCII payload,
  seeked by `byte_offset`. Filter by endpoint / direction / transfer type.
- **Diff aid** — select two checkpoints and diff the frames between them. This is the "what's
  different between button A and button B" question, which is most of the RE loop.

### 9.1 Recorder surfaces that are not the viewer

These accreted into §9 historically. Mechanism is in `crates/recorder/src/notes_ui.rs` and
`main.rs`; what matters at the design level:

- **The recording window is the primary surface, and notes are captured live, not after.** Typing
  a note stamps it on the master clock *at the keypress* and stores it as a `Manual` checkpoint
  anchored to the frame live at that instant — which is what lets an agent later correlate "what
  the operator said" against "what was on the wire". While that window is focused the input hook
  suppresses keystroke/click checkpoints, so writing the note does not litter the timeline.
- **The dashboard shows aggregates only, never contents** — counters sampled every 250 ms. Raw
  events stay in the logs and are queried offline. This is a deliberate boundary, not an
  optimisation.
- **The device picker relaunches the process** with the chosen devices as explicit args (elevated
  via UAC if needed), so the child skips the picker. Leaving everything unticked records
  input + notes only.
- **Zero capture sources is a supported case**, not an error: the whole pipeline runs with no
  device and no admin.
- **Volume reduction is opt-in and never silent.** Defaults are byte-exact; `--usb-snaplen`,
  `--drop-isoc`/`--drop-bulk` and `--endpoints` trade fidelity for size, and every dropped packet
  is counted and reported. On the wire backend most of these are refused outright because they
  break reassembly (§4.1).
- **The engine is source-agnostic**, and input is the *primary* driver: traffic is what gets
  anchored to a click, not the other way round (§7). A PCIe-only session behaves exactly like a
  USB-only one. With `--with-pcie`, one click reaches both wires — `Checkpoint.anchor` stays the
  USB frame and `anchors` carries the nearest preceding PCIe event, each source-tagged.

---

## 10. Export / decode / Wireshark handoff

- **Open in Wireshark at this frame:** the whole `usb.pcapng` opens directly; the viewer shells out
  `wireshark.exe -r usb.pcapng -g <frame_number>` to jump to the checkpoint's frame. Checkpoint
  comments are already embedded, so they're visible in Wireshark's packet list.
- **Export a slice:** select a checkpoint (or a range between two) → the `export` crate writes a new
  `.pcapng` containing just those frames (we own the writer and have the offsets), optionally with
  the surrounding ±N frames for context.
- **Export payloads:** dump the raw payload bytes of the selected frames (e.g. for feeding a
  protocol decoder or a diff tool).

---

## 11. Configuration & CLI

Every setting has a CLI flag; a `--config <file.toml>` supplies defaults that flags override.
The recorder is `reveng-rec record`; discovery is `reveng-rec devices`.

### 11.1 Device discovery & selection

An LLM (or user) must be able to find the target device and pin the capture to it. Discovery is
scriptable — it emits JSON — because ephemeral bus addresses aren't known ahead of time:

```
reveng-rec devices --format json      # enumerate the USB tree, exit; JSON for programmatic pick
reveng-rec devices                     # human-readable tree
```

```jsonc
// one entry per attached device
{ "usbpcap": "\\\\.\\USBPcap1", "bus": 1, "address": 5,
  "vid": "1234", "pid": "abcd", "serial": "A1B2",
  "product": "Acme Widget", "manufacturer": "Acme",
  "class": "vendor-specific", "endpoints": ["0x81 in bulk","0x02 out bulk"] }
```

Selection flags on `record` (repeat to target several devices; **VID:PID is preferred** — it's
stable across replug, whereas bus address is not and is resolved to an address at start):

| Flag | Meaning |
|---|---|
| `--usbpcap-device \\.\USBPcapN` | which root-hub control device to tap (default: prompt/auto if one) |
| `--device-vidpid 1234:abcd` | target device(s) by VID:PID (repeatable) |
| `--device-serial A1B2` | disambiguate when several units share a VID:PID |
| `--device-address N` | target by USB bus address directly (repeatable) |
| `--all-devices` | capture everything on the hub (default if no selector; warns about volume) |
| `--endpoints 0x02,0x81` | keep only these endpoints in the index/decode views (capture is still whole) |

If nothing matches at startup the recorder errors out rather than silently capturing everything.

### 11.2 Checkpoint-control flags

Checkpoints default to: mouse button-down, a special-key set, and interval-during-traffic (§7).
**The flag list itself lives in `reveng-rec record --help`**, which cannot drift, and in README's
CLI reference. What is worth recording here is why two of the defaults are shaped as they are:

- **Interval checkpoints are gated on bytes as well as time** (`--interval-bytes`, default 4096).
  A pure timer would litter an idle capture with anchors that all point at the same frame; the
  byte gate means an interval checkpoint only appears where traffic actually moved.
- **Mouse-*down* is the default, not mouse-up.** The screenshot then shows the UI in the state
  that *caused* the traffic. `--checkpoint-on-mouseup` captures the result instead, which is the
  right choice when you care about what the click produced on screen rather than what it sent.

### 11.3 Screenshot & control flags

Again, `--help` is the reference. The non-obvious ones:

- **`--screenshot-min-interval-ms` (default 150) is burst coalescing**, not throttling for its own
  sake — a double-click or a drag would otherwise queue several near-identical grabs onto the hot
  path. Skipped grabs are recorded on the checkpoint so the gap is visible (§6).
- **`--screenshot-scope` defaults to the cursor's monitor**, because a multi-monitor `all` grab is
  several times the pixels for no extra evidence about the click that triggered it.
- **`--traffic-only` overrides all of the above** (§4.4) — no hooks, no screenshots, no UIA.

### 11.4 Config file — not implemented

A TOML config was specified here as an alternative to the flags. It was never built: `record` is
flags-only, and nothing reads a recorder config file. TOML is used in the codebase, but only for
`annotate`'s decoder specs. The shape it *would* have taken, kept only as a sketch:

```toml
[usb]
usbpcap_device = "\\\\.\\USBPcap1"
device_vidpid  = ["1234:abcd"]   # preferred; or device_address = [5]
all_devices    = false
endpoints      = ["0x02","0x81"] # optional index/decode filter

[checkpoints]
on_any_key     = false
special_keys   = ["Return","Escape","Tab","Back","Delete","F1..F12"]
key_combos     = ["Ctrl+S"]
mouse_buttons  = ["L","R","M"]
on_mouseup     = false
on_wheel       = false
interval_ms    = 1000            # 0 = disable
interval_bytes = 4096
manual_hotkey  = "Ctrl+Alt+M"

[screenshot]
on             = "mousedown"     # mousedown | mouseup | both | none
on_keys        = true
scope          = "cursor-monitor"
min_interval_ms = 150
format         = "png"

[control]
stop_hotkey    = "Ctrl+Alt+Pause"
rotate_mb      = 0               # 0 = single file
```

**Example — LLM targets one device, checkpoints on every key, grabs on press and release:**

```
reveng-rec record --device-vidpid 1234:abcd \
    --checkpoint-on-any-key --checkpoint-on-mouseup --screenshot-on both --out ./widget_run
```

---

## 12. Constraints, risks, and non-goals

- **Admin required** (USBPcap kernel driver). Recorder checks for elevation and USBPcap install.
- **LL-hook latency budget** — the single most likely footgun. Callbacks must stay trivial or
  Windows silently drops input. Enforced by design (timestamp+enqueue only) and worth a startup
  self-test.
- **USB throughput** — a busy device can flood the reader. Mitigations: device-address filtering at
  the source, a high-priority non-blocking reader, write-through to disk. USBPcap's own kernel
  buffer is the real backstop; if we can't keep up, *it* drops and we log a gap marker. The
  analyzer backend has the harder version of this problem — its uplink is itself USB 2.0, so a
  saturating high-speed target can outrun it. That overflow is at least reported rather than
  silent (§4.1).
- **Clock skew** between USB (system-time) and input (QPC) is a few ms — fine for click-seeking,
  called out for anyone needing bus-accurate timing.
- **This is, functionally, a keylogger + screen recorder** — and, with `--mem-pid`/`--mem-process`
  (§6a), a **process-memory reader** (admin + SeDebugPrivilege). It's legitimate RE/defensive tooling,
  but it must only be run on a machine the operator owns/is authorized to instrument. Sessions stay
  local; no network egress. Worth a consent banner + a visible "RECORDING" indicator.
- **Non-goals (for now):** **raw PCIe TLP capture** (hardware-only; software capture is TLP-free —
  see §4a); live real-time decode; automated protocol reverse-engineering; USB 3 / SuperSpeed.
  PCIe DMA is best-effort in software.

  > Two of these used to be non-goals and no longer are. *Hardware analyzers* were ruled out; the
  > `CaptureSource` seam did host one, and §4.1 is the result. *Non-Windows platforms* were ruled
  > out; traffic capture and the whole read side are now OS-agnostic, though only the correlation
  > half remains genuinely Windows-bound. The seam earned its keep.

---

## 13. Build order (historical)

The order this was actually built in, kept because the dependency reasoning still holds for anyone
restructuring it. Steps 1–7 are done; the analyzer backend (§4.1) slotted in behind step 2's
`CaptureSource` without touching 3–7, which is the strongest evidence the seam was drawn in the
right place.

1. **`core` + clock anchor + session schema + `CaptureSource` trait** — the timeline foundation.
2. **`usbcap`** — parse frames, pcapng writer + index. Verify against Wireshark.
3. **`winput`** — hooks + InputEvent; prove the latency budget holds.
4. **Checkpoint engine + `winshot`** — clicks → checkpoint + screenshot; interval logic.
5. **`recorder` bin** — wire the threads, stop hotkey, finalize + comment injection.
6. **`viewer`** — timeline → screenshot + USB inspector → seek.
7. **`export`** — slice + Wireshark handoff.

**PCIe track (separate, later — much higher risk; USB path proves out the whole pipeline first).**
Acquisition is a swappable leaf behind `CaptureSource`, so **postponing or cutting any one PCIe tier
changes nothing above the seam** — provided the shared layers stay source-agnostic (see the
`TrafficAnchor` in §7; keep the index/decode byte-oriented). If the DTrace tier (step 8) is
postponed, add a trivial **replay `CaptureSource`** that emits a hand-authored `PcieEvent` JSONL, so
storage/index/decode/viewer for PCIe can be built and validated with **zero kernel code** before the
hypervisor exists.

8. **`pcicap` MMIO-only via Windows DTrace / HAL hooks** *(optional / may be skipped)* — the lighter
   tier (§4a): capture the driver's register accesses with no hypervisor. Cheap way to validate the
   PCIe event schema + storage end-to-end; a replay source (above) substitutes if skipped.
9. **`driver/reveng-hv`** — thin VT-x/EPT hypervisor for real MMIO trapping (read-side-effect-safe),
   config/interrupt capture, `--mmio-ranges` scoping. VBS/HVCI-off precondition enforced at startup.
10. **DMA descriptor-following** (then optional IOMMU mode) — reconstruct DMA from ring/doorbell
    activity captured in steps 8–9.
```
