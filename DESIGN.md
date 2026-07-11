# reveng-recorder — Design

A Windows tool for reverse-engineering USB devices by **correlating USB bus traffic with what
the user was doing on screen**. It records USB traffic (via USBPcap), global mouse/keyboard
input, and event-triggered screenshots into a single time-synchronized session, then lets you
seek through the USB stream using mouse clicks and key events as natural checkpoints.

- **Platform:** Windows only (x64). Everything else out of scope.
- **Stack:** Rust. Recorder is a CLI/service binary; viewer is an [egui](https://github.com/emilk/egui) desktop app.
- **USB capture:** [USBPcap](https://desowin.org/usbpcap/) (free kernel driver, pcap-compatible). No extra hardware.
- **Wireshark:** raw capture stays Wireshark-openable; viewer can hand off to Wireshark at a specific frame.

---

## 1. The workflow it enables

1. Start `reveng-rec`, pick the USBPcap root hub + (optionally) filter to the target device.
2. Drive the vendor software normally — click buttons, type, etc.
3. Every mouse-button press (and selected special keys) drops a **checkpoint** and grabs a
   **screenshot**. Long stretches of continuous USB traffic also get periodic checkpoints.
4. Stop with a global hotkey. The session is written to disk (USB as `.pcapng`, events as an
   append-only log, screenshots as files, plus a rebuildable SQLite index).
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
                          │                                              │
  USBPcapCMD.exe  ──pipe──▶  usbcap reader ──▶ pcapng writer (usb.pcapng)│
  (\\.\USBPcapN)          │        │           frame index (ts,offset)   │
                          │        └──▶ bytes_since_ckpt (atomic) ──┐    │
                          │                                          │    │
  WH_MOUSE_LL   ─┐        │  input thread ──▶ InputEvent channel ──┐ │    │
  WH_KEYBOARD_LL ┘ hooks  │  (msg loop)                            │ │    │
                          │                                        ▼ ▼    │
                          │                          checkpoint engine    │
                          │                          - click → ckpt+shot  │
                          │                          - special key → ckpt │
                          │                          - interval timer     │
                          │                                │   │          │
                          │                     screenshot ▼   ▼ session   │
                          │                     worker (GDI/DXGI) writer   │
                          │                        │        events.ndjson  │
                          │                        ▼        index.sqlite   │
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

### Thread model (recorder)

| Thread | Job | Constraint |
|---|---|---|
| **usbcap reader** | drain USBPcap pipe, write-through to `usb.pcapng`, parse header-only for index, bump `bytes_since_ckpt` | Highest priority. Must never block — USBPcap's kernel buffer drops if we stall. |
| **input** | owns the LL hooks + `GetMessage` loop; timestamps events and pushes to a channel | Hook callback does *only* timestamp+enqueue. LL hooks are dropped/removed by Windows if a callback exceeds `LowLevelHooksTimeout` (~300 ms). |
| **checkpoint engine** | consumes input events, interval timer, and traffic counter; emits `Checkpoint`s; resolves nearest USB frame; requests screenshots | — |
| **screenshot worker** | on request, grabs + encodes PNG off the hot path | Bounded queue; coalesces bursts (see §6). |
| **session writer** | serializes `events.ndjson`, updates `index.sqlite` | Single writer = simple ordering. |
| **control** | global stop hotkey, Ctrl+C, clean flush/finalize | — |

Channels: `crossbeam-channel`. Shutdown via a `CancellationToken`-style atomic + channel close.

### Rust crate/module layout

```
reveng-recorder/
  crates/
    core/        # shared types, clock anchor, session schema, ndjson + sqlite IO, CaptureSource trait
    usbcap/      # USB CaptureSource: spawn USBPcapCMD, parse frames, pcapng writer w/ comments
    pcicap/      # PCIe CaptureSource: talks to reveng-hv, emits Mmio/Dma/Irq/Config events (§4a)
    winput/      # LL mouse/keyboard hooks, InputEvent
    winshot/     # screen capture (GDI default, DXGI Desktop Duplication optional) + PNG encode
    recorder/    # bin: orchestration, checkpoint engine, control/hotkey
    viewer/      # bin: egui app — timeline, inspector, seek, export
    export/      # pcapng slicing + Wireshark handoff (shared by viewer)
  driver/
    reveng-hv/   # kernel-mode: thin VT-x/EPT hypervisor + PCI/IRQ driver (PCIe capture only)
```

All acquisition backends implement one `CaptureSource` trait (emit timestamped events onto the
shared timeline); USB and PCIe differ only in acquisition, not in anything downstream.

Key deps: `windows` (windows-rs) for hooks/capture/clock, `crossbeam-channel`, `rusqlite`,
`serde`/`serde_json`, `image` (PNG), `eframe`/`egui` for the viewer, `clap` for the CLI.

---

## 4. USB capture (USBPcap backend)

- Spawn `USBPcapCMD.exe -d \\.\USBPcapN -o -` and read the pcap stream from its **stdout**.
  Requires **Administrator** (kernel driver). We detect and prompt for elevation.
- **Device selection:** run USBPcapCMD's device enumeration first, present the tree
  (hub → device → interfaces) to the user, and pass `--devices <addr,addr>` to filter to just the
  target device address. Filtering at the source dramatically cuts volume (isochronous/bulk
  devices can be very chatty).
- **Parsing:** each record = pcap record header (ts) + `USBPCAP_BUFFER_PACKET_HEADER`
  (irpId, status, function, info, bus, device, endpoint, transfer type, dataLength) + payload.
  The reader parses the fixed header only (cheap) to build the index; payloads are written
  straight to disk.
- **Storage — we own the pcapng writer.** Instead of dumping USBPcap's raw pcap verbatim, we
  re-emit frames into a **pcapng** with `LINKTYPE_USBPCAP` (249):
  - Preserves original per-frame timestamps.
  - Lets us inject **per-packet Comment options** at checkpoint frames
    (`"CHECKPOINT #12 — click @ (842,391) in Vendor.exe"`). Those show up natively in Wireshark,
    so checkpoints are visible even outside our viewer.
  - Fully Wireshark-openable.
- **Frame index** (written to `index.sqlite`, header-only — payloads stay in the pcapng):

  ```
  usb_frame(frame_index PK, ts_ns, byte_offset, bus, device, endpoint,
            transfer_type, direction, data_length, status, function)
  ```

  `byte_offset` = offset of the frame's block in `usb.pcapng`, enabling O(1) seek + partial reads.

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
  meta.json          # clock anchor, USBPcap device+filter, config, tool/OS versions, monitor layout
  usb.pcapng         # USB truth — Wireshark-openable, checkpoint comments injected
  frames.idx         # fixed-width binary seek index, one 24-byte record per USB frame
  events.ndjson      # append-only truth: every InputEvent + Checkpoint, in ts order
  index.sqlite       # DERIVED, rebuildable: checkpoint, screenshot, decoded-field tables
  screenshots/
    000001.png ...
```

- **Sources of truth:** `usb.pcapng` (USB) and `events.ndjson` (input/checkpoints). Both are
  append-only and flushed — crash-safe. If the recorder dies mid-session, the data is intact.
- **`index.sqlite`** is a query accelerator for the viewer and can be **fully rebuilt** from the
  pcapng + `frames.idx` + ndjson (`reveng-rec reindex <session>`). This keeps the hot recording path
  from depending on transactional DB writes.

### 8.2 Seeking at scale

None of the *container* formats are self-seekable — `usb.pcapng` is a stream of variable-length
blocks and `events.ndjson` must be scanned line by line. Seeking is provided entirely by the
**index layer**, in two parts:

- **`frames.idx` — fixed-width binary sidecar, the primary USB seek structure.** One record per USB
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

- **`index.sqlite` — relational seek** for checkpoints, screenshots, and decoded fields (B-tree,
  O(log n)). Checkpoints number in the hundreds/thousands regardless of capture size, so these
  queries are trivial. Input events live in `events.ndjson` but are indexed here for range queries.

**Reading a USB window is independent of session size:** one index lookup → one `fseek` into the
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
| `index.sqlite` | binary SQLite | ❌ not directly — needs the query CLI |

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
reveng-rec ls                        # manifest — one line per checkpoint (read FIRST)
reveng-rec show <ckpt>               # full checkpoint card (JSON)
reveng-rec frames --around <ckpt> -w 20   # decoded frames near a checkpoint
reveng-rec frames --range 10400:10460
reveng-rec diff <ckptA> <ckptB>      # frames that differ between two checkpoints
reveng-rec payload <frame> --format hex   # raw payload bytes of one frame
reveng-rec grep <hexpattern>         # frames whose payload contains a byte pattern
```

Output is bounded, decoded text (add `--format json|text|hex`). These commands are backed by
`index.sqlite` + byte-offset seeks into `usb.pcapng`, so they're O(1)-ish and never stream the whole
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

- **Timeline** — horizontal track of checkpoints, color-coded by type (click / key / interval /
  manual). Zoom + pan. Overlaid USB-traffic density so you can *see* the busy regions.
- **Seek** — click a marker, or `←/→` to step prev/next checkpoint. Screenshot pane + USB inspector
  update together.
- **Screenshot pane** — the grab at that checkpoint, with the cursor position drawn on it.
- **USB inspector** — the frames in a window around the checkpoint (±K frames or ±T ms, from the
  index). Decoded header (dev/endpoint/transfer/dir/len/status) + hex/ASCII payload (seeked from
  `byte_offset` in the pcapng). Filter by endpoint/direction/transfer type.
- **Notes** — annotate a checkpoint; persisted back to `events.ndjson`/sqlite.
- **Diff aid** — select two click checkpoints and diff the USB frames between them (great for
  "what's different between pressing button A vs button B").

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

Checkpoints default to: mouse button-down, a special-key set, and interval-during-traffic
(see §7). These flags tune what generates a checkpoint:

| Flag | Default | Meaning |
|---|---|---|
| `--checkpoint-on-any-key` | off | **every** key-down is a checkpoint, not just special keys |
| `--checkpoint-keys Return,Escape,Tab,F1..F12` | see §7 | override the special-key set |
| `--no-checkpoint-keys` | — | disable key-triggered checkpoints entirely |
| `--checkpoint-key-combos Ctrl+S,Ctrl+Enter` | off | modifier combos that trigger a checkpoint |
| `--checkpoint-mouse-buttons L,R,M,X1,X2` | `L,R,M` | which buttons trigger a checkpoint |
| `--checkpoint-on-mouseup` | off | also checkpoint on button **release** (captures the result) |
| `--checkpoint-on-wheel` | off | mouse-wheel scroll triggers a checkpoint |
| `--no-checkpoint-clicks` | — | disable mouse-triggered checkpoints |
| `--interval-checkpoint-ms N` | `1000` | period for interval checkpoints; `0` disables |
| `--interval-bytes N` | `4096` | min USB bytes since last checkpoint to emit an interval one |
| `--manual-checkpoint-hotkey Ctrl+Alt+M` | set | hotkey to drop a manual checkpoint on demand |

### 11.3 Screenshot & control flags

| Flag | Default | Meaning |
|---|---|---|
| `--screenshot-on mousedown\|mouseup\|both\|none` | `mousedown` | when to grab |
| `--screenshot-on-keys` | on | also grab on key-triggered checkpoints |
| `--screenshot-scope cursor-monitor\|all\|foreground-window` | `cursor-monitor` | capture area |
| `--screenshot-min-interval-ms N` | `150` | burst coalescing floor |
| `--screenshot-format png\|webp-lossless` | `png` | encoding |
| `--out <dir>` | `./session_<ts>` | session output directory |
| `--stop-hotkey Ctrl+Alt+Pause` | set | clean-stop hotkey |
| `--rotate-mb N` | off | rotate `usb.pcapng` into segments every N MB (see §8.2) |

### 11.4 Equivalent TOML

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
- **USB throughput** — a busy device can flood the pipe. Mitigations: device-address filtering at
  the source, a high-priority non-blocking reader, write-through to disk. USBPcap's own kernel
  buffer is the real backstop; if we can't keep up, *it* drops and we log a gap marker.
- **Clock skew** between USB (system-time) and input (QPC) is a few ms — fine for click-seeking,
  called out for anyone needing bus-accurate timing.
- **This is, functionally, a keylogger + screen recorder.** It's legitimate RE/defensive tooling,
  but it must only be run on a machine the operator owns/is authorized to instrument. Sessions stay
  local; no network egress. Worth a consent banner + a visible "RECORDING" indicator.
- **Non-goals (for now):** non-Windows platforms; **raw PCIe TLP / hardware analyzers** (the
  `CaptureSource` seam could host one later, but software capture is TLP-free — see §4a); live
  real-time decode; automated protocol reverse-engineering. PCIe DMA is best-effort in software.

---

## 13. Suggested build order

1. **`core` + clock anchor + session schema + `CaptureSource` trait** — the timeline foundation.
2. **`usbcap`** — spawn USBPcapCMD, parse frames, pcapng writer + index. Verify against Wireshark.
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
