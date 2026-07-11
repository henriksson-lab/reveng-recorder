* **under development, not ready for use**
* Before you reverse engineer anything, read up on the law. Especially [clean-room design](https://en.wikipedia.org/wiki/Clean-room_design). Law also differs EU vs US

# reveng-recorder

> **Handover note for an LLM/agent picking up this project.** Read this file first, then
> [`DESIGN.md`](./DESIGN.md). This README tells you *what state the project is in and how to work
> on it*; `DESIGN.md` is the authoritative spec for *what it is and how it's built*.

## What this is

A **Windows-only** tool for reverse-engineering hardware devices. It records device traffic plus
user activity into one time-synchronized session and lets you seek through the traffic using user
actions as anchors:

1. **Device traffic**, from a pluggable **capture source** (all backends share one `CaptureSource` seam):
   - **USB** — via [USBPcap](https://desowin.org/usbpcap/) (free kernel driver, pcap-compatible; no extra hardware).
   - **PCIe** — software-only MMIO/DMA/config+interrupt capture via a thin VT-x/EPT hypervisor
     driver (`driver/reveng-hv/`). No raw-TLP capture (hardware-only, out of scope). See `DESIGN.md` §4a for the substantial caveats (VBS/HVCI, driver signing, best-effort DMA).
2. **Mouse + keyboard input** — global low-level Windows hooks.
3. **Screenshots** — grabbed automatically when a mouse button is pressed (and on selected special keys).

Then a **viewer** shows a timeline of *checkpoints* (mouse clicks, special keys, and
periodic markers during continuous traffic). Selecting a checkpoint shows the screenshot at that
instant plus the USB frames around it, and can hand off to Wireshark at the exact frame.

**The one-sentence purpose:** answer *"what did clicking this button send on the wire?"* in two clicks.

## Locked-in decisions (do not re-litigate without asking the user)

| Decision | Choice | Why |
|---|---|---|
| Platform | Windows x64 only | Everything else is explicitly out of scope for now. |
| Language | **Rust** | Single fast binaries; tight timing for the USB pipe and input hooks. |
| USB capture | **USBPcap** (software) | Free, no hardware, Wireshark-compatible. A capture-source seam is designed in so a HW analyzer can be added later. |
| Scope | Full end-to-end | Recorder **+** viewer **+** export/Wireshark handoff. |
| Master clock | QueryPerformanceCounter (QPC) | Single monotonic timeline; all sources normalized to ns-since-start. See `DESIGN.md` §2. |
| GUI | egui (`eframe`) | Timeline + hex + image inspector in a single native binary. |

## Current state

**A full platform-neutral slice works end-to-end; only OS-specific acquisition is stubbed.**
`cargo build --workspace` and `cargo test --workspace` pass (13 tests). Windows-only code is
`cfg`-gated so everything compiles and the non-Windows pieces run anywhere.

- **Real, tested, and runnable on any OS:**
  - `core` — clock, source-agnostic event schema (`TrafficRecord`/`PcieEvent`/`TrafficAnchor`),
    fixed-width `IndexFile` (O(1) get, binary-search-by-time), checkpoint + interval logic,
    session read/write.
  - **PCIe record→session→query pipeline** via the replay source: `reveng-rec record --source pcie
    --replay <events.jsonl>` writes a real session (pcie.bin + pcie.idx + events.ndjson +
    meta.json) with interval checkpoints anchored to traffic.
  - **Query CLI:** `ls`, `show`, `frames`, `payload`, `diff`, `grep`, `stream`, `reindex`
    (rebuilds the index byte-for-byte), and the **`decode` harness** (runs any stdin/stdout-JSONL
    decoder — the LLM decode loop).
  - **pcapng** writer/reader + **export slicing** (`reveng-export`) — the USB storage layer,
    tested by roundtrip and slice.
  - USBPcap header parsing; the USB `frames.idx` record.
- **Stub — needs Windows (returns a clear error here):** live USB capture (`USBPcapCMD` spawn),
  input hooks, screen capture, the hypervisor PCIe source, USB device enumeration, and the egui
  viewer. The full CLI flag surface is wired, so `reveng-rec record --help` documents the tool.

## Building

```
cargo build --workspace      # all crates (Windows bits cfg-gated on non-Windows)
cargo test  --workspace      # 13 tests: index, checkpoints, USBPcap parse, pcie log, pcapng
./target/debug/reveng-rec --help
```

## Try the working pipeline (any OS, no hardware)

```bash
# 1. make a PCIe event stream (or hand-author events.jsonl: one PcieEvent per line)
printf '%s\n' \
  '{"op":"config","ts_ns":1000,"offset":0,"width":4,"value":305419896,"dir":"in"}' \
  '{"op":"mmio","ts_ns":3000,"bar":0,"offset":0,"width":4,"value":1,"dir":"out"}' \
  '{"op":"mmio","ts_ns":8000,"bar":0,"offset":80,"width":4,"value":0,"dir":"out"}' \
  '{"op":"dma","ts_ns":9000,"dir":"in","dev_addr":439812096,"len":4096}' > /tmp/dev.jsonl

# 2. record a session
reveng-rec record --source pcie --replay /tmp/dev.jsonl --out /tmp/dev.session \
    --interval-checkpoint-ms 1 --interval-bytes 2048

# 3. query it (the surface an LLM drives)
reveng-rec ls          /tmp/dev.session          # checkpoint manifest
reveng-rec show        /tmp/dev.session 1         # a checkpoint card + anchored event
reveng-rec frames      /tmp/dev.session --around 1 -w 5
reveng-rec grep        /tmp/dev.session '"op":"dma"'
reveng-rec decode      /tmp/dev.session --with "python3 mydecoder.py" --ep 0
```

`PcieEvent` JSON shapes (tag = `op`): `mmio{bar,offset,width,value,dir}`,
`dma{dir,dev_addr,len}`, `irq{vector}`, `config{offset,width,value,dir}` — each with `ts_ns`,
`dir` ∈ {`in`,`out`}.

## If you're implementing this

Follow the build order in `DESIGN.md` §13. In short:

1. `crates/core` — clock anchor + session schema (the shared timeline foundation).
2. `crates/usbcap` — spawn `USBPcapCMD.exe -d \\.\USBPcapN -o -`, parse USBPcap frames, write
   `usb.pcapng`, build the header-only frame index. Verify output opens in Wireshark.
3. `crates/winput` — `WH_MOUSE_LL` / `WH_KEYBOARD_LL` hooks on a dedicated message-loop thread.
   **Critical constraint:** the hook callback must only timestamp + enqueue and return — heavy work
   in the callback gets the hook killed by Windows (~300 ms `LowLevelHooksTimeout`).
4. Checkpoint engine + `crates/winshot` — clicks → checkpoint + screenshot; interval-during-traffic logic.
5. `crates/recorder` (bin) — wire the threads, stop hotkey, finalize + inject checkpoint comments into the pcapng.
6. `crates/viewer` (bin, egui) — timeline → screenshot + USB inspector → seek.
7. `crates/export` — slice pcapng around a checkpoint + Wireshark handoff.

Data model, schemas, config format, and the exact threading contract are all specified in
`DESIGN.md` — treat it as the source of truth and update it if you change the design.

### Things you'll need to know to run/test it

- **Requires Administrator** — USBPcap is a kernel driver.
- **USBPcap must be installed** (`USBPcapCMD.exe` on `PATH` or a configured location).
- Discover targets with `reveng-rec devices --format json`, then pin the capture to the device of
  interest — `reveng-rec record --device-vidpid 1234:abcd` (preferred; stable across replug) — to
  keep volume down. Checkpoint behaviour is tunable via flags (`--checkpoint-on-any-key`,
  `--checkpoint-on-mouseup`, `--interval-checkpoint-ms`, …). Full CLI reference in `DESIGN.md` §11.
- Sessions are written to a session directory; see `DESIGN.md` §8 for the layout
  (`meta.json`, `usb.pcapng`, `events.ndjson`, `index.sqlite`, `screenshots/`).
- `usb.pcapng` and `events.ndjson` are the crash-safe sources of truth; `index.sqlite` is derived
  and rebuildable (`reveng-rec reindex <session>`).

## How an agent uses a recorded session

You do **not** read `usb.pcapng` (binary) — you *query* the session and let your *code* decode the
binary. The loop for reverse-engineering a proprietary protocol:

1. `reveng-rec ls` — read the manifest (one line per checkpoint). Pick the action you care about.
2. `reveng-rec show <ckpt>` — get the checkpoint card; `Read` the referenced screenshot (vision).
3. `reveng-rec stream --ep <n> --logical` — pull reassembled logical messages as base64/hex text.
4. Form a hypothesis, write a decoder (any language; stdin/stdout JSONL contract, or a Kaitai `.ksy`).
5. `reveng-rec decode --with <decoder> --ep <n>` — run it, inspect the output.
6. **Validate against the oracle:** every checkpoint pairs bytes with the on-screen state, so check
   decoded fields against what the screenshot showed (`reveng-rec track`, `diff`, `bytes --stats`).
7. Refine, save the decoder to `decoders/`, re-decode to render semantic fields.

The full contract (CLI, file formats, decoder interface, reassembly) is in `DESIGN.md` §8–§8b.

## Ethical / safety note

This is, functionally, a keylogger plus screen recorder combined with a USB sniffer. It is
legitimate reverse-engineering / defensive tooling, but it must **only** be run on a machine the
operator owns or is authorized to instrument. All data stays local — no network egress. A visible
"RECORDING" indicator and a consent banner are part of the design.

## Layout

```
reveng-recorder/
  README.md            # you are here — handover / orientation
  DESIGN.md            # authoritative design spec
  Cargo.toml           # workspace
  crates/
    core/              # REAL: clock, event schema, CaptureSource, IndexFile, checkpoints, session
    usbcap/            # USB source: real USBPcap parsing + frames.idx; capture spawn stubbed (win)
    pcicap/            # PCIe source: real ReplayPcieSource; HvPcieSource stubbed
    winput/            # input hooks (win) — schema real, hooks stubbed
    winshot/           # screen capture (win) — stubbed
    export/            # pcapng slicing + Wireshark handoff — stubbed
    recorder/          # bin `reveng-rec`: full CLI surface, handlers stubbed
    viewer/            # bin `reveng-viewer`: egui GUI — stubbed
  driver/
    reveng-hv/         # kernel hypervisor driver (built/signed separately) — not started
```
