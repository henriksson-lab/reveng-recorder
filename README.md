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

**The entire USB path is implemented and verified end-to-end on Windows; the PCIe hypervisor
is the only remaining tier.** `cargo build --workspace` and `cargo test --workspace` pass (20
tests). Windows-only code is `cfg`-gated so everything still compiles on other OSes.

- **Real, tested, cross-platform (any OS):**
  - `core` — clock, source-agnostic event schema (`TrafficRecord`/`PcieEvent`/`TrafficAnchor`),
    fixed-width `IndexFile` (O(1) get, binary-search-by-time), checkpoint + interval logic,
    session read/write.
  - **PCIe record→session→query pipeline** via the replay source: `reveng-rec record --source pcie
    --replay <events.jsonl>` writes a real session (pcie.bin + pcie.idx + events.ndjson + meta.json).
  - **Query CLI over both USB and PCIe sessions:** `ls`, `show`, `frames`, `payload`
    (hex/bin/base64), `diff`, `grep` (hex-pattern for USB), `stream --logical` (USB logical
    reassembly), `reindex` (rebuilds `frames.idx`/`pcie.idx` from the raw truth), and the
    **`decode` harness** (any stdin/stdout-JSONL decoder — the LLM decode loop).
  - **pcapng** writer/reader, **checkpoint-comment injection**, and **export slicing**
    (`reveng-export`) — the USB storage layer, tested by roundtrip/slice/inject.
  - USBPcap header parsing + libpcap-stream parsing; the USB `frames.idx` record.
- **Real, implemented for Windows (verified on this machine):**
  - `winshot` — GDI `BitBlt` screen capture (cursor-monitor / all / foreground-window) → PNG.
  - `winput` — `WH_MOUSE_LL`/`WH_KEYBOARD_LL` hooks on a dedicated message-loop thread, plus
    foreground process/window context enrichment.
  - `usbcap` live capture — spawns `USBPcapCMD.exe -o -`, parses its libpcap stream onto the
    session timeline, writes `usb.pcapng` + `frames.idx`; best-effort device enumeration.
  - `recorder` USB orchestration — the reader/hooks/screenshot-worker/checkpoint-engine threads,
    the stop hotkey (Ctrl+Alt+Pause) and `--max-seconds`, and finalize with comment injection.
  - `viewer` — the egui timeline / screenshot pane / traffic inspector with click + ←/→ seek.
  - `export` Wireshark handoff (`wireshark.exe -r … -g <frame>`) and the `devices` command.

  > The whole live USB pipeline (reader → checkpoints → screenshots → comment injection →
  > query → viewer) is verified without real USBPcap hardware via a fake `USBPcapCMD` emitting
  > the identical `DLT_USBPCAP` libpcap stream (see `crates/usbcap/examples/fake_usbpcapcmd.rs`).
  > Set `USBPCAPCMD` to override the executable path/name.
  - `pci-devices` — real user-mode PCI(e) enumeration via SetupAPI (BDF, VID:PID, class,
    description); no driver needed, so it works today for picking a `--pci-vidpid`/`--pci-bdf`.
- **Not implemented — the one remaining tier:** the PCIe **hypervisor** *capture* source
  (`HvPcieSource` + `driver/reveng-hv`) — the actual EPT/MMIO/DMA trapping. This is the
  highest-risk, explicitly-postponable kernel work (BSOD risk, driver signing, VBS/HVCI-off
  precondition — DESIGN.md §4a/§13); the replay source stands in for it, and `pci-devices`
  already provides the device-selection half of the PCIe surface.

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

### Installing USBPcap (the USB capture driver)

USB capture needs the **USBPcap** kernel driver (`USBPcap.sys`). `reveng-rec` talks to that
driver **directly over its IOCTL interface** (`crates/usbcap/src/ioctl.rs`) — it does *not* shell
out to `USBPcapCMD.exe` — so all you need installed is the driver itself. Install it once, from the
repo root, in any shell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/get-usbpcap.ps1           # interactive
powershell -ExecutionPolicy Bypass -File scripts/get-usbpcap.ps1 -Silent   # no NSIS UI
```

The script downloads the official signed `USBPcapSetup-*.exe` from the `desowin/usbpcap` GitHub
releases, verifies its size + Authenticode signature (Tomasz Moń), and runs it (the installer
self-elevates via UAC). Useful flags: `-Silent`, `-DownloadOnly`, `-Version 1.5.4.0` (pin a
release), `-NoEnv`. Then:

1. **Reboot once after install.** USBPcap's filter driver only attaches to the USB root hubs at
   boot, so the `\\.\USBPcap1..N` control devices — and therefore `reveng-rec devices` and capture
   — do not exist until you reboot. Empty results before the first reboot are expected, not a bug.
2. **Verify:** `reveng-rec devices --format json` lists USB devices with VID/PID, USB bus address,
   and (when elevated) the `usbpcap` control-device path. Unelevated it still lists devices, but
   `usbpcap`/`bus` are blank — reading the hub symlink needs admin.
3. **No admin shell needed to capture.** `reveng-rec record` detects it isn't elevated and raises a
   UAC prompt itself (`crates/recorder/src/elevate.rs`). Set `REVENG_NO_ELEVATE=1` to opt out (e.g.
   automation that manages elevation). The legacy `USBPcapCMD.exe` subprocess path remains as a
   fallback behind `REVENG_USBPCAP_CLI=1`.

If the driver isn't installed (or you haven't rebooted), capture fails when opening `\\.\USBPcapN`.

### Things you'll need to know to run/test it

- **USB capture needs Administrator** — USBPcap is a kernel driver — but `reveng-rec record`
  self-elevates (UAC prompt), so you can launch it from an ordinary shell. See the install section
  above.
- **The USBPcap driver must be installed and the machine rebooted once** (see above). No
  `USBPcapCMD.exe` on `PATH` is required — the tool drives the driver directly.
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
   `reveng-rec notes` — just the free-text notes the operator typed live while recording (each with
   its elapsed time + the frame that was on the wire when they pressed Enter). Great orientation for
   "what was the human doing here?"
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
"RECORDING" indicator and a consent banner are part of the design — the USB `record` path shows
them in a live Slint window that doubles as the note-taking surface (headless with
`REVENG_NO_NOTES_UI=1` or `--max-seconds`).

## Layout

```
reveng-recorder/
  README.md            # you are here — handover / orientation
  DESIGN.md            # authoritative design spec
  Cargo.toml           # workspace
  crates/
    core/              # REAL: clock, event schema, CaptureSource, IndexFile, checkpoints, session
    usbcap/            # REAL: USBPcap/libpcap parsing, frames.idx, pcapng r/w + comment inject,
                       #       live UsbCaptureSource (spawns USBPcapCMD), reader/writer, enumeration
    pcicap/            # PCIe source: real ReplayPcieSource; HvPcieSource stubbed (hypervisor tier)
    winput/            # REAL (win): WH_MOUSE_LL/WH_KEYBOARD_LL hooks + fg context enrichment
    winshot/           # REAL (win): GDI BitBlt screen capture → PNG
    export/            # REAL: pcapng slicing + Wireshark handoff
    recorder/          # bin `reveng-rec`: full CLI + USB orchestration + query over USB/PCIe
    viewer/            # bin `reveng-viewer`: REAL egui timeline / screenshot / inspector / seek
  driver/
    reveng-hv/         # kernel hypervisor driver (built/signed separately) — NOT started (last tier)
```


## License

Code generated using agentic AI. Consider it MIT licensed, but be sure to review code for copyright infringement in case you wish
to integrate it in another project.
