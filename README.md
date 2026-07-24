# reveng-recorder

> **Handover note for an LLM/agent picking up this project.** Read this file first, then
> [`DESIGN.md`](./DESIGN.md). This README tells you *what state the project is in and how to work
> on it*; `DESIGN.md` is the authoritative spec for *what it is and how it's built*.

**Before you reverse engineer anything, read up on the law. Especially [clean-room design](https://en.wikipedia.org/wiki/Clean-room_design). Law also differs EU vs US**

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


## Current state

**The entire USB path is implemented and verified end-to-end on Windows; the PCIe hypervisor
is the only remaining tier.** `cargo build --workspace` and `cargo test --workspace` pass (41
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
  - `memcap` — **process-memory snapshots** (the "decoded-form oracle", DESIGN.md §6a). `record
    --mem-pid <PID>` / `--mem-process <name.exe>` arms a 📸 Snapshot button in the recording window;
    each press dumps the target's committed memory to `memsnaps/<id>/` on a worker, anchored to the
    live frame. Query the before/after delta with `reveng-rec mem ls|regions|diff|scan|read`. Capture
    is chunked/streamed (bounded RAM) with optional `--mem-compress` (region-parallel deflate);
    Windows-only capture, cross-platform diff/scan.

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
cargo test  --workspace      # 41 tests: index, checkpoints, USBPcap/pcapng parse, pcie log, text/dashboard formatters, mem diff/scan/deflate
./target/debug/reveng-rec --help
```

Windows release artifacts are built by GitHub Actions on `windows-latest` and can also be made on a
Windows build machine with GNU Make:

```powershell
make windows-zip
```

That produces `target/windows/reveng-recorder-<version>-windows-x64.zip` containing
`reveng-rec.exe`, `reveng-viewer.exe`, `README.md`, and `get-usbpcap.ps1`. This is a user-mode
build only; the kernel drivers under `driver/` still require MSBuild + WDK and separate signing.

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

**No clean export?** When the wire bytes are opaque and the vendor app is the only thing that decodes
them, arm a memory snapshot (`record --mem-pid <PID>`), click 📸 Snapshot just before and after
acquiring a reading, then `reveng-rec mem diff` → `mem scan "<on-screen value>"` → `mem read` to
recover the *decoded* struct out of the app's memory — cross-referenced with the same checkpoint's
wire `anchor`. That's the wire → memory → screen triple (the decoded-form oracle, `DESIGN.md` §6a).

The full contract (CLI, file formats, decoder interface, reassembly) is in `DESIGN.md` §8–§8b.
For a systematic list of every subcommand see [Complete CLI reference](#complete-cli-reference-for-llm-agents);
if you're new to reverse engineering, start with [the practical guide](#reverse-engineering-a-device-a-practical-guide).

### Control-transfer command log (`ctrl`) — vendor USB protocols

For a vendor USB device (e.g. a Cypress-based camera) the *command layer* is the EP0
control transfers, not the bulk/interrupt data. `reveng-rec ctrl <session>` decodes them:
it pairs each SETUP with its completion (by IRP id) and prints one line per request —
direction, type/recipient, `bRequest`/`wValue`/`wIndex`, the data payload, and status.

```bash
reveng-rec ctrl <session>                       # every control transfer, decoded
reveng-rec ctrl <session> --req-type vendor      # just vendor requests
reveng-rec ctrl <session> --around <ckpt> -w 40  # commands around a click/keypress
reveng-rec ctrl <session> --json                 # one JSON object per command (for tooling)
```

Example (a camera's sensor-register init table + stream start):

```
#5114  t=  69.454s  OUT vendor/device  req=0x51 val=0x00f1 idx=0x2708 wlen=0  ok
#5104  t=  69.375s  OUT vendor/device  req=0x49 val=0x0000 idx=0x0000 wlen=16  data=b52f3f20…  ok
#5892  t=  70.736s  OUT vendor/device  req=0x01 val=0x0003 idx=0x000f wlen=0  ok
```

Supporting changes in the same area:

- **`frames --format` is now honored.** `--format text` gives one scannable line per frame
  (identity + short payload preview, and the decoded SETUP for control frames); `--format hex`
  gives an xxd dump; `json` (default) is unchanged. Previously the flag was silently ignored and
  every frame dumped its full hex/ascii/base64 — unreadable on a bulk endpoint.
- **Control-transfer direction is fixed.** `dir` for a control frame now comes from
  `bmRequestType` bit 7 (the real direction) instead of the EP0 address (always `0x00`→"out"),
  so IN reads are no longer mislabeled as OUT. The decoded SETUP and IRP id are exposed on the
  USB frame JSON (`setup`, `stage`, `irp`).

These land the "read a vendor command protocol off the wire" workflow — decode the EP0 control
vocabulary of a vendor USB device (register writes, mode/stream commands, handshakes) directly
from a capture.

### Screenshot geometry + OCR — analyzing the screen side at scale

Screenshots now carry their spatial context, and their text is queryable:

- **`displays.json`** (written once at session start) — the monitor layout: each monitor's
  bounds, work area, primary flag, and DPI/scaling.
- **`screenshots.ndjson`** (one line per screenshot) — the capture rectangle (`origin_x/y`,
  `width/height`), the cursor position at capture, monitor index, DPI, and scope. This is what
  lets later analysis map an absolute point (a click, an OCR box) to a pixel in the PNG:
  `pixel = absolute − origin`. The mouse cursor is **not** drawn into the PNG (GDI `BitBlt`
  doesn't capture it), so the stored cursor position is the source of truth for "where the click
  landed."

**`reveng-rec ocr`** runs on-device OCR (the built-in **Windows.Media.Ocr** engine — no install,
no network) over screenshots and emits each recognized word with its pixel box, **ordered by
distance to the cursor** at capture time:

```bash
reveng-rec ocr <session> <id>        # OCR one screenshot, words nearest the cursor first
reveng-rec ocr <session> --all       # OCR every screenshot (builds the cache)
reveng-rec ocr <session> <id> --json # machine-readable: {text, x, y, w, h, dist} per word
```

Results cache under `ocr/<id>.json`, so re-analysing a large session is instant. Example (the
cursor was on an app's exposure controls):

```
# screenshot 46 — 77 words, cursor at pixel (223,710)
  d=  131  (  81, 655)  40x12   "Time:"
  d=  153  ( 329, 656)  78x12   "178.629ms"
  d=  167  ( 364, 742)  43x12   "857%"
```

Ordering text by cursor distance turns "what did I just click?" into a ranked list.

### UI-Automation widget capture — typed controls + live values

Beyond OCR'd *text*, the recorder captures the **UI-Automation widget tree** of the clicked
window at each checkpoint (`crates/winui`), written to `ui/<id>.json`. UIA is the typed control
tree Windows already publishes for screen readers, so instead of guessing widgets from pixels you
get, per control: its **type** (Button / CheckBox / RadioButton / Slider / Edit / ComboBox / …),
screen rect, label, and **live state/value** via control patterns:

- CheckBox / toggle → `toggle: on|off|indeterminate`
- RadioButton / TabItem → `selected: true|false`
- Slider / Spinner → `range_value` (+ min/max)
- Edit / ComboBox → `value` (the text)

```bash
reveng-rec ui <session> <checkpoint>              # controls nearest the cursor first
reveng-rec ui <session> <checkpoint> --interactive # only buttons/checkboxes/sliders/edits/…
reveng-rec ui <session> --all --json               # machine-readable, every checkpoint
```

Example (a camera app's control panel): `ComboBox value="3328 × 2548"` (resolution),
`ComboBox "Snap:" value="RGB24"` (format), `CheckBox "Auto Exposure" toggle=off`, `Slider
"Exposure Time:"`, `Slider "Gain:"`. Because the widget carries the *value*, this reads a control's
number directly — and, joined through the checkpoint's traffic `anchor`, lets you correlate a UI
change with the bytes it produced (e.g. to attack an obfuscated register channel by pairing each
value with its wire burst). Probe any window's tree with the standalone `uia-probe` binary;
`uia-set` drives controls to precise values for automated single-variable sweeps. `displays.json` +
`screenshots.ndjson` put every rect in the same virtual-screen frame as the widgets, so pixels,
OCR boxes, and controls all line up.

GUI structure beyond text now comes from the OS itself; a pixel/template fallback can layer on for
custom-drawn UIs that expose a thin UIA tree.

### Device-RE toolkit (protocol → driver)

The commands that turn a capture into a working driver, roughly in the order you use them:

```bash
reveng-rec monitor --device-vidpid V:P      # pre-flight: is the device streaming? live rate table, no session
reveng-rec record ... --abort-if-idle 5     # stop the instant no frame arrives for 5s (no more 0-frame waits)
reveng-rec verify <session>                 # is this capture complete? (drops = unpaired SETUPs)
reveng-rec ctrl   <session> --req-type vendor   # the decoded command log
reveng-rec ctrl-diff <A> <B>                # what did the working run do that mine didn't?
reveng-rec reg-state <session> [--at CKPT] --req-type vendor  # device register map, folded from writes
reveng-rec reg-diff  <session> <ckptA> <ckptB>   # which registers a click/keypress changed
reveng-rec track  <session> --reg 0x40:0x1000    # one register's value across every checkpoint
reveng-rec track  <session> --ui "Exposure Time" # a UIA control's value across every checkpoint (+ --json)
reveng-rec annotate <session> --spec cam.toml    # decode transfers to meaning: "exposure = 30000 us"
reveng-rec sweep  --device-vidpid V:P --window "App" --control "Exposure Time" \
                  --values 10,30,50,70,90 --out sess     # drive a control + record, auto-paired
reveng-rec solve  sess/sweep_pairs.csv --var 0 --bytes 1,2,3,4   # brute-force the encoding
reveng-rec usb-poke --vidpid V:P            # live device oracle: control xfers + queued bulk + replay
reveng-rec usb-poke --vidpid V:P --doctor --ep 0x81   # bring-up diagnosis: why isn't the endpoint streaming?
reveng-rec usb-poke --vidpid V:P --check cap.jsonl    # replay a `ctrl --json` + flag non-deterministic IN responses
reveng-rec frame-guess   <session> --ep 0x81  # infer W×H×bpp + fps from transfer cadence (no guessing N)
reveng-rec frame-extract <session> --ep 0x81 --frame-bytes N --out f.raw
reveng-rec frame-decode  f.raw --width W --height H --pix raw8 --bayer --out img
```

`sweep` records while driving a UIA control to known values, then `sweep-correlate` pairs each value
with the control-transfer burst it produced; `solve` finds the transform (XOR/pairing/inversion,
linear or `1/x`/`ln`) that explains it — e.g. it re-derives a camera's XOR obfuscation, its
exposure line-time, and its inverse gain curve straight from the sweep.

`reg-state`/`reg-diff`/`track` are the *semantic* layer over the raw `ctrl` log: they fold every
control write into a register map (last byte per `(bRequest,wIndex)`, cut off at a checkpoint's
timestamp) so you can ask "what is the device's state here?", "which registers did *this* click
change?", and "how did register X move over the whole session?" — instead of eyeballing transfers.

`annotate` is the top of that stack: a **device spec** (TOML — the bundled camera's `cam.toml`)
names requests and registers and describes how to combine registers into engineering-unit fields
(deobfuscation `xor`, big/little-endian `combine`, a `linear` or `reciprocal` transform whose
constants come straight from `solve`). `reveng-rec annotate <session> --spec cam.toml` folds the
capture and applies the spec — turning `PROTOCOL.md` prose into a *reusable, executable* decoder
(the example spec round-trips captured traffic to an `exposure` value in µs byte-exact). `--log` also
prints every folded register tagged with its spec name. `--spec` is repeatable and **layers** — put
a shared sensor-knowledge base under a per-device spec (`--spec sensor-base.toml --spec cam.toml`);
later files override names and append fields, so protocol knowledge accumulates across devices.

**Writing the driver:** `templates/nusb-driver.rs` is a cross-platform (`nusb`) skeleton that bakes
in the two bring-up gotchas that cost the most time:
1. **Bulk streaming needs a queue** — keep ~16 IN requests outstanding; a single `bulk_in` NAKs
   forever (looks like a dead endpoint). 2. **Aborted attempts wedge the device** — reset on open
   (or physically replug) to get a clean state. On Linux, `detach_and_claim_interface` frees the
   interface from a kernel driver, and you need udev permissions.

## Reverse-engineering a device: a practical guide

New to reverse engineering? This section is the "how do I even start?" walkthrough. It assumes no
prior RE experience — just that you own the device and can run its vendor software.

### The one idea that makes this tractable

A hardware device speaks a private language over the wire. You can't read a datasheet for it, but you
*can* watch the vendor's own app talk to it while **you** drive that app — and this tool records the
wire traffic **and the screen at the same instant**, on one clock. So every packet is paired with
"what was on screen when it happened." That pairing is the **oracle**: it lets you confirm a guess
("this byte is the exposure value") against ground truth ("the screen said 30 ms"), instead of
staring at hex. Everything below is in service of building and using that oracle.

### The two layers of almost every device protocol

- **Command/control layer** — small messages that configure the device ("set exposure = 30 ms",
  "start streaming"). On USB these are **EP0 control transfers**; you read them with `ctrl`. This is
  usually where the interesting, learnable protocol lives.
- **Data layer** — the bulk stream the device produces (camera frames, scanner lines, audio). Large,
  repetitive, and often a simple pixel/sample format once you know its shape (`frames`, `stream`,
  `frame-guess`).

Attack the command layer first — it's small and each message maps to an action you took.

### Step by step

1. **Set up capture.** Install USBPcap (`scripts/get-usbpcap.ps1`) and **reboot once** — the filter
   only attaches to USB root hubs at boot. Find your device: `reveng-rec devices` (note its
   `VID:PID`, e.g. `1234:abcd`).
2. **Pre-flight — confirm it's actually streaming.** `reveng-rec monitor --device-vidpid <V:P>`
   prints a live per-endpoint rate table with an `IDLE` flag. If it says IDLE while the app is
   "running," the device isn't producing yet — fix that *before* recording. (The #1 beginner
   time-sink is a capture that got 0 frames.)
3. **Record while doing ONE thing at a time.** `reveng-rec record --device-vidpid <V:P>`. Then, in
   the vendor app, change a *single* setting (drag the exposure slider, click one button) and pause.
   Type a note in the recording window each time ("set exposure 30ms") — notes are timestamped and
   anchored to the wire. One variable at a time is what makes the traffic diff-able later. Stop with
   Ctrl+Alt+Pause, or use `--max-seconds N --abort-if-idle 5` for a bounded unattended run.
   - **Camera/audio firehose?** Add `--auto-truncate` (keeps control transfers intact, truncates the
     bulk payload) so the capture stays small while you study the command layer.
4. **Read the manifest.** `reveng-rec ls <session>` lists every checkpoint (each click/keypress, with
   the screenshot + wire anchor). `reveng-rec notes <session>` shows what you typed. This is your map:
   "checkpoint 32 is where I set exposure to 30 ms."
5. **Look at the command layer.** `reveng-rec ctrl <session> --req-type vendor` prints the decoded
   control transfers. `--around <ckpt>` narrows to the commands near one action.
6. **Find what your action changed.** This is the leverage step. `reveng-rec reg-diff <session> <a>
   <b>` shows exactly which registers changed between two checkpoints ("setting exposure changed
   these two registers"). `reg-state` shows the whole device state at a checkpoint; `ctrl-diff`
   compares two whole sessions ("what did the working run do that mine didn't?").
7. **Crack an encoding.** When a value is obfuscated (the wire bytes don't obviously equal the number
   you set), sweep it: `reveng-rec sweep --control "Exposure Time" --values 10,20,30,40 …` drives the
   app to known values and records; then `reveng-rec solve <csv> --bytes …` brute-forces the
   transform (XOR, byte-pairing, `1/x`, linear fit) that maps your value to the bytes. This is how the
   bundled camera's XOR key + line-time formula was recovered automatically.
8. **Write down what you learned — as code, not prose.** Put requests/registers/formulas in a device
   **spec** (`cam.toml` is the worked example) and run `reveng-rec annotate <session> --spec
   cam.toml`. Now the tool decodes raw transfers into meaning ("exposure = 30000 µs") on *any* future
   capture. This is the highest-leverage habit: your knowledge becomes reusable and testable.
9. **Decode the data layer.** For the bulk stream: `reveng-rec frame-guess --ep 0x81` infers the
   frame size and candidate `W×H×bpp`; `frame-extract` pulls one frame to a file; `frame-decode`
   renders it to PNG (with `--bayer` for camera sensors). For structured/logical messages, write a
   small decoder in any language (stdin/stdout JSONL) and run it with `decode --with`.
10. **When the wire is opaque, use the other oracles.** If bytes are encrypted/compressed and only the
    app can decode them: `record --mem-pid <PID>`, snapshot the app's memory before/after a reading,
    then `mem diff` → `mem scan "<the on-screen number>"` → `mem read` to find the *decoded* value in
    the app's memory. `ocr` and `ui` capture the screen text and the actual UI widget values, so you
    can correlate "the slider said 30" with the bytes automatically.
11. **Write the driver.** `templates/nusb-driver.rs` is a cross-platform skeleton with the two
    hard-won gotchas baked in (queue 16 bulk reads; reset/replug to unwedge). Validate it against your
    spec and the captured oracle. Confirm it reproduces (`usb-poke --check`), diagnose bring-up
    (`usb-poke --doctor`).

### Habits that save hours

- **One variable per action.** Diffs only mean something if only one thing changed.
- **Confirm streaming before recording** (`monitor`) — don't discover 0 frames after a 60 s timer.
- **Capture losslessly for the command layer**; only truncate the bulk firehose (`--auto-truncate`).
- **Replug or reset a wedged device.** An aborted capture attempt can leave a camera stuck; a physical
  replug or `usb-poke` `reset` restores a clean state.
- **Determinism check early.** `usb-poke --check <capture>` replays your control transfers and flags
  any device response that *changed* — that's how you tell a real handshake (nonce/auth) from bytes
  that are actually constant and can be ignored.
- **Keep knowledge in the spec, not your head.** Every formula you crack → into the `.toml`. Specs
  layer (`--spec sensor-base.toml --spec device.toml`), so knowledge accumulates across devices.

## Complete CLI reference (for LLM agents)

Every subcommand of `reveng-rec`, grouped by purpose. `<session>` is a session directory. Add
`--help` to any command for the exact flags. You never read `usb.pcapng`/`pcie.bin` directly — you
drive these commands and let *your own code* (via `decode`) interpret bytes. Conventions: endpoints
are hex like `0x81`; `<ckpt>` is a checkpoint id from `ls`; frame indices come from `frames`.

### Recording & pre-flight

| Command | Purpose | Key args / notes |
|---|---|---|
| `record` | Capture a session: traffic + input + event-triggered screenshots on one QPC clock. | `--device-vidpid V:P` (USB target), or `--source pcie …`. Stop: Ctrl+Alt+Pause, `--max-seconds N`, `--abort-if-idle N`, `--stop-after-frames N`, `--max-bytes N`. Reduce firehose: `--auto-truncate`, `--usb-snaplen 256`, `--drop-isoc`/`--drop-bulk`. `--headless` for no-UI automation. `--with-pcie` co-logs PCIe. `--mem-pid PID` arms the memory oracle. Self-elevates (UAC); `REVENG_NO_ELEVATE=1` to opt out. |
| `monitor` | Live per-endpoint rate table (frames/s, bytes/s, `IDLE` flag). **No session written.** | `--device-vidpid V:P` (omit = all hubs), `--max-seconds N`. Use to confirm the device streams *before* `record`. |
| `devices` | Enumerate USB devices to pick a capture target. | Lists `VID:PID`, product, bus/addr, which USBPcap hub. Empty until USBPcap is installed **and** you've rebooted. |
| `pci-devices` | Enumerate PCI(e) devices (BDF, VID:PID, BARs, class). | For the PCIe tiers. |

### Reading a session (start here: manifest → drill down)

| Command | Purpose | Key args / notes |
|---|---|---|
| `ls` | List checkpoints — the manifest. **Read this first.** | One line per checkpoint (id, time, type, cause, anchor). |
| `notes` | Free-text notes the operator typed live, with elapsed time + anchored frame. | Best orientation for "what was the human doing here?" |
| `show` | One checkpoint's full card (screenshot id, anchor, foreground app/window, cursor). | `show <session> <ckpt>`. `Read` the referenced screenshot for vision. |
| `frames` | Decoded traffic frames near a checkpoint or by range. | `--around <ckpt> -w N`, `--range A:B`, `--ep 0x81`, `--format json\|text\|hex\|auto`. |
| `payload` | Raw payload bytes of one frame. | `payload <session> <frame> --format auto\|hex\|text\|bin`. |
| `stream` | Reassembled *logical* messages on an endpoint (across transfer boundaries). | `--ep 0x81 --logical`, or `--text` for serial/log-style newline-split streams. |
| `grep` | Find frames whose payload contains a byte pattern. | `grep <session> <hexpattern>`, or `--text <substr>`. |
| `diff` | Frames that differ between two checkpoints. | `diff <session> <a> <b>`. |
| `export` | Export a pcapng slice, or open the frame in Wireshark. | `--checkpoint <c>` / `--range A:B`, `--out file`, `--wireshark`. |
| `reindex` | Rebuild `index.sqlite` / `*.idx` from the raw truth (pcapng/ndjson). | Run if an index is stale/corrupt; the raw files are the source of truth. |

### USB control-protocol analysis (the command layer)

| Command | Purpose | Key args / notes |
|---|---|---|
| `ctrl` | Decoded EP0 control-transfer log — one line per request (SETUP paired with completion). | `--req-type vendor\|class\|standard`, `--around <ckpt> -w N`, `--range A:B`, `--json`. The command layer of a vendor protocol. |
| `ctrl-diff` | Diff two sessions' control streams (align by request/value/index/dir). | `ctrl-diff <A> <B> [--req-type vendor]`. "What did the working run do that mine didn't?" |
| `reg-state` | Reconstructed register map (last write per `(bRequest,wIndex)`) as of a checkpoint. | `--at <ckpt>` (default: end), `--req-type vendor`. Semantic device state, not raw transfers. |
| `reg-diff` | Registers that changed between two checkpoints. | `reg-diff <session> <a> <b> [--req-type vendor]`. "Clicking X set registers A and B." |
| `track` | A value's time-series across checkpoints. | `--reg 0x40:0x1000` (register byte) or `--ui "Exposure Time"` (UIA control value), `--json`. |
| `annotate` | Apply a device **spec** (TOML) to decode transfers into engineering units. | `--spec cam.toml` (repeatable — layers), `--at <ckpt>`, `--req-type`, `--log` (labeled registers). Turns protocol knowledge into a reusable decoder. |
| `verify` | Capture-integrity check: endpoint histogram, SETUP↔completion pairing, statuses, ordering. | Non-zero exit on problems (unpaired SETUPs ⇒ likely dropped packets). |

### Cracking obfuscated fields (drive a value → fit the transform)

| Command | Purpose | Key args / notes |
|---|---|---|
| `sweep` | Drive a UIA control across known values while recording, then correlate each value with the control-transfer burst it produced → a CSV. | `--device-vidpid V:P --window "App" --control "Exposure Time" --values 10,20,30 --out sess`. |
| `sweep-correlate` | The analysis half of `sweep` on an existing session → `value → bytes` table + CSV. | `sweep-correlate <session> --values … [--out-csv f]`. |
| `solve` | Brute-force the fixed transform behind an obfuscated field (XOR/pairing/inversion; linear/`1/x`/`ln` fit). | `solve <csv> --var 0 --bytes 3,4,5,6 [--where COL=VAL]`. Re-derives the encoding + formula. |

### Frame / image formats (the data layer)

| Command | Purpose | Key args / notes |
|---|---|---|
| `frame-guess` | Infer a bulk endpoint's frame format from transfer cadence: bytes/frame → candidate `W×H×bpp` + fps. | `--ep 0x81`. Needs a clean (low-loss) capture to resolve a real multi-URB frame. |
| `frame-extract` | Reassemble one logical frame from a bulk endpoint → raw file. | `--ep 0x81 --frame-bytes N --out f.raw`. Warns if the capture was snaplen-truncated. |
| `frame-decode` | Decode a RAW frame file into PNG(s). | `--width W --height H --pix raw8\|raw16le [--bayer]` (emits all 4 debayer phases). |

### Writing & running decoders

| Command | Purpose | Key args / notes |
|---|---|---|
| `decode` | Run *your* candidate decoder over frames and render its output. | `--with "python3 decode.py"` (imperative, JSONL stdin/stdout), `--ep 0x81`, or `--ksy def.ksy` (Kaitai, partial). Contract in `DESIGN.md` §8b. |

### Screen-side oracle (correlate bytes with what was displayed)

| Command | Purpose | Key args / notes |
|---|---|---|
| `ocr` | OCR on-screen text in screenshots (Windows.Media.Ocr), words ordered by distance to the cursor. | `ocr <session> [id]` or `--all`, `--json`, `--refresh`. Cached under `ocr/<id>.json`. |
| `ui` | Read the UI-Automation widget snapshot at a checkpoint: typed controls (buttons, sliders, edits…) with rects + live values, nearest-cursor first. | `ui <session> [ckpt]` or `--all`, `--interactive`, `--json`. This is where `track --ui` gets its values. |

### Decoded-form oracle: process memory (`mem …`)

For when the wire bytes are opaque and only the vendor app decodes them. Requires `record --mem-pid`.

| Command | Purpose |
|---|---|
| `mem ls` | List memory snapshots (id, elapsed, pid, size, anchored frame). |
| `mem regions` | Region table for one snapshot. |
| `mem diff` | Before→after delta between two snapshots (new/changed/freed regions). |
| `mem scan` | Find a value's encodings in a snapshot — seed with the on-screen number/string. |
| `mem read` | Hex/auto-render a slice of a snapshot at an address. |

### Live device interaction (no capture; needs the device present)

| Command | Purpose | Key args / notes |
|---|---|---|
| `usb-poke` | Interactive/scripted control transfers + queued bulk reads against a live device — the "device oracle." | `--vidpid V:P` opens a REPL (`out`/`in`/`stream`/`replay`/`reset`/`probe`); `--script f` runs a file. |
| `usb-poke --doctor` | Streaming bring-up diagnosis: single vs queued bulk read → NAK/STALL/data classification + the fix. | `--vidpid V:P --doctor --ep 0x81 [--reset]`. |
| `usb-poke --check` | Replay a `ctrl --json` capture and flag any IN response that differs from the captured bytes. | `--vidpid V:P --check cap.jsonl`. All-match ⇒ deterministic protocol; divergences ⇒ nonce/challenge. |

### PCIe / hypervisor tiers (advanced; see `driver/*/README.md`)

| Command | Purpose |
|---|---|
| `record --source pcie` | Capture PCIe via a backend (`--pci-backend drv\|etw`) or `--replay events.jsonl`. |
| `pci-attach` / `pci-detach` | Install/remove the `reveng-pcidrv` upper filter on a PCI device (M2 interrupts). |
| `hv-probe` | Probe VT-x capability via the `reveng-hv` driver (read-only). |
| `hv-vmxtest` | VMXON+VMXOFF on every CPU (proves VMX entry works; no VMLAUNCH). |
| `hv-selftest` | Hyperjack self-test: VMLAUNCH on CPU 0, verify via CPUID backdoor, devirtualize. |
| `hv-diag` | Read `reveng-hv`'s diagnostic record (last devirtualize reason/RIP, ctls status). |

### The viewer (separate binary)

`reveng-viewer <session>` — egui timeline: checkpoint ticks + traffic-density strips, click a
checkpoint for its screenshot + traffic + co-logged PCIe, ←/→ to seek. Add `--track "Exposure Time"`
to overlay a UIA control's value curve on the timeline axis.

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
    memcap/            # REAL (win capture) + portable diff/scan: process-memory snapshots (mem CLI)
    export/            # REAL: pcapng slicing + Wireshark handoff
    recorder/          # bin `reveng-rec`: full CLI + USB orchestration + query over USB/PCIe
    viewer/            # bin `reveng-viewer`: REAL egui timeline / screenshot / inspector / seek
                       #   `reveng-viewer <session> --track "Exposure Time"` overlays a UIA value curve
  driver/
    reveng-hv/         # kernel hypervisor driver (built/signed separately) — NOT started (last tier)
```


## License

Code generated using agentic AI. Consider it MIT licensed, but be sure to review code for copyright infringement in case you wish
to integrate it in another project.
