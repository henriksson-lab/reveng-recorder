# reveng-recorder

> **Handover note for an LLM/agent picking up this project.** Read this file first, then
> [`DESIGN.md`](./DESIGN.md). This README tells you *what state the project is in and how to work
> on it*; `DESIGN.md` is the authoritative spec for *what it is and how it's built*.

## What this is

A **Windows-only** tool for reverse-engineering USB devices. It records three streams into one
time-synchronized session and lets you seek through the USB traffic using user actions as anchors:

1. **USB bus traffic** — captured via [USBPcap](https://desowin.org/usbpcap/) (free kernel driver, pcap-compatible; no extra hardware).
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

**Design phase — no code yet.** The repository currently contains only `DESIGN.md` and this
`README.md`. Nothing has been implemented. The intended crate layout, data model, thread model,
and build order all live in `DESIGN.md`.

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
  README.md      # you are here — handover / orientation
  DESIGN.md      # authoritative design spec
  crates/        # (not yet created) core, usbcap, winput, winshot, recorder, viewer, export
```
