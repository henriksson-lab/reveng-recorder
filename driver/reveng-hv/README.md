# reveng-hv — PCIe capture kernel driver (placeholder)

Kernel-mode component for the **software-only PCIe capture** backend (see `DESIGN.md` §4a).
It is **not** a Cargo workspace member — a Windows kernel driver is built and signed
separately (WDK / test-signing), and a bug here is a BSOD.

## Responsibilities

- Thin **VT-x hypervisor** that puts the running Windows into VMX-root and uses **EPT** to
  trap access to the target device's BAR pages → MMIO read/write events
  (read-side-effect-safe: trap → emulate once → re-arm).
- **Config-space** trapping (`0xCF8/0xCFC` / MMCONFIG) and **MSI/MSI-X** interrupt capture.
- **DMA** reconstruction by descriptor-following (optional IOMMU/VT-d full-trap mode).
- Timestamps every event with `KeQueryPerformanceCounter` (the same QPC used everywhere
  else) and pushes them to user mode over a lock-free ring buffer, consumed by
  `crates/pcicap` (`HvPcieSource`).

## Preconditions / caveats

- **VBS / HVCI / Hyper-V must be off** — otherwise Windows is already the root partition and
  a custom hypervisor conflicts. Detected and refused at startup.
- Requires test-signing or a signed certificate.
- Bring-up is validated first via `crates/pcicap::ReplayPcieSource` (zero kernel code) and
  the lighter DTrace/HAL-hook MMIO tier, per the build order in `DESIGN.md` §13.

## Status

Kernel driver **not started** — this is the last, highest-risk tier (see `DESIGN.md` §13).
Prior art to study: SimpleVisor, hvpp, Bareflank, gbhv.

The **user-mode half** of the PCIe surface already exists and needs no kernel code:
- `reveng-rec pci-devices` — real SetupAPI enumeration (`crates/pcicap/src/pci.rs`): BDF,
  VID:PID, class code, description — the device-selection input to a future `--pci-vidpid`.
- `crates/pcicap::ReplayPcieSource` — feeds hand-authored `PcieEvent` JSONL through the exact
  storage/index/checkpoint/decode/viewer path a real `HvPcieSource` will use, so everything
  downstream of the `CaptureSource` seam is already built and validated.

When the driver lands, it implements `HvPcieSource` (currently a stub) against the ring-buffer
ABI described above; nothing above the seam should need to change.
