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

Not started. Prior art to study: SimpleVisor, hvpp, Bareflank, gbhv.
