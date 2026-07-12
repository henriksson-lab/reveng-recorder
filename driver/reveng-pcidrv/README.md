# reveng-pcidrv — driver-only PCIe capture (no hypervisor)

The **lighter tier** of the PCIe backend (DESIGN.md §4a): a signed KMDF driver that captures
PCIe events and streams them to user-mode `crates/pcicap` (`DrvPcieSource`). Unlike the
`reveng-hv` hypervisor tier, this needs **no VBS-off and no EPT** — a normal signed driver that
loads with Virtualization-Based Security left on. Lower fidelity for MMIO (see milestones), but
deployable on locked-down machines where only "add a driver" is allowed.

Not a Cargo workspace member — a Windows kernel driver is built and signed separately.

## Contract

`reveng_pci_abi.h` is the shared ABI (mirrored by `crates/pcicap/src/drv.rs`): a control device
`\\.\RevengPciCap`, `IOCTL_REVENG_PCI_SET_TARGET` to pick the device by BDF, then `ReadFile`
returns a stream of fixed 32-byte `REVENG_PCI_EVENT` records → `core::event::PcieEvent`.

## Milestones (risk, low → high)

- **M1 — config-space capture (this first).** A *software* (non-PnP) control driver: `SET_TARGET`
  stores the BDF; the driver reads full PCI config space via `HalGetBusData`/MMCONFIG and emits
  `CONFIG` events. No device attach, no trapping — near-zero risk. Proves build→sign→load→stream
  →session→query on real hardware. Load with `sc create`/`sc start`.
- **M2 — interrupts.** *Attempted two ways; blocked for MSI.* (1) ETW NT-Kernel-Logger ISR
  consumer (`crates/pcicap::etw`, `--pci-backend etw`): works but this machine collapses every ISR
  to one funnel vector — no per-device attribution (DPC routines do differ, but that's per-driver).
  (2) PnP upper-filter + `IoConnectInterruptEx` sharing (this driver's filter role): the filter
  attaches cleanly and M1 config capture works through it, but connecting to the target's
  interrupt returns **`STATUS_INVALID_PARAMETER`** — a filter cannot share a device's dedicated
  **MSI/MSI-X** messages (the function driver owns them). Verified against the xHCI/DualSense at
  `0000:00:14.0`: filter in-stack, connect FAILED, zero interrupts. Would only work for legacy
  *line-based* shareable interrupts. **Real MSI interrupt capture needs the hypervisor tier below.**
  Reusable infra shipped: `pci-attach`/`pci-detach` (SetupAPI UpperFilters + restart),
  `DrvPcieSource::new_live` poll capture, a connect-diagnostic marker (`REVENG_DRV_DEBUG`).
- **M3 — MMIO. DONE (read-only BAR snapshotting).** Rather than hook register accessors (patching
  = PatchGuard/HVCI-hostile) the filter maps the device's memory BARs (from its START resources)
  and `IOCTL_REVENG_PCI_MMIO_SNAP` reads them, emitting an `MMIO` event per *changed* dword
  (baseline on first call, deltas after). `record --pci-backend drv --pci-bdf … --trace-mmio`
  snapshots every 100 ms; window is runtime-tunable (default 16 KB/BAR, `REVENG_MMIO_BYTES`, cap
  64 KB). Verified on the xHCI/DualSense at `0000:00:14.0`: baseline read genuine cap registers
  (HCIVERSION 0x0120, RTSOFF 0x2000, DBOFF 0x3000) and under USB traffic captured **MFINDEX**
  (microframe counter) and **ERDP** (event-ring dequeue pointer) changing. Captures register
  *state changes*, not individual accesses (that needs EPT); xHCI keeps transfer payloads in DMA
  rings (system memory), so MMIO shows control/status + ring pointers — DMA (M4) is the complement.
- **M4 — DMA. DONE (best-effort, worked here).** Follow the xHCI **Event Ring** in system memory:
  read the interrupter's ERSTBA/ERSTSZ (MMIO), then ERST entry → ring segment base, then emit a
  `Dma` event per Event TRB that changed (`record … --trace-dma`). Reads physical memory with
  **`MmCopyMemory(MM_COPY_MEMORY_PHYSICAL)`** (no cache-alias BSOD; errors instead of faulting) +
  a `MmGetPhysicalMemoryRanges` guard. Defeated by IOMMU/VT-d if the DMA addresses are IOVAs —
  diagnostic markers report that (stage 9/10 = "not in RAM"). Verified on the xHCI/DualSense at
  `0000:00:14.0` **with VBS running**: ERSTBA/segment were identity-mapped (no IOMMU), and 256
  genuine Transfer Event TRBs were captured — 245 Success + 9 Short-Packet completions with real
  transfer lengths (64B/46B). This gets the actual USB transfer completions the MMIO tier can't.

## Toolchain setup (needed before building M1)

This machine has the Windows SDK bits (`Windows Kits\10\bin`, incl. 10.0.26100) but **no C++
compiler, MSBuild, or WDK**. Two ways to get a driver build environment:

### Option A — EWDK (recommended; self-contained, nothing permanently installed)

1. Download the **Enterprise WDK (EWDK)** ISO for Windows 11 24H2 (matches the 10.0.26100 SDK
   already present) from Microsoft (search "Download the Windows Driver Kit (WDK) → EWDK").
2. Mount the ISO (double-click, or `Mount-DiskImage`).
3. From the mounted drive, run `LaunchBuildEnv.cmd` → opens a shell with MSBuild + WDK + SDK on
   PATH.
4. Build: `msbuild reveng-pcidrv.vcxproj /p:Configuration=Release /p:Platform=x64` (once the
   project is scaffolded in M1).

### Option B — Visual Studio + WDK

Install **VS 2022 Build Tools** ("Desktop development with C++") + the **WDK 10.0.26100** (adds
the driver MSBuild targets). Then build the `.vcxproj` as above.

## Loading a self-signed build (spare machine)

VBS may stay on; only kernel code-signing is relaxed for a self-signed driver:

```
bcdedit /set testsigning on          # requires Secure Boot OFF; reboot after
:: create a test cert + sign reveng-pcidrv.sys (makecert/signtool, one-time)
sc create RevengPciCap type= kernel binPath= C:\path\to\reveng-pcidrv.sys
sc start  RevengPciCap
```

Then `reveng-rec` (once the live PCIe path is wired) opens `\\.\RevengPciCap` via `DrvPcieSource`.
To unload: `sc stop RevengPciCap` / `sc delete RevengPciCap`. A crash here is a BSOD — this is the
spare machine.

## Building M1

Built and confirmed with VS 2026 + WDK/SDK 10.0.28000 (`reveng-pcidrv.c` is WDM):

```
MSBuild reveng-pcidrv.vcxproj /p:Configuration=Release /p:Platform=x64
# -> x64\Release\reveng-pcidrv.sys
```

vcxproj settings that made it build on this toolchain:
- `PlatformToolset = WindowsKernelModeDriver10.0` (the driver toolset — not `v14x`; it wires
  the kernel includes/libs, `_AMD64_`/`_KERNEL_MODE`, and driver linking).
- `WindowsTargetPlatformVersion = 10.0.28000.0` (the `km` headers live only under 28000 here).
- `SpectreMitigation = false` — the Spectre-mitigated libs aren't installed. For a *shipping*
  driver, install them (VS Installer → Individual Components → "spectre") and set this to
  `Spectre` instead.
- `SignMode = Off` — we test-sign manually (below) rather than in the build.

## Status

- ✅ Shared ABI (`reveng_pci_abi.h`) + user-mode client (`crates/pcicap::DrvPcieSource`).
- ✅ Toolchain (VS 2026 + WDK 28000) and **M1 driver builds to `reveng-pcidrv.sys`**.
- ✅ **Test-signed, loaded, and captured end-to-end on real hardware.** Self-signed cert in
  Root + TrustedPublisher, `bcdedit /set testsigning on` (Secure Boot off), `sc create/start
  RevengPciCap`. `reveng-rec record --source pcie --pci-bdf 0000:00:00.0` produced 64 CONFIG
  events (full 256-byte config space); decoded offset 0 = `0x46218086` (Intel 8086:4621 host
  bridge), offset 8 = `0x06000002` (class 060000, host bridge) — genuine config space.
- ⚠️ **M2 (interrupts): blocked for MSI.** ETW ISR = one funnel vector (no attribution); PnP
  filter `IoConnectInterruptEx` = `STATUS_INVALID_PARAMETER` (a filter can't share dedicated MSI
  messages). Real MSI interrupt capture needs the hypervisor tier.
- ✅ **M3 (MMIO): DONE.** Read-only BAR snapshot/diff via the filter; captured live MFINDEX + ERDP
  on the xHCI at `0000:00:14.0`. Runtime-tunable window (`REVENG_MMIO_BYTES`).
- ✅ **M4 (DMA): DONE.** Followed the xHCI Event Ring in system memory (`MmCopyMemory`); captured
  256 real Transfer Event TRBs (Success + Short-Packet completions) under USB traffic, with VBS on.
- ⏳ Only the `reveng-hv` hypervisor tier remains — for MSI interrupts (M2) and per-access (not
  just state-diff) MMIO. Everything else in the driver-only tier is done.
