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
- **M2 — interrupts.** Attach as an upper filter in the device stack (or `IoConnectInterruptEx`
  sharing) → `IRQ` events on each ISR.
- **M3 — MMIO.** The fragile part with no hypervisor: hook the HAL register accessors
  (`READ/WRITE_REGISTER_*`, `MmMapIoSpace`) or Windows DTrace `fbt`. Catches the driver's
  *intended* register access; misses inlined accesses. Upgrade path is the `reveng-hv` EPT tier.
- **M4 — DMA (best-effort).** Follow descriptor rings learned from M3 MMIO; snapshot buffers.

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
- ⏳ Next: M2 (interrupts via `IoConnectInterruptEx`), then M3 (MMIO hooks), M4 (DMA follow).
