# reveng-hv — the hypervisor tier (experimental H1)

The heaviest PCIe capture tier (DESIGN.md §4a). A thin **type-2 "hyperjacking" hypervisor**: a
Windows kernel driver that puts the *already-running* Windows into VMX non-root guest mode (nobody
reboots into a new OS), then uses **EPT** to trap the target device's MMIO per-access and VMCS
controls to trap its interrupts. It exists to capture the two things the driver-only tier
(`../reveng-pcidrv`) provably cannot:

1. **MSI/MSI-X interrupts** — a filter can't share dedicated MSI messages (`STATUS_INVALID_PARAMETER`,
   proven in M2). A hypervisor sees interrupt delivery regardless of driver ownership.
2. **Per-access MMIO** — M3 only diffs register *state* on a timer; it misses transient and inlined
   accesses. EPT faults on *every* access, with the exact value, direction, and width.
   (Stretch: trap DMA *writes* by the device via EPT write-traps on the ring pages — richer than
   M4's read-only ring following.)

Status: **H1 is implemented as a one-CPU experimental hyperjack; H2–H5 are not implemented.**
The current H1 code can VMXON/VMLAUNCH, handle CPUID, and devirtualize through VMCALL or its
unexpected-exit safety path. Controller-handle cleanup now acts as a liveness watchdog, but it is
still experimental and not ready for unattended use. A bugcheck callback devirtualizes when the
crashing processor is the H1 VMX guest; if another processor crashes, the already-stopped guest is
left resident until hardware reset. H1 enables native guest
`XSAVES`/`XRSTORS` only when the CPU and
VMCS secondary control support it, and preserves both XCR0 and IA32_XSS state across every exit.
`crates/pcicap::HvPcieSource` remains a stub.

**Prior art to study before writing a line:** SimpleVisor, hvpp, Bareflank, gbhv (all MIT/BSD-ish;
gbhv and hvpp are the closest templates — EPT hooking on Windows).

---

## 0. Boot-safety contract (non-negotiable — user accepts BSOD, NOT an unbootable machine)

Every choice below obeys these:

- **Demand-start service ONLY.** `sc create ... start= demand`. A broken build is simply *not loaded*
  at boot, so the machine always boots to a working desktop. NEVER `start= boot/system/auto`. This is
  the single most important guarantee — a triple-faulting `VMLAUNCH` bugchecks the *running* session,
  but the next boot is clean because the driver isn't auto-loaded.
- **Reversible preconditions only.** The one required host change (disable Hyper-V, §1) is a `bcdedit`
  toggle, trivially reversible, and does not affect the ability to boot.
- **Devirtualize on every exit path:** IOCTL stop, `DriverUnload`, and a
  **`KeRegisterBugCheckCallback`** that devirtualizes when the callback runs on the H1 guest CPU.
  Bugcheck callbacks run at `HIGH_LEVEL`, so they cannot migrate to a different stopped processor;
  hardware reset clears VMX there without touching pageable driver state.
- **Controller-liveness auto-devirtualize:** the handle that successfully sends `START` owns the
  session. `IRP_MJ_CLEANUP` synchronously devirtualizes if that handle closes without a clean
  `STOP`, including when its process terminates. Other handles cannot stop its session.
- **Observe-only:** no writes to the target device, no kernel code patching → PatchGuard is a non-issue.
- **Flush disk before every risky load:** `Write-VolumeCache C:` before each `sc start`, because a bad
  `VMLAUNCH` bugchecks instantly and can lose unsaved buffers.
- **Keep a known-good `.sys`** next to the working one so recovery from a bad build is one `sc start`,
  never a reinstall.

---

## 1. Precondition H0 — free VT-x from Hyper-V/VBS

Confirmed on this box (2026-07-13): `HypervisorPresent = True`, `hypervisorlaunchtype = Auto`, VBS
**running**. Microsoft's hypervisor holds VMX root, so our `VMXON` fails today. Disable it (reversible):

```
bcdedit /set hypervisorlaunchtype off        # stop Hyper-V launching at boot
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" /v Enabled /t REG_DWORD /d 0 /f
```
Reboot, then verify VT-x is ours:
- `(Get-CimInstance Win32_ComputerSystem).HypervisorPresent` → **False**.
- A tiny probe: `CPUID.1:ECX.VMX[5]=1`, and `IA32_FEATURE_CONTROL` (MSR 0x3A) has lock=1 **and**
  "VMXON outside SMX"=1. If lock=1 but enable=0, VT-x is firmware-disabled → UEFI change needed first.

**Reverse anytime:** `bcdedit /set hypervisorlaunchtype auto` + reg values back to 1 + reboot. Boot-safe
both directions. (Secure Boot + testsigning already set from the driver-only tier.)

**Hybrid-CPU note (i5-12500H Alder Lake): 16 logical CPUs across P-cores + E-cores.** We must
`VMXON`+`VMLAUNCH` on **every** logical CPU (a core left un-virtualized wouldn't trap the target and
could see inconsistent memory). Fan bring-up across all CPUs via `KeIpiGenericCall`; read capability
MSRs per-CPU and use only the P/E common subset.

---

## 2. Milestones (each independently verifiable; every one leaves the machine bootable)

### H1 — Hyperjack + resume (make-or-break)
Per CPU: check VMX, alloc VMXON/VMCS regions (4 KB aligned, revision id from `IA32_VMX_BASIC`),
`VMXON`, fill VMCS host state = fixed re-entry, guest state = *current* regs/segments/CR/RIP captured
just before launch, minimal pin/proc-exec controls, `VMLAUNCH` so Windows continues where it was — now
non-root. Handle a trivial `CPUID` exit as proof (expose a `reveng-hv present` backdoor leaf). IOCTL
start/stop; stop = `VMXOFF` all CPUs. *Verify:* machine stays fully usable; CPUID backdoor returns our
signature; clean stop → bare metal; unload+reload works. **Highest risk (bad VMCS = instant bugcheck),
boot-safe via demand-start.**

### H2 — EPT identity map
4-level EPT with guest-physical = host-physical for all RAM + MMIO (walk `MmGetPhysicalMemoryRanges`;
MMIO uncacheable, RAM write-back). Enable EPT in secondary proc controls. *Verify:* no crash / no perf
collapse over minutes of normal use.

### H3 — Per-access MMIO (payoff for M3's gap)
Mark the target BAR's EPT entries **not-present**. On EPT-violation exit: read guest RIP, **decode the
faulting instruction** (§3), extract {read|write, width, value, GPA→BAR+offset}, push an `MMIO` event,
then set page present + **MTF** single-step, `VMRESUME`; on the MTF exit re-mark not-present and resume.
Per-CPU handling with a lock over the protect/unprotect toggle. *Verify:* every register poke on the
target appears with the exact value; cross-check vs M3's state diffs.

### H4 — Interrupts (payoff for M2's wall)
Set **"external-interrupt exiting"** (pin control); on that exit, read the vector from exit
interruption-info, push an `IRQ` event, **re-inject** via VM-entry interruption-info so Windows still
services it. Optionally filter to the target's MSI vector(s) (from its MSI/MSI-X capability). *Verify:*
the target's real MSI vectors appear under load (xHCI/DualSense); reinjection keeps the device working.

### H5 — Integration
Route H3/H4 events through the existing 32-byte ABI + ring → `HvPcieSource` (mirror `DrvPcieSource`) →
same session format, so `frames`/`grep`/`diff` just work. Reuse `pci-attach`-style BDF selection to
resolve the target's BAR GPAs to protect in EPT.

---

## 3. Hardest components & de-risking

- **MMIO instruction decoder (H3).** To log an access we must decode the faulting `MOV` (+`MOVZX/MOVSX`,
  `STOS/rep`, RMW `AND/OR`). Cheapest first: (a) hand-decode the ~15 common MMIO ModRM forms — enough
  for most drivers; (b) vendor a small permissive x86 disassembler. Start with (a) and **log-and-skip**
  unrecognized forms (never guess); surface an "undecoded access" counter. Most likely component to be
  wrong.
- **Multi-core protect/unprotect race (H3).** While one CPU single-steps with the page present, another
  could access it untrapped. Mitigate with a brief global "trap in progress" gate, or **per-CPU EPT**
  (each CPU its own EPTP → unprotect is local). Bring up single-core-scoped, then generalize.
- **APIC/x2APIC reinjection (H4).** Wrong reinjection hangs/storms the box. De-risk by first only
  *counting* exits with immediate reinject before adding logging/filtering.
- **`INVEPT` invalidation, MTF availability** (check `IA32_VMX_PROCBASED_CTLS2`), **EPT large-page
  splitting** for sub-page BARs. Standard but must be exact.

---

## 4. Toolchain & signing

Same as `reveng-pcidrv`: VS 2026 + WDK 28000, `PlatformToolset=WindowsKernelModeDriver10.0`,
`WindowsTargetPlatformVersion=10.0.28000.0`, `SpectreMitigation=false`, `SignMode=Off`, test-sign with
the existing cert (thumbprint E2A8E708527B8127CA3673F11D11CAA706363CF8). C + a MASM `.asm` for the VMX
stubs (`VMXON/VMLAUNCH/VMRESUME/VMXOFF/VMREAD/VMWRITE`) and the host-entry trampoline. Demand-start; NEVER
auto/boot-start. Refuse to load if `HypervisorPresent` (detect a hypervisor already present) to avoid a
double-virtualize.

---

## 5. Reboot-cycle discipline (from the driver tier)

This is a **non-PnP control driver**, so `sc stop` unloads it cleanly (unlike the PnP filter that got
stuck "marked for deletion" and forced reboots). If a stop ever fails, reboot. Always
`Write-VolumeCache C:` before `sc start`. Build H1 in a **git worktree** so the stable driver-only tier
is never disturbed while iterating on the risky hypervisor.

---

## 6. Sequencing & effort

H0 (precondition + reboot, ~1 session) → H1 (hyperjack, multiple sessions) → H2 (EPT, moderate) → H3
(MMIO trap + decoder, largest) → H4 (interrupts, moderate) → H5 (wire-up, small). Realistically
multi-week. Each milestone is a stopping point leaving the machine bootable and the M1/M3/M4 tiers
intact. Validate downstream logic with `ReplayPcieSource` (zero kernel code) before trusting live exits.
