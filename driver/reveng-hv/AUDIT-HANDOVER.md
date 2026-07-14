# reveng-hv — crash audit handover (2026-07-13)

**Status of this doc:** conclusions from a static audit of `reveng-hv.c` (1271 lines),
`reveng-hv-asm.asm` (224 lines), `reveng_hv_abi.h`, and `reveng-hv.vcxproj`, triggered by
"the hypervisor code crashed my computer." **No code changed** — this is the log written
before any fix work, per standing rule. The definitive root cause is in the minidump; this
ranks the static-review candidates and tells the next session where to look first.

## TL;DR

- The driver is **not** "PLAN ONLY" as the README claims. **H1 is fully implemented**
  (VMXON + full VMCS build + `VMLAUNCH` hyperjack + `#UD`/VMCALL/unknown-exit devirtualize +
  VMRESUME-failure recovery). Docs are stale; that is being fixed in the same pass as this audit.
- Build/load posture is **boot-safe** (WDM control driver, no auto/boot-start anywhere) — this
  was a one-shot BSOD of the running session, not an unbootable machine. Good.
- **Leading crash hypothesis (F1 + F2 together):** on modern Win11/Alder Lake the kernel executes
  `XSAVES/XRSTORS` (supervisor xstate: CET etc.) constantly. Those instructions `#UD` because the
  "enable XSAVES/XRSTORS" secondary VMCS control (bit 20) is **not** set — only RDTSCP(3) and
  INVPCID(12) are. The `#UD` exit path then calls **`DbgPrintEx` from VMX-root exit context**
  (interrupts off, host stack, System CR3) before devirtualizing. Calling a complex, lock-taking
  kernel API from the exit handler is unsafe and is the most probable BSOD/deadlock trigger.
- **First empirical step next session (no debugger needed):** load, `IOCTL_REVENG_HV_START`, then
  `IOCTL_REVENG_HV_DIAG` and read `last_devirt_reason` / `last_exit_reason`. `2` = `#UD` confirms
  the XSAVES hypothesis. Also record the bugcheck code from the minidump.

## Findings, ranked

### F1 — Unsafe kernel calls (`DbgPrintEx`) from the VM-exit host handler *(BSOD-class)*
`VmExitDispatcher` calls `DbgPrintEx` on the `#UD` path (~line 1025) and the unexpected-exit path
(~line 1039); `VmResumeFailed` calls it too (~line 973). All three run as the **host**, on the
per-CPU exit stack, with interrupts disabled and `HOST_CR3` = System — this is not a normal IRQL
context. `DbgPrintEx` acquires locks and can touch pageable state; if the interrupted guest held a
related lock, re-entering it from root mode deadlocks or faults (a fault in root mode → host IDT →
no clean recovery → bugcheck/triple-fault). **Fix direction:** the exit handler must do zero
complex kernel calls. Record everything into `g_Diag` (already the pattern) and drop the
`DbgPrintEx` calls, or gate them behind a "safe to log" path that never runs in root context.

### F2 — `XSAVES/XRSTORS` not enabled in secondary controls, yet assumed handled *(functional + feeds F1)*
`BuildVmcsAndLaunch` sets secondary controls to `RDTSCP | INVPCID` only (bits 3, 12). The comment
at ~line 810 lists "XSAVES/XRSTORS" as part of the class that `#UD`s without an enable bit, but bit
20 is never set, and `g_Diag.xsaves_enabled` is hardcoded `0`. Consequence on Win11/Alder Lake:
the first kernel `XSAVES` after `VMLAUNCH` (essentially the first context switch) `#UD`s → exit →
F1's unsafe path → devirtualize. Even absent F1, the hyperjack silently falls out almost
immediately. **Fix direction:** either (a) set secondary bit 20 so guest `XSAVES/XRSTORS` run
natively (requires IA32_XSS-aware save/restore in the exit stub — the comment already flags this as
not yet safe), or (b) keep trapping but make the `#UD` devirt path completely silent/safe (F1) and
accept that H1 self-devirtualizes on first supervisor-xstate use. (b) is the smaller, safer step.

### F3 — README-mandated boot-safety nets are absent from the code *(safety-net gap)*
README §0 requires two recovery mechanisms that **do not exist** in `reveng-hv.c`:
- `KeRegisterBugCheckReasonCallback` that `VMXOFF`s all CPUs during a bugcheck.
- A **watchdog timer** that auto-devirtualizes if the user-mode controller dies without a clean STOP.

Neither is implemented. CPU reset clears VMX on reboot, so this doesn't brick boot, but it means a
crash while virtualized (or a wedged controller) has no in-driver safety net — exactly the scenario
that just happened. **Fix direction:** implement both before the next live `START`.

### F4 — Host segment selectors masked with `& 0xF8` instead of `& 0xFFF8` *(latent triple-fault)*
`BuildVmcsAndLaunch` (~lines 730–736) writes `HOST_*_SELECTOR = ctx->Seg* & 0xF8`. VMX only requires
clearing the low 3 bits (RPL/TI), i.e. `& 0xFFF8`. `0xF8` also clears the selector's high byte.
Harmless today because every Windows kernel selector here is < 0x100, but any selector index ≥ 32
would be silently corrupted, and a bad host selector triggers an **instant triple-fault on the first
VM-exit**. **Fix direction:** change the mask to `0xFFF8`.

### F5 — EFER VMCS fields written but their load-controls not enabled *(dead config / low)*
`HOST_IA32_EFER` and `GUEST_IA32_EFER` are written, but the VM-exit "load IA32_EFER" (bit 21) and
VM-entry "load IA32_EFER" (bit 15) controls are never set, so those fields are ignored. Works in
practice (LMA/LME follow the address-space-size controls) but the writes are dead and misleading,
and SCE/NXE aren't explicitly managed. **Fix direction:** either set the load controls or drop the
writes and document the reliance on address-space-size behaviour.

## What is correct (so the next session doesn't re-investigate it)
- Host state RIP/RSP/CR3/CR0/CR4, FS/GS/TR bases, GDTR/IDTR: correct. `HOST_CR3` = never-dying
  System CR3 (not the caller's) — deliberate and right.
- Exit-trampoline GPR save/restore order matches `GUEST_REGISTERS`; 16-byte stack alignment at the
  `call` is correct; XSAVE/XRSTOR of XCR0-enabled state around the C dispatcher is present.
- `VMLAUNCH` resume via `RtlCaptureContext` + the fixed-address `volatile g_ResumeAfterLaunch`
  (read as a plain global, not via a possibly-stale GPR) is sound.
- `IsVmxRegionPhysicalAddressValid`, the CR0/CR4 fixed-bit application, VMXON/VMCLEAR/VMPTRLD
  sequencing, and the START/STOP atomic-claim on `g_VirtualizedCpuIndex` all look correct.
- `IO_REMOVE_LOCK` drain-on-unload closes the `sc stop`-vs-in-flight-START race.
- A failed `VMLAUNCH`/`VMRESUME` returns/recovers cleanly rather than crashing — bad *guest* VMCS
  state fails closed (VMfailValid), it does not BSOD. The BSOD is therefore on the **post-launch
  exit path**, which is why F1/F2 are the lead.

## Recommended fix order (when authorized to touch code)
1. F1 — strip `DbgPrintEx` (and any other non-trivial kernel call) out of the exit/root path.
2. F3 — add the bugcheck-reason callback + watchdog before any further live `START`.
3. F2 — decide (a) enable XSAVES or (b) silent-trap; do (b) first.
4. F4 — `0xF8` → `0xFFF8`.
5. F5 — reconcile EFER controls.

Validate each with `IOCTL_REVENG_HV_DIAG` (`last_devirt_reason`/`last_exit_reason`) and
`Write-VolumeCache C:` before every `sc start`, per README §0 / §5.
