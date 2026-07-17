; reveng-hv-asm.asm — the two things MSVC has no x64 intrinsic for: VMLAUNCH/VMRESUME and the
; VM-exit trampoline (a VM-exit lands the CPU at a fixed RIP with only VMX-defined state restored;
; GPRs are NOT saved by hardware, so the trampoline must save them by hand, like a manual ISR).
;
; Calling convention: fastcall (RCX/RDX/R8/R9), non-volatile RBX/RBP/RSI/RDI/R12-R15 preserved.

.CODE

; UCHAR AsmVmxLaunch(void)
; Executes VMLAUNCH. On SUCCESS control never returns here — it jumps to the guest RIP programmed
; into the VMCS (the resume point captured by RtlCaptureContext in C). On FAILURE, VMLAUNCH just
; falls through to the next instruction with CF/ZF indicating the error class.
AsmVmxLaunch PROC
    vmlaunch
    jz      launch_fail_valid      ; ZF=1 -> VMfailValid (VM-instruction-error field is live)
    jc      launch_fail_invalid    ; CF=1 -> VMfailInvalid (no current VMCS)
    mov     al, 0                  ; unreachable on real success (control transferred to guest)
    ret
launch_fail_invalid:
    mov     al, 2
    ret
launch_fail_valid:
    mov     al, 1
    ret
AsmVmxLaunch ENDP

; VM-exit entry point. Set as the Host RIP field in the VMCS. The CPU jumps here on every VM-exit
; with RSP = the Host RSP field (our dedicated per-CPU host stack) and nothing else preserved.
; We push all 15 GPRs (RSP is tracked via the VMCS guest-state, not here), call the C dispatcher
; with RCX = pointer to the saved registers, then either VMRESUME (dispatcher returned) or the
; dispatcher itself devirtualized and never returns (it jumps straight to the restored guest).
PUBLIC AsmVmExitHandler
EXTERN VmExitDispatcher:PROC
EXTERN VmResumeFailed:PROC
EXTERN g_ExitXsaveArea:QWORD
EXTERN g_ExitXsaveMask:QWORD

AsmVmExitHandler PROC
    ; VM exits do not save extended state. XSAVES preserves both XCR0-managed user state and
    ; IA32_XSS-managed supervisor state (notably CET) in compacted format before C can touch it.
    push    rax
    push    rdx
    push    rcx
    mov     rcx, qword ptr [g_ExitXsaveArea]
    mov     eax, dword ptr [g_ExitXsaveMask]
    mov     edx, dword ptr [g_ExitXsaveMask+4]
    xsaves  [rcx]
    pop     rcx
    pop     rdx
    pop     rax

    ; Push in REVERSE struct-field order so the LAST push (rax) ends up at [rsp+0] — matching
    ; GUEST_REGISTERS { Rax@0, Rcx@8, Rdx@16, Rbx@24, Rbp@32, Rsi@40, Rdi@48, R8@56..R15@112 }.
    push    r15
    push    r14
    push    r13
    push    r12
    push    r11
    push    r10
    push    r9
    push    r8
    push    rdi
    push    rsi
    push    rbp
    push    rbx
    push    rdx
    push    rcx
    push    rax

    mov     rcx, rsp                ; arg1 = pointer to GUEST_REGISTERS (matches the C struct)
    ; 15 pushes leave RSP misaligned by 8 bytes. Reserve shadow space plus an
    ; 8-byte alignment pad so RSP is 16-byte aligned at the CALL instruction.
    sub     rsp, 28h
    call    VmExitDispatcher
    add     rsp, 28h

    push    rax
    push    rdx
    push    rcx
    mov     rcx, qword ptr [g_ExitXsaveArea]
    mov     eax, dword ptr [g_ExitXsaveMask]
    mov     edx, dword ptr [g_ExitXsaveMask+4]
    xrstors [rcx]
    pop     rcx
    pop     rdx
    pop     rax

    pop     rax
    pop     rcx
    pop     rdx
    pop     rbx
    pop     rbp
    pop     rsi
    pop     rdi
    pop     r8
    pop     r9
    pop     r10
    pop     r11
    pop     r12
    pop     r13
    pop     r14
    pop     r15

    vmresume
    ; VMRESUME only falls through on failure (VMfailValid/VMfailInvalid) — it does NOT touch GPRs
    ; either way, so the values we just popped above already hold exactly what the guest should
    ; resume with. Re-push them (same order as the entry sequence, reconstructing a
    ; GUEST_REGISTERS-shaped block) and hand off to VmResumeFailed, which reuses the same
    ; Devirtualize() recovery path as every other exit reason instead of an unconditional crash.
    push    r15
    push    r14
    push    r13
    push    r12
    push    r11
    push    r10
    push    r9
    push    r8
    push    rdi
    push    rsi
    push    rbp
    push    rbx
    push    rdx
    push    rcx
    push    rax

    mov     rcx, rsp                ; arg1 = pointer to the reconstructed GUEST_REGISTERS
    sub     rsp, 28h                 ; same 8-byte alignment pad as the entry call, see above
    call    VmResumeFailed
    ; VmResumeFailed tail-calls Devirtualize, which jumps into the guest and never returns here —
    ; or, if the VMCS is now too broken even for that, deliberately bugchecks with diagnostics
    ; already recorded. Either way nothing reaches this point; kept only as a documented invariant.
    int     3
AsmVmExitHandler ENDP

; void AsmRestoreContextAndResume(PGUEST_REGISTERS regs, ULONG64 guestRsp, ULONG64 guestRip,
;                                  ULONG64 guestRflags)
; Called from VmExitDispatcher AFTER it has already executed VMXOFF (so we are plain bare-metal
; here, no more VMX). Switches onto the guest's own stack and resumes it at guestRip with GPRs and
; RFLAGS restored, exactly as if the instruction that triggered devirtualization (VMCALL) had been
; a no-op. Never returns.
PUBLIC AsmRestoreContextAndResume
AsmRestoreContextAndResume PROC
    ; rcx = regs, rdx = guestRsp, r8 = guestRip, r9 = guestRflags
    mov     rsp, rdx                ; onto the guest's stack
    push    r9
    popfq                           ; restore RFLAGS
    push    r8                      ; will `ret` into this
    ; restore GPRs from the saved array (offsets match the push order in AsmVmExitHandler,
    ; i.e. GUEST_REGISTERS field order in the C header: Rax,Rcx,Rdx,Rbx,Rbp,Rsi,Rdi,R8..R15)
    mov     rax, [rcx +  0]
    mov     rdx, [rcx + 16]
    mov     rbx, [rcx + 24]
    mov     rbp, [rcx + 32]
    mov     rsi, [rcx + 40]
    mov     rdi, [rcx + 48]
    mov     r8,  [rcx + 56]
    mov     r9,  [rcx + 64]
    mov     r10, [rcx + 72]
    mov     r11, [rcx + 80]
    mov     r12, [rcx + 88]
    mov     r13, [rcx + 96]
    mov     r14, [rcx + 104]
    mov     r15, [rcx + 112]
    mov     rcx, [rcx +  8]         ; restore rcx last — we were using it as the base pointer
    ret                             ; pops guestRip pushed above, RSP ends up == guestRsp
AsmRestoreContextAndResume ENDP

; void AsmVmCallDevirtualize(void) — executed FROM inside the VMX guest (the pinned thread that
; called START). Traps to VmExitDispatcher, which recognizes the magic in RCX and devirtualizes
; this CPU; from the caller's perspective this just "returns" once bare-metal again.
PUBLIC AsmVmCallDevirtualize
AsmVmCallDevirtualize PROC
    mov     rcx, 1234567887654321h  ; MUST match HV_DEVIRT_MAGIC in reveng-hv.c
    vmcall
    ret
AsmVmCallDevirtualize ENDP

; Restore all guest user and supervisor state before VMXOFF. Devirtualization tail-resumes directly
; into guest code, so unlike the normal VMRESUME path it does not return through the exit stub.
PUBLIC AsmRestoreGuestXstate
AsmRestoreGuestXstate PROC
    push    rax
    push    rdx
    push    rcx
    mov     rcx, qword ptr [g_ExitXsaveArea]
    mov     eax, dword ptr [g_ExitXsaveMask]
    mov     edx, dword ptr [g_ExitXsaveMask+4]
    xrstors [rcx]
    pop     rcx
    pop     rdx
    pop     rax
    ret
AsmRestoreGuestXstate ENDP

; USHORT AsmReadTr(void) / AsmReadLdtr(void) — MSVC has no intrinsic for STR/SLDT.
PUBLIC AsmReadTr
AsmReadTr PROC
    xor     eax, eax
    str     ax
    ret
AsmReadTr ENDP

PUBLIC AsmReadLdtr
AsmReadLdtr PROC
    xor     eax, eax
    sldt    ax
    ret
AsmReadLdtr ENDP

; void AsmReadGdtr(PSEUDO_DESC *out) / AsmReadIdtr(PSEUDO_DESC *out) — MSVC's _sgdt intrinsic
; availability is inconsistent across WDK versions; do it directly to be certain of the format.
PUBLIC AsmReadGdtr
AsmReadGdtr PROC
    sgdt    [rcx]
    ret
AsmReadGdtr ENDP

PUBLIC AsmReadIdtr
AsmReadIdtr PROC
    sidt    [rcx]
    ret
AsmReadIdtr ENDP

END
