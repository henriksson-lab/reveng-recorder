/*
 * reveng-hv — hypervisor tier (plan in README.md). H1 step 1: capability PROBE only.
 *
 * A non-PnP software control driver (\\.\RevengHv), DEMAND-START ONLY (boot-safety contract §0:
 * a bad build must never be auto-loaded, so the machine always boots). This first cut does NOT
 * enter VMX — it only reads CPUID + the VMX capability MSRs and reports them, so we can confirm
 * on real hardware that (a) Hyper-V released VT-x, (b) VMX is unlocked/allowed, and (c) EPT/MTF
 * are available — before writing a single VMXON. Zero risk.
 *
 * Next steps (separate, riskier commits): VMXON+VMXOFF all CPUs, then VMLAUNCH hyperjack (H1),
 * then EPT (H2), MMIO traps (H3), interrupt exiting (H4).
 */
#include <ntddk.h>
#include <wdmsec.h> /* IoCreateDeviceSecure (links against Wdmsec.lib) */
#include <intrin.h>
#include "reveng_hv_abi.h"

#define MSR_IA32_FEATURE_CONTROL 0x3A
#define MSR_IA32_VMX_BASIC       0x480
#define MSR_IA32_VMX_PINBASED_CTLS   0x481
#define MSR_IA32_VMX_PROCBASED_CTLS  0x482
#define MSR_IA32_VMX_EXIT_CTLS       0x483
#define MSR_IA32_VMX_ENTRY_CTLS      0x484
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS  0x48D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x48E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS      0x48F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS     0x490
#define MSR_IA32_VMX_PROCBASED_CTLS2     0x48B /* secondary controls — no "true" variant exists */
#define MSR_IA32_VMX_EPT_VPID    0x48C
#define MSR_IA32_VMX_CR0_FIXED0  0x486
#define MSR_IA32_VMX_CR0_FIXED1  0x487
#define MSR_IA32_VMX_CR4_FIXED0  0x488
#define MSR_IA32_VMX_CR4_FIXED1  0x489
#define MSR_IA32_SYSENTER_CS  0x174
#define MSR_IA32_SYSENTER_ESP 0x175
#define MSR_IA32_SYSENTER_EIP 0x176
#define MSR_IA32_FS_BASE  0xC0000100
#define MSR_IA32_GS_BASE  0xC0000101
#define MSR_IA32_DEBUGCTL 0x1D9
#define MSR_IA32_EFER     0xC0000080

/* VMCS field encoding (Intel SDM Vol.3C §24.11.2 / Appendix B): a 16-bit value built from
 * access_type | index<<1 | type<<10 | width<<13. access_type only matters for a 32-bit host
 * reading a 64-bit field as two 32-bit halves; on x64 VMREAD/VMWRITE take the full 64-bit value
 * in one shot, so it's always "full" (0) here — the field-encode() technique and index ordering
 * below are cross-checked against wbenny/hvpp and QEMU's vmxcap (kvm capability tool), not typed
 * from memory as bare hex: this makes the (type, width, index) intent auditable at the call site
 * instead of requiring every hex constant to be independently trusted. */
#define VMCS_ENC(type, width, index) (((type) << 10) | ((width) << 13) | ((index) << 1))
#define VMCS_T_CONTROL 0 /* control field                    */
#define VMCS_T_RO      1 /* VM-exit info, read-only          */
#define VMCS_T_GUEST   2 /* guest-state field                */
#define VMCS_T_HOST    3 /* host-state field                 */
#define VMCS_W_16      0
#define VMCS_W_64      1
#define VMCS_W_32      2
#define VMCS_W_NATURAL 3 /* 64-bit on x64                    */

/* 16-bit guest/host segment selectors (guest has LDTR; host does not — Windows doesn't use LDT). */
#define VMCS_GUEST_ES_SELECTOR   VMCS_ENC(VMCS_T_GUEST, VMCS_W_16, 0)
#define VMCS_GUEST_CS_SELECTOR   VMCS_ENC(VMCS_T_GUEST, VMCS_W_16, 1)
#define VMCS_GUEST_SS_SELECTOR   VMCS_ENC(VMCS_T_GUEST, VMCS_W_16, 2)
#define VMCS_GUEST_DS_SELECTOR   VMCS_ENC(VMCS_T_GUEST, VMCS_W_16, 3)
#define VMCS_GUEST_FS_SELECTOR   VMCS_ENC(VMCS_T_GUEST, VMCS_W_16, 4)
#define VMCS_GUEST_GS_SELECTOR   VMCS_ENC(VMCS_T_GUEST, VMCS_W_16, 5)
#define VMCS_GUEST_LDTR_SELECTOR VMCS_ENC(VMCS_T_GUEST, VMCS_W_16, 6)
#define VMCS_GUEST_TR_SELECTOR   VMCS_ENC(VMCS_T_GUEST, VMCS_W_16, 7)
#define VMCS_HOST_ES_SELECTOR    VMCS_ENC(VMCS_T_HOST, VMCS_W_16, 0)
#define VMCS_HOST_CS_SELECTOR    VMCS_ENC(VMCS_T_HOST, VMCS_W_16, 1)
#define VMCS_HOST_SS_SELECTOR    VMCS_ENC(VMCS_T_HOST, VMCS_W_16, 2)
#define VMCS_HOST_DS_SELECTOR    VMCS_ENC(VMCS_T_HOST, VMCS_W_16, 3)
#define VMCS_HOST_FS_SELECTOR    VMCS_ENC(VMCS_T_HOST, VMCS_W_16, 4)
#define VMCS_HOST_GS_SELECTOR    VMCS_ENC(VMCS_T_HOST, VMCS_W_16, 5)
#define VMCS_HOST_TR_SELECTOR    VMCS_ENC(VMCS_T_HOST, VMCS_W_16, 6)

/* 64-bit control (index 0/1 are the I/O bitmap A/B fields we don't use) + guest fields. */
#define VMCS_MSR_BITMAP          VMCS_ENC(VMCS_T_CONTROL, VMCS_W_64, 2)
#define VMCS_GUEST_VMCS_LINK_PTR VMCS_ENC(VMCS_T_GUEST, VMCS_W_64, 0)
#define VMCS_GUEST_DEBUGCTL      VMCS_ENC(VMCS_T_GUEST, VMCS_W_64, 1)
#define VMCS_GUEST_IA32_EFER     VMCS_ENC(VMCS_T_GUEST, VMCS_W_64, 3)
#define VMCS_HOST_IA32_EFER      VMCS_ENC(VMCS_T_HOST,  VMCS_W_64, 1)

/* 32-bit control fields. */
#define VMCS_PIN_BASED_CTLS             VMCS_ENC(VMCS_T_CONTROL, VMCS_W_32, 0)
#define VMCS_PROC_BASED_CTLS            VMCS_ENC(VMCS_T_CONTROL, VMCS_W_32, 1)
#define VMCS_EXCEPTION_BITMAP           VMCS_ENC(VMCS_T_CONTROL, VMCS_W_32, 2)
#define VMCS_CR3_TARGET_COUNT           VMCS_ENC(VMCS_T_CONTROL, VMCS_W_32, 5)
#define VMCS_EXIT_CTLS                  VMCS_ENC(VMCS_T_CONTROL, VMCS_W_32, 6)
#define VMCS_EXIT_MSR_STORE_COUNT       VMCS_ENC(VMCS_T_CONTROL, VMCS_W_32, 7)
#define VMCS_EXIT_MSR_LOAD_COUNT        VMCS_ENC(VMCS_T_CONTROL, VMCS_W_32, 8)
#define VMCS_ENTRY_CTLS                 VMCS_ENC(VMCS_T_CONTROL, VMCS_W_32, 9)
#define VMCS_ENTRY_MSR_LOAD_COUNT       VMCS_ENC(VMCS_T_CONTROL, VMCS_W_32, 10)
#define VMCS_ENTRY_INTR_INFO            VMCS_ENC(VMCS_T_CONTROL, VMCS_W_32, 11)
#define VMCS_ENTRY_EXCEPTION_ERR        VMCS_ENC(VMCS_T_CONTROL, VMCS_W_32, 12)
#define VMCS_ENTRY_INSTR_LEN            VMCS_ENC(VMCS_T_CONTROL, VMCS_W_32, 13)
/* index 14 = TPR threshold, unused */
#define VMCS_SECONDARY_PROC_BASED_CTLS  VMCS_ENC(VMCS_T_CONTROL, VMCS_W_32, 15)

/* 32-bit read-only VM-exit info fields. */
#define VMCS_VM_INSTRUCTION_ERROR VMCS_ENC(VMCS_T_RO, VMCS_W_32, 0)
#define VMCS_EXIT_REASON          VMCS_ENC(VMCS_T_RO, VMCS_W_32, 1)
#define VMCS_EXIT_INTR_INFO       VMCS_ENC(VMCS_T_RO, VMCS_W_32, 2)
/* index 3=exit-intr-error-code, 4/5=IDT-vectoring info/error — unused */
#define VMCS_EXIT_INSTR_LEN       VMCS_ENC(VMCS_T_RO, VMCS_W_32, 6)

/* 32-bit guest-state + host-state fields. */
#define VMCS_GUEST_ES_LIMIT         VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 0)
#define VMCS_GUEST_CS_LIMIT         VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 1)
#define VMCS_GUEST_SS_LIMIT         VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 2)
#define VMCS_GUEST_DS_LIMIT         VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 3)
#define VMCS_GUEST_FS_LIMIT         VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 4)
#define VMCS_GUEST_GS_LIMIT         VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 5)
#define VMCS_GUEST_LDTR_LIMIT       VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 6)
#define VMCS_GUEST_TR_LIMIT         VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 7)
#define VMCS_GUEST_GDTR_LIMIT       VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 8)
#define VMCS_GUEST_IDTR_LIMIT       VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 9)
#define VMCS_GUEST_ES_AR            VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 10)
#define VMCS_GUEST_CS_AR            VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 11)
#define VMCS_GUEST_SS_AR            VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 12)
#define VMCS_GUEST_DS_AR            VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 13)
#define VMCS_GUEST_FS_AR            VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 14)
#define VMCS_GUEST_GS_AR            VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 15)
#define VMCS_GUEST_LDTR_AR          VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 16)
#define VMCS_GUEST_TR_AR            VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 17)
#define VMCS_GUEST_INTERRUPTIBILITY VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 18)
#define VMCS_GUEST_ACTIVITY_STATE   VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 19)
/* index 20 = SMBASE, unused */
#define VMCS_GUEST_SYSENTER_CS      VMCS_ENC(VMCS_T_GUEST, VMCS_W_32, 21)
#define VMCS_HOST_SYSENTER_CS       VMCS_ENC(VMCS_T_HOST, VMCS_W_32, 0)

/* Natural-width (64-bit on x64) control fields. */
#define VMCS_CR0_GUEST_HOST_MASK VMCS_ENC(VMCS_T_CONTROL, VMCS_W_NATURAL, 0)
#define VMCS_CR4_GUEST_HOST_MASK VMCS_ENC(VMCS_T_CONTROL, VMCS_W_NATURAL, 1)
#define VMCS_CR0_READ_SHADOW     VMCS_ENC(VMCS_T_CONTROL, VMCS_W_NATURAL, 2)
#define VMCS_CR4_READ_SHADOW     VMCS_ENC(VMCS_T_CONTROL, VMCS_W_NATURAL, 3)

/* Natural-width read-only + guest-state + host-state fields. */
#define VMCS_EXIT_QUALIFICATION VMCS_ENC(VMCS_T_RO, VMCS_W_NATURAL, 0)
#define VMCS_GUEST_CR0           VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 0)
#define VMCS_GUEST_CR3           VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 1)
#define VMCS_GUEST_CR4           VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 2)
#define VMCS_GUEST_ES_BASE       VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 3)
#define VMCS_GUEST_CS_BASE       VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 4)
#define VMCS_GUEST_SS_BASE       VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 5)
#define VMCS_GUEST_DS_BASE       VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 6)
#define VMCS_GUEST_FS_BASE       VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 7)
#define VMCS_GUEST_GS_BASE       VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 8)
#define VMCS_GUEST_LDTR_BASE     VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 9)
#define VMCS_GUEST_TR_BASE       VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 10)
#define VMCS_GUEST_GDTR_BASE     VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 11)
#define VMCS_GUEST_IDTR_BASE     VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 12)
#define VMCS_GUEST_DR7           VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 13)
#define VMCS_GUEST_RSP           VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 14)
#define VMCS_GUEST_RIP           VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 15)
#define VMCS_GUEST_RFLAGS        VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 16)
/* index 17 = pending debug exceptions, unused (left at implicit 0) */
#define VMCS_GUEST_SYSENTER_ESP  VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 18)
#define VMCS_GUEST_SYSENTER_EIP  VMCS_ENC(VMCS_T_GUEST, VMCS_W_NATURAL, 19)
#define VMCS_HOST_CR0            VMCS_ENC(VMCS_T_HOST, VMCS_W_NATURAL, 0)
#define VMCS_HOST_CR3            VMCS_ENC(VMCS_T_HOST, VMCS_W_NATURAL, 1)
#define VMCS_HOST_CR4            VMCS_ENC(VMCS_T_HOST, VMCS_W_NATURAL, 2)
#define VMCS_HOST_FS_BASE        VMCS_ENC(VMCS_T_HOST, VMCS_W_NATURAL, 3)
#define VMCS_HOST_GS_BASE        VMCS_ENC(VMCS_T_HOST, VMCS_W_NATURAL, 4)
#define VMCS_HOST_TR_BASE        VMCS_ENC(VMCS_T_HOST, VMCS_W_NATURAL, 5)
#define VMCS_HOST_GDTR_BASE      VMCS_ENC(VMCS_T_HOST, VMCS_W_NATURAL, 6)
#define VMCS_HOST_IDTR_BASE      VMCS_ENC(VMCS_T_HOST, VMCS_W_NATURAL, 7)
#define VMCS_HOST_SYSENTER_ESP   VMCS_ENC(VMCS_T_HOST, VMCS_W_NATURAL, 8)
#define VMCS_HOST_SYSENTER_EIP   VMCS_ENC(VMCS_T_HOST, VMCS_W_NATURAL, 9)
#define VMCS_HOST_RSP            VMCS_ENC(VMCS_T_HOST, VMCS_W_NATURAL, 10)
#define VMCS_HOST_RIP            VMCS_ENC(VMCS_T_HOST, VMCS_W_NATURAL, 11)

/* Permanent regression guards: pin the fields most central to the RDTSCP-crash fix (and a
 * handful of others) to their externally-verified raw values (cross-checked against QEMU's
 * vmxcap and wbenny/hvpp), so an index typo here fails the BUILD instead of silently writing to
 * the wrong VMCS field. */
C_ASSERT(VMCS_SECONDARY_PROC_BASED_CTLS == 0x401E);
C_ASSERT(VMCS_EXIT_INTR_INFO == 0x4404);
C_ASSERT(VMCS_MSR_BITMAP == 0x2004);
C_ASSERT(VMCS_GUEST_RIP == 0x681E);
C_ASSERT(VMCS_GUEST_RSP == 0x681C);
C_ASSERT(VMCS_HOST_RIP == 0x6C16);
C_ASSERT(VMCS_HOST_RSP == 0x6C14);
C_ASSERT(VMCS_VM_INSTRUCTION_ERROR == 0x4400);
C_ASSERT(VMCS_EXIT_REASON == 0x4402);

#define PIN_BASED_NONE 0
/* CPUID is UNCONDITIONALLY trapped by VMX (SDM: "Instructions That Cause VM Exits
 * Unconditionally") — there is no enable bit for it. Bit 21 of primary proc-based controls is
 * actually "Use TPR shadow", a DIFFERENT control this driver must not enable: it requires a
 * companion VIRTUAL_APIC_ADDRESS VMCS field we never set, so turning it on would have guest
 * MOV-CR8 accesses serviced through whatever garbage physical address is in that uninitialized
 * field — a physical-memory-corruption risk, not just a crash. Confirmed via independent audit
 * against SDM §25.1.2 and cross-referenced control-bit tables (FreeBSD vmx.h, Apple
 * Hypervisor.framework, QEMU vmxcap) before this was caught. Do not re-add this bit. */
#define PROC_BASED_USE_MSR_BITMAPS (1u << 28)
#define PROC_BASED_ACTIVATE_SECONDARY_CTLS (1u << 31)
#define EXIT_CTL_HOST_ADDR_SPACE_SIZE (1u << 9)
#define ENTRY_CTL_IA32E_MODE_GUEST (1u << 9)
#define CR0_TS (1ull << 3)

/* Secondary proc-based control bits that gate specific instructions to avoid #UD in the guest
 * (as opposed to most other secondary bits, which just opt IN to trapping/exiting — absence of
 * those is native execution, not a fault). High-confidence, well-documented across every public
 * hypervisor reference implementation. RDTSCP's bit also covers RDPID (same TSC_AUX gate). */
#define SECONDARY_ENABLE_RDTSCP  (1u << 3)
#define SECONDARY_ENABLE_INVPCID (1u << 12)

#define VMX_EXIT_REASON_EXCEPTION_NMI 0
#define VMX_EXIT_REASON_CPUID  10
#define VMX_EXIT_REASON_VMCALL 18
#define VECTOR_UD 6

#define HV_BACKDOOR_LEAF   0x52564748u /* 'RVGH' */
#define HV_BACKDOOR_SIG_EBX 0x676E6576u /* "veng" */
#define HV_BACKDOOR_SIG_ECX 0x2D766568u /* "eh-v" */
#define HV_BACKDOOR_SIG_EDX 0x00000031u /* "1"    */
#define HV_DEVIRT_MAGIC 0x1234567887654321ull /* must match reveng-hv-asm.asm */

#define HOST_STACK_SIZE 0x6000u /* 24KB — plenty for our tiny, non-reentrant exit handler */
#define REVENG_HV_POOL_TAG 'vHgR'

#pragma pack(push, 1)
typedef struct _GUEST_REGISTERS {
    ULONG64 Rax, Rcx, Rdx, Rbx, Rbp, Rsi, Rdi;
    ULONG64 R8, R9, R10, R11, R12, R13, R14, R15;
} GUEST_REGISTERS, *PGUEST_REGISTERS;
#pragma pack(pop)

/* SGDT/SIDT write exactly this 10-byte layout in 64-bit mode. */
#pragma pack(push, 1)
typedef struct _PSEUDO_DESC {
    USHORT  Limit;
    ULONG64 Base;
} PSEUDO_DESC;
#pragma pack(pop)

typedef struct _SEG_INFO {
    USHORT  Selector;
    ULONG   Limit;
    ULONG64 Base;
    ULONG   AccessRights;
} SEG_INFO;

NTKERNELAPI VOID NTAPI RtlCaptureContext(PCONTEXT ContextRecord);

/* Per-CPU virtualization state, kept alive for the lifetime of that CPU's VMX session. */
typedef struct _VCPU {
    PVOID   VmxonRegion;
    PVOID   VmcsRegion;
    PVOID   MsrBitmap;
    PVOID   HostStack;
    PVOID   XsaveAllocation;
    PVOID   XsaveArea;
    ULONG64 XsaveMask;
    ULONG64 OriginalCr0;
    ULONG64 OriginalCr4;
    BOOLEAN Active;
} VCPU, *PVCPU;

#define MAX_VCPUS 64
static VCPU g_Vcpu[MAX_VCPUS];
static LONG g_ActiveCount;
static LONG g_VirtualizedCpuIndex = -1; /* H1: current-CPU-only, one at a time */

/* Distinguishes the two "returns" from RtlCaptureContext in VirtualizeCurrentCpu: 0 on the first
 * (setup) pass, 1 when the guest resumes after a successful VMLAUNCH. MUST be read as a plain
 * global at a fixed (RIP-relative) address, NOT via any GPR: on the resume pass the CPU restores
 * RSP/RIP from the captured context but NOT the general-purpose registers, so any register the
 * resume-path code reads holds its VMLAUNCH-time (BuildVmcsAndLaunch-internal) value, not what the
 * source thinks. `volatile` forces the store-before-launch and the load-after to real memory. A
 * single global is safe because H1 serializes START (atomic claim + remove-lock) — only one
 * VirtualizeCurrentCpu is ever in flight. This closes a confirmed miscompile (the compiler had
 * computed `vcpu->Active` via callee-saved r15+rbx, which are stale on resume). */
static volatile LONG g_ResumeAfterLaunch;

/* CR3 to load on every VM-exit (VMCS_HOST_CR3). Captured in DriverEntry, which runs in the System
 * process context, so this is the System directory base — a page-table root that never dies. Using
 * the *calling* process's CR3 instead (the reveng-rec.exe that issued START) would be a latent
 * crash: if that process exits while a CPU is still virtualized, the next VM-exit loads a freed
 * PML4 → bugcheck/triple-fault. The host only ever touches kernel memory, which is mapped in every
 * process's CR3, so the System CR3 is always a correct choice. */
static ULONG64 g_HostCr3;

/* H1 virtualizes only one CPU, so the assembly entry path can use this published per-vCPU area. */
PVOID g_ExitXsaveArea;
ULONG64 g_ExitXsaveMask;

static UNICODE_STRING g_SymLink;

/* Coordinates RevengHvUnload against in-flight RevengHvDeviceControl calls (same pattern already
 * proven in reveng-pcidrv.c's PnP remove handling). Without this, `sc stop` racing an in-flight
 * START could delete the device/unmap the driver image while a CPU is still executing (or about
 * to execute) inside it as a VMX guest — a genuine use-after-free-of-code, worse than the "clean
 * crash" this project's boot-safety contract accepts. Found via independent audit. */
static IO_REMOVE_LOCK g_RemoveLock;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD RevengHvUnload;
DRIVER_DISPATCH RevengHvCreateClose;
DRIVER_DISPATCH RevengHvDeviceControl;

/* ASM (reveng-hv-asm.asm) */
UCHAR AsmVmxLaunch(void);
VOID AsmVmExitHandler(void);
VOID AsmRestoreContextAndResume(PGUEST_REGISTERS regs, ULONG64 guestRsp, ULONG64 guestRip,
                                ULONG64 guestRflags);
VOID AsmVmCallDevirtualize(void);
VOID AsmRestoreGuestXstate(void);
USHORT AsmReadTr(void);
USHORT AsmReadLdtr(void);
VOID AsmReadGdtr(PSEUDO_DESC *out);
VOID AsmReadIdtr(PSEUDO_DESC *out);

static void FillProbe(REVENG_HV_PROBE *p)
{
    int regs[4] = {0, 0, 0, 0};
    ULONG64 fc;

    RtlZeroMemory(p, sizeof(*p));

    __cpuid(regs, 1);
    p->vmx_cpuid = (regs[2] >> 5) & 1;   /* ECX bit 5  = VMX            */
    p->hv_present = (ULONG)(regs[2] >> 31) & 1; /* ECX bit 31 = hypervisor present */

    p->logical_cpus = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    /* The VMX capability MSRs are not safe to read on a CPU that does not advertise VMX. */
    if (!p->vmx_cpuid) {
        return;
    }

    fc = __readmsr(MSR_IA32_FEATURE_CONTROL);
    p->feature_control = fc;
    p->feature_locked = (UCHAR)(fc & 1);
    p->vmxon_allowed = (UCHAR)((fc >> 2) & 1); /* VMXON outside SMX */

    p->vmx_basic = __readmsr(MSR_IA32_VMX_BASIC);
    /* EPT/VPID cap MSR only exists if secondary controls + EPT are advertised; read guarded. */
    __try {
        p->vmx_ept_vpid = __readmsr(MSR_IA32_VMX_EPT_VPID);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        p->vmx_ept_vpid = 0;
    }
}

/* Do not attempt VMXON unless bare-metal VMX is explicitly available on this CPU. */
static NTSTATUS CheckVmxPreconditions(void)
{
    int regs[4] = { 0, 0, 0, 0 };
    ULONG64 featureControl;

    __cpuid(regs, 1);
    if (!(regs[2] & (1 << 5)) || (regs[2] & (1u << 31))) {
        return STATUS_NOT_SUPPORTED;
    }
    featureControl = __readmsr(MSR_IA32_FEATURE_CONTROL);
    if (!(featureControl & 1) || !(featureControl & (1ull << 2))) {
        return STATUS_NOT_SUPPORTED;
    }
    return STATUS_SUCCESS;
}

/* The VMXON and VMCS regions must meet the implementation-specific BASIC constraints. */
static NTSTATUS CheckVmxRegionRequirements(void)
{
    ULONG64 basic = __readmsr(MSR_IA32_VMX_BASIC);
    ULONG regionSize = (ULONG)((basic >> 32) & 0x1FFF);
    ULONG memoryType = (ULONG)((basic >> 50) & 0xF);

    if (regionSize == 0 || regionSize > PAGE_SIZE || memoryType != 6 /* write-back */) {
        return STATUS_NOT_SUPPORTED;
    }
    return STATUS_SUCCESS;
}

static BOOLEAN IsVmxRegionPhysicalAddressValid(PHYSICAL_ADDRESS pa)
{
    /* IA32_VMX_BASIC[48]: 1 => VMXON/VMCS physical addresses are limited to 32 bits (< 4GB);
     * 0 => no such limit (and it is ALWAYS 0 on Intel 64 CPUs). So the region is valid if there
     * is no 32-bit restriction, OR the address already fits in 32 bits. (The `!` was missing —
     * the old form wrongly rejected any >4GB allocation on every Intel 64 part, which is what made
     * START fail with STATUS_NOT_SUPPORTED before VMLAUNCH.) */
    ULONG64 basic = __readmsr(MSR_IA32_VMX_BASIC);
    return !(basic & (1ull << 48)) || ((ULONG64)pa.QuadPart < 0x100000000ull);
}

/* Enter then immediately leave VMX operation on the *current* CPU (must already be affinitized
 * here). Returns 0 on success; on failure returns the VMXON status byte (1/2) or 0xFF for an
 * allocation failure, and sets *stage (1=alloc, 2=vmxon). Restores CR0/CR4 either way. */
static UCHAR VmxOnOffHere(UCHAR *stage)
{
    PHYSICAL_ADDRESS maxAddr, pa;
    PVOID region;
    ULONG64 rev, cr0, cr4, cr0orig, cr4orig;
    unsigned __int64 paval;
    UCHAR r;

    *stage = 1;
    if (!NT_SUCCESS(CheckVmxPreconditions())) {
        *stage = 2;
        return 0xFE;
    }
    if (!NT_SUCCESS(CheckVmxRegionRequirements())) {
        *stage = 1;
        return 0xFD;
    }
    maxAddr.QuadPart = ~0ULL;
    region = MmAllocateContiguousMemory(PAGE_SIZE, maxAddr);
    if (region == NULL) {
        return 0xFF;
    }
    RtlZeroMemory(region, PAGE_SIZE);
    rev = __readmsr(MSR_IA32_VMX_BASIC) & 0x7FFFFFFF;   /* VMCS revision id */
    *(volatile ULONG *)region = (ULONG)rev;
    pa = MmGetPhysicalAddress(region);
    if (!IsVmxRegionPhysicalAddressValid(pa)) {
        MmFreeContiguousMemory(region);
        return 0xFD;
    }

    /* VMXON requires CR0/CR4 to satisfy the VMX fixed bits (this also sets CR4.VMXE). */
    cr0orig = __readcr0();
    cr4orig = __readcr4();
    cr0 = (cr0orig | __readmsr(MSR_IA32_VMX_CR0_FIXED0)) & __readmsr(MSR_IA32_VMX_CR0_FIXED1);
    cr4 = (cr4orig | __readmsr(MSR_IA32_VMX_CR4_FIXED0)) & __readmsr(MSR_IA32_VMX_CR4_FIXED1);
    __writecr0(cr0);
    __writecr4(cr4);

    *stage = 2;
    paval = (unsigned __int64)pa.QuadPart;
    r = __vmx_on(&paval);
    if (r == 0) {
        __vmx_off(); /* leave VMX root immediately — this is only a reach test */
    }

    __writecr0(cr0orig);
    __writecr4(cr4orig);
    MmFreeContiguousMemory(region);
    return r;
}

/* VMXON+VMXOFF on every logical CPU, one at a time (thread pinned via group affinity). Skips
 * whichever CPU an active hyperjack currently owns (if any): that CPU is already in VMX
 * non-root, and executing VMXON there would unconditionally trap into VmExitDispatcher (like
 * VMCALL) and get silently devirtualized via the catch-all safety net — not a crash, but it would
 * yank the rug out from under an in-progress START behind its back. Cheaper to just not do that. */
static void DoVmxTest(REVENG_HV_VMXTEST *out)
{
    ULONG n = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    ULONG i;
    LONG activeIdx = g_VirtualizedCpuIndex;

    RtlZeroMemory(out, sizeof(*out));
    out->first_fail_cpu = -1;

    for (i = 0; i < n; i++) {
        PROCESSOR_NUMBER pn;
        GROUP_AFFINITY aff, old;
        UCHAR stage = 0, r;

        if (activeIdx >= 0 && i == (ULONG)activeIdx) {
            continue; /* leave the actively-hyperjacked CPU alone */
        }
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(i, &pn))) {
            continue;
        }
        RtlZeroMemory(&aff, sizeof(aff));
        aff.Group = pn.Group;
        aff.Mask = (KAFFINITY)1 << pn.Number;
        KeSetSystemGroupAffinityThread(&aff, &old);
        r = VmxOnOffHere(&stage);
        KeRevertToUserGroupAffinityThread(&old);

        out->cpus_tested++;
        if (r == 0) {
            out->cpus_ok++;
        } else if (out->first_fail_cpu < 0) {
            out->first_fail_cpu = (int)i;
            out->first_fail_stage = stage;
            out->first_fail_code = r;
        }
    }
}

/* Diagnostics without a live kernel debugger — see REVENG_HV_DIAG / IOCTL_REVENG_HV_DIAG. */
#define DEVIRT_REASON_NONE      0
#define DEVIRT_REASON_VMCALL    1
#define DEVIRT_REASON_UD        2
#define DEVIRT_REASON_UNKNOWN   3
#define DEVIRT_REASON_LAUNCH_FAILED   4
#define DEVIRT_REASON_VMRESUME_FAILED 5
static REVENG_HV_DIAG g_Diag;

static ULONG AdjustControls(ULONG64 capMsr, ULONG desired)
{
    ULONG allowed0 = (ULONG)(capMsr & 0xFFFFFFFF);
    ULONG allowed1 = (ULONG)(capMsr >> 32);
    return (desired | allowed0) & allowed1;
}

/* IA32_VMX_TRUE_* MSRs are only architecturally available when BASIC[55] is set. */
static ULONG64 ReadVmxControlMsr(ULONG legacyMsr, ULONG trueMsr)
{
    if (__readmsr(MSR_IA32_VMX_BASIC) & (1ull << 55)) {
        return __readmsr(trueMsr);
    }
    return __readmsr(legacyMsr);
}

/* Decode a GDT entry for `selector` into base/limit/VMX-format access rights. Handles the 16-byte
 * system descriptors (TR) used in long mode and reports null selectors as "unusable". */
static void GetSegmentInfo(PUCHAR gdtBase, USHORT selector, SEG_INFO *info)
{
    ULONG64 entry, entry2;
    UCHAR access, flags;
    ULONG limit;
    ULONG64 base;

    info->Selector = selector;
    if ((selector & 0xFFF8) == 0) {
        info->Limit = 0;
        info->Base = 0;
        info->AccessRights = 0x10000; /* unusable */
        return;
    }

    entry = *(PULONG64)(gdtBase + (selector & 0xFFF8));
    limit = (ULONG)(entry & 0xFFFF) | (ULONG)((entry >> 48) & 0xF) << 16;
    base = ((entry >> 16) & 0xFFFFFF) | (((entry >> 56) & 0xFF) << 24);
    access = (UCHAR)((entry >> 40) & 0xFF);
    flags = (UCHAR)((entry >> 52) & 0xF); /* AVL, L, D/B, G */

    if (!(access & 0x10)) { /* S=0: system descriptor (e.g. TSS) — 16 bytes, extended base */
        entry2 = *(PULONG64)(gdtBase + (selector & 0xFFF8) + 8);
        base |= (entry2 & 0xFFFFFFFF) << 32;
    }
    if (flags & 0x8) { /* G=1: limit is in 4KB units */
        limit = (limit << 12) | 0xFFF;
    }

    info->Limit = limit;
    info->Base = base;
    info->AccessRights = (ULONG)access
        | (((ULONG)flags & 0x1) << 12)        /* AVL */
        | ((((ULONG)flags >> 1) & 1) << 13)   /* L   */
        | ((((ULONG)flags >> 2) & 1) << 14)   /* D/B */
        | ((((ULONG)flags >> 3) & 1) << 15);  /* G   */
}

static void FreeVcpu(PVCPU vcpu)
{
    if (vcpu->VmxonRegion) {
        MmFreeContiguousMemory(vcpu->VmxonRegion);
        vcpu->VmxonRegion = NULL;
    }
    if (vcpu->VmcsRegion) {
        MmFreeContiguousMemory(vcpu->VmcsRegion);
        vcpu->VmcsRegion = NULL;
    }
    if (vcpu->MsrBitmap) {
        MmFreeContiguousMemory(vcpu->MsrBitmap);
        vcpu->MsrBitmap = NULL;
    }
    if (vcpu->HostStack) {
        ExFreePoolWithTag(vcpu->HostStack, REVENG_HV_POOL_TAG);
        vcpu->HostStack = NULL;
    }
    if (vcpu->XsaveAllocation) {
        ExFreePoolWithTag(vcpu->XsaveAllocation, REVENG_HV_POOL_TAG);
        vcpu->XsaveAllocation = NULL;
        vcpu->XsaveArea = NULL;
        vcpu->XsaveMask = 0;
    }
    vcpu->Active = FALSE;
}

static NTSTATUS AllocateXsaveArea(PVCPU vcpu)
{
    int regs[4] = { 0, 0, 0, 0 };
    ULONG64 xcr0;
    ULONG size;
    ULONG_PTR aligned;

    __cpuid(regs, 0);
    if ((ULONG)regs[0] < 0xD) {
        return STATUS_NOT_SUPPORTED;
    }
    __cpuid(regs, 1);
    if (!(regs[2] & (1 << 26)) || !(regs[2] & (1 << 27))) { /* XSAVE + OSXSAVE */
        return STATUS_NOT_SUPPORTED;
    }
    xcr0 = _xgetbv(0);
    if (!(xcr0 & 1)) { /* x87 state is mandatory for XSAVE/XRSTOR. */
        return STATUS_NOT_SUPPORTED;
    }
    __cpuidex(regs, 0xD, 0);
    size = (ULONG)regs[1]; /* size for the XCR0-enabled feature set */
    if (size == 0 || size > 0x10000) {
        return STATUS_NOT_SUPPORTED;
    }
    vcpu->XsaveAllocation = ExAllocatePool2(POOL_FLAG_NON_PAGED, size + 63,
                                             REVENG_HV_POOL_TAG);
    if (vcpu->XsaveAllocation == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    aligned = ((ULONG_PTR)vcpu->XsaveAllocation + 63) & ~(ULONG_PTR)63;
    vcpu->XsaveArea = (PVOID)aligned;
    vcpu->XsaveMask = xcr0;
    RtlZeroMemory(vcpu->XsaveArea, size);
    return STATUS_SUCCESS;
}

/* vcpu can be NULL from Devirtualize()'s defensive `idx >= MAX_VCPUS` case — unreachable on real
 * hardware here (16 cores vs MAX_VCPUS=64) but a real latent NULL-deref for that theoretical case. */
static void RestoreControlRegisters(PVCPU vcpu)
{
    if (vcpu == NULL) {
        return;
    }
    __writecr4(vcpu->OriginalCr4);
    __writecr0(vcpu->OriginalCr0);
}

/* Accumulates a sticky failure flag across the ~60 individual VMWRITEs in BuildVmcsAndLaunch, so
 * setup can do ONE check right before VMLAUNCH instead of branching after every field write. A
 * VMWRITE can only fail here if there's no current VMCS (never true in this linear flow) or the
 * field encoding is unsupported (now externally verified — see the C_ASSERTs above) — so this is
 * defense-in-depth against the class of bug, not an expected runtime path. */
static void VmWriteChecked(BOOLEAN *failed, ULONG64 field, ULONG64 value)
{
    if (__vmx_vmwrite(field, value) != 0) {
        *failed = TRUE;
    }
}

/* Build a VMCS that mirrors the CURRENT running thread's exact state (host=guest at launch time
 * — this is what makes it a "hyperjack": nothing about the running OS changes) and VMLAUNCH.
 * On success this function's caller resumes execution transparently as a VMX guest — see
 * VirtualizeCurrentCpu(). On failure, all resources are released and an error is returned.
 *
 * Every __vmx_vmwrite below is redirected (via the macro just below) to VmWriteChecked, which
 * accumulates failures into `vmWriteFailed` instead of silently discarding the status code. */
#define __vmx_vmwrite(field, value) VmWriteChecked(&vmWriteFailed, (field), (value))
static NTSTATUS BuildVmcsAndLaunch(PVCPU vcpu, PCONTEXT ctx)
{
    PHYSICAL_ADDRESS maxAddr;
    unsigned __int64 vmxonPa, vmcsPa, msrBitmapPa;
    ULONG64 rev, cr0, cr4, hostCr0;
    PSEUDO_DESC gdtr, idtr;
    SEG_INFO es, cs, ss, ds, fs, gs, tr, ldtr;
    ULONG pin, proc, exitCtl, entryCtl;
    UCHAR launchResult;
    BOOLEAN vmWriteFailed = FALSE;

    if (!NT_SUCCESS(CheckVmxRegionRequirements())) {
        return STATUS_NOT_SUPPORTED;
    }
    maxAddr.QuadPart = ~0ULL;
    vcpu->VmxonRegion = MmAllocateContiguousMemory(PAGE_SIZE, maxAddr);
    vcpu->VmcsRegion = MmAllocateContiguousMemory(PAGE_SIZE, maxAddr);
    vcpu->MsrBitmap = MmAllocateContiguousMemory(PAGE_SIZE, maxAddr);
    vcpu->HostStack = ExAllocatePool2(POOL_FLAG_NON_PAGED, HOST_STACK_SIZE, REVENG_HV_POOL_TAG);
    if (!vcpu->VmxonRegion || !vcpu->VmcsRegion || !vcpu->MsrBitmap || !vcpu->HostStack) {
        FreeVcpu(vcpu);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    {
        NTSTATUS xsaveStatus = AllocateXsaveArea(vcpu);
        if (!NT_SUCCESS(xsaveStatus)) {
            FreeVcpu(vcpu);
            return xsaveStatus;
        }
    }
    RtlZeroMemory(vcpu->VmxonRegion, PAGE_SIZE);
    RtlZeroMemory(vcpu->VmcsRegion, PAGE_SIZE);
    RtlZeroMemory(vcpu->MsrBitmap, PAGE_SIZE);

    rev = __readmsr(MSR_IA32_VMX_BASIC) & 0x7FFFFFFF;
    *(volatile ULONG *)vcpu->VmxonRegion = (ULONG)rev;
    *(volatile ULONG *)vcpu->VmcsRegion = (ULONG)rev;
    vmxonPa = (unsigned __int64)MmGetPhysicalAddress(vcpu->VmxonRegion).QuadPart;
    vmcsPa = (unsigned __int64)MmGetPhysicalAddress(vcpu->VmcsRegion).QuadPart;
    msrBitmapPa = (unsigned __int64)MmGetPhysicalAddress(vcpu->MsrBitmap).QuadPart;
    if (!IsVmxRegionPhysicalAddressValid(MmGetPhysicalAddress(vcpu->VmxonRegion)) ||
        !IsVmxRegionPhysicalAddressValid(MmGetPhysicalAddress(vcpu->VmcsRegion))) {
        FreeVcpu(vcpu);
        return STATUS_NOT_SUPPORTED;
    }

    vcpu->OriginalCr0 = __readcr0();
    vcpu->OriginalCr4 = __readcr4();
    cr0 = (vcpu->OriginalCr0 | __readmsr(MSR_IA32_VMX_CR0_FIXED0)) & __readmsr(MSR_IA32_VMX_CR0_FIXED1);
    cr4 = (vcpu->OriginalCr4 | __readmsr(MSR_IA32_VMX_CR4_FIXED0)) & __readmsr(MSR_IA32_VMX_CR4_FIXED1);
    hostCr0 = cr0 & ~CR0_TS; /* XSAVE/XRSTOR in the root-mode exit stub must not raise #NM. */
    if ((hostCr0 & __readmsr(MSR_IA32_VMX_CR0_FIXED0)) != __readmsr(MSR_IA32_VMX_CR0_FIXED0) ||
        (hostCr0 & ~__readmsr(MSR_IA32_VMX_CR0_FIXED1)) != 0) {
        FreeVcpu(vcpu);
        return STATUS_NOT_SUPPORTED;
    }
    __writecr0(cr0);
    __writecr4(cr4);

    if (__vmx_on(&vmxonPa) != 0) {
        RestoreControlRegisters(vcpu);
        FreeVcpu(vcpu);
        return STATUS_UNSUCCESSFUL;
    }
    if (__vmx_vmclear(&vmcsPa) != 0 || __vmx_vmptrld(&vmcsPa) != 0) {
        __vmx_off();
        RestoreControlRegisters(vcpu);
        FreeVcpu(vcpu);
        return STATUS_UNSUCCESSFUL;
    }

    AsmReadGdtr(&gdtr);
    AsmReadIdtr(&idtr);
    GetSegmentInfo((PUCHAR)gdtr.Base, ctx->SegEs, &es);
    GetSegmentInfo((PUCHAR)gdtr.Base, ctx->SegCs, &cs);
    GetSegmentInfo((PUCHAR)gdtr.Base, ctx->SegSs, &ss);
    GetSegmentInfo((PUCHAR)gdtr.Base, ctx->SegDs, &ds);
    GetSegmentInfo((PUCHAR)gdtr.Base, ctx->SegFs, &fs);
    GetSegmentInfo((PUCHAR)gdtr.Base, ctx->SegGs, &gs);
    GetSegmentInfo((PUCHAR)gdtr.Base, AsmReadTr(), &tr);
    GetSegmentInfo((PUCHAR)gdtr.Base, AsmReadLdtr(), &ldtr);

    /* --- Host state: where a VM-exit lands us --- */
    __vmx_vmwrite(VMCS_HOST_CR0, hostCr0);
    /* System CR3 (never-dying), NOT the START-caller's — see g_HostCr3. */
    __vmx_vmwrite(VMCS_HOST_CR3, g_HostCr3);
    __vmx_vmwrite(VMCS_HOST_CR4, __readcr4());
    __vmx_vmwrite(VMCS_HOST_ES_SELECTOR, ctx->SegEs & 0xF8);
    __vmx_vmwrite(VMCS_HOST_CS_SELECTOR, ctx->SegCs & 0xF8);
    __vmx_vmwrite(VMCS_HOST_SS_SELECTOR, ctx->SegSs & 0xF8);
    __vmx_vmwrite(VMCS_HOST_DS_SELECTOR, ctx->SegDs & 0xF8);
    __vmx_vmwrite(VMCS_HOST_FS_SELECTOR, ctx->SegFs & 0xF8);
    __vmx_vmwrite(VMCS_HOST_GS_SELECTOR, ctx->SegGs & 0xF8);
    __vmx_vmwrite(VMCS_HOST_TR_SELECTOR, tr.Selector & 0xF8);
    __vmx_vmwrite(VMCS_HOST_FS_BASE, __readmsr(MSR_IA32_FS_BASE));
    __vmx_vmwrite(VMCS_HOST_GS_BASE, __readmsr(MSR_IA32_GS_BASE));
    __vmx_vmwrite(VMCS_HOST_TR_BASE, tr.Base);
    __vmx_vmwrite(VMCS_HOST_GDTR_BASE, gdtr.Base);
    __vmx_vmwrite(VMCS_HOST_IDTR_BASE, idtr.Base);
    __vmx_vmwrite(VMCS_HOST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_HOST_IA32_EFER, __readmsr(MSR_IA32_EFER));
    __vmx_vmwrite(VMCS_HOST_RSP, (ULONG64)vcpu->HostStack + HOST_STACK_SIZE - 32);
    __vmx_vmwrite(VMCS_HOST_RIP, (ULONG64)AsmVmExitHandler);

    /* --- Guest state: an exact mirror of the currently running thread --- */
    __vmx_vmwrite(VMCS_GUEST_CR0, __readcr0());
    __vmx_vmwrite(VMCS_GUEST_CR3, __readcr3());
    __vmx_vmwrite(VMCS_GUEST_CR4, __readcr4());
    __vmx_vmwrite(VMCS_CR0_GUEST_HOST_MASK, 0);
    __vmx_vmwrite(VMCS_CR4_GUEST_HOST_MASK, 0);
    __vmx_vmwrite(VMCS_CR0_READ_SHADOW, __readcr0());
    __vmx_vmwrite(VMCS_CR4_READ_SHADOW, __readcr4());
    __vmx_vmwrite(VMCS_GUEST_DR7, __readdr(7));
    __vmx_vmwrite(VMCS_GUEST_RSP, ctx->Rsp);
    __vmx_vmwrite(VMCS_GUEST_RIP, ctx->Rip);
    __vmx_vmwrite(VMCS_GUEST_RFLAGS, ctx->EFlags);
    __vmx_vmwrite(VMCS_GUEST_ES_SELECTOR, ctx->SegEs);
    __vmx_vmwrite(VMCS_GUEST_CS_SELECTOR, ctx->SegCs);
    __vmx_vmwrite(VMCS_GUEST_SS_SELECTOR, ctx->SegSs);
    __vmx_vmwrite(VMCS_GUEST_DS_SELECTOR, ctx->SegDs);
    __vmx_vmwrite(VMCS_GUEST_FS_SELECTOR, ctx->SegFs);
    __vmx_vmwrite(VMCS_GUEST_GS_SELECTOR, ctx->SegGs);
    __vmx_vmwrite(VMCS_GUEST_LDTR_SELECTOR, ldtr.Selector);
    __vmx_vmwrite(VMCS_GUEST_TR_SELECTOR, tr.Selector);
    __vmx_vmwrite(VMCS_GUEST_ES_LIMIT, es.Limit);
    __vmx_vmwrite(VMCS_GUEST_CS_LIMIT, cs.Limit);
    __vmx_vmwrite(VMCS_GUEST_SS_LIMIT, ss.Limit);
    __vmx_vmwrite(VMCS_GUEST_DS_LIMIT, ds.Limit);
    __vmx_vmwrite(VMCS_GUEST_FS_LIMIT, fs.Limit);
    __vmx_vmwrite(VMCS_GUEST_GS_LIMIT, gs.Limit);
    __vmx_vmwrite(VMCS_GUEST_LDTR_LIMIT, ldtr.Limit);
    __vmx_vmwrite(VMCS_GUEST_TR_LIMIT, tr.Limit);
    __vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, gdtr.Limit);
    __vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, idtr.Limit);
    __vmx_vmwrite(VMCS_GUEST_ES_AR, es.AccessRights);
    __vmx_vmwrite(VMCS_GUEST_CS_AR, cs.AccessRights);
    __vmx_vmwrite(VMCS_GUEST_SS_AR, ss.AccessRights);
    __vmx_vmwrite(VMCS_GUEST_DS_AR, ds.AccessRights);
    __vmx_vmwrite(VMCS_GUEST_FS_AR, fs.AccessRights);
    __vmx_vmwrite(VMCS_GUEST_GS_AR, gs.AccessRights);
    /* Windows doesn't use the LDT; force unusable regardless of what the (likely null) descriptor says. */
    __vmx_vmwrite(VMCS_GUEST_LDTR_AR, ldtr.AccessRights | 0x10000);
    __vmx_vmwrite(VMCS_GUEST_TR_AR, tr.AccessRights);
    __vmx_vmwrite(VMCS_GUEST_ES_BASE, es.Base);
    __vmx_vmwrite(VMCS_GUEST_CS_BASE, cs.Base);
    __vmx_vmwrite(VMCS_GUEST_SS_BASE, ss.Base);
    __vmx_vmwrite(VMCS_GUEST_DS_BASE, ds.Base);
    __vmx_vmwrite(VMCS_GUEST_FS_BASE, __readmsr(MSR_IA32_FS_BASE));
    __vmx_vmwrite(VMCS_GUEST_GS_BASE, __readmsr(MSR_IA32_GS_BASE));
    __vmx_vmwrite(VMCS_GUEST_LDTR_BASE, ldtr.Base);
    __vmx_vmwrite(VMCS_GUEST_TR_BASE, tr.Base);
    __vmx_vmwrite(VMCS_GUEST_GDTR_BASE, gdtr.Base);
    __vmx_vmwrite(VMCS_GUEST_IDTR_BASE, idtr.Base);
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_CS, (ULONG)__readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_GUEST_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL));
    __vmx_vmwrite(VMCS_GUEST_IA32_EFER, __readmsr(MSR_IA32_EFER));
    __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY, 0);
    __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0);
    __vmx_vmwrite(VMCS_GUEST_VMCS_LINK_PTR, 0xFFFFFFFFFFFFFFFFull);

    /* --- Controls: minimal — no EPT, no interrupt exiting yet (H2/H4), MSR bitmap all-clear
     * so RDMSR/WRMSR don't exit either (avoids an exit storm with our tiny handler). Secondary
     * controls activated ONLY for the instructions that #UD without an explicit enable bit
     * (RDTSCP/RDPID, INVPCID, XSAVES/XRSTORS — confirmed by the RDTSCP crash + high-confidence
     * documentation); #UD is also trapped as a catch-all for anything else in that class we
     * haven't identified (see VmExitDispatcher). --- */
    pin = AdjustControls(ReadVmxControlMsr(MSR_IA32_VMX_PINBASED_CTLS,
                                           MSR_IA32_VMX_TRUE_PINBASED_CTLS), PIN_BASED_NONE);
    proc = AdjustControls(ReadVmxControlMsr(MSR_IA32_VMX_PROCBASED_CTLS,
                                            MSR_IA32_VMX_TRUE_PROCBASED_CTLS),
                          PROC_BASED_USE_MSR_BITMAPS | PROC_BASED_ACTIVATE_SECONDARY_CTLS);
    exitCtl = AdjustControls(ReadVmxControlMsr(MSR_IA32_VMX_EXIT_CTLS,
                                                MSR_IA32_VMX_TRUE_EXIT_CTLS),
                             EXIT_CTL_HOST_ADDR_SPACE_SIZE);
    entryCtl = AdjustControls(ReadVmxControlMsr(MSR_IA32_VMX_ENTRY_CTLS,
                                                 MSR_IA32_VMX_TRUE_ENTRY_CTLS),
                              ENTRY_CTL_IA32E_MODE_GUEST);
    __vmx_vmwrite(VMCS_PIN_BASED_CTLS, pin);
    __vmx_vmwrite(VMCS_PROC_BASED_CTLS, proc);
    __vmx_vmwrite(VMCS_EXIT_CTLS, exitCtl);
    __vmx_vmwrite(VMCS_ENTRY_CTLS, entryCtl);
    {
        ULONG secondary = AdjustControls(
            __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2),
            SECONDARY_ENABLE_RDTSCP | SECONDARY_ENABLE_INVPCID);
        __vmx_vmwrite(VMCS_SECONDARY_PROC_BASED_CTLS, secondary);

        /* AdjustControls silently masks off anything the hardware doesn't allow — verify what we
         * ASKED for actually took effect before launching into a configuration that would just
         * reproduce the RDTSCP crash. Recorded either way so IOCTL_REVENG_HV_DIAG can show it. */
        g_Diag.secondary_ctls_requested_ok = (proc & PROC_BASED_ACTIVATE_SECONDARY_CTLS) ? 1 : 0;
        g_Diag.rdtscp_enabled = (secondary & SECONDARY_ENABLE_RDTSCP) ? 1 : 0;
        g_Diag.invpcid_enabled = (secondary & SECONDARY_ENABLE_INVPCID) ? 1 : 0;
        g_Diag.xsaves_enabled = 0; /* XSAVES needs IA32_XSS-aware save/restore; not safe in H1. */
        if (!g_Diag.secondary_ctls_requested_ok || !g_Diag.rdtscp_enabled) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                      "reveng-hv: secondary-ctls=%u rdtscp=%u not actually enabled by hardware — "
                      "refusing to VMLAUNCH (would reproduce the RDTSCP #UD crash)\n",
                      g_Diag.secondary_ctls_requested_ok, g_Diag.rdtscp_enabled);
            __vmx_off();
            RestoreControlRegisters(vcpu);
            FreeVcpu(vcpu);
            return STATUS_NOT_SUPPORTED;
        }
    }
    __vmx_vmwrite(VMCS_EXCEPTION_BITMAP, 1u << VECTOR_UD);
    __vmx_vmwrite(VMCS_CR3_TARGET_COUNT, 0);
    __vmx_vmwrite(VMCS_EXIT_MSR_STORE_COUNT, 0);
    __vmx_vmwrite(VMCS_EXIT_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VMCS_ENTRY_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VMCS_ENTRY_INTR_INFO, 0);
    __vmx_vmwrite(VMCS_MSR_BITMAP, msrBitmapPa);

    if (vmWriteFailed) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                  "reveng-hv: one or more VMWRITEs failed during setup — refusing to VMLAUNCH "
                  "into a possibly-incomplete VMCS\n");
        __vmx_off();
        RestoreControlRegisters(vcpu);
        FreeVcpu(vcpu);
        return STATUS_UNSUCCESSFUL;
    }

    vcpu->Active = TRUE;
    g_ExitXsaveArea = vcpu->XsaveArea;
    g_ExitXsaveMask = vcpu->XsaveMask;
    /* Set LAST, immediately before the launch: on a successful VMLAUNCH the guest resumes at the
     * RtlCaptureContext call site and reads this to know it's the resume pass (see its comment). */
    g_ResumeAfterLaunch = 1;
    launchResult = AsmVmxLaunch();

    /* Only reached if VMLAUNCH FAILED — success jumps to guest RIP (back into
     * VirtualizeCurrentCpu's RtlCaptureContext call site), never returning here. */
    g_ResumeAfterLaunch = 0; /* launch didn't take; keep the first-pass semantics consistent */
    vcpu->Active = FALSE;
    g_ExitXsaveArea = NULL;
    g_ExitXsaveMask = 0;
    {
        ULONG64 errCode = 0;
        __vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &errCode);
        g_Diag.last_devirt_reason = DEVIRT_REASON_LAUNCH_FAILED;
        g_Diag.launch_error = errCode;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                  "reveng-hv: VMLAUNCH failed, result=%u error=%llu\n", launchResult, errCode);
    }
    __vmx_off();
    RestoreControlRegisters(vcpu);
    FreeVcpu(vcpu);
    return STATUS_UNSUCCESSFUL;
}
#undef __vmx_vmwrite /* restore the real intrinsic for VmExitDispatcher's single vmwrite call */

/* Entry point for virtualizing the CURRENT cpu. On the first pass this builds the VMCS and
 * launches; if VMLAUNCH succeeds, execution "returns" a SECOND time — via the guest RIP set to
 * right after RtlCaptureContext — at which point vcpu->Active is already TRUE and we just report
 * success. This is the whole hyperjack: no new context is created, the running thread continues. */
static NTSTATUS VirtualizeCurrentCpu(PVCPU vcpu)
{
    CONTEXT ctx;
    g_ResumeAfterLaunch = 0;         /* first pass */
    RtlCaptureContext(&ctx);
    /* Read ONLY this fixed-address volatile global here — see g_ResumeAfterLaunch's comment for
     * why the previous `vcpu->Active` (address built from callee-saved GPRs) miscompiled. */
    if (g_ResumeAfterLaunch != 0) {
        return STATUS_SUCCESS; /* the guest resumed here via a successful VMLAUNCH */
    }
    return BuildVmcsAndLaunch(vcpu, &ctx);
}

static ULONG CurrentCpuIndex(void)
{
    PROCESSOR_NUMBER pn;
    KeGetCurrentProcessorNumberEx(&pn);
    return KeGetProcessorIndexFromNumber(&pn);
}

/* Shared devirtualize path: VMXOFF this CPU then jump straight to `resumeRip` on the guest's own
 * stack with RFLAGS/GPRs restored — used by the VMCALL hypercall, the #UD safety net, and the
 * catch-all for any other unexpected exit. Never returns. `resumeRip` is the exact guest RIP to
 * resume at: callers pass guestRip+instrLen to skip a handled instruction (VMCALL), or the
 * unmodified guestRip to re-present the same instruction to bare-metal fault handling (#UD /
 * unknown exits) — the latter is what makes the #UD trap "get out of the way" correctly instead
 * of silently swallowing a genuine fault. */
static VOID Devirtualize(PVCPU vcpu, PGUEST_REGISTERS regs, ULONG64 resumeRip, UCHAR reason,
                         ULONG rawExitReason)
{
    ULONG64 guestRsp = 0, rflags = 0;
    __vmx_vmread(VMCS_GUEST_RSP, &guestRsp);
    __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags);

    /* Record BEFORE VMXOFF so this is visible via IOCTL_REVENG_HV_DIAG even without a live
     * kernel debugger attached — this is what makes a future gap diagnosable without another
     * crash-dump forensics exercise. */
    g_Diag.last_devirt_reason = reason;
    g_Diag.last_exit_reason = rawExitReason;
    g_Diag.last_devirt_rip = resumeRip;

    if (vcpu != NULL) {
        vcpu->Active = FALSE;
    }
    AsmRestoreGuestXstate();
    __vmx_off();
    RestoreControlRegisters(vcpu);
    g_ExitXsaveArea = NULL;
    g_ExitXsaveMask = 0;
    AsmRestoreContextAndResume(regs, guestRsp, resumeRip, rflags); /* never returns */
}

/* Called from AsmVmExitHandler's VMRESUME-failure fallthrough (see reveng-hv-asm.asm) instead of
 * the old unconditional bugcheck. A failed VMRESUME (VMfailValid/VMfailInvalid) does NOT
 * invalidate the current VMCS — guest RIP/RSP/RFLAGS are still readable exactly as if the
 * resume attempt never happened — and critically, VM-entry never touches GPRs whether it
 * succeeds or fails, so the GPRs the caller just re-pushed into `regs` already hold exactly what
 * the guest should resume with. This lets us reuse the same, already-audited Devirtualize() path
 * used by every other exit reason instead of writing new recovery logic: read the diagnostic
 * VM_INSTRUCTION_ERROR, then get the guest safely back to bare metal at the exact instruction
 * that would have resumed. */
VOID VmResumeFailed(PGUEST_REGISTERS regs)
{
    ULONG64 guestRip = 0, errCode = 0;
    ULONG idx = CurrentCpuIndex();
    PVCPU vcpu = (idx < MAX_VCPUS) ? &g_Vcpu[idx] : NULL;

    __vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &errCode);
    __vmx_vmread(VMCS_GUEST_RIP, &guestRip);
    g_Diag.launch_error = errCode; /* reused field: VM_INSTRUCTION_ERROR from the failed resume */
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
              "reveng-hv: VMRESUME failed, error=%llu at guest RIP %llx — recovering via "
              "devirtualize instead of crashing\n", errCode, guestRip);
    Devirtualize(vcpu, regs, guestRip, DEVIRT_REASON_VMRESUME_FAILED, 0);
}

/* VM-exit dispatcher, called from the AsmVmExitHandler trampoline for every VM-exit on a
 * virtualized CPU. Handles CPUID (mandatory trap; also the backdoor-signature leaf), VMCALL (our
 * devirtualize hypercall), and #UD (safety net — see Devirtualize doc comment: converts any
 * instruction we didn't know needed a secondary-control enable bit into a clean, logged,
 * recoverable devirtualize instead of a bugcheck). Anything else unexpected under this minimal
 * H1 configuration also devirtualizes rather than risk a stuck loop. */
VOID VmExitDispatcher(PGUEST_REGISTERS regs)
{
    ULONG64 exitReason = 0, guestRip = 0, instrLen = 0;
    ULONG idx = CurrentCpuIndex();
    PVCPU vcpu = (idx < MAX_VCPUS) ? &g_Vcpu[idx] : NULL;

    __vmx_vmread(VMCS_EXIT_REASON, &exitReason);
    __vmx_vmread(VMCS_GUEST_RIP, &guestRip);
    __vmx_vmread(VMCS_EXIT_INSTR_LEN, &instrLen);
    exitReason &= 0xFFFF;

    if (exitReason == VMX_EXIT_REASON_CPUID) {
        int cpuOut[4] = {0, 0, 0, 0};
        ULONG leaf = (ULONG)regs->Rax;
        ULONG sub = (ULONG)regs->Rcx;
        if (leaf == HV_BACKDOOR_LEAF) {
            regs->Rax = HV_BACKDOOR_LEAF;
            regs->Rbx = HV_BACKDOOR_SIG_EBX;
            regs->Rcx = HV_BACKDOOR_SIG_ECX;
            regs->Rdx = HV_BACKDOOR_SIG_EDX;
        } else {
            __cpuidex(cpuOut, (int)leaf, (int)sub);
            regs->Rax = (ULONG)cpuOut[0];
            regs->Rbx = (ULONG)cpuOut[1];
            regs->Rcx = (ULONG)cpuOut[2];
            regs->Rdx = (ULONG)cpuOut[3];
        }
        __vmx_vmwrite(VMCS_GUEST_RIP, guestRip + instrLen);
        return; /* AsmVmExitHandler will VMRESUME */
    }

    if (exitReason == VMX_EXIT_REASON_VMCALL && regs->Rcx == HV_DEVIRT_MAGIC && vcpu != NULL) {
        Devirtualize(vcpu, regs, guestRip + instrLen, DEVIRT_REASON_VMCALL, (ULONG)exitReason);
        return; /* unreachable at runtime — Devirtualize's asm tail jumps away; kept for clarity */
    }

    if (exitReason == VMX_EXIT_REASON_EXCEPTION_NMI) {
        ULONG64 intrInfo = 0;
        __vmx_vmread(VMCS_EXIT_INTR_INFO, &intrInfo);
        if (((intrInfo >> 31) & 1) && (intrInfo & 0xFF) == VECTOR_UD) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                      "reveng-hv: #UD trapped at guest RIP %llx — devirtualizing so bare metal "
                      "re-presents the same instruction (this RIP is what to look up next)\n",
                      guestRip);
        }
        /* Whether #UD or some other exception under this config, don't try to be clever about
         * it: devirtualize WITHOUT advancing RIP, so the exact same instruction is re-presented
         * to normal (non-virtualized) fault handling — correct for both a genuine fault and any
         * instruction we didn't know needed a secondary-control bit. */
        Devirtualize(vcpu, regs, guestRip, DEVIRT_REASON_UD, (ULONG)exitReason);
        return; /* unreachable at runtime, see above */
    }

    /* Unexpected exit reason: devirtualize rather than risk a stuck loop. */
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
              "reveng-hv: unexpected VM-exit reason=%llu at RIP %llx — devirtualizing\n",
              exitReason, guestRip);
    Devirtualize(vcpu, regs, guestRip, DEVIRT_REASON_UNKNOWN, (ULONG)exitReason);
    /* unreachable at runtime, see above */
}

/* IOCTL_REVENG_HV_START: virtualize whichever CPU this thread is currently running on (pinned
 * for the duration). H1 scope is deliberately current-CPU-only — see README §2 H1.
 *
 * g_VirtualizedCpuIndex is claimed atomically (-1 -> -2 "claiming") so two concurrent START calls
 * can't both proceed — without this, a second STOP racing a first could execute the devirtualize
 * VMCALL on a CPU the first STOP already returned to bare metal, where VMCALL is #UD with no VMX
 * layer left to catch it (a real, if currently low-probability, crash path we're closing here). */
static NTSTATUS StartHv(void)
{
    PROCESSOR_NUMBER pn;
    GROUP_AFFINITY aff, old;
    NTSTATUS status;
    ULONG idx;

    status = CheckVmxPreconditions();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (InterlockedCompareExchange(&g_VirtualizedCpuIndex, -2, -1) != -1) {
        return STATUS_DEVICE_BUSY; /* already active, or another START/STOP in progress */
    }

    KeGetCurrentProcessorNumberEx(&pn);
    idx = KeGetProcessorIndexFromNumber(&pn);
    if (idx >= MAX_VCPUS) {
        InterlockedExchange(&g_VirtualizedCpuIndex, -1); /* release the claim */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(&aff, sizeof(aff));
    aff.Group = pn.Group;
    aff.Mask = (KAFFINITY)1 << pn.Number;
    KeSetSystemGroupAffinityThread(&aff, &old);

    RtlZeroMemory(&g_Vcpu[idx], sizeof(VCPU));
    status = VirtualizeCurrentCpu(&g_Vcpu[idx]);

    KeRevertToUserGroupAffinityThread(&old);

    if (NT_SUCCESS(status)) {
        InterlockedExchange(&g_VirtualizedCpuIndex, (LONG)idx); /* publish the real index */
        InterlockedIncrement(&g_ActiveCount);
    } else {
        InterlockedExchange(&g_VirtualizedCpuIndex, -1); /* release the claim on failure */
    }
    return status;
}

/* IOCTL_REVENG_HV_STOP: devirtualize the CPU START virtualized, via a VMCALL executed while
 * pinned to that same CPU (VmExitDispatcher does the actual VMXOFF + context restore).
 *
 * Claims g_VirtualizedCpuIndex atomically (swap to -1) BEFORE touching anything, so two
 * concurrent STOP calls can't both proceed: only the one that actually reads back a valid index
 * (>=0) runs the devirtualize VMCALL; a second racing caller reads back -1 (already claimed) and
 * safely no-ops instead of issuing VMCALL on a CPU the first call already returned to bare metal
 * (which would #UD with no VMX layer left to catch it). */
static NTSTATUS StopHv(void)
{
    PROCESSOR_NUMBER pn;
    GROUP_AFFINITY aff, old;
    LONG idx = InterlockedCompareExchange(&g_VirtualizedCpuIndex, -2, -2);

    if (idx < 0) {
        return STATUS_SUCCESS; /* nothing virtualized, or another STOP already claimed it */
    }
    if (!NT_SUCCESS(KeGetProcessorNumberFromIndex((ULONG)idx, &pn))) {
        return STATUS_UNSUCCESSFUL;
    }
    if (InterlockedCompareExchange(&g_VirtualizedCpuIndex, -1, idx) != idx) {
        return STATUS_DEVICE_BUSY;
    }
    RtlZeroMemory(&aff, sizeof(aff));
    aff.Group = pn.Group;
    aff.Mask = (KAFFINITY)1 << pn.Number;
    KeSetSystemGroupAffinityThread(&aff, &old);

    if (g_Vcpu[idx].Active) {
        AsmVmCallDevirtualize();
    }

    KeRevertToUserGroupAffinityThread(&old);

    FreeVcpu(&g_Vcpu[idx]);
    InterlockedDecrement(&g_ActiveCount);
    return STATUS_SUCCESS;
}

NTSTATUS RevengHvCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS RevengHvDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    /* Held for the ENTIRE IOCTL, including the actual VMLAUNCH/VMXOFF/CPU work — not just a
     * pointer check — so RevengHvUnload's drain-and-block (IoReleaseRemoveLockAndWait) can never
     * proceed while a START/STOP/VMXTEST is genuinely in flight. Fails closed: if removal has
     * already started, this IOCTL is refused before touching any VMX state. */
    status = IoAcquireRemoveLock(&g_RemoveLock, Irp);
    if (!NT_SUCCESS(status)) {
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    switch (sp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_REVENG_HV_PROBE:
        if (sp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(REVENG_HV_PROBE)) {
            FillProbe((REVENG_HV_PROBE *)Irp->AssociatedIrp.SystemBuffer);
            info = sizeof(REVENG_HV_PROBE);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    case IOCTL_REVENG_HV_VMXTEST:
        if (sp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(REVENG_HV_VMXTEST)) {
            DoVmxTest((REVENG_HV_VMXTEST *)Irp->AssociatedIrp.SystemBuffer);
            info = sizeof(REVENG_HV_VMXTEST);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    case IOCTL_REVENG_HV_DIAG:
        if (sp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(REVENG_HV_DIAG)) {
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &g_Diag, sizeof(REVENG_HV_DIAG));
            info = sizeof(REVENG_HV_DIAG);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    case IOCTL_REVENG_HV_START:
        status = StartHv();
        break;
    case IOCTL_REVENG_HV_STOP:
        status = StopHv();
        break;
    default:
        break;
    }

    IoReleaseRemoveLock(&g_RemoveLock, Irp);
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID RevengHvUnload(PDRIVER_OBJECT DriverObject)
{
    /* Drain + block FIRST: wait for any in-flight IOCTL (including a mid-flight START, which
     * holds the lock for the entire VMLAUNCH) to finish, and refuse any new ones from this point
     * on. Only once no RevengHvDeviceControl call can possibly be touching VMX/CPU state is it
     * safe to call StopHv() and then delete the device — closing the race an independent audit
     * found: `sc stop` racing an in-flight START could otherwise unmap this driver's image while
     * a CPU still executes inside it as a VMX guest. Boot-safety contract §0: never unload while
     * still virtualized — StopHv() is safe to call unconditionally regardless. */
    IoReleaseRemoveLockAndWait(&g_RemoveLock, DriverObject);
    StopHv();
    IoDeleteSymbolicLink(&g_SymLink);
    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING devName;
    PDEVICE_OBJECT devObj = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    /* DriverEntry runs in the System process context (demand load via a system worker thread), so
     * this is the System directory base — a never-dying page-table root for VMCS_HOST_CR3. Capture
     * it before anything else so it's always set if a later START succeeds. */
    g_HostCr3 = __readcr3();

    RtlInitUnicodeString(&devName, L"\\Device\\RevengHv");
    RtlInitUnicodeString(&g_SymLink, L"\\DosDevices\\RevengHv");

    /* FILE_DEVICE_SECURE_OPEN alone only means "enforce whatever ACL exists" — it does not
     * itself restrict who that is. Without an explicit SDDL, an unprivileged local process could
     * open this device and issue START (VMLAUNCH) directly, bypassing our own tool's user-mode
     * elevation check entirely. Restrict to SYSTEM + built-in Administrators only. */
    {
        UNICODE_STRING sddl;
        RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        status = IoCreateDeviceSecure(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
                                      FILE_DEVICE_SECURE_OPEN, FALSE, &sddl, NULL, &devObj);
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = IoCreateSymbolicLink(&g_SymLink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(devObj);
        return status;
    }

    devObj->Flags |= DO_BUFFERED_IO;
    devObj->Flags &= ~DO_DEVICE_INITIALIZING;

    IoInitializeRemoveLock(&g_RemoveLock, 'gveR', 0, 0);

    DriverObject->DriverUnload = RevengHvUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = RevengHvCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = RevengHvCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RevengHvDeviceControl;

    return STATUS_SUCCESS;
}
