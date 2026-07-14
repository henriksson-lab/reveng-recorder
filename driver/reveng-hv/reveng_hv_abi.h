/*
 * reveng-hv <-> user-mode shared ABI (plan §5). The hypervisor tier's control device.
 *
 * H1 bring-up is incremental and safe-first:
 *   PROBE  — read VMX capability (CPUID + MSRs) and report; no VMX entry, zero risk.
 *   START  — VMXON + VMLAUNCH (hyperjack the running Windows); the risky step.
 *   STOP   — VMXOFF (devirtualize) on all CPUs.
 * Kept in lockstep with the Rust side when H5 wires HvPcieSource.
 */
#ifndef REVENG_HV_ABI_H
#define REVENG_HV_ABI_H

#define REVENG_HV_USERMODE_PATH L"\\\\.\\RevengHv"

#define IOCTL_REVENG_HV_PROBE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REVENG_HV_START   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REVENG_HV_STOP    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* VMXON+VMXOFF on every logical CPU (no VMLAUNCH) — proves we can enter/leave VMX root safely. */
#define IOCTL_REVENG_HV_VMXTEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* Diagnostics without a live kernel debugger: what happened on the most recent devirtualize (or
 * failed VMLAUNCH), and whether the RDTSCP/INVPCID/XSAVES secondary controls actually took
 * effect (AdjustControls silently masks anything the hardware doesn't support). */
#define IOCTL_REVENG_HV_DIAG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Output of IOCTL_REVENG_HV_PROBE — what we learned about VT-x on this machine. */
#pragma pack(push, 1)
typedef struct _REVENG_HV_PROBE {
    unsigned char      vmx_cpuid;        /* CPUID.1:ECX.VMX[5]                              */
    unsigned char      hv_present;       /* CPUID.1:ECX.hypervisor[31] — someone owns VT-x  */
    unsigned char      feature_locked;   /* IA32_FEATURE_CONTROL.lock[0]                     */
    unsigned char      vmxon_allowed;    /* IA32_FEATURE_CONTROL.vmxon-outside-smx[2]        */
    unsigned int       logical_cpus;     /* KeQueryActiveProcessorCountEx                    */
    unsigned long long feature_control;  /* raw IA32_FEATURE_CONTROL (0x3A)                  */
    unsigned long long vmx_basic;        /* raw IA32_VMX_BASIC (0x480)                       */
    unsigned long long vmx_ept_vpid;     /* raw IA32_VMX_EPT_VPID_CAP (0x48C)                */
} REVENG_HV_PROBE;
#pragma pack(pop)

/* Output of IOCTL_REVENG_HV_VMXTEST. */
#pragma pack(push, 1)
typedef struct _REVENG_HV_VMXTEST {
    unsigned int  cpus_tested;
    unsigned int  cpus_ok;         /* VMXON+VMXOFF succeeded                       */
    int           first_fail_cpu;  /* -1 if none                                  */
    unsigned char first_fail_stage;/* 1=alloc, 2=vmxon                            */
    unsigned char first_fail_code; /* VMXON result byte (1=fail-valid,2=fail)     */
    unsigned char _pad[2];
} REVENG_HV_VMXTEST;
#pragma pack(pop)

/* Output of IOCTL_REVENG_HV_DIAG. `last_devirt_reason`: 0=never, 1=VMCALL (normal STOP),
 * 2=#UD trapped, 3=other unexpected VM-exit, 4=VMLAUNCH itself failed (see launch_error). */
#pragma pack(push, 1)
typedef struct _REVENG_HV_DIAG {
    unsigned char      secondary_ctls_requested_ok; /* activate-secondary bit actually set  */
    unsigned char      rdtscp_enabled;               /* secondary RDTSCP bit actually set    */
    unsigned char      invpcid_enabled;
    unsigned char      xsaves_enabled;
    unsigned char      last_devirt_reason;
    unsigned char      _pad[3];
    unsigned int       last_exit_reason;   /* raw VMX exit reason, if reason==3            */
    unsigned long long last_devirt_rip;    /* guest RIP at the last devirtualize            */
    unsigned long long launch_error;       /* VM_INSTRUCTION_ERROR from the last failed VMLAUNCH */
} REVENG_HV_DIAG;
#pragma pack(pop)

#endif /* REVENG_HV_ABI_H */
