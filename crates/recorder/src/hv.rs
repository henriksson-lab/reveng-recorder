//! User-mode client for the `reveng-hv` hypervisor-tier driver (Windows only).
//!
//! H1 step 1: read the VMX capability PROBE and print it, so we can confirm on real hardware that
//! Hyper-V released VT-x and that VMX/EPT/MTF are usable before writing any `VMXON`.

#![cfg(windows)]

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Threading::{GetCurrentThread, SetThreadAffinityMask};

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}
const FILE_DEVICE_UNKNOWN: u32 = 0x0000_0022;
const IOCTL_REVENG_HV_PROBE: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x900, 0, 0);
const IOCTL_REVENG_HV_START: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x901, 0, 0);
const IOCTL_REVENG_HV_STOP: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x902, 0, 0);
const IOCTL_REVENG_HV_VMXTEST: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x903, 0, 0);
const IOCTL_REVENG_HV_DIAG: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x904, 0, 0);

const HV_BACKDOOR_LEAF: u32 = 0x5256_4748; /* must match reveng-hv.c */
const HV_BACKDOOR_SIG_EBX: u32 = 0x676E_6576;
const HV_BACKDOOR_SIG_ECX: u32 = 0x2D76_6568;
const HV_BACKDOOR_SIG_EDX: u32 = 0x0000_0031;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Open the reveng-hv control device, run one buffered IOCTL, return the output bytes.
fn hv_ioctl(code: u32, out_len: usize) -> anyhow::Result<Vec<u8>> {
    let path = wide("\\\\.\\RevengHv");
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            0xC000_0000u32,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .map_err(|e| anyhow::anyhow!("open \\\\.\\RevengHv failed: {e} (is RevengHv started? `sc start RevengHv`)"))?;
    if handle == INVALID_HANDLE_VALUE {
        anyhow::bail!("\\\\.\\RevengHv returned an invalid handle");
    }
    let mut buf = vec![0u8; out_len];
    let mut returned = 0u32;
    let res = unsafe {
        DeviceIoControl(
            handle,
            code,
            None,
            0,
            Some(buf.as_mut_ptr() as *mut _),
            buf.len() as u32,
            Some(&mut returned),
            None,
        )
    };
    unsafe {
        let _ = CloseHandle(handle);
    }
    res.map_err(|e| anyhow::anyhow!("ioctl {code:#x} failed: {e}"))?;
    buf.truncate(returned as usize);
    Ok(buf)
}

pub fn probe() -> anyhow::Result<()> {
    let buf = hv_ioctl(IOCTL_REVENG_HV_PROBE, 32)?;
    if buf.len() < 32 {
        anyhow::bail!("PROBE returned {} bytes, expected 32", buf.len());
    }
    let vmx_cpuid = buf[0];
    let hv_present = buf[1];
    let feature_locked = buf[2];
    let vmxon_allowed = buf[3];
    let logical_cpus = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let feature_control = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let vmx_basic = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let vmx_ept_vpid = u64::from_le_bytes(buf[24..32].try_into().unwrap());

    let yn = |b: u8| if b != 0 { "yes" } else { "no" };
    println!("reveng-hv VT-x probe:");
    println!("  CPUID VMX supported : {}", yn(vmx_cpuid));
    println!("  hypervisor present  : {}  (must be 'no' — else Hyper-V/VBS still owns VT-x)", yn(hv_present));
    println!("  FEATURE_CONTROL lock: {}", yn(feature_locked));
    println!("  VMXON allowed       : {}  (lock=yes & this=yes → we can VMXON)", yn(vmxon_allowed));
    println!("  logical CPUs        : {logical_cpus}  (must VMXON all of them)");
    println!("  IA32_FEATURE_CONTROL: {feature_control:#018x}");
    println!("  IA32_VMX_BASIC      : {vmx_basic:#018x}");
    println!("  IA32_VMX_EPT_VPID   : {vmx_ept_vpid:#018x}");

    let ready = vmx_cpuid != 0 && hv_present == 0 && vmxon_allowed != 0;
    println!(
        "  => {}",
        if ready {
            "READY to VMXON (Hyper-V released VT-x; VMX unlocked)."
        } else if hv_present != 0 {
            "NOT ready: hypervisor still present — disable Hyper-V/VBS and reboot."
        } else {
            "NOT ready: VMX unsupported or firmware-locked."
        }
    );
    Ok(())
}

/// H1 step 2: VMXON+VMXOFF on every logical CPU (no VMLAUNCH). Proves we can enter/leave VMX root.
pub fn vmxtest() -> anyhow::Result<()> {
    let buf = hv_ioctl(IOCTL_REVENG_HV_VMXTEST, 16)?;
    if buf.len() < 12 {
        anyhow::bail!("VMXTEST returned {} bytes", buf.len());
    }
    let tested = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let ok = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let fail_cpu = i32::from_le_bytes(buf[8..12].try_into().unwrap());
    let fail_stage = buf.get(12).copied().unwrap_or(0);
    let fail_code = buf.get(13).copied().unwrap_or(0);

    println!("reveng-hv VMXON/VMXOFF reach test:");
    println!("  CPUs entered+left VMX root: {ok}/{tested}");
    if fail_cpu < 0 {
        println!("  => SUCCESS on all CPUs — VMX entry works. Ready for VMLAUNCH (hyperjack).");
    } else {
        let stage = match fail_stage {
            1 => "contiguous-alloc",
            2 => "VMXON",
            _ => "?",
        };
        println!("  => FAILED first on CPU {fail_cpu} at stage '{stage}' (code {fail_code}).");
    }
    Ok(())
}

/// Read the driver's diagnostic record — what happened on the most recent devirtualize (or failed
/// VMLAUNCH), and whether the RDTSCP/INVPCID/XSAVES secondary controls actually took effect on
/// this hardware. This is the only way to see that without a live kernel debugger attached, since
/// DbgPrintEx output is otherwise unobservable (nothing is listening for it).
pub fn diag() -> anyhow::Result<()> {
    print_diag()
}

fn print_diag() -> anyhow::Result<()> {
    let buf = hv_ioctl(IOCTL_REVENG_HV_DIAG, 28)?;
    if buf.len() < 28 {
        anyhow::bail!("DIAG returned {} bytes, expected 28", buf.len());
    }
    let yn = |b: u8| if b != 0 { "yes" } else { "no" };
    println!("reveng-hv diagnostics:");
    println!("  secondary controls activated: {}", yn(buf[0]));
    println!("  RDTSCP enabled  (the crash fix): {}", yn(buf[1]));
    println!("  INVPCID enabled: {}", yn(buf[2]));
    println!("  XSAVES enabled : {}", yn(buf[3]));
    let reason = buf[4];
    let exit_reason = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    let rip = u64::from_le_bytes(buf[12..20].try_into().unwrap());
    let launch_error = u64::from_le_bytes(buf[20..28].try_into().unwrap());
    match reason {
        0 => println!("  last devirtualize: none yet"),
        1 => println!("  last devirtualize: VMCALL (normal STOP) at guest RIP {rip:#x}"),
        2 => println!("  last devirtualize: #UD TRAPPED at guest RIP {rip:#x} — this is the RIP to look up (that instruction needs a control bit we haven't enabled, or is a genuine fault)"),
        3 => println!("  last devirtualize: unexpected VM-exit reason={exit_reason} at guest RIP {rip:#x}"),
        4 => println!("  last event: VMLAUNCH FAILED, VM_INSTRUCTION_ERROR={launch_error}"),
        5 => println!("  last event: VMRESUME FAILED (error={launch_error}) at guest RIP {rip:#x} — recovered via devirtualize instead of crashing"),
        _ => println!("  last devirtualize: unknown reason code {reason}"),
    }
    Ok(())
}

/// H1: full VMLAUNCH hyperjack self-test on ONE known CPU (pinned so we verify the exact core the
/// driver virtualized). Sends START, checks the CPUID backdoor leaf
/// *while still virtualized*, then STOP to devirtualize. Reports each step so a failure/hang is
/// diagnosable from wherever it stopped.
pub fn selftest() -> anyhow::Result<()> {
    println!("reveng-hv H1 hyperjack self-test (pinned to CPU 0):");

    let thread = unsafe { GetCurrentThread() };
    let prev = unsafe { SetThreadAffinityMask(thread, 1) };
    if prev == 0 {
        anyhow::bail!("SetThreadAffinityMask failed");
    }
    println!("  [1] pinned this thread to logical CPU 0");

    println!("  [2] sending START (VMLAUNCH)...");
    hv_ioctl(IOCTL_REVENG_HV_START, 0)?;
    println!("      START returned — if you're reading this, VMLAUNCH succeeded and we're running virtualized.");

    let backdoor_ok = {
        let r = std::arch::x86_64::__cpuid(HV_BACKDOOR_LEAF);
        r.eax == HV_BACKDOOR_LEAF && r.ebx == HV_BACKDOOR_SIG_EBX && r.ecx == HV_BACKDOOR_SIG_ECX && r.edx == HV_BACKDOOR_SIG_EDX
    };
    println!("  [3] CPUID backdoor leaf {HV_BACKDOOR_LEAF:#010x}: {}", if backdoor_ok { "SIGNATURE MATCHED" } else { "no match" });

    println!("  [4] CPUID.1 is left unmodified; this avoids making Windows consume an incomplete hypervisor CPUID ABI.");

    println!("  [5] sending STOP (devirtualize)...");
    hv_ioctl(IOCTL_REVENG_HV_STOP, 0)?;
    println!("      STOP returned — back to bare metal.");

    println!("  [6] STOP returned without a VM-exit failure.");

    unsafe {
        let _ = SetThreadAffinityMask(thread, prev);
    }

    if backdoor_ok {
        println!("  => SUCCESS: hyperjack verified end-to-end on CPU 0, cleanly devirtualized.");
    } else {
        println!(
            "  => INCOMPLETE: see steps above for where it diverged. If backdoor/hv_present were \
             unexpectedly false, the CPU may have silently devirtualized itself via the #UD \
             safety net before we got to check — the diagnostics below say why."
        );
    }
    println!();
    print_diag()?;
    Ok(())
}
