//! Install/remove `reveng-pcidrv` as a **device-specific upper filter** (Windows only), the
//! deployment side of DESIGN.md §4a M2.
//!
//! To sit in a device's stack and share its ISR, our driver must be an UpperFilter on the target
//! device instance. The device Enum key is not writable even by administrators, so we go through
//! the supported SetupAPI broker: `SetupDiSetDeviceRegistryProperty(SPDRP_UPPERFILTERS)` sets the
//! filter to our service name, then `SetupDiCallClassInstaller(DIF_PROPERTYCHANGE)` restarts the
//! device so PnP re-enumerates it and calls our `AddDevice`. `detach` clears the filter and
//! restarts again — fully reversible.
//!
//! The service named in UpperFilters (`RevengPciCap`) must already exist (`sc create … type=
//! kernel`). Device-specific (not class-wide) so only the chosen controller is touched.

#![cfg(windows)]

use windows::core::PCWSTR;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiCallClassInstaller, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
    SetupDiGetClassDevsW, SetupDiGetDeviceRegistryPropertyW, SetupDiSetClassInstallParamsW,
    SetupDiSetDeviceRegistryPropertyW, DICS_FLAG_CONFIGSPECIFIC, DICS_PROPCHANGE,
    DIF_PROPERTYCHANGE, DIGCF_ALLCLASSES, DIGCF_PRESENT, HDEVINFO, SETUP_DI_REGISTRY_PROPERTY,
    SPDRP_ADDRESS, SPDRP_BUSNUMBER, SPDRP_UPPERFILTERS, SP_CLASSINSTALL_HEADER, SP_DEVINFO_DATA,
    SP_PROPCHANGE_PARAMS,
};
use windows::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_DATA, ERROR_NO_MORE_ITEMS,
};

/// The driver's service name, and the value we install into the target's UpperFilters.
pub const SERVICE_NAME: &str = "RevengPciCap";

/// Install `RevengPciCap` as an upper filter on the PCI device at `bus:device.function` and
/// restart it so PnP loads our filter into its stack.
pub fn attach(bus: u8, device: u8, function: u8) -> anyhow::Result<()> {
    with_device(bus, device, function, |hdev, info| unsafe {
        update_upper_filters(hdev, info, true)?;
        if let Err(restart_error) = restart_device(hdev, info) {
            // Do not leave a filter armed for the next reboot when activation failed now.
            return match update_upper_filters(hdev, info, false) {
                Ok(()) => Err(restart_error.context("device restart failed; filter registration rolled back")),
                Err(rollback_error) => Err(anyhow::anyhow!(
                    "device restart failed ({restart_error:#}) and UpperFilters rollback also failed ({rollback_error:#})"
                )),
            };
        }
        Ok(())
    })
}

/// Remove our upper filter from the device and restart it while preserving any other filters.
pub fn detach(bus: u8, device: u8, function: u8) -> anyhow::Result<()> {
    with_device(bus, device, function, |hdev, info| unsafe {
        update_upper_filters(hdev, info, false)?;
        restart_device(hdev, info)
    })
}

/// Locate the PCI function by BDF and run `f` against its device-info handle.
fn with_device(
    bus: u8,
    device: u8,
    function: u8,
    mut f: impl FnMut(HDEVINFO, &SP_DEVINFO_DATA) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let pci: Vec<u16> = "PCI\0".encode_utf16().collect();
    unsafe {
        let hdev = SetupDiGetClassDevsW(
            None,
            PCWSTR(pci.as_ptr()),
            None,
            DIGCF_PRESENT | DIGCF_ALLCLASSES,
        )?;

        let mut idx = 0u32;
        let mut found = false;
        let mut result = Ok(());
        loop {
            let mut info = SP_DEVINFO_DATA {
                cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
                ..Default::default()
            };
            match SetupDiEnumDeviceInfo(hdev, idx, &mut info) {
                Ok(()) => {}
                Err(e) if e.code() == ERROR_NO_MORE_ITEMS.to_hresult() => break,
                Err(_) => break,
            }
            idx += 1;

            let b = get_u32(hdev, &info, SPDRP_BUSNUMBER).unwrap_or(u32::MAX);
            let addr = get_u32(hdev, &info, SPDRP_ADDRESS).unwrap_or(u32::MAX);
            let dev = (addr >> 16) & 0xffff;
            let func = addr & 0xffff;
            if b == bus as u32 && dev == device as u32 && func == function as u32 {
                found = true;
                result = f(hdev, &info);
                break;
            }
        }
        let _ = SetupDiDestroyDeviceInfoList(hdev);
        if !found {
            anyhow::bail!("no present PCI device at {bus:02x}:{device:02x}.{function}");
        }
        result
    }
}

/// Add or remove only our service from `UpperFilters`, preserving filters installed by the
/// device vendor or other software.
unsafe fn update_upper_filters(
    hdev: HDEVINFO,
    info: &SP_DEVINFO_DATA,
    attach: bool,
) -> anyhow::Result<()> {
    let mut filters = get_multi_sz(hdev, info, SPDRP_UPPERFILTERS)?;
    if attach {
        if !filters.iter().any(|f| f.eq_ignore_ascii_case(SERVICE_NAME)) {
            filters.push(SERVICE_NAME.to_owned());
        }
    } else {
        filters.retain(|f| !f.eq_ignore_ascii_case(SERVICE_NAME));
    }

    if filters.is_empty() {
        // No remaining filters: delete the property.
        return SetupDiSetDeviceRegistryPropertyW(hdev, info as *const _ as *mut _, SPDRP_UPPERFILTERS, None)
            .map_err(|e| anyhow::anyhow!("clear UpperFilters failed: {e}"));
    }

    // REG_MULTI_SZ: each entry is NUL-terminated, with one final NUL terminator.
    let mut u16s = Vec::new();
    for filter in filters {
        u16s.extend(filter.encode_utf16());
        u16s.push(0);
    }
    u16s.push(0);
    let bytes = u16_slice_as_bytes(&u16s);
    SetupDiSetDeviceRegistryPropertyW(hdev, info as *const _ as *mut _, SPDRP_UPPERFILTERS, Some(bytes))
        .map_err(|e| anyhow::anyhow!("set UpperFilters failed: {e}"))
}

/// Restart the device (DIF_PROPERTYCHANGE / DICS_PROPCHANGE) so the filter change takes effect.
unsafe fn restart_device(hdev: HDEVINFO, info: &SP_DEVINFO_DATA) -> anyhow::Result<()> {
    let params = SP_PROPCHANGE_PARAMS {
        ClassInstallHeader: SP_CLASSINSTALL_HEADER {
            cbSize: std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32,
            InstallFunction: DIF_PROPERTYCHANGE,
        },
        StateChange: DICS_PROPCHANGE,
        Scope: DICS_FLAG_CONFIGSPECIFIC,
        HwProfile: 0,
    };
    SetupDiSetClassInstallParamsW(
        hdev,
        Some(info as *const _),
        Some(&params.ClassInstallHeader),
        std::mem::size_of::<SP_PROPCHANGE_PARAMS>() as u32,
    )
    .map_err(|e| anyhow::anyhow!("SetClassInstallParams failed: {e}"))?;
    SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hdev, Some(info as *const _))
        .map_err(|e| anyhow::anyhow!("restart device (CallClassInstaller) failed: {e}"))
}

fn u16_slice_as_bytes(s: &[u16]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(s.as_ptr() as *const u8, std::mem::size_of_val(s)) }
}

/// Read a REG_DWORD-ish property as u32 (first 4 bytes), via the two-call size/fetch pattern.
unsafe fn get_u32(hdev: HDEVINFO, info: &SP_DEVINFO_DATA, prop: SETUP_DI_REGISTRY_PROPERTY) -> Option<u32> {
    let mut needed = 0u32;
    let _ = SetupDiGetDeviceRegistryPropertyW(hdev, info, prop, None, None, Some(&mut needed));
    if needed < 4 {
        return None;
    }
    let mut buf = vec![0u8; needed as usize];
    SetupDiGetDeviceRegistryPropertyW(hdev, info, prop, None, Some(&mut buf), Some(&mut needed))
        .ok()?;
    Some(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

/// Read a REG_MULTI_SZ property. Missing or malformed values are treated as empty so attach can
/// safely establish the property; valid existing entries are always preserved verbatim.
unsafe fn get_multi_sz(
    hdev: HDEVINFO,
    info: &SP_DEVINFO_DATA,
    prop: SETUP_DI_REGISTRY_PROPERTY,
) -> anyhow::Result<Vec<String>> {
    let mut needed = 0u32;
    match SetupDiGetDeviceRegistryPropertyW(hdev, info, prop, None, None, Some(&mut needed)) {
        Ok(()) => {}
        Err(e) if e.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() => {}
        Err(e) if e.code() == ERROR_INVALID_DATA.to_hresult() => return Ok(Vec::new()),
        Err(e) => return Err(anyhow::anyhow!("read existing UpperFilters size failed: {e}")),
    }
    if needed < 2 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; needed as usize];
    SetupDiGetDeviceRegistryPropertyW(hdev, info, prop, None, Some(&mut buf), Some(&mut needed))
        .map_err(|e| anyhow::anyhow!("read existing UpperFilters failed: {e}"))?;
    buf.truncate(needed as usize);
    Ok(buf
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect::<Vec<_>>()
        .split(|&c| c == 0)
        .filter(|s| !s.is_empty())
        .map(String::from_utf16_lossy)
        .collect())
}
