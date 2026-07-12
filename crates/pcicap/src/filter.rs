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
use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;

/// The driver's service name, and the value we install into the target's UpperFilters.
pub const SERVICE_NAME: &str = "RevengPciCap";

/// Install `RevengPciCap` as an upper filter on the PCI device at `bus:device.function` and
/// restart it so PnP loads our filter into its stack.
pub fn attach(bus: u8, device: u8, function: u8) -> anyhow::Result<()> {
    with_device(bus, device, function, |hdev, info| unsafe {
        set_upper_filters(hdev, info, Some(SERVICE_NAME))?;
        restart_device(hdev, info)
    })
}

/// Remove our upper filter from the device and restart it (reverts to the stock stack).
pub fn detach(bus: u8, device: u8, function: u8) -> anyhow::Result<()> {
    with_device(bus, device, function, |hdev, info| unsafe {
        set_upper_filters(hdev, info, None)?;
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

/// Set (or, with `None`, clear) the device's `UpperFilters` to a single service name.
unsafe fn set_upper_filters(
    hdev: HDEVINFO,
    info: &SP_DEVINFO_DATA,
    service: Option<&str>,
) -> anyhow::Result<()> {
    match service {
        Some(name) => {
            // REG_MULTI_SZ: one entry + double-NUL terminator, as UTF-16 little-endian bytes.
            let mut u16s: Vec<u16> = name.encode_utf16().collect();
            u16s.push(0); // terminate the string
            u16s.push(0); // terminate the multi-sz
            let bytes = u16_slice_as_bytes(&u16s);
            SetupDiSetDeviceRegistryPropertyW(hdev, info as *const _ as *mut _, SPDRP_UPPERFILTERS, Some(bytes))
                .map_err(|e| anyhow::anyhow!("set UpperFilters failed: {e}"))
        }
        None => {
            // Empty buffer deletes the property.
            SetupDiSetDeviceRegistryPropertyW(hdev, info as *const _ as *mut _, SPDRP_UPPERFILTERS, None)
                .map_err(|e| anyhow::anyhow!("clear UpperFilters failed: {e}"))
        }
    }
}

/// Restart the device (DIF_PROPERTYCHANGE / DICS_PROPCHANGE) so the filter change takes effect.
unsafe fn restart_device(hdev: HDEVINFO, info: &SP_DEVINFO_DATA) -> anyhow::Result<()> {
    let mut params = SP_PROPCHANGE_PARAMS {
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
        Some(&mut params.ClassInstallHeader),
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
