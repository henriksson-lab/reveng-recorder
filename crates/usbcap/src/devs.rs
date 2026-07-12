//! Pure-Rust USB device enumeration + control-device mapping (Windows only).
//!
//! Replaces parsing `USBPcapCMD.exe`'s human-oriented (and, on some builds, UTF-16) device
//! tree. We enumerate USB devnodes with SetupAPI — VID/PID from the hardware IDs, USB address
//! from `SPDRP_ADDRESS` (exactly the address USBPcap's filter bitmask wants) — then map each
//! device to the `\\.\USBPcapN` that filters its root hub by walking `CM_Get_Parent` up to the
//! `USB\ROOT_HUB*` node and matching it against each control device's `GET_HUB_SYMLINK`.

#![cfg(windows)]

use crate::UsbDevice;

use windows::core::PCWSTR;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_Device_IDW, CM_Get_Device_Interface_ListW, CM_Get_Device_Interface_List_SizeW,
    CM_Get_Parent, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
    SetupDiGetDeviceRegistryPropertyW, CM_GET_DEVICE_INTERFACE_LIST_PRESENT, CR_SUCCESS,
    DIGCF_ALLCLASSES, DIGCF_PRESENT, HDEVINFO, SETUP_DI_REGISTRY_PROPERTY, SPDRP_ADDRESS,
    SPDRP_DEVICEDESC, SPDRP_HARDWAREID, SP_DEVINFO_DATA,
};
use windows::Win32::Devices::Usb::GUID_DEVINTERFACE_USB_HUB;
use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;

/// Enumerate present USB devices and map each to its USBPcap control device.
pub fn list() -> anyhow::Result<Vec<UsbDevice>> {
    // Which live root-hub filters exist, and the root-hub instance id each one filters.
    let controls: Vec<(String, String)> = crate::ioctl::probe_control_devices(64)
        .into_iter()
        .map(|(dev, sym)| (dev, normalize_symlink(&sym).unwrap_or_default()))
        .collect();

    let usb: Vec<u16> = "USB\0".encode_utf16().collect();
    let mut out = Vec::new();

    unsafe {
        let hdev =
            SetupDiGetClassDevsW(None, PCWSTR(usb.as_ptr()), None, DIGCF_PRESENT | DIGCF_ALLCLASSES)?;

        let mut idx = 0u32;
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

            let hwids = get_multi_sz(hdev, &info, SPDRP_HARDWAREID);
            let (vid, pid) = super::extract_vidpid(&hwids.join(" "));
            // Skip nodes without a VID/PID (root hubs, controllers): not capture targets.
            if vid.is_empty() || pid.is_empty() {
                continue;
            }
            // Skip composite-function children (`&MI_xx`); the parent devnode carries the
            // real USB address and we want to list the physical device once.
            let this_id = device_id(info.DevInst).unwrap_or_default();
            if this_id.to_ascii_uppercase().contains("&MI_") {
                continue;
            }

            // `SPDRP_ADDRESS` is the port number on the parent hub; resolve the real USB bus
            // address (what USBPcap filters on) by asking that hub about the port.
            let port = get_u32(hdev, &info, SPDRP_ADDRESS).unwrap_or(0);
            let address = immediate_parent(info.DevInst)
                .and_then(hub_interface_path)
                .and_then(|hub| crate::ioctl::usb_device_address(&hub, port))
                .unwrap_or(port as u16);
            let product = get_string(hdev, &info, SPDRP_DEVICEDESC).unwrap_or_default();

            // Walk up to the root hub, then match its instance id to a control device.
            let usbpcap = root_hub_id(info.DevInst)
                .and_then(|rh| {
                    let rh = rh.to_ascii_uppercase();
                    controls
                        .iter()
                        .find(|(_, id)| !id.is_empty() && rh == *id)
                        .map(|(dev, _)| dev.clone())
                })
                .unwrap_or_default();
            let bus = bus_of(&usbpcap);

            out.push(UsbDevice {
                usbpcap,
                bus,
                address,
                vid,
                pid,
                product,
            });
        }

        let _ = SetupDiDestroyDeviceInfoList(hdev);
    }
    Ok(out)
}

/// Walk `CM_Get_Parent` from `devinst` until a `USB\ROOT_HUB*` node, returning its instance id.
fn root_hub_id(devinst: u32) -> Option<String> {
    let mut cur = devinst;
    for _ in 0..16 {
        let id = device_id(cur)?;
        if id.to_ascii_uppercase().starts_with("USB\\ROOT_HUB") {
            return Some(id);
        }
        let mut parent = 0u32;
        if unsafe { CM_Get_Parent(&mut parent, cur, 0) } != CR_SUCCESS || parent == 0 {
            return None;
        }
        cur = parent;
    }
    None
}

/// The devnode this device is directly connected to (its parent hub in the USB tree).
fn immediate_parent(devinst: u32) -> Option<u32> {
    let mut parent = 0u32;
    (unsafe { CM_Get_Parent(&mut parent, devinst, 0) } == CR_SUCCESS && parent != 0)
        .then_some(parent)
}

/// The `GUID_DEVINTERFACE_USB_HUB` device-interface path for a hub devnode, openable with
/// `CreateFile` to issue node-connection IOCTLs. `None` if the node exposes no hub interface.
fn hub_interface_path(hub_devinst: u32) -> Option<String> {
    let id = device_id(hub_devinst)?;
    let idw: Vec<u16> = id.encode_utf16().chain(std::iter::once(0)).collect();
    let guid = GUID_DEVINTERFACE_USB_HUB;

    let mut len = 0u32;
    let flags = CM_GET_DEVICE_INTERFACE_LIST_PRESENT;
    if unsafe {
        CM_Get_Device_Interface_List_SizeW(&mut len, &guid, PCWSTR(idw.as_ptr()), flags)
    } != CR_SUCCESS
        || len == 0
    {
        return None;
    }
    let mut buf = vec![0u16; len as usize];
    if unsafe { CM_Get_Device_Interface_ListW(&guid, PCWSTR(idw.as_ptr()), &mut buf, flags) }
        != CR_SUCCESS
    {
        return None;
    }
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let s = String::from_utf16_lossy(&buf[..n]);
    (!s.is_empty()).then_some(s)
}

/// Device instance id for a devnode, e.g. `USB\VID_054C&PID_0CE6\5&abc&0&3`.
fn device_id(devinst: u32) -> Option<String> {
    let mut buf = [0u16; 256];
    if unsafe { CM_Get_Device_IDW(devinst, &mut buf, 0) } != CR_SUCCESS {
        return None;
    }
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..n]))
}

/// Normalize a `GET_HUB_SYMLINK` device-interface path to a device instance id:
/// `\??\USB#ROOT_HUB30#4&2bd7ffc0&0&0#{guid}` → `USB\ROOT_HUB30\4&2bd7ffc0&0&0` (uppercased).
fn normalize_symlink(sym: &str) -> Option<String> {
    let s = sym.trim();
    if s.is_empty() {
        return None;
    }
    let s = s
        .strip_prefix("\\??\\")
        .or_else(|| s.strip_prefix("\\\\?\\"))
        .unwrap_or(s);
    // Drop the trailing `#{interface-guid}` if present.
    let s = match s.rfind("#{") {
        Some(i) => &s[..i],
        None => s,
    };
    Some(s.replace('#', "\\").to_ascii_uppercase())
}

/// Trailing digits of a `\\.\USBPcapN` path → bus number N.
fn bus_of(usbpcap: &str) -> u16 {
    usbpcap
        .rsplit(|c: char| !c.is_ascii_digit())
        .find(|s| !s.is_empty())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

// --- SetupAPI property helpers (mirror pcicap::pci::imp) ---------------------------------

fn get_string(hdev: HDEVINFO, info: &SP_DEVINFO_DATA, prop: SETUP_DI_REGISTRY_PROPERTY) -> Option<String> {
    let raw = get_raw(hdev, info, prop)?;
    let u16s = bytes_to_u16(&raw);
    u16s.split(|&c| c == 0).next().map(String::from_utf16_lossy)
}

fn get_multi_sz(hdev: HDEVINFO, info: &SP_DEVINFO_DATA, prop: SETUP_DI_REGISTRY_PROPERTY) -> Vec<String> {
    let Some(raw) = get_raw(hdev, info, prop) else {
        return Vec::new();
    };
    bytes_to_u16(&raw)
        .split(|&c| c == 0)
        .filter(|s| !s.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

fn get_u32(hdev: HDEVINFO, info: &SP_DEVINFO_DATA, prop: SETUP_DI_REGISTRY_PROPERTY) -> Option<u32> {
    let raw = get_raw(hdev, info, prop)?;
    (raw.len() >= 4).then(|| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn get_raw(hdev: HDEVINFO, info: &SP_DEVINFO_DATA, prop: SETUP_DI_REGISTRY_PROPERTY) -> Option<Vec<u8>> {
    unsafe {
        let mut needed = 0u32;
        let _ = SetupDiGetDeviceRegistryPropertyW(hdev, info, prop, None, None, Some(&mut needed));
        if needed == 0 {
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        SetupDiGetDeviceRegistryPropertyW(hdev, info, prop, None, Some(&mut buf), Some(&mut needed))
            .ok()?;
        buf.truncate(needed as usize);
        Some(buf)
    }
}

fn bytes_to_u16(b: &[u8]) -> Vec<u16> {
    b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()
}

#[cfg(test)]
mod tests {
    use super::{bus_of, normalize_symlink};

    #[test]
    fn normalizes_hub_symlink_to_instance_id() {
        let sym = "\\??\\USB#ROOT_HUB30#4&2bd7ffc0&0&0#{f18a0e88-c30c-11d0-8815-00a0c906bed8}";
        assert_eq!(
            normalize_symlink(sym).unwrap(),
            "USB\\ROOT_HUB30\\4&2BD7FFC0&0&0"
        );
    }

    #[test]
    fn bus_of_parses_trailing_index() {
        assert_eq!(bus_of("\\\\.\\USBPcap2"), 2);
        assert_eq!(bus_of("\\\\.\\USBPcap15"), 15);
    }
}
