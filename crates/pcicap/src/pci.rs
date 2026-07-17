//! PCI(e) device enumeration for `reveng-rec pci-devices` (DESIGN.md §4a, §11).
//!
//! User-mode only (SetupAPI) — no driver required, so this is available before the
//! hypervisor tier exists. Reports BDF, VID:PID, class code, and a description; the caller
//! uses it to pick `--pci-vidpid` / `--pci-bdf`.

use serde::Serialize;

/// One enumerated PCI(e) function.
#[derive(Debug, Clone, Serialize)]
pub struct PciDevice {
    /// `segment:bus:device.function`, e.g. `0000:03:00.0`.
    pub bdf: String,
    pub vid: String,
    pub pid: String,
    /// PCI class code (`CC_hhhhhh`) if present in the hardware IDs, else empty.
    pub class: String,
    pub description: String,
}

/// Pull `VEN_xxxx`, `DEV_xxxx`, `CC_xxxxxx` out of a device's hardware IDs. Pure/portable
/// so it is unit-tested off Windows.
fn parse_ids(hwids: &[String]) -> (String, String, String) {
    let joined = hwids.join(" ").to_ascii_uppercase();
    let grab = |key: &str, n: usize| -> String {
        joined
            .find(key)
            .map(|i| {
                joined[i + key.len()..]
                    .chars()
                    .take_while(|c| c.is_ascii_hexdigit())
                    .take(n)
                    .collect::<String>()
            })
            .unwrap_or_default()
    };
    (grab("VEN_", 4), grab("DEV_", 4), grab("CC_", 6))
}

/// Enumerate present PCI(e) devices. Windows-only; errors elsewhere.
pub fn list_pci_devices() -> anyhow::Result<Vec<PciDevice>> {
    #[cfg(windows)]
    {
        imp::list()
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("PCI enumeration requires Windows")
    }
}

#[cfg(windows)]
mod imp {
    use super::PciDevice;
    use windows::core::PCWSTR;
    use windows::Win32::Devices::DeviceAndDriverInstallation::{
        SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
        SetupDiGetDeviceRegistryPropertyW, DIGCF_ALLCLASSES, DIGCF_PRESENT, SPDRP_ADDRESS,
        SPDRP_BUSNUMBER, SPDRP_DEVICEDESC, SPDRP_HARDWAREID, SP_DEVINFO_DATA,
    };
    use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;

    pub fn list() -> anyhow::Result<Vec<PciDevice>> {
        let pci: Vec<u16> = "PCI\0".encode_utf16().collect();
        let mut out = Vec::new();

        unsafe {
            // Null ClassGuid + an Enumerator requires DIGCF_ALLCLASSES.
            let hdev = SetupDiGetClassDevsW(
                None,
                PCWSTR(pci.as_ptr()),
                None,
                DIGCF_PRESENT | DIGCF_ALLCLASSES,
            )?;

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
                let (vid, pid, class) = super::parse_ids(&hwids);
                let description = get_string(hdev, &info, SPDRP_DEVICEDESC).unwrap_or_default();
                let bus = get_u32(hdev, &info, SPDRP_BUSNUMBER).unwrap_or(0);
                let addr = get_u32(hdev, &info, SPDRP_ADDRESS).unwrap_or(0);
                let dev = (addr >> 16) & 0xffff;
                let func = addr & 0xffff;
                let bdf = format!("0000:{bus:02x}:{dev:02x}.{func}");

                out.push(PciDevice {
                    bdf,
                    vid,
                    pid,
                    class,
                    description,
                });
            }

            let _ = SetupDiDestroyDeviceInfoList(hdev);
        }
        Ok(out)
    }

    /// Read a `REG_SZ`/`REG_MULTI_SZ` property as UTF-16 → the first string.
    fn get_string(
        hdev: windows::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
        info: &SP_DEVINFO_DATA,
        prop: windows::Win32::Devices::DeviceAndDriverInstallation::SETUP_DI_REGISTRY_PROPERTY,
    ) -> Option<String> {
        let raw = get_raw(hdev, info, prop)?;
        let u16s = bytes_to_u16(&raw);
        u16s.split(|&c| c == 0).next().map(from_u16)
    }

    /// Read a `REG_MULTI_SZ` property as a Vec of strings.
    fn get_multi_sz(
        hdev: windows::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
        info: &SP_DEVINFO_DATA,
        prop: windows::Win32::Devices::DeviceAndDriverInstallation::SETUP_DI_REGISTRY_PROPERTY,
    ) -> Vec<String> {
        let Some(raw) = get_raw(hdev, info, prop) else {
            return Vec::new();
        };
        let u16s = bytes_to_u16(&raw);
        u16s.split(|&c| c == 0)
            .filter(|s| !s.is_empty())
            .map(from_u16)
            .collect()
    }

    fn get_u32(
        hdev: windows::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
        info: &SP_DEVINFO_DATA,
        prop: windows::Win32::Devices::DeviceAndDriverInstallation::SETUP_DI_REGISTRY_PROPERTY,
    ) -> Option<u32> {
        let raw = get_raw(hdev, info, prop)?;
        (raw.len() >= 4).then(|| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    /// Raw property bytes via a two-call size/fetch.
    fn get_raw(
        hdev: windows::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
        info: &SP_DEVINFO_DATA,
        prop: windows::Win32::Devices::DeviceAndDriverInstallation::SETUP_DI_REGISTRY_PROPERTY,
    ) -> Option<Vec<u8>> {
        unsafe {
            let mut needed = 0u32;
            // First call: learn the required size (ignores the expected buffer-too-small error).
            let _ = SetupDiGetDeviceRegistryPropertyW(
                hdev,
                info,
                prop,
                None,
                None,
                Some(&mut needed),
            );
            if needed == 0 {
                return None;
            }
            let mut buf = vec![0u8; needed as usize];
            SetupDiGetDeviceRegistryPropertyW(
                hdev,
                info,
                prop,
                None,
                Some(&mut buf),
                Some(&mut needed),
            )
            .ok()?;
            buf.truncate(needed as usize);
            Some(buf)
        }
    }

    fn bytes_to_u16(b: &[u8]) -> Vec<u16> {
        b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()
    }

    fn from_u16(s: &[u16]) -> String {
        String::from_utf16_lossy(s)
    }
}

#[cfg(test)]
mod tests {
    use super::parse_ids;

    #[test]
    fn parse_ids_extracts_vid_pid_class() {
        let ids = vec![
            "PCI\\VEN_8086&DEV_1234&SUBSYS_00000000&REV_02".to_string(),
            "PCI\\VEN_8086&DEV_1234&CC_040300".to_string(),
        ];
        let (v, p, c) = parse_ids(&ids);
        assert_eq!(v, "8086");
        assert_eq!(p, "1234");
        assert_eq!(c, "040300");
    }
}
