//! Direct USBPcap kernel-driver client (Windows only).
//!
//! USBPcapCMD.exe is a thin userspace client of the `USBPcap.sys` filter driver: it opens a
//! `\\.\USBPcapN` control device, issues a few IOCTLs (snaplen, buffer size, start filtering),
//! then `ReadFile`s the classic-pcap stream the driver produces. We reimplement that client
//! directly so live capture needs no subprocess, no stdout pipe, and no CLI-text parsing.
//!
//! The IOCTL codes and the [`AddressFilter`] layout are USBPcap's public *interface* (from
//! `USBPcap.h`, BSD-2-Clause) — we define them here rather than linking any USBPcap code.
//! Verified against USBPcap 1.5.4.0.
//!
//! Differences from USBPcapCMD's own reader: it opens the device `FILE_FLAG_OVERLAPPED` and
//! pumps async reads; we open it synchronously and do blocking `ReadFile`s on the reader
//! thread, unblocking a parked read from another thread via `CancelIoEx` (see [`Killer`]).

#![cfg(windows)]

use std::io::{self, Read};
use std::sync::Arc;

use windows::core::PCWSTR;
use windows::Win32::Devices::Usb::{
    IOCTL_USB_GET_NODE_CONNECTION_INFORMATION, USB_NODE_CONNECTION_INFORMATION,
};
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_NONE, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::Win32::System::IO::{CancelIoEx, DeviceIoControl};

// --- IOCTL interface (USBPcap.h) --------------------------------------------------------

const FILE_DEVICE_UNKNOWN: u32 = 0x0000_0022;
const METHOD_BUFFERED: u32 = 0;
const FILE_READ_ACCESS: u32 = 0x0001;
const FILE_WRITE_ACCESS: u32 = 0x0002;

/// The Windows `CTL_CODE` macro: `(DeviceType<<16) | (Access<<14) | (Function<<2) | Method`.
const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

const IOCTL_USBPCAP_SETUP_BUFFER: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS);
const IOCTL_USBPCAP_START_FILTERING: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    0x801,
    METHOD_BUFFERED,
    FILE_READ_ACCESS | FILE_WRITE_ACCESS,
);
const IOCTL_USBPCAP_GET_HUB_SYMLINK: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, 0);
const IOCTL_USBPCAP_SET_SNAPLEN_SIZE: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS);

/// USBPcapCMD's defaults (`DEFAULT_SNAPSHOT_LENGTH`, `DEFAULT_INTERNAL_KERNEL_BUFFER_SIZE`).
pub const DEFAULT_SNAPLEN: u32 = 65535;
pub const DEFAULT_BUFFER: u32 = 1024 * 1024;

/// Parameter to the size-setting IOCTLs (`USBPCAP_IOCTL_SIZE`).
#[repr(C)]
struct IoctlSize {
    size: u32,
}

/// Parameter to `IOCTL_USBPCAP_START_FILTERING` (`USBPCAP_ADDRESS_FILTER`, `#pragma pack(1)`
/// → 17 bytes, no tail padding). `addresses` is a 128-bit bitmask of device addresses to
/// capture; bit 0 set means "also auto-capture newly connected devices".
#[repr(C, packed)]
struct AddressFilter {
    addresses: [u32; 4],
    filter_all: u8,
}

impl AddressFilter {
    fn new(addresses: &[u16], filter_all: bool) -> Self {
        let mut bits = [0u32; 4];
        for &a in addresses {
            if a < 128 {
                bits[(a / 32) as usize] |= 1 << (a % 32);
            }
        }
        Self {
            addresses: bits,
            filter_all: filter_all as u8,
        }
    }
}

// --- handle ownership -------------------------------------------------------------------

/// Sole owner of a device `HANDLE`; closes it exactly once on drop. Shared behind an `Arc`
/// so the reader and its [`Killer`] can both reference the handle without a double-close.
struct OwnedHandle(HANDLE);

// The handle is an opaque kernel object; moving/sharing the value across threads is sound
// (Win32 handles are process-global and the API calls we make on it are thread-safe).
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Cancels a blocking `ReadFile` parked on the capture handle, so the reader thread wakes and
/// sees EOF. Cheaply cloneable and `Send` (mirrors the process-killer used by the CLI backend).
#[derive(Clone)]
pub struct Killer(Arc<OwnedHandle>);

impl Killer {
    pub fn kill(&self) {
        unsafe {
            // Cancel any I/O issued on this handle by any thread; the parked ReadFile returns
            // ERROR_OPERATION_ABORTED, which [`DeviceReader::read`] maps to a clean EOF.
            let _ = CancelIoEx(self.0 .0, None);
        }
    }
}

// --- capture ----------------------------------------------------------------------------

/// A blocking reader over the driver's pcap stream. `read` issues one synchronous `ReadFile`;
/// a cancel/close (via [`Killer`]) surfaces as `Ok(0)` so the pcap layer treats it as EOF.
pub struct DeviceReader {
    handle: Arc<OwnedHandle>,
}

impl Read for DeviceReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut read: u32 = 0;
        let res = unsafe { ReadFile(self.handle.0, Some(buf), Some(&mut read), None) };
        match res {
            Ok(()) => Ok(read as usize),
            Err(e) => {
                // Stop path: the handle was cancelled or closed underneath us → clean EOF.
                const ABORTED: i32 = 0x8007_03E3u32 as i32; // HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED=995)
                const INVALID_HANDLE: i32 = 0x8007_0006u32 as i32; // ERROR_INVALID_HANDLE=6
                let code = e.code().0;
                if code == ABORTED || code == INVALID_HANDLE {
                    Ok(0)
                } else {
                    Err(io::Error::from_raw_os_error(code))
                }
            }
        }
    }
}

/// A started capture: the pcap byte stream plus a handle to stop it.
pub struct Capture {
    pub reader: DeviceReader,
    pub killer: Killer,
}

/// Encode a Rust string as a NUL-terminated UTF-16 buffer for the `*W` Win32 APIs.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Open a `\\.\USBPcapN` control device for capture and issue the start IOCTLs, matching
/// `create_filter_read_handle`: set snaplen, set buffer size, start filtering.
///
/// `addresses` are the USB device addresses to capture on this root hub; `filter_all` grabs
/// every device on the hub (ignoring `addresses`). Returns a [`Capture`] whose `reader`
/// yields the classic-pcap stream (global header first, then records).
pub fn open_capture(
    device: &str,
    addresses: &[u16],
    filter_all: bool,
    snaplen: u32,
    buffer_bytes: u32,
) -> anyhow::Result<Capture> {
    let path = wide(device);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            0xC000_0000u32, // GENERIC_READ | GENERIC_WRITE
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0), // synchronous
            None,
        )
    }
    .map_err(|e| anyhow::anyhow!("open {device} failed: {e} (USBPcap installed? admin?)"))?;

    if handle == INVALID_HANDLE_VALUE {
        anyhow::bail!("open {device} returned an invalid handle");
    }
    let owned = Arc::new(OwnedHandle(handle));

    // snaplen, then buffer size, then start filtering — order matters (see USBPcap thread.c).
    ioctl_set_size(&owned, IOCTL_USBPCAP_SET_SNAPLEN_SIZE, snaplen, "set snaplen")?;
    ioctl_set_size(&owned, IOCTL_USBPCAP_SETUP_BUFFER, buffer_bytes, "setup buffer")?;

    let filter = AddressFilter::new(addresses, filter_all);
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            owned.0,
            IOCTL_USBPCAP_START_FILTERING,
            Some(&filter as *const _ as *const _),
            std::mem::size_of::<AddressFilter>() as u32,
            None,
            0,
            Some(&mut returned),
            None,
        )
    }
    .map_err(|e| anyhow::anyhow!("start filtering on {device} failed: {e}"))?;

    Ok(Capture {
        reader: DeviceReader {
            handle: owned.clone(),
        },
        killer: Killer(owned),
    })
}

fn ioctl_set_size(handle: &OwnedHandle, code: u32, value: u32, what: &str) -> anyhow::Result<()> {
    let arg = IoctlSize { size: value };
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            handle.0,
            code,
            Some(&arg as *const _ as *const _),
            std::mem::size_of::<IoctlSize>() as u32,
            None,
            0,
            Some(&mut returned),
            None,
        )
    }
    .map_err(|e| anyhow::anyhow!("{what} failed: {e}"))?;
    Ok(())
}

/// Query a control device for the symbolic-link name of the root hub it filters
/// (`IOCTL_USBPCAP_GET_HUB_SYMLINK`). Used to map devices → control device. Returns the raw
/// symlink string, e.g. `\??\USB#ROOT_HUB30#4&2bd7ffc0&0&0#{f18a0e88-...}`.
pub fn get_hub_symlink(device: &str) -> anyhow::Result<String> {
    let path = wide(device);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            0xC000_0000u32,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .map_err(|e| anyhow::anyhow!("open {device} failed: {e}"))?;
    let owned = OwnedHandle(handle);

    // The driver writes a wide (UTF-16) string into our buffer.
    let mut buf = vec![0u16; 1024];
    let mut returned = 0u32;
    let res = unsafe {
        DeviceIoControl(
            owned.0,
            IOCTL_USBPCAP_GET_HUB_SYMLINK,
            None,
            0,
            Some(buf.as_mut_ptr() as *mut _),
            (buf.len() * 2) as u32,
            Some(&mut returned),
            None,
        )
    };
    res.map_err(|e| anyhow::anyhow!("get hub symlink for {device} failed: {e}"))?;

    let n = (returned as usize / 2).min(buf.len());
    let s: String = String::from_utf16_lossy(&buf[..n]);
    Ok(s.trim_end_matches('\0').trim().to_string())
}

/// Probe `\\.\USBPcap1..=max` and return the ones that open, paired with the hub symlink each
/// filters. This is how many live root-hub filters (buses) exist right now.
pub fn probe_control_devices(max: u16) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for n in 1..=max {
        let dev = format!("\\\\.\\USBPcap{n}");
        // A device that isn't present fails to open; skip it. If it opens, get its symlink.
        match get_hub_symlink(&dev) {
            Ok(sym) => out.push((dev, sym)),
            Err(_) => {
                // Distinguish "not present" from "present but symlink failed": if we can open
                // it at all, still record it (empty symlink) so capture can target it.
                if can_open(&dev) {
                    out.push((dev, String::new()));
                }
            }
        }
    }
    out
}

/// Resolve a connected device's real USB **bus address** (what USBPcap's filter matches on) by
/// asking its parent hub about the port it occupies (`IOCTL_USB_GET_NODE_CONNECTION_INFORMATION`
/// with `ConnectionIndex = port`). `SPDRP_ADDRESS` only gives the port number, not this address.
/// Opening a hub does not require elevation. Returns `None` if the hub/port can't be queried.
pub fn usb_device_address(hub_interface_path: &str, port: u32) -> Option<u16> {
    let path = wide(hub_interface_path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            0x4000_0000u32, // GENERIC_WRITE (matches USBPcap's hub open)
            FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .ok()?;
    let owned = OwnedHandle(handle);

    let mut info: USB_NODE_CONNECTION_INFORMATION = unsafe { std::mem::zeroed() };
    info.ConnectionIndex = port;
    let size = std::mem::size_of::<USB_NODE_CONNECTION_INFORMATION>() as u32;
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            owned.0,
            IOCTL_USB_GET_NODE_CONNECTION_INFORMATION,
            Some(&info as *const _ as *const _),
            size,
            Some(&mut info as *mut _ as *mut _),
            size,
            Some(&mut returned),
            None,
        )
    }
    .ok()?;
    Some(info.DeviceAddress)
}

fn can_open(device: &str) -> bool {
    let path = wide(device);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            0xC000_0000u32,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    };
    match handle {
        Ok(h) => {
            let _ = OwnedHandle(h); // close on drop
            true
        }
        Err(_) => {
            let _ = unsafe { GetLastError() };
            false
        }
    }
}
