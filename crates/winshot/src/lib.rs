//! Event-triggered screenshots (DESIGN.md §6).
//!
//! GDI `BitBlt` from the screen DC is the default path — simple, reliable, event-driven,
//! so there is no need for a streaming grabber. DXGI Desktop Duplication is left as the
//! opt-in high-rate path (not wired here). Encoding is lossless PNG.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The monitor under the cursor (default — that's where the action is).
    CursorMonitor,
    /// The whole virtual desktop (all monitors).
    All,
    /// Just the foreground window's rectangle (smaller files).
    ForegroundWindow,
}

impl Scope {
    pub fn name(self) -> &'static str {
        match self {
            Scope::CursorMonitor => "cursor-monitor",
            Scope::All => "all",
            Scope::ForegroundWindow => "foreground-window",
        }
    }
}

/// A grabbed frame: tightly-packed RGB8, `width * height * 3` bytes.
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub rgb: Vec<u8>,
}

/// The spatial context of one screenshot: where its top-left sits in virtual-screen
/// coordinates, its size, the cursor at capture time, and which monitor it came from.
/// This is what lets later analysis map an absolute cursor / an OCR bounding box back to
/// a pixel in the PNG (pixel = absolute − origin).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Geometry {
    /// Top-left of the capture rectangle in virtual-screen coordinates (may be negative).
    pub origin_x: i32,
    pub origin_y: i32,
    pub width: u32,
    pub height: u32,
    /// Cursor position (virtual-screen coords) sampled at capture time.
    pub cursor_x: i32,
    pub cursor_y: i32,
    /// Index into [`enumerate_displays`] of the monitor under the cursor (−1 if unknown).
    pub monitor_index: i32,
    /// Effective DPI of that monitor (0 if unknown). 96 = 100% scaling.
    pub dpi: u32,
    pub scope: &'static str,
}

impl Geometry {
    /// Map an absolute (virtual-screen) point to a pixel in this screenshot.
    pub fn to_pixel(&self, x: i32, y: i32) -> (i32, i32) {
        (x - self.origin_x, y - self.origin_y)
    }
    /// The cursor as a pixel within this screenshot.
    pub fn cursor_pixel(&self) -> (i32, i32) {
        self.to_pixel(self.cursor_x, self.cursor_y)
    }
}

/// One monitor in the desktop layout (from [`enumerate_displays`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Display {
    pub index: i32,
    pub primary: bool,
    /// Full monitor bounds in virtual-screen coordinates.
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    /// Work area (monitor minus taskbar).
    pub work_x: i32,
    pub work_y: i32,
    pub work_width: i32,
    pub work_height: i32,
    pub dpi: u32,
}

/// Grab a screenshot, write it (PNG) to `out`, and return its [`Geometry`]. Windows-only.
pub fn capture_to(out: &Path, scope: Scope) -> anyhow::Result<Geometry> {
    let (frame, geom) = capture_geom(scope)?;
    encode_png(&frame, out)?;
    Ok(geom)
}

/// Grab a screenshot into memory (RGB8). Windows-only.
pub fn capture(scope: Scope) -> anyhow::Result<Frame> {
    Ok(capture_geom(scope)?.0)
}

/// Grab a screenshot plus its spatial [`Geometry`]. Windows-only.
pub fn capture_geom(scope: Scope) -> anyhow::Result<(Frame, Geometry)> {
    #[cfg(windows)]
    {
        imp::capture(scope)
    }
    #[cfg(not(windows))]
    {
        let _ = scope;
        anyhow::bail!("screen capture requires Windows")
    }
}

/// Enumerate the monitors making up the desktop (bounds, work area, primary flag, DPI).
/// Empty on non-Windows.
pub fn enumerate_displays() -> anyhow::Result<Vec<Display>> {
    #[cfg(windows)]
    {
        Ok(imp::enumerate_displays())
    }
    #[cfg(not(windows))]
    {
        Ok(Vec::new())
    }
}

/// Encode a grabbed [`Frame`] to a PNG file (lossless — UI text/edges matter, §6).
pub fn encode_png(frame: &Frame, out: &Path) -> anyhow::Result<()> {
    let img: image::RgbImage =
        image::ImageBuffer::from_raw(frame.width, frame.height, frame.rgb.clone())
            .ok_or_else(|| anyhow::anyhow!("frame buffer size does not match {}x{}", frame.width, frame.height))?;
    img.save_with_format(out, image::ImageFormat::Png)?;
    Ok(())
}

#[cfg(windows)]
mod imp {
    use super::{Display, Frame, Geometry, Scope};
    use windows::core::BOOL;
    use windows::Win32::Foundation::{LPARAM, POINT, RECT};

    /// `MONITORINFO::dwFlags` primary-monitor bit (winuser.h `MONITORINFOF_PRIMARY`).
    const MONITORINFOF_PRIMARY: u32 = 0x0000_0001;
    use windows::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC,
        EnumDisplayMonitors, GetDIBits, GetMonitorInfoW, MonitorFromPoint, ReleaseDC, SelectObject,
        BITMAPINFO, BITMAPINFOHEADER, BI_RGB, CAPTUREBLT, DIB_RGB_COLORS, HDC, HGDIOBJ, HMONITOR,
        MONITORINFO, MONITOR_DEFAULTTONEAREST, SRCCOPY,
    };
    use windows::Win32::UI::HiDpi::{GetDpiForMonitor, MDT_EFFECTIVE_DPI};
    use windows::Win32::UI::WindowsAndMessaging::{
        GetCursorPos, GetForegroundWindow, GetSystemMetrics, GetWindowRect, SM_CXVIRTUALSCREEN,
        SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    };

    const MAX_CAPTURE_PIXELS: usize = 100_000_000;

    /// Effective DPI of a monitor (96 = 100%); 0 if the query fails.
    fn monitor_dpi(mon: HMONITOR) -> u32 {
        let (mut dx, mut dy) = (0u32, 0u32);
        unsafe {
            if GetDpiForMonitor(mon, MDT_EFFECTIVE_DPI, &mut dx, &mut dy).is_ok() {
                dx
            } else {
                0
            }
        }
    }

    /// Enumerate all monitors (bounds, work area, primary flag, DPI).
    pub fn enumerate_displays() -> Vec<Display> {
        unsafe extern "system" fn cb(mon: HMONITOR, _dc: HDC, _r: *mut RECT, lp: LPARAM) -> BOOL {
            let out = &mut *(lp.0 as *mut Vec<Display>);
            let mut mi = MONITORINFO {
                cbSize: std::mem::size_of::<MONITORINFO>() as u32,
                ..Default::default()
            };
            if GetMonitorInfoW(mon, &mut mi).as_bool() {
                let m = mi.rcMonitor;
                let w = mi.rcWork;
                out.push(Display {
                    index: out.len() as i32,
                    primary: mi.dwFlags & MONITORINFOF_PRIMARY != 0,
                    x: m.left,
                    y: m.top,
                    width: m.right - m.left,
                    height: m.bottom - m.top,
                    work_x: w.left,
                    work_y: w.top,
                    work_width: w.right - w.left,
                    work_height: w.bottom - w.top,
                    dpi: monitor_dpi(mon),
                });
            }
            BOOL(1)
        }
        let mut out: Vec<Display> = Vec::new();
        unsafe {
            let _ = EnumDisplayMonitors(None, None, Some(cb), LPARAM(&mut out as *mut _ as isize));
        }
        out
    }

    /// Index into [`enumerate_displays`] of the monitor containing `pt` (−1 if none).
    fn monitor_index_at(pt: POINT) -> i32 {
        enumerate_displays()
            .iter()
            .find(|d| pt.x >= d.x && pt.x < d.x + d.width && pt.y >= d.y && pt.y < d.y + d.height)
            .map(|d| d.index)
            .unwrap_or(-1)
    }

    /// The capture rectangle in virtual-screen coordinates (may be negative on the left/top).
    fn scope_rect(scope: Scope) -> anyhow::Result<RECT> {
        unsafe {
            match scope {
                Scope::All => Ok(RECT {
                    left: GetSystemMetrics(SM_XVIRTUALSCREEN),
                    top: GetSystemMetrics(SM_YVIRTUALSCREEN),
                    right: GetSystemMetrics(SM_XVIRTUALSCREEN) + GetSystemMetrics(SM_CXVIRTUALSCREEN),
                    bottom: GetSystemMetrics(SM_YVIRTUALSCREEN) + GetSystemMetrics(SM_CYVIRTUALSCREEN),
                }),
                Scope::CursorMonitor => {
                    let mut pt = POINT::default();
                    GetCursorPos(&mut pt)?;
                    let mon = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
                    let mut mi = MONITORINFO {
                        cbSize: std::mem::size_of::<MONITORINFO>() as u32,
                        ..Default::default()
                    };
                    if !GetMonitorInfoW(mon, &mut mi).as_bool() {
                        anyhow::bail!("GetMonitorInfoW failed");
                    }
                    Ok(mi.rcMonitor)
                }
                Scope::ForegroundWindow => {
                    let hwnd = GetForegroundWindow();
                    if hwnd.0.is_null() {
                        anyhow::bail!("no foreground window");
                    }
                    let mut r = RECT::default();
                    GetWindowRect(hwnd, &mut r)?;
                    Ok(r)
                }
            }
        }
    }

    pub fn capture(scope: Scope) -> anyhow::Result<(Frame, Geometry)> {
        let rect = scope_rect(scope)?;
        let width64 = i64::from(rect.right) - i64::from(rect.left);
        let height64 = i64::from(rect.bottom) - i64::from(rect.top);
        if width64 <= 0 || height64 <= 0 || width64 > i64::from(i32::MAX) || height64 > i64::from(i32::MAX) {
            anyhow::bail!("invalid capture rectangle {rect:?}");
        }
        let width = width64 as i32;
        let height = height64 as i32;
        let pixels = (width as usize)
            .checked_mul(height as usize)
            .filter(|&n| n <= MAX_CAPTURE_PIXELS)
            .ok_or_else(|| anyhow::anyhow!("capture rectangle is too large: {width}x{height}"))?;

        unsafe {
            // Screen DC (origin at the primary monitor; BitBlt reaches other monitors via
            // possibly-negative source coordinates).
            let screen = GetDC(None);
            if screen.is_invalid() {
                anyhow::bail!("GetDC(screen) failed");
            }
            // Guard that always releases the screen DC.
            let _screen_guard = ScreenDc(screen);

            let mem = CreateCompatibleDC(Some(screen));
            if mem.is_invalid() {
                anyhow::bail!("CreateCompatibleDC failed");
            }
            let _mem_guard = MemDc(mem);

            let bmp = CreateCompatibleBitmap(screen, width, height);
            if bmp.is_invalid() {
                anyhow::bail!("CreateCompatibleBitmap failed");
            }
            let _bmp_guard = Bitmap(bmp);

            let old = SelectObject(mem, HGDIOBJ(bmp.0));
            // Restore the previous selection before propagating a blit failure. A bitmap
            // cannot be deleted while selected into a DC, so returning directly from
            // `BitBlt(...)?` would leak the bitmap on this error path.
            let blit = BitBlt(
                mem, 0, 0, width, height, Some(screen), rect.left, rect.top,
                SRCCOPY | CAPTUREBLT,
            );
            SelectObject(mem, old);
            blit?;

            // Pull pixels as top-down 32bpp BGRA via GetDIBits.
            let mut bi = BITMAPINFO {
                bmiHeader: BITMAPINFOHEADER {
                    biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                    biWidth: width,
                    biHeight: -height, // negative => top-down rows
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB.0,
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut bgra = vec![0u8; pixels * 4];
            let got = GetDIBits(
                mem,
                bmp,
                0,
                height as u32,
                Some(bgra.as_mut_ptr() as *mut _),
                &mut bi,
                DIB_RGB_COLORS,
            );
            if got != height {
                anyhow::bail!("GetDIBits returned {got} of {height} scanlines");
            }

            // BGRA (GDI) -> RGB. GDI's alpha byte is meaningless, so drop it.
            let mut rgb = vec![0u8; pixels * 3];
            for (src, dst) in bgra.chunks_exact(4).zip(rgb.chunks_exact_mut(3)) {
                dst[0] = src[2]; // R
                dst[1] = src[1]; // G
                dst[2] = src[0]; // B
            }

            // Spatial context, sampled at capture time.
            let mut cur = POINT::default();
            let _ = GetCursorPos(&mut cur);
            let mon = MonitorFromPoint(cur, MONITOR_DEFAULTTONEAREST);
            let geom = Geometry {
                origin_x: rect.left,
                origin_y: rect.top,
                width: width as u32,
                height: height as u32,
                cursor_x: cur.x,
                cursor_y: cur.y,
                monitor_index: monitor_index_at(cur),
                dpi: monitor_dpi(mon),
                scope: scope.name(),
            };

            Ok((
                Frame {
                    width: width as u32,
                    height: height as u32,
                    rgb,
                },
                geom,
            ))
        }
    }

    // --- RAII guards so a mid-capture error still frees GDI objects ---
    struct ScreenDc(windows::Win32::Graphics::Gdi::HDC);
    impl Drop for ScreenDc {
        fn drop(&mut self) {
            unsafe { ReleaseDC(None, self.0) };
        }
    }
    struct MemDc(windows::Win32::Graphics::Gdi::HDC);
    impl Drop for MemDc {
        fn drop(&mut self) {
            unsafe {
                let _ = DeleteDC(self.0);
            }
        }
    }
    struct Bitmap(windows::Win32::Graphics::Gdi::HBITMAP);
    impl Drop for Bitmap {
        fn drop(&mut self) {
            unsafe {
                let _ = DeleteObject(HGDIOBJ(self.0 .0));
            }
        }
    }
}
