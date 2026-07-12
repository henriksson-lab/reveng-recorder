//! Event-triggered screenshots (DESIGN.md §6).
//!
//! GDI `BitBlt` from the screen DC is the default path — simple, reliable, event-driven,
//! so there is no need for a streaming grabber. DXGI Desktop Duplication is left as the
//! opt-in high-rate path (not wired here). Encoding is lossless PNG.

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

/// A grabbed frame: tightly-packed RGB8, `width * height * 3` bytes.
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub rgb: Vec<u8>,
}

/// Grab a screenshot and write it (PNG) to `out`. Windows-only.
pub fn capture_to(out: &Path, scope: Scope) -> anyhow::Result<()> {
    let frame = capture(scope)?;
    encode_png(&frame, out)
}

/// Grab a screenshot into memory (RGB8). Windows-only.
pub fn capture(scope: Scope) -> anyhow::Result<Frame> {
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
    use super::{Frame, Scope};
    use windows::Win32::Foundation::{POINT, RECT};
    use windows::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC,
        GetDIBits, GetMonitorInfoW, MonitorFromPoint, ReleaseDC, SelectObject, BITMAPINFO,
        BITMAPINFOHEADER, BI_RGB, CAPTUREBLT, DIB_RGB_COLORS, HGDIOBJ, MONITORINFO,
        MONITOR_DEFAULTTONEAREST, SRCCOPY,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetCursorPos, GetForegroundWindow, GetSystemMetrics, GetWindowRect, SM_CXVIRTUALSCREEN,
        SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    };

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

    pub fn capture(scope: Scope) -> anyhow::Result<Frame> {
        let rect = scope_rect(scope)?;
        let width = (rect.right - rect.left).max(1);
        let height = (rect.bottom - rect.top).max(1);

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
            BitBlt(
                mem, 0, 0, width, height, Some(screen), rect.left, rect.top,
                SRCCOPY | CAPTUREBLT,
            )?;
            SelectObject(mem, old);

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
            let mut bgra = vec![0u8; (width as usize) * (height as usize) * 4];
            let got = GetDIBits(
                mem,
                bmp,
                0,
                height as u32,
                Some(bgra.as_mut_ptr() as *mut _),
                &mut bi,
                DIB_RGB_COLORS,
            );
            if got == 0 {
                anyhow::bail!("GetDIBits returned 0 scanlines");
            }

            // BGRA (GDI) -> RGB. GDI's alpha byte is meaningless, so drop it.
            let mut rgb = vec![0u8; (width as usize) * (height as usize) * 3];
            for (src, dst) in bgra.chunks_exact(4).zip(rgb.chunks_exact_mut(3)) {
                dst[0] = src[2]; // R
                dst[1] = src[1]; // G
                dst[2] = src[0]; // B
            }

            Ok(Frame {
                width: width as u32,
                height: height as u32,
                rgb,
            })
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
