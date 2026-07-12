//! Global input capture (DESIGN.md §5).
//!
//! The [`InputEvent`] schema is portable; the actual `WH_MOUSE_LL` / `WH_KEYBOARD_LL`
//! hooks are Windows-only. The hook callback must only timestamp + enqueue and return,
//! or Windows drops the hook (~300 ms `LowLevelHooksTimeout`). We honour that: the
//! callback reads the clock, builds an [`InputEvent`], and calls the sink (which the
//! recorder wires to a non-blocking channel send).

pub use reveng_core::input::{InputEvent, InputKind};
use reveng_core::clock::Clock;

/// Handle to installed hooks; dropping it uninstalls them and joins the hook thread.
pub struct InputHooks {
    #[cfg(windows)]
    thread_id: u32,
    #[cfg(windows)]
    join: Option<std::thread::JoinHandle<()>>,
}

impl InputHooks {
    /// Uninstall the hooks and wait for the hook thread to exit.
    pub fn stop(mut self) {
        self.stop_inner();
    }

    #[cfg(windows)]
    fn stop_inner(&mut self) {
        use windows::Win32::UI::WindowsAndMessaging::{PostThreadMessageW, WM_QUIT};
        if let Some(join) = self.join.take() {
            unsafe {
                let _ = PostThreadMessageW(
                    self.thread_id,
                    WM_QUIT,
                    windows::Win32::Foundation::WPARAM(0),
                    windows::Win32::Foundation::LPARAM(0),
                );
            }
            let _ = join.join();
        }
    }

    #[cfg(not(windows))]
    fn stop_inner(&mut self) {}
}

impl Drop for InputHooks {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

/// Install the low-level hooks and forward events to `sink`. Windows-only.
///
/// `clock` is the shared session clock, so events land on the unified timeline. The
/// hooks run on a dedicated message-loop thread owned by the returned [`InputHooks`].
pub fn install<F>(clock: Clock, sink: F) -> anyhow::Result<InputHooks>
where
    F: FnMut(InputEvent) + Send + 'static,
{
    #[cfg(windows)]
    {
        imp::install(clock, sink)
    }
    #[cfg(not(windows))]
    {
        let _ = (clock, sink);
        anyhow::bail!("input capture requires Windows")
    }
}

/// Snapshot the foreground window's process name + title, for checkpoint context
/// enrichment (DESIGN.md §5). Done off the hook path when a checkpoint fires.
pub fn foreground_context() -> (Option<String>, Option<String>) {
    #[cfg(windows)]
    {
        imp::foreground_context()
    }
    #[cfg(not(windows))]
    {
        (None, None)
    }
}

#[cfg(windows)]
mod imp {
    use super::{InputEvent, InputKind};
    use reveng_core::clock::Clock;
    use std::cell::RefCell;
    use windows::Win32::Foundation::{LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, GetMessageW, SetWindowsHookExW, UnhookWindowsHookEx, KBDLLHOOKSTRUCT,
        LLKHF_INJECTED, LLMHF_INJECTED, MSG, MSLLHOOKSTRUCT, WH_KEYBOARD_LL, WH_MOUSE_LL,
        WM_KEYDOWN, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MBUTTONDOWN, WM_MBUTTONUP, WM_MOUSEWHEEL,
        WM_RBUTTONDOWN, WM_RBUTTONUP, WM_SYSKEYDOWN, WM_XBUTTONDOWN, WM_XBUTTONUP, XBUTTON1,
    };

    struct HookState {
        clock: Clock,
        sink: Box<dyn FnMut(InputEvent)>,
    }

    thread_local! {
        static STATE: RefCell<Option<HookState>> = const { RefCell::new(None) };
    }

    fn emit(ev: InputEvent) {
        STATE.with(|s| {
            if let Some(st) = s.borrow_mut().as_mut() {
                (st.sink)(ev);
            }
        });
    }

    fn now_ns() -> i64 {
        STATE.with(|s| s.borrow().as_ref().map(|st| st.clock.now_ns()).unwrap_or(0))
    }

    unsafe extern "system" fn mouse_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        if code >= 0 {
            let ms = &*(lparam.0 as *const MSLLHOOKSTRUCT);
            let injected = ms.flags & LLMHF_INJECTED != 0;
            let msg = wparam.0 as u32;
            let mk = |kind: InputKind, button: Option<&str>| InputEvent {
                ts_ns: now_ns(),
                kind,
                button: button.map(|b| b.to_string()),
                vk: None,
                scancode: None,
                x: ms.pt.x,
                y: ms.pt.y,
                injected,
            };
            // XBUTTON1/2 are distinguished by the high word of mouseData.
            let xbtn = if (ms.mouseData >> 16) as u16 == XBUTTON1 { "X1" } else { "X2" };
            let ev = match msg {
                WM_LBUTTONDOWN => Some(mk(InputKind::MouseDown, Some("L"))),
                WM_LBUTTONUP => Some(mk(InputKind::MouseUp, Some("L"))),
                WM_RBUTTONDOWN => Some(mk(InputKind::MouseDown, Some("R"))),
                WM_RBUTTONUP => Some(mk(InputKind::MouseUp, Some("R"))),
                WM_MBUTTONDOWN => Some(mk(InputKind::MouseDown, Some("M"))),
                WM_MBUTTONUP => Some(mk(InputKind::MouseUp, Some("M"))),
                WM_XBUTTONDOWN => Some(mk(InputKind::MouseDown, Some(xbtn))),
                WM_XBUTTONUP => Some(mk(InputKind::MouseUp, Some(xbtn))),
                WM_MOUSEWHEEL => Some(mk(InputKind::Wheel, None)),
                _ => None, // mouse moves are deliberately not logged (§5)
            };
            if let Some(ev) = ev {
                emit(ev);
            }
        }
        CallNextHookEx(None, code, wparam, lparam)
    }

    unsafe extern "system" fn kbd_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        if code >= 0 {
            let kb = &*(lparam.0 as *const KBDLLHOOKSTRUCT);
            let msg = wparam.0 as u32;
            let kind = if msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN {
                InputKind::KeyDown
            } else {
                InputKind::KeyUp
            };
            emit(InputEvent {
                ts_ns: now_ns(),
                kind,
                button: None,
                vk: Some(kb.vkCode as u16),
                scancode: Some(kb.scanCode as u16),
                x: 0,
                y: 0,
                injected: kb.flags.0 & LLKHF_INJECTED.0 != 0,
            });
        }
        CallNextHookEx(None, code, wparam, lparam)
    }

    pub fn install<F>(clock: Clock, sink: F) -> anyhow::Result<super::InputHooks>
    where
        F: FnMut(InputEvent) + Send + 'static,
    {
        // The hook thread reports install success/failure and its own thread id back here.
        let (tx, rx) = std::sync::mpsc::channel::<anyhow::Result<u32>>();
        let mut sink = Some(sink);

        let join = std::thread::Builder::new()
            .name("winput-hooks".into())
            .spawn(move || {
                let sink = sink.take().unwrap();
                STATE.with(|s| {
                    *s.borrow_mut() = Some(HookState {
                        clock,
                        sink: Box::new(sink),
                    });
                });

                let (mouse_hook, kbd_hook) = unsafe {
                    let hmod = match GetModuleHandleW(None) {
                        Ok(h) => h,
                        Err(e) => {
                            let _ = tx.send(Err(anyhow::anyhow!("GetModuleHandleW: {e}")));
                            return;
                        }
                    };
                    let m = SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_proc), Some(hmod.into()), 0);
                    let k = SetWindowsHookExW(WH_KEYBOARD_LL, Some(kbd_proc), Some(hmod.into()), 0);
                    match (m, k) {
                        (Ok(m), Ok(k)) => (m, k),
                        (m, k) => {
                            if let Ok(h) = m {
                                let _ = UnhookWindowsHookEx(h);
                            }
                            if let Ok(h) = k {
                                let _ = UnhookWindowsHookEx(h);
                            }
                            let _ = tx.send(Err(anyhow::anyhow!("SetWindowsHookExW failed")));
                            return;
                        }
                    }
                };

                let tid = unsafe { windows::Win32::System::Threading::GetCurrentThreadId() };
                let _ = tx.send(Ok(tid));

                // Message loop: LL hooks are delivered on this thread; WM_QUIT (from
                // InputHooks::stop) ends it.
                let mut msg = MSG::default();
                unsafe {
                    while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
                        // No dispatch needed; the hook procs fire out of band.
                    }
                    let _ = UnhookWindowsHookEx(mouse_hook);
                    let _ = UnhookWindowsHookEx(kbd_hook);
                }
                STATE.with(|s| *s.borrow_mut() = None);
            })?;

        match rx.recv() {
            Ok(Ok(thread_id)) => Ok(super::InputHooks {
                thread_id,
                join: Some(join),
            }),
            Ok(Err(e)) => {
                let _ = join.join();
                Err(e)
            }
            Err(_) => {
                let _ = join.join();
                anyhow::bail!("hook thread exited before reporting status")
            }
        }
    }

    pub fn foreground_context() -> (Option<String>, Option<String>) {
        use windows::Win32::Foundation::{CloseHandle, MAX_PATH};
        use windows::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
            PROCESS_QUERY_LIMITED_INFORMATION,
        };
        use windows::Win32::UI::WindowsAndMessaging::{
            GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId,
        };

        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.0.is_null() {
                return (None, None);
            }

            // Window title.
            let mut title_buf = [0u16; 512];
            let n = GetWindowTextW(hwnd, &mut title_buf);
            let title = if n > 0 {
                Some(String::from_utf16_lossy(&title_buf[..n as usize]))
            } else {
                None
            };

            // Process name (file name of the full image path).
            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            let mut process = None;
            if pid != 0 {
                if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                    let mut buf = [0u16; MAX_PATH as usize];
                    let mut len = buf.len() as u32;
                    let mut pwstr = windows::core::PWSTR(buf.as_mut_ptr());
                    if QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, pwstr, &mut len).is_ok()
                    {
                        let full = String::from_utf16_lossy(&buf[..len as usize]);
                        process = full.rsplit(['\\', '/']).next().map(|s| s.to_string());
                    }
                    let _ = &mut pwstr;
                    let _ = CloseHandle(handle);
                }
            }
            (process, title)
        }
    }
}
