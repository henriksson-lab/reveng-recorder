//! Self-elevation via UAC (Windows). Passive USB capture opens `\\.\USBPcapN`, which requires
//! administrator rights. Rather than make the user launch an elevated shell, `reveng-rec record`
//! detects it isn't elevated and relaunches *itself* through `ShellExecuteEx`'s `runas` verb —
//! the UAC consent/password prompt. The elevated instance is a separate process (its own
//! console); the original waits for it and exits with its code.
//!
//! Set `REVENG_NO_ELEVATE` to suppress this (e.g. automation that manages elevation itself).

/// True if the current process token is elevated (always true off Windows, so callers skip).
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        imp::is_elevated().unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        true
    }
}

/// Relaunch this executable elevated with `args` (everything after the program name),
/// inheriting the current working directory. Returns the child's exit code.
#[cfg(windows)]
pub fn relaunch_elevated(args: &[String]) -> anyhow::Result<u32> {
    imp::relaunch_elevated(args)
}

/// Enable `SeDebugPrivilege` in this process token so `OpenProcess(PROCESS_VM_READ)` reaches
/// targets owned by other users (needed for memory snapshots). Best-effort: it's present only
/// in an elevated token, and enterprise policy can remove it — on failure the later
/// `OpenProcess` just returns a clear error. No-op off Windows.
pub fn enable_debug_privilege() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        imp::enable_debug_privilege()
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

#[cfg(windows)]
mod imp {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_CANCELLED, ERROR_NOT_ALL_ASSIGNED, HANDLE,
    };
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject, INFINITE,
    };
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    pub fn is_elevated() -> anyhow::Result<bool> {
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
            let mut elevation = TOKEN_ELEVATION::default();
            let mut ret_len = 0u32;
            let res = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            );
            let _ = CloseHandle(token);
            res?;
            Ok(elevation.TokenIsElevated != 0)
        }
    }

    pub fn enable_debug_privilege() -> anyhow::Result<()> {
        use windows::core::w;
        use windows::Win32::Foundation::LUID;
        use windows::Win32::Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES,
            SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
        };
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )?;
            let mut luid = LUID::default();
            let looked = LookupPrivilegeValueW(None, w!("SeDebugPrivilege"), &mut luid);
            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
            };
            let adjusted = AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None);
            let adjust_error = GetLastError();
            let _ = CloseHandle(token);
            looked?;
            adjusted?;
            if adjust_error == ERROR_NOT_ALL_ASSIGNED {
                anyhow::bail!("SeDebugPrivilege is not present in this process token");
            }
        }
        Ok(())
    }

    pub fn relaunch_elevated(args: &[String]) -> anyhow::Result<u32> {
        let exe = std::env::current_exe()?;
        let cwd = std::env::current_dir()?;
        let params = args
            .iter()
            .map(|a| quote_arg(a))
            .collect::<Vec<_>>()
            .join(" ");

        let exe_w = wide(&exe.to_string_lossy());
        let params_w = wide(&params);
        let cwd_w = wide(&cwd.to_string_lossy());
        let verb_w = wide("runas");

        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: PCWSTR(verb_w.as_ptr()),
            lpFile: PCWSTR(exe_w.as_ptr()),
            lpParameters: PCWSTR(params_w.as_ptr()),
            lpDirectory: PCWSTR(cwd_w.as_ptr()),
            nShow: SW_SHOWNORMAL.0,
            ..Default::default()
        };

        unsafe {
            ShellExecuteExW(&mut info).map_err(|e| {
                if e.code() == ERROR_CANCELLED.to_hresult() {
                    anyhow::anyhow!("elevation was declined at the UAC prompt")
                } else {
                    anyhow::anyhow!("failed to relaunch elevated: {e}")
                }
            })?;

            if info.hProcess.is_invalid() {
                anyhow::bail!("elevated relaunch returned no process handle");
            }
            WaitForSingleObject(info.hProcess, INFINITE);
            let mut code = 0u32;
            GetExitCodeProcess(info.hProcess, &mut code)?;
            let _ = CloseHandle(info.hProcess);
            Ok(code)
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Quote a single argument for a Windows command line (simplified CommandLineToArgvW rules).
    fn quote_arg(arg: &str) -> String {
        if !arg.is_empty() && !arg.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
            return arg.to_string();
        }
        let mut out = String::from('"');
        let mut backslashes = 0usize;
        for c in arg.chars() {
            match c {
                '\\' => {
                    backslashes += 1;
                    out.push('\\');
                }
                '"' => {
                    // Escape all pending backslashes, then the quote.
                    out.extend(std::iter::repeat_n('\\', backslashes));
                    backslashes = 0;
                    out.push('\\');
                    out.push('"');
                }
                _ => {
                    backslashes = 0;
                    out.push(c);
                }
            }
        }
        out.extend(std::iter::repeat_n('\\', backslashes)); // double trailing before closing "
        out.push('"');
        out
    }
}
