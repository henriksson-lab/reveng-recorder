//! Global input capture (DESIGN.md §5).
//!
//! The [`InputEvent`] schema is portable; the actual `WH_MOUSE_LL` / `WH_KEYBOARD_LL`
//! hooks are Windows-only. The hook callback must only timestamp + enqueue and return,
//! or Windows drops the hook (~300 ms `LowLevelHooksTimeout`).

pub use reveng_core::input::{InputEvent, InputKind};

/// Handle to installed hooks; dropping it uninstalls them.
pub struct InputHooks {
    _private: (),
}

/// Install the low-level hooks and forward events to `sink`. Windows-only.
pub fn install<F>(_sink: F) -> anyhow::Result<InputHooks>
where
    F: FnMut(InputEvent) + Send + 'static,
{
    #[cfg(windows)]
    {
        // TODO: SetWindowsHookExW(WH_MOUSE_LL/WH_KEYBOARD_LL) on a dedicated message-loop
        // thread; callback timestamps via QPC and enqueues only (DESIGN.md §5).
        anyhow::bail!("input hooks not yet implemented")
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("input capture requires Windows")
    }
}
