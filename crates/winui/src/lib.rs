//! Capture the **UI-Automation** widget tree of a window — the typed control tree Windows
//! already publishes for screen readers. Far more reliable than pixel/OCR analysis: every
//! control comes with its type (Button/CheckBox/RadioButton/Slider/Edit/…), bounding rect,
//! label, and live state/value (a checkbox's toggle, a slider's numeric value, …).
//!
//! This is the structured "screen side" oracle: recorded alongside each screenshot it tells
//! you exactly which widget a click hit and what its value was — e.g. `Slider "Exposure Time"
//! = 178.629`, no OCR guessing.
//!
//! Windows-only; a stub returns empty elsewhere so the workspace still builds cross-platform.

use serde::{Deserialize, Serialize};

/// One UI-Automation element, flattened (subtree order).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiElement {
    /// Control-type name ("Button", "CheckBox", "Slider", …).
    pub role: String,
    /// Raw UIA control-type id (50000 = Button, …), for anything not in the name table.
    pub control_type: i32,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub automation_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub class_name: String,
    /// Bounding rectangle in **virtual-screen** coordinates (same frame as screenshot geometry).
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    /// Nesting depth in the tree (0 = the root window).
    pub depth: u32,
    // --- live state, present only when the control supports the pattern ---
    /// Toggle pattern (CheckBox / toggle Button): "on" | "off" | "indeterminate".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toggle: Option<String>,
    /// SelectionItem pattern (RadioButton / ListItem / TabItem): is it selected?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected: Option<bool>,
    /// Value pattern (Edit / ComboBox): the text value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// RangeValue pattern (Slider / Spinner / ProgressBar): the numeric value + bounds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range_value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range_min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range_max: Option<f64>,
}

impl UiElement {
    /// Does this control carry interactive state worth surfacing (button/checkbox/slider/…)?
    pub fn is_interactive(&self) -> bool {
        self.toggle.is_some()
            || self.selected.is_some()
            || self.value.is_some()
            || self.range_value.is_some()
            || matches!(
                self.control_type,
                50000 | 50002 | 50003 | 50004 | 50013 | 50015 | 50016 | 50019 | 50011 | 50031
            )
    }
}

/// A top-level window (from [`list_windows`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowInfo {
    pub hwnd: isize,
    pub title: String,
    pub class_name: String,
}

/// Human name for a UIA control-type id (the common ones; unknown → "Type<id>").
pub fn control_type_name(id: i32) -> String {
    let n = match id {
        50000 => "Button",
        50001 => "Calendar",
        50002 => "CheckBox",
        50003 => "ComboBox",
        50004 => "Edit",
        50005 => "Hyperlink",
        50006 => "Image",
        50007 => "ListItem",
        50008 => "List",
        50009 => "Menu",
        50010 => "MenuBar",
        50011 => "MenuItem",
        50012 => "ProgressBar",
        50013 => "RadioButton",
        50014 => "ScrollBar",
        50015 => "Slider",
        50016 => "Spinner",
        50017 => "StatusBar",
        50018 => "Tab",
        50019 => "TabItem",
        50020 => "Text",
        50021 => "ToolBar",
        50022 => "ToolTip",
        50023 => "Tree",
        50024 => "TreeItem",
        50025 => "Custom",
        50026 => "Group",
        50027 => "Thumb",
        50028 => "DataGrid",
        50029 => "DataItem",
        50030 => "Document",
        50031 => "SplitButton",
        50032 => "Window",
        50033 => "Pane",
        50034 => "Header",
        50035 => "HeaderItem",
        50036 => "Table",
        50037 => "TitleBar",
        50038 => "Separator",
        _ => return format!("Type{id}"),
    };
    n.to_string()
}

/// List visible top-level windows that have a title. Windows-only ([] elsewhere).
pub fn list_windows() -> Vec<WindowInfo> {
    #[cfg(windows)]
    {
        imp::list_windows()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// Snapshot the UIA widget tree of the first top-level window whose title contains `substr`
/// (case-insensitive). `Ok(None)` = no matching window. Windows-only.
pub fn snapshot_by_title(substr: &str) -> anyhow::Result<Option<Vec<UiElement>>> {
    #[cfg(windows)]
    {
        imp::snapshot_by_title(substr)
    }
    #[cfg(not(windows))]
    {
        let _ = substr;
        anyhow::bail!("UI Automation requires Windows")
    }
}

/// Snapshot the UIA widget tree of a specific window handle. Windows-only.
pub fn snapshot_hwnd(hwnd: isize) -> anyhow::Result<Vec<UiElement>> {
    #[cfg(windows)]
    {
        imp::snapshot_hwnd(hwnd)
    }
    #[cfg(not(windows))]
    {
        let _ = hwnd;
        anyhow::bail!("UI Automation requires Windows")
    }
}

/// Snapshot the root window containing screen point `(x, y)` — i.e. the window the user just
/// clicked. Empty if there is no window there. Windows-only.
pub fn snapshot_at_point(x: i32, y: i32) -> anyhow::Result<Vec<UiElement>> {
    #[cfg(windows)]
    {
        imp::snapshot_at_point(x, y)
    }
    #[cfg(not(windows))]
    {
        let _ = (x, y);
        anyhow::bail!("UI Automation requires Windows")
    }
}

/// Snapshot the current foreground window's tree. Windows-only.
pub fn snapshot_foreground() -> anyhow::Result<Vec<UiElement>> {
    #[cfg(windows)]
    {
        imp::snapshot_foreground()
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("UI Automation requires Windows")
    }
}

/// Drive a control programmatically (for automated RE data collection): find the first control
/// in a window (title contains `window_substr`) whose name contains `name_substr`, and act on it.
/// This lets a capture drive an app to precise, known values while recording the wire.
///
/// `set_range` sets a Slider/Spinner via the RangeValue pattern and returns the value read back.
pub fn set_range(window_substr: &str, name_substr: &str, value: f64) -> anyhow::Result<Option<f64>> {
    #[cfg(windows)]
    {
        imp::set_range(window_substr, name_substr, value)
    }
    #[cfg(not(windows))]
    {
        let _ = (window_substr, name_substr, value);
        anyhow::bail!("UI Automation requires Windows")
    }
}

/// Set a CheckBox/toggle to `on` (toggles only if it isn't already there). Returns the new state.
pub fn set_toggle(window_substr: &str, name_substr: &str, on: bool) -> anyhow::Result<Option<bool>> {
    #[cfg(windows)]
    {
        imp::set_toggle(window_substr, name_substr, on)
    }
    #[cfg(not(windows))]
    {
        let _ = (window_substr, name_substr, on);
        anyhow::bail!("UI Automation requires Windows")
    }
}

/// Invoke a Button (Invoke pattern). Returns true if a matching control was invoked.
pub fn invoke(window_substr: &str, name_substr: &str) -> anyhow::Result<bool> {
    #[cfg(windows)]
    {
        imp::invoke(window_substr, name_substr)
    }
    #[cfg(not(windows))]
    {
        let _ = (window_substr, name_substr);
        anyhow::bail!("UI Automation requires Windows")
    }
}

#[cfg(windows)]
mod imp {
    use super::{control_type_name, UiElement, WindowInfo};
    use anyhow::{Context, Result};
    use windows::core::{Interface, BOOL};
    use windows::Win32::Foundation::{HWND, LPARAM, RECT};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
    };
    use windows::Win32::UI::Accessibility::{
        CUIAutomation, IUIAutomation, IUIAutomationElement, IUIAutomationInvokePattern,
        IUIAutomationRangeValuePattern, IUIAutomationSelectionItemPattern,
        IUIAutomationTogglePattern, IUIAutomationValuePattern, TreeScope_Subtree,
        UIA_InvokePatternId, UIA_RangeValuePatternId, UIA_SelectionItemPatternId,
        UIA_TogglePatternId, UIA_ValuePatternId,
    };
    use windows::Win32::Foundation::POINT;
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetAncestor, GetForegroundWindow, GetWindowTextLengthW, GetWindowTextW,
        IsWindowVisible, RealGetWindowClassW, WindowFromPoint, GA_ROOT,
    };

    fn init_com() {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }
    }

    pub fn list_windows() -> Vec<WindowInfo> {
        unsafe extern "system" fn cb(hwnd: HWND, lp: LPARAM) -> BOOL {
            let out = &mut *(lp.0 as *mut Vec<WindowInfo>);
            if IsWindowVisible(hwnd).as_bool() {
                let len = GetWindowTextLengthW(hwnd);
                if len > 0 {
                    let mut buf = vec![0u16; len as usize + 1];
                    let got = GetWindowTextW(hwnd, &mut buf);
                    let title = String::from_utf16_lossy(&buf[..got as usize]);
                    let mut cbuf = [0u16; 256];
                    let clen = RealGetWindowClassW(hwnd, &mut cbuf);
                    let class_name = String::from_utf16_lossy(&cbuf[..clen as usize]);
                    out.push(WindowInfo { hwnd: hwnd.0 as isize, title, class_name });
                }
            }
            BOOL(1)
        }
        let mut out: Vec<WindowInfo> = Vec::new();
        unsafe {
            let _ = EnumWindows(Some(cb), LPARAM(&mut out as *mut _ as isize));
        }
        out
    }

    pub fn snapshot_by_title(substr: &str) -> Result<Option<Vec<UiElement>>> {
        let needle = substr.to_lowercase();
        match list_windows()
            .into_iter()
            .find(|w| w.title.to_lowercase().contains(&needle))
        {
            Some(w) => Ok(Some(snapshot_hwnd(w.hwnd)?)),
            None => Ok(None),
        }
    }

    pub fn snapshot_at_point(x: i32, y: i32) -> Result<Vec<UiElement>> {
        unsafe {
            let hwnd = WindowFromPoint(POINT { x, y });
            if hwnd.0.is_null() {
                return Ok(Vec::new());
            }
            // Walk up to the top-level window so we snapshot the whole app, not just the control.
            let root = GetAncestor(hwnd, GA_ROOT);
            let target = if root.0.is_null() { hwnd } else { root };
            snapshot_hwnd(target.0 as isize)
        }
    }

    pub fn snapshot_foreground() -> Result<Vec<UiElement>> {
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.0.is_null() {
                return Ok(Vec::new());
            }
            snapshot_hwnd(hwnd.0 as isize)
        }
    }

    /// hwnds of visible top-level windows whose title contains `substr` (case-insensitive).
    fn matching_hwnds(substr: &str) -> Vec<isize> {
        let needle = substr.to_lowercase();
        list_windows()
            .into_iter()
            .filter(|w| w.title.to_lowercase().contains(&needle))
            .map(|w| w.hwnd)
            .collect()
    }

    /// Run `f` on the first element (across matching windows) whose name contains `name_substr`
    /// AND that satisfies `f` (returns `Some`). This lets a caller require a specific pattern —
    /// e.g. the *Slider* "Exposure Time", not the same-named Text label.
    unsafe fn on_named<T>(
        window_substr: &str,
        name_substr: &str,
        mut f: impl FnMut(&IUIAutomationElement) -> Option<T>,
    ) -> Result<Option<T>> {
        init_com();
        let needle = name_substr.to_lowercase();
        for hwnd in matching_hwnds(window_substr) {
            let automation: IUIAutomation =
                match CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER) {
                    Ok(a) => a,
                    Err(_) => continue,
                };
            let Ok(root) = automation.ElementFromHandle(HWND(hwnd as *mut _)) else { continue };
            let Ok(cond) = automation.CreateTrueCondition() else { continue };
            let Ok(array) = root.FindAll(TreeScope_Subtree, &cond) else { continue };
            let n = array.Length().unwrap_or(0);
            for i in 0..n {
                let Ok(el) = array.GetElement(i) else { continue };
                let name = el.CurrentName().map(|b| b.to_string()).unwrap_or_default().to_lowercase();
                if !name.contains(&needle) {
                    continue;
                }
                if let Some(v) = f(&el) {
                    return Ok(Some(v));
                }
            }
        }
        Ok(None)
    }

    pub fn set_range(window_substr: &str, name_substr: &str, value: f64) -> Result<Option<f64>> {
        unsafe {
            on_named(window_substr, name_substr, |el| {
                let unk = el.GetCurrentPattern(UIA_RangeValuePatternId).ok()?;
                let p: IUIAutomationRangeValuePattern = unk.cast().ok()?;
                p.SetValue(value).ok()?;
                Some(p.CurrentValue().unwrap_or(value))
            })
        }
    }

    pub fn set_toggle(window_substr: &str, name_substr: &str, on: bool) -> Result<Option<bool>> {
        unsafe {
            on_named(window_substr, name_substr, |el| {
                let unk = el.GetCurrentPattern(UIA_TogglePatternId).ok()?;
                let p: IUIAutomationTogglePattern = unk.cast().ok()?;
                let is_on = p.CurrentToggleState().ok()?.0 == 1;
                if is_on != on {
                    p.Toggle().ok()?;
                }
                Some(p.CurrentToggleState().map(|s| s.0 == 1).unwrap_or(on))
            })
        }
    }

    pub fn invoke(window_substr: &str, name_substr: &str) -> Result<bool> {
        unsafe {
            Ok(on_named(window_substr, name_substr, |el| {
                let unk = el.GetCurrentPattern(UIA_InvokePatternId).ok()?;
                let p: IUIAutomationInvokePattern = unk.cast().ok()?;
                p.Invoke().ok()?;
                Some(())
            })?
            .is_some())
        }
    }

    pub fn snapshot_hwnd(hwnd: isize) -> Result<Vec<UiElement>> {
        init_com();
        unsafe {
            let automation: IUIAutomation =
                CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER)
                    .context("CoCreateInstance(CUIAutomation) failed")?;
            let root = automation
                .ElementFromHandle(HWND(hwnd as *mut _))
                .context("ElementFromHandle failed")?;
            let cond = automation.CreateTrueCondition()?;
            // TreeScope_Subtree = the window element plus every descendant, as one flat array.
            let array = root.FindAll(TreeScope_Subtree, &cond)?;
            let n = array.Length()?;
            let root_rect = root.CurrentBoundingRectangle().unwrap_or_default();

            let mut out = Vec::with_capacity(n as usize);
            for i in 0..n {
                let Ok(el) = array.GetElement(i) else { continue };
                out.push(read_element(&el, &root_rect));
            }
            Ok(out)
        }
    }

    /// Read one element's identity + geometry + any live pattern state.
    unsafe fn read_element(el: &IUIAutomationElement, root: &RECT) -> UiElement {
        let bstr = |r: windows::core::Result<windows::core::BSTR>| {
            r.map(|b| b.to_string()).unwrap_or_default()
        };
        let control_type = el.CurrentControlType().map(|c| c.0).unwrap_or(0);
        let rect = el.CurrentBoundingRectangle().unwrap_or_default();

        // Rough depth proxy: elements fully inside the root but smaller are deeper. We don't
        // reconstruct exact nesting from a flat FindAll, so depth is left as containment vs root
        // (0 for the window, 1 for everything under it) — good enough for the probe; the
        // capture-time path can walk the true tree if depth matters.
        let depth = if rect == *root { 0 } else { 1 };

        let mut e = UiElement {
            role: control_type_name(control_type),
            control_type,
            name: bstr(el.CurrentName()),
            automation_id: bstr(el.CurrentAutomationId()),
            class_name: bstr(el.CurrentClassName()),
            x: rect.left,
            y: rect.top,
            w: rect.right - rect.left,
            h: rect.bottom - rect.top,
            depth,
            toggle: None,
            selected: None,
            value: None,
            range_value: None,
            range_min: None,
            range_max: None,
        };

        // Toggle (CheckBox / toggle button).
        if let Ok(unk) = el.GetCurrentPattern(UIA_TogglePatternId) {
            if let Ok(p) = unk.cast::<IUIAutomationTogglePattern>() {
                if let Ok(st) = p.CurrentToggleState() {
                    e.toggle = Some(
                        match st.0 {
                            0 => "off",
                            1 => "on",
                            _ => "indeterminate",
                        }
                        .to_string(),
                    );
                }
            }
        }
        // SelectionItem (RadioButton / ListItem / TabItem).
        if let Ok(unk) = el.GetCurrentPattern(UIA_SelectionItemPatternId) {
            if let Ok(p) = unk.cast::<IUIAutomationSelectionItemPattern>() {
                e.selected = p.CurrentIsSelected().ok().map(|b| b.as_bool());
            }
        }
        // Value (Edit / ComboBox text).
        if let Ok(unk) = el.GetCurrentPattern(UIA_ValuePatternId) {
            if let Ok(p) = unk.cast::<IUIAutomationValuePattern>() {
                let v = bstr(p.CurrentValue());
                if !v.is_empty() {
                    e.value = Some(v);
                }
            }
        }
        // RangeValue (Slider / Spinner / ProgressBar) — the numeric value we most want.
        if let Ok(unk) = el.GetCurrentPattern(UIA_RangeValuePatternId) {
            if let Ok(p) = unk.cast::<IUIAutomationRangeValuePattern>() {
                e.range_value = p.CurrentValue().ok();
                e.range_min = p.CurrentMinimum().ok();
                e.range_max = p.CurrentMaximum().ok();
            }
        }
        e
    }
}
