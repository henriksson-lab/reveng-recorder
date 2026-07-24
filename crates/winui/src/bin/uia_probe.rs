//! Probe how rich a window's UI-Automation tree is.
//!
//! Usage: `uia-probe <title-substring> [--json]`
//!   - with no argument (or no match), lists the visible top-level windows so you can pick one.
//!
//! Prints a control-type histogram and every interactive control (buttons, checkboxes,
//! radios, sliders, edits…) with its label, screen rect, and live state/value.

use anyhow::Result;
use std::collections::BTreeMap;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|a| a == "--json");
    let Some(title) = args.iter().find(|a| !a.starts_with("--")).cloned() else {
        println!("usage: uia-probe <title-substring> [--json]. Open windows:");
        for w in reveng_winui::list_windows() {
            println!("  [{}] {:?}", w.class_name, w.title);
        }
        return Ok(());
    };

    // A title substring may match several windows (e.g. a dialog + the real main window).
    // Snapshot every match and keep the richest (most elements) — that's the app window.
    let needle = title.to_lowercase();
    let matches: Vec<_> = reveng_winui::list_windows()
        .into_iter()
        .filter(|w| w.title.to_lowercase().contains(&needle))
        .collect();
    if matches.is_empty() {
        println!("No visible window title contains {title:?}. Open windows:");
        for w in reveng_winui::list_windows() {
            println!("  [{}] {:?}", w.class_name, w.title);
        }
        return Ok(());
    }

    let mut best: Option<(reveng_winui::WindowInfo, Vec<reveng_winui::UiElement>)> = None;
    for w in matches {
        let els = reveng_winui::snapshot_hwnd(w.hwnd).unwrap_or_default();
        if !json {
            println!("  candidate [{}] {:?} -> {} elements", w.class_name, w.title, els.len());
        }
        if best.as_ref().map(|(_, b)| els.len() > b.len()).unwrap_or(true) {
            best = Some((w, els));
        }
    }
    let (win, elements) = best.unwrap();

    // --json: dump the chosen window's element vector (the exact on-disk `ui/<id>.json` shape).
    if json {
        println!("{}", serde_json::to_string(&elements)?);
        return Ok(());
    }

    println!(
        "\nUIA snapshot of [{}] {:?}: {} elements\n",
        win.class_name,
        win.title,
        elements.len()
    );

    // Control-type histogram — the quick "is the tree rich?" read.
    let mut hist: BTreeMap<String, u32> = BTreeMap::new();
    for e in &elements {
        *hist.entry(e.role.clone()).or_default() += 1;
    }
    println!("== control-type histogram ==");
    for (role, n) in hist.iter().rev() {
        println!("  {n:>4}  {role}");
    }

    // Interactive controls with their state/value — the money view.
    println!("\n== interactive controls (label — rect — state) ==");
    let mut shown = 0;
    for e in &elements {
        if !e.is_interactive() {
            continue;
        }
        let mut state = String::new();
        if let Some(t) = &e.toggle {
            state += &format!(" toggle={t}");
        }
        if let Some(s) = e.selected {
            state += &format!(" selected={s}");
        }
        if let Some(v) = &e.value {
            state += &format!(" value={v:?}");
        }
        if let Some(rv) = e.range_value {
            state += &format!(" range={rv}");
            if let (Some(mn), Some(mx)) = (e.range_min, e.range_max) {
                state += &format!(" [{mn}..{mx}]");
            }
        }
        println!(
            "  {:<12} {:<28} @({:>5},{:>5}) {:>4}x{:<4}{}",
            e.role,
            truncate(&e.name, 28),
            e.x,
            e.y,
            e.w,
            e.h,
            state,
        );
        shown += 1;
    }
    println!("\n{shown} interactive controls.");
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}
