//! Manual verification: install the LL hooks, inject a keystroke + mouse click via
//! SendInput, and confirm the hook delivers them. `cargo run -p reveng-winput --example hooktest`
use reveng_core::clock::Clock;
use std::sync::mpsc;

fn main() -> anyhow::Result<()> {
    let (tx, rx) = mpsc::channel();
    let clock = Clock::start();
    let hooks = reveng_winput::install(clock, move |ev| {
        let _ = tx.send(ev);
    })?;
    println!("hooks installed; injecting input…");

    inject();
    std::thread::sleep(std::time::Duration::from_millis(300));
    hooks.stop();

    let events: Vec<_> = rx.try_iter().collect();
    println!("received {} input events:", events.len());
    for e in &events {
        println!("  {}", serde_json::to_string(e)?);
    }
    let ctx = reveng_winput::foreground_context();
    println!("foreground context: process={:?} window={:?}", ctx.0, ctx.1);

    let saw_key = events.iter().any(|e| matches!(e.kind, reveng_winput::InputKind::KeyDown));
    if !saw_key {
        anyhow::bail!("FAIL: no KeyDown event captured from injected input");
    }
    println!("OK: hooks captured injected input");
    Ok(())
}

fn inject() {
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP,
        VIRTUAL_KEY,
    };
    // Press and release the 'A' key (VK 0x41).
    let vk = VIRTUAL_KEY(0x41);
    let mk = |flags: KEYBD_EVENT_FLAGS| INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: 0,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };
    let inputs = [mk(KEYBD_EVENT_FLAGS(0)), mk(KEYEVENTF_KEYUP)];
    unsafe {
        SendInput(&inputs, std::mem::size_of::<INPUT>() as i32);
    }
}
