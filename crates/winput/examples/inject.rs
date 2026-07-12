//! Inject a mouse click and a couple of key presses via SendInput, so a running recorder
//! captures real checkpoints. `cargo run -p reveng-winput --example inject`
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYBD_EVENT_FLAGS,
    KEYEVENTF_KEYUP, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEINPUT, VIRTUAL_KEY,
};

fn send(inputs: &[INPUT]) {
    unsafe {
        SendInput(inputs, std::mem::size_of::<INPUT>() as i32);
    }
}

fn mouse(flags: windows::Win32::UI::Input::KeyboardAndMouse::MOUSE_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx: 0,
                dy: 0,
                mouseData: 0,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn key(vk: u16, up: bool) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(vk),
                wScan: 0,
                dwFlags: if up { KEYEVENTF_KEYUP } else { KEYBD_EVENT_FLAGS(0) },
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn main() {
    let pause = || std::thread::sleep(std::time::Duration::from_millis(250));
    // Left click.
    send(&[mouse(MOUSEEVENTF_LEFTDOWN)]);
    send(&[mouse(MOUSEEVENTF_LEFTUP)]);
    pause();
    // Type 'A' (ordinary key — not a checkpoint by default).
    send(&[key(0x41, false)]);
    send(&[key(0x41, true)]);
    pause();
    // Press Enter (a special key — triggers a KeyDown checkpoint).
    send(&[key(0x0D, false)]);
    send(&[key(0x0D, true)]);
    pause();
    println!("injected: click, 'A', Enter");
}
