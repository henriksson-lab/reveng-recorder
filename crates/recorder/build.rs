//! Compile the Slint "recording" note-taking window.
//!
//! Only built when targeting Windows (the notes window rides the Windows-only live-capture
//! path). Detecting the *target* — not the host — keeps cross-compiles and non-Windows
//! `cargo build --workspace` correct: the `slint::include_modules!()` in `notes_ui.rs` is
//! itself `#[cfg(windows)]`-gated, so nothing references the generated code off Windows.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        slint_build::compile("ui/record.slint").expect("compile ui/record.slint");
    }
}
