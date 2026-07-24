//! Compile the Slint "recording" note-taking window.
//!
//! Only built when targeting Windows (the notes window rides the Windows-only live-capture
//! path). Detecting the *target* — not the host — keeps cross-compiles and non-Windows
//! `cargo build --workspace` correct: the `slint::include_modules!()` in `notes_ui.rs` is
//! itself `#[cfg(windows)]`-gated, so nothing references the generated code off Windows.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        slint_build::compile("ui/record.slint").expect("compile ui/record.slint");
        // Windows gives the main thread only ~1 MB of stack (Linux/macOS give 8 MB). clap builds
        // the whole parser — 28 subcommands, ~110 options — on the stack in one derived function
        // (`augment_subcommands`), which exceeds 1 MB even for `--version`. Reserve 16 MB so every
        // command runs. This is the standard fix for a large CLI on Windows; it's a linker
        // directive with zero behavioural effect (unlike moving work to a worker thread, which
        // would risk the Slint window / input hooks). Boxing `Cmd::Record` shrinks the enum value
        // but does NOT help here — the cost is parser *construction*, not the value.
        println!("cargo:rustc-link-arg-bins=/STACK:16777216");
    }
}
