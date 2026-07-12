//! Manual verification: grab the cursor monitor to a PNG.
//! `cargo run -p reveng-winshot --example grab -- out.png`
fn main() -> anyhow::Result<()> {
    let out = std::env::args().nth(1).unwrap_or_else(|| "grab.png".into());
    let frame = reveng_winshot::capture(reveng_winshot::Scope::CursorMonitor)?;
    println!("captured {}x{} ({} bytes RGB)", frame.width, frame.height, frame.rgb.len());
    reveng_winshot::encode_png(&frame, std::path::Path::new(&out))?;
    println!("wrote {out}");
    Ok(())
}
