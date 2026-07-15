//! Build a synthetic USB session (usb.pcapng + frames.idx + events.ndjson + meta.json)
//! so the query CLI can be exercised without USBPcap/hardware.
//! `cargo run -p reveng-usbcap --example mksession -- <out_dir>`
use reveng_core::checkpoint::{Checkpoint, CheckpointType};
use reveng_core::event::{SourceKind, TrafficAnchor};
use reveng_core::session::{SessionRecord, SessionWriter};
use reveng_usbcap::UsbWriter;

/// Build a raw USBPcap packet: 27-byte header (headerLen=27) + payload.
fn packet(device: u16, ep: u8, xfer: u8, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![0u8; 27];
    h[0..2].copy_from_slice(&27u16.to_le_bytes()); // headerLen
    h[10..14].copy_from_slice(&0u32.to_le_bytes()); // status
    h[17..19].copy_from_slice(&1u16.to_le_bytes()); // bus
    h[19..21].copy_from_slice(&device.to_le_bytes());
    h[21] = ep;
    h[22] = xfer;
    h[23..27].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    h.extend_from_slice(payload);
    h
}

fn main() -> anyhow::Result<()> {
    let out = std::env::args().nth(1).unwrap_or_else(|| "usb.session".into());
    let mut session = SessionWriter::create(&out)?;
    let mut usb = UsbWriter::create(session.usb_pcapng(), session.frames_idx())?;

    // Three frames on the wire.
    let frames = [
        (5u16, 0x80u8, 0u8, vec![0x12, 0x01, 0x00, 0x02, 0x09, 0x02]), // control IN
        (5, 0x02, 2, vec![0xde, 0xad, 0xbe, 0xef]),                    // bulk OUT
        (5, 0x81, 2, vec![0x01, 0x02, 0x03, 0x04]),                    // bulk IN
    ];
    let mut offsets = Vec::new();
    for (i, (dev, ep, xfer, payload)) in frames.iter().enumerate() {
        let ts = (i as i64 + 1) * 1_000_000; // 1ms apart
        let (idx, off) = usb.append_packet(ts, &packet(*dev, *ep, *xfer, payload))?;
        offsets.push((idx, off));
    }
    usb.flush()?;

    // Checkpoints: session start, a click anchored to the bulk-OUT frame, session stop.
    let mk = |id, ts, kind, cause: &str, anchor: Option<(u64, u64)>| {
        SessionRecord::Checkpoint(Checkpoint {
            id,
            ts_ns: ts,
            kind,
            cause: cause.to_string(),
            anchor: anchor.map(|(ei, bo)| TrafficAnchor {
                source: SourceKind::Usb,
                event_index: ei,
                byte_offset: bo,
            }),
            anchors: Vec::new(),
            screenshot_id: None,
            fg_process: Some("Vendor.exe".into()),
            fg_window: Some("Device Config".into()),
            cursor: (842, 391),
            note: None,
        })
    };
    session.append_record(&mk(0, 0, CheckpointType::SessionStart, "session_start", None))?;
    session.append_record(&mk(
        1,
        1_500_000,
        CheckpointType::Click,
        "LButtonDown @ (842,391)",
        Some((offsets[1].0, offsets[1].1)),
    ))?;
    session.append_record(&mk(
        2,
        3_000_000,
        CheckpointType::SessionStop,
        "session_stop",
        Some((offsets[2].0, offsets[2].1)),
    ))?;

    session.write_meta(&serde_json::json!({
        "tool": "reveng-rec",
        "source": "usb",
        "acquisition": "synthetic",
        "frames": frames.len(),
    }))?;

    println!("wrote session to {out}");
    Ok(())
}
