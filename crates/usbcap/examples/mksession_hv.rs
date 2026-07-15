//! Build a HIGH-VOLUME, multi-endpoint synthetic USB session so the query CLI + volume
//! features can be exercised end-to-end without USBPcap/hardware (this machine's input
//! devices are PS/2 + I2C, its external ports sit on a controller USBPcap doesn't filter,
//! and the one filtered hub delivers no live packets — see BACKLOG). Models an "Acme HD
//! Webcam": a control string descriptor, text bulk-OUT commands, a snaplen-truncated isoc
//! video firehose, binary bulk-IN JPEG blobs, and small interrupt-IN status reports, with
//! click checkpoints and typed notes anchored onto the same timeline.
//!
//! `cargo run -p reveng-usbcap --example mksession_hv -- <out_dir>`
use reveng_core::checkpoint::{Checkpoint, CheckpointType};
use reveng_core::event::{SourceKind, TrafficAnchor};
use reveng_core::session::{SessionRecord, SessionWriter};
use reveng_usbcap::UsbWriter;

const DEV: u16 = 7;

/// Raw USBPcap packet: 27-byte header (headerLen=27) + `captured` bytes, but advertise
/// `orig_len` as the on-wire dataLength. When `orig_len > captured.len()` this models a
/// kernel **snaplen** truncation: the index/`frames` report the true on-wire length while
/// only the captured prefix is stored (the P1.1 invariant).
fn packet(ep: u8, xfer: u8, orig_len: u32, captured: &[u8]) -> Vec<u8> {
    let mut h = vec![0u8; 27];
    h[0..2].copy_from_slice(&27u16.to_le_bytes()); // headerLen
    h[10..14].copy_from_slice(&0u32.to_le_bytes()); // status = success
    h[17..19].copy_from_slice(&1u16.to_le_bytes()); // bus
    h[19..21].copy_from_slice(&DEV.to_le_bytes()); // device
    h[21] = ep;
    h[22] = xfer;
    h[23..27].copy_from_slice(&orig_len.to_le_bytes()); // dataLength (on-wire length)
    h.extend_from_slice(captured);
    h
}

// USBPCAP_TRANSFER_*
const ISO: u8 = 0;
const INTR: u8 = 1;
const CTRL: u8 = 2;
const BULK: u8 = 3;

fn main() -> anyhow::Result<()> {
    let out = std::env::args().nth(1).unwrap_or_else(|| "usb-hv.session".into());
    let mut session = SessionWriter::create(&out)?;
    let mut usb = UsbWriter::create(session.usb_pcapng(), session.frames_idx())?;

    // Remember (frame_index, byte_offset) for a few notable frames so checkpoints/notes anchor.
    let mut anchor_at: std::collections::BTreeMap<&str, (u64, u64)> = Default::default();
    let mut ts: i64 = 0;
    let append = |usb: &mut UsbWriter, ts: i64, pkt: &[u8]| -> anyhow::Result<(u64, u64)> {
        Ok(usb.append_packet(ts, pkt)?)
    };

    // 1) Control IN: device string descriptor "Acme HD Webcam" (texty → stream --text / grep).
    ts += 1_000_000;
    let desc = b"Acme HD Webcam".to_vec();
    let a = append(&mut usb, ts, &packet(0x80, CTRL, desc.len() as u32, &desc))?;
    anchor_at.insert("descriptor", a);

    // 2) Bulk OUT: text control commands the host sends (texty protocol).
    for cmd in [
        &b"SET_FORMAT MJPG 1920x1080\n"[..],
        &b"SET_FPS 30\n"[..],
        &b"START_STREAM\n"[..],
    ] {
        ts += 500_000;
        let a = append(&mut usb, ts, &packet(0x02, BULK, cmd.len() as u32, cmd))?;
        anchor_at.insert(if cmd.starts_with(b"START") { "start_cmd" } else { "cmd" }, a);
    }

    // 3) The isoc video firehose: 300 frames, each 3072 B on the wire but snaplen-truncated
    //    to a 256 B header prefix (binary). This is the high-volume / drop-isoc / snaplen path.
    let mut first_iso = None;
    for i in 0..300u32 {
        ts += 33_000; // ~30 fps microframe pacing
        // Deterministic pseudo-binary payload prefix (an MJPEG-ish frame start on the first).
        let mut cap = vec![0u8; 256];
        cap[0] = 0xFF;
        cap[1] = 0xD8; // JPEG SOI so it reads clearly "binary"
        cap[2] = 0xFF;
        cap[3] = 0xE0;
        for (j, b) in cap.iter_mut().enumerate().skip(4) {
            *b = ((i as usize).wrapping_mul(31).wrapping_add(j)) as u8;
        }
        let a = append(&mut usb, ts, &packet(0x81, ISO, 3072, &cap))?;
        if first_iso.is_none() {
            first_iso = Some(a);
            anchor_at.insert("first_frame", a);
        }
        if i == 149 {
            anchor_at.insert("mid_frame", a);
        }
    }

    // 4) Bulk IN: 40 JPEG-still blobs (binary, full-length, not truncated).
    for i in 0..40u32 {
        ts += 200_000;
        let mut blob = vec![0xFFu8, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F'];
        blob.extend((0..118u32).map(|j| (i.wrapping_mul(7).wrapping_add(j)) as u8));
        let a = append(&mut usb, ts, &packet(0x82, BULK, blob.len() as u32, &blob))?;
        if i == 0 {
            anchor_at.insert("first_still", a);
        }
    }

    // 5) Interrupt IN: 20 small status reports (binary, 4 B).
    for i in 0..20u32 {
        ts += 1_000_000;
        let rep = [0x01u8, (i & 0xff) as u8, 0x00, 0x5a];
        append(&mut usb, ts, &packet(0x83, INTR, 4, &rep))?;
    }

    usb.flush()?;

    // ---- Checkpoints + notes on the SAME timeline -----------------------------------------
    let anchor = |k: &str| -> Option<TrafficAnchor> {
        anchor_at.get(k).map(|(ei, bo)| TrafficAnchor {
            source: SourceKind::Usb,
            event_index: *ei,
            byte_offset: *bo,
        })
    };
    let mk = |id, ts, kind, cause: &str, note: Option<&str>, a: Option<TrafficAnchor>| {
        SessionRecord::Checkpoint(Checkpoint {
            id,
            ts_ns: ts,
            kind,
            cause: cause.to_string(),
            anchor: a,
            anchors: Vec::new(),
            screenshot_id: None,
            fg_process: Some("CameraApp.exe".into()),
            fg_window: Some("Acme Webcam — Live".into()),
            cursor: (960, 540),
            note: note.map(|s| s.to_string()),
        })
    };

    let mut id = 0u64;
    let mut push = |session: &mut SessionWriter, ts, kind, cause, note, a| -> anyhow::Result<()> {
        session.append_record(&mk(id, ts, kind, cause, note, a))?;
        id += 1;
        Ok(())
    };

    push(&mut session, 0, CheckpointType::SessionStart, "session_start", None, None)?;
    // A click that starts the stream, anchored to the START_STREAM command frame.
    push(&mut session, 2_100_000, CheckpointType::Click, "LButtonDown @ (960,540)", None, anchor("start_cmd"))?;
    // Typed notes — the human narrating in real time, each anchored to what was on the wire.
    push(&mut session, 2_200_000, CheckpointType::Manual, "note", Some("clicked Start — stream should begin"), anchor("first_frame"))?;
    push(&mut session, 5_000_000, CheckpointType::Manual, "note", Some("resolution set to 1080p MJPG"), anchor("mid_frame"))?;
    push(&mut session, 12_000_000, CheckpointType::Manual, "note", Some("captured a still photo"), anchor("first_still"))?;
    push(&mut session, ts, CheckpointType::SessionStop, "session_stop", None, None)?;

    session.write_meta(&serde_json::json!({
        "tool": "reveng-rec",
        "source": "usb",
        "acquisition": "synthetic-high-volume",
        "device": "Acme HD Webcam (VID 048D synthetic)",
        "note": "isoc EP 0x81 snaplen-truncated 3072->256; text bulk-OUT on 0x02; JPEG bulk-IN on 0x82",
    }))?;

    println!("wrote high-volume session to {out}");
    Ok(())
}
