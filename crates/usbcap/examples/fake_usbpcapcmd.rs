//! A stand-in for `USBPcapCMD.exe -o -`: emits a valid libpcap (DLT_USBPCAP) stream of
//! synthetic USB frames to stdout, so the whole live-capture pipeline can be exercised
//! without the USBPcap driver/hardware. Set `USBPCAPCMD` to this binary.
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let mut out = std::io::stdout().lock();

    // Global header: magic 0xa1b2c3d4 (microsecond), DLT_USBPCAP (249).
    let mut gh = Vec::new();
    gh.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    gh.extend_from_slice(&2u16.to_le_bytes());
    gh.extend_from_slice(&4u16.to_le_bytes());
    gh.extend_from_slice(&0i32.to_le_bytes());
    gh.extend_from_slice(&0u32.to_le_bytes());
    gh.extend_from_slice(&65535u32.to_le_bytes());
    gh.extend_from_slice(&249u32.to_le_bytes());
    if out.write_all(&gh).is_err() {
        return;
    }
    let _ = out.flush();

    for i in 0..250u32 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        // A USBPcap packet: 27-byte header (headerLen=27) + payload.
        let payload: Vec<u8> = {
            let mut p = b"MARK".to_vec();
            p.extend_from_slice(&i.to_le_bytes());
            p.resize(96, 0xAB); // ~100-byte frames so interval checkpoints can accrue
            p
        };
        let mut hdr = vec![0u8; 27];
        hdr[0..2].copy_from_slice(&27u16.to_le_bytes()); // headerLen
        hdr[17..19].copy_from_slice(&1u16.to_le_bytes()); // bus
        hdr[19..21].copy_from_slice(&5u16.to_le_bytes()); // device
        hdr[21] = 0x02; // endpoint (bulk OUT)
        hdr[22] = 2; // transfer = bulk
        hdr[23..27].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        let mut packet = hdr;
        packet.extend_from_slice(&payload);

        let mut rec = Vec::new();
        rec.extend_from_slice(&(now.as_secs() as u32).to_le_bytes());
        rec.extend_from_slice(&(now.subsec_micros()).to_le_bytes());
        rec.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        rec.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        rec.extend_from_slice(&packet);

        if out.write_all(&rec).is_err() {
            return; // recorder closed the pipe (stop)
        }
        if out.flush().is_err() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
