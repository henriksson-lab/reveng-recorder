//! Reading a recorded USB session: decoded frames from `usb.pcapng` + `frames.idx`
//! (DESIGN.md §8, §8a). Seeking is O(1) by index (direct-address into `frames.idx`,
//! then one `seek` into the pcapng at `byte_offset`) and O(log n) by time.
//!
//! A pcapng Enhanced Packet Block for `LINKTYPE_USBPCAP` carries the raw USBPcap packet:
//! a `USBPCAP_BUFFER_PACKET_HEADER` (its length in the first `u16`) followed by the
//! payload. We decode the header for the indexed fields and expose the payload as
//! hex/ascii/base64 text — the binary pcapng is never handed to an LLM (§8.1).

use crate::parse::parse_packet_header;
use crate::UsbIdxRecord;
use base64::Engine;
use reveng_core::index::IndexFile;
use serde::Serialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// A decoded USB frame, ready to render as one JSON line (DESIGN.md §8a).
#[derive(Debug, Clone, Serialize)]
pub struct UsbFrame {
    pub i: u64,
    pub ts_ns: i64,
    pub dev: u16,
    /// Endpoint address, e.g. `0x81`.
    pub ep: String,
    pub dir: &'static str, // "in" | "out"
    pub xfer: &'static str, // "control" | "iso" | "bulk" | "interrupt"
    pub len: u32,
    pub status: u32,
    pub hex: String,
    pub ascii: String,
    /// base64 of the raw payload — the decoder-consumable form (§8b).
    pub b64: String,
    #[serde(skip)]
    pub payload: Vec<u8>,
    #[serde(skip)]
    pub endpoint: u8,
}

fn xfer_name(t: u8) -> &'static str {
    match t {
        0 => "control",
        1 => "iso",
        2 => "bulk",
        3 => "interrupt",
        _ => "unknown",
    }
}

fn hexdump(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn asciidump(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
        .collect()
}

/// Reads decoded frames from a session's `usb.pcapng` + `frames.idx`.
pub struct UsbReader {
    pcapng: File,
    idx: IndexFile<UsbIdxRecord>,
}

impl UsbReader {
    pub fn open(pcapng_path: impl AsRef<Path>, idx_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let pcapng = File::open(pcapng_path)?;
        let idx = IndexFile::<UsbIdxRecord>::open(idx_path)?;
        Ok(Self { pcapng, idx })
    }

    pub fn len(&self) -> u64 {
        self.idx.len()
    }
    pub fn is_empty(&self) -> bool {
        self.idx.is_empty()
    }

    /// The byte offset of frame `i`'s block in `usb.pcapng` (for a checkpoint anchor).
    pub fn offset_of(&mut self, i: u64) -> anyhow::Result<u64> {
        Ok(self.idx.get(i)?.byte_offset)
    }

    /// Largest frame index whose `ts_ns <= target` (checkpoint-anchor rule, §7).
    pub fn index_le_ts(&mut self, target_ns: i64) -> anyhow::Result<Option<u64>> {
        Ok(self.idx.search_le_ts(target_ns)?)
    }

    /// Frame `i`'s endpoint straight from the index record — no pcapng read or decode.
    /// Cheap enough to call per frame when filtering by endpoint.
    pub fn endpoint_at(&mut self, i: u64) -> anyhow::Result<u8> {
        Ok(self.idx.get(i)?.endpoint)
    }

    /// Just the raw payload bytes of frame `i` (no hex/ascii/base64 rendering).
    pub fn payload_at(&mut self, i: u64) -> anyhow::Result<Vec<u8>> {
        let (_rec, packet) = self.raw_packet(i)?;
        let header_len = if packet.len() >= 2 {
            u16::from_le_bytes([packet[0], packet[1]]) as usize
        } else {
            0
        };
        Ok(if header_len > 0 && header_len <= packet.len() {
            packet[header_len..].to_vec()
        } else {
            Vec::new()
        })
    }

    /// Read the raw USBPcap packet (header + payload) for frame `i` out of the pcapng.
    fn raw_packet(&mut self, i: u64) -> anyhow::Result<(UsbIdxRecord, Vec<u8>)> {
        let rec = self.idx.get(i)?;
        // Enhanced Packet Block layout: at byte_offset we have
        //   [0..4] block type, [4..8] total len, [8..12] iface id,
        //   [12..16] ts_high, [16..20] ts_low, [20..24] caplen, [24..28] origlen,
        //   [28..28+caplen] packet data.
        self.pcapng.seek(SeekFrom::Start(rec.byte_offset + 20))?;
        let mut caplen_buf = [0u8; 4];
        self.pcapng.read_exact(&mut caplen_buf)?;
        let caplen = u32::from_le_bytes(caplen_buf) as usize;
        self.pcapng.seek(SeekFrom::Start(rec.byte_offset + 28))?;
        let mut data = vec![0u8; caplen];
        self.pcapng.read_exact(&mut data)?;
        Ok((rec, data))
    }

    /// Decode frame `i` into a [`UsbFrame`].
    pub fn frame_at(&mut self, i: u64) -> anyhow::Result<UsbFrame> {
        let (rec, packet) = self.raw_packet(i)?;
        let header = parse_packet_header(&packet);
        // headerLen is the first u16 of the USBPcap header; payload follows it.
        let header_len = if packet.len() >= 2 {
            u16::from_le_bytes([packet[0], packet[1]]) as usize
        } else {
            0
        };
        let payload = if header_len > 0 && header_len <= packet.len() {
            packet[header_len..].to_vec()
        } else {
            Vec::new()
        };
        let (dev, status) = header
            .as_ref()
            .map(|h| (h.device, h.status))
            .unwrap_or((0, 0));
        let dir = if rec.endpoint & 0x80 != 0 { "in" } else { "out" };
        Ok(UsbFrame {
            i,
            ts_ns: rec.ts_ns,
            dev,
            ep: format!("0x{:02x}", rec.endpoint),
            dir,
            xfer: xfer_name(rec.xfer),
            len: rec.data_length,
            status,
            hex: hexdump(&payload),
            ascii: asciidump(&payload),
            b64: base64::engine::general_purpose::STANDARD.encode(&payload),
            endpoint: rec.endpoint,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UsbWriter;

    /// A raw USBPcap packet: 27-byte header (headerLen=27) + payload.
    fn packet(ep: u8, xfer: u8, payload: &[u8]) -> Vec<u8> {
        let mut h = vec![0u8; 27];
        h[0..2].copy_from_slice(&27u16.to_le_bytes());
        h[19..21].copy_from_slice(&7u16.to_le_bytes()); // device
        h[21] = ep;
        h[22] = xfer;
        h[23..27].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        h.extend_from_slice(payload);
        h
    }

    #[test]
    fn write_then_read_frame_roundtrips() {
        let dir = std::env::temp_dir();
        let pcapng = dir.join("reveng_usbrw_test.pcapng");
        let idx = dir.join("reveng_usbrw_test.idx");
        let _ = std::fs::remove_file(&pcapng);
        let _ = std::fs::remove_file(&idx);

        let payload = [0xde, 0xad, 0xbe, 0xef];
        {
            let mut w = UsbWriter::create(&pcapng, &idx).unwrap();
            let (i, _off) = w.append_packet(2_000_000, &packet(0x81, 2, &payload)).unwrap();
            assert_eq!(i, 0);
            w.flush().unwrap();
        }

        let mut r = UsbReader::open(&pcapng, &idx).unwrap();
        assert_eq!(r.len(), 1);
        let f = r.frame_at(0).unwrap();
        assert_eq!(f.endpoint, 0x81);
        assert_eq!(f.dir, "in");
        assert_eq!(f.xfer, "bulk");
        assert_eq!(f.dev, 7);
        assert_eq!(f.ts_ns, 2_000_000);
        assert_eq!(f.payload, payload);
        assert_eq!(f.hex, "de ad be ef");
        assert_eq!(r.index_le_ts(2_500_000).unwrap(), Some(0));
        assert_eq!(r.index_le_ts(1_000_000).unwrap(), None);

        let _ = std::fs::remove_file(&pcapng);
        let _ = std::fs::remove_file(&idx);
    }
}
