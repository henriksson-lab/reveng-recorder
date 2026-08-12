//! Reading a recorded USB session: decoded frames from `usb.pcapng` + `frames.idx`
//! (DESIGN.md §8, §8a). Seeking is O(1) by index (direct-address into `frames.idx`,
//! then one `seek` into the pcapng at `byte_offset`) and O(log n) by time.
//!
//! A pcapng Enhanced Packet Block for `LINKTYPE_USBPCAP` carries the raw USBPcap packet:
//! a `USBPCAP_BUFFER_PACKET_HEADER` (its length in the first `u16`) followed by the
//! payload. We decode the header for the indexed fields and expose the payload as
//! hex/ascii/base64 text — the binary pcapng is never handed to an LLM (§8.1).
//!
//! A capture from a hardware analyzer stores raw USB 2.0 **wire packets** instead, under a
//! `LINKTYPE_USB_2_0*` link type. [`UsbReader::open`] reads the link type out of the
//! pcapng's interface block and decodes accordingly, so every caller of this reader —
//! `frames`, `payload`, `grep`, `diff`, `decode`, the viewer, `export` — works on either
//! kind of session without knowing which it has. See [`crate::wire`] for what differs.

use crate::parse::parse_packet_header;
use crate::{CaptureFormat, UsbIdxRecord};
use base64::Engine;
use reveng_core::index::IndexFile;
use serde::Serialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const BT_EPB: u32 = 0x0000_0006;
const MAX_PACKET_LEN: usize = 64 * 1024 * 1024;

/// A decoded USB control-transfer SETUP packet (the 8-byte `bmRequestType`… header),
/// with the type/recipient/direction fields broken out. This is the *command* layer of a
/// vendor protocol — for a device like a Cypress-based camera almost the entire control
/// vocabulary is vendor requests on EP0, so decoding this is what turns a byte firehose
/// into a readable command log.
#[derive(Debug, Clone, Serialize)]
pub struct Setup {
    /// `bmRequestType`, rendered as `0xNN`.
    pub bm_request_type: String,
    /// `bRequest`, rendered as `0xNN`.
    pub b_request: String,
    /// `wValue`, rendered as `0xNNNN`.
    pub w_value: String,
    /// `wIndex`, rendered as `0xNNNN`.
    pub w_index: String,
    pub w_length: u16,
    pub dir: &'static str,       // "in" | "out"  (from bmRequestType bit 7)
    pub req_type: &'static str,  // "standard" | "class" | "vendor" | "reserved"
    pub recipient: &'static str, // "device" | "interface" | "endpoint" | "other"
}

/// USBPcap control-transfer stage codes (USBPcap.h `USBPCAP_CONTROL_STAGE_*`).
pub const CTRL_STAGE_SETUP: u8 = 0;
pub const CTRL_STAGE_DATA: u8 = 1;
pub const CTRL_STAGE_STATUS: u8 = 2;
pub const CTRL_STAGE_COMPLETE: u8 = 3;

fn ctrl_stage_name(s: u8) -> &'static str {
    match s {
        CTRL_STAGE_SETUP => "setup",
        CTRL_STAGE_DATA => "data",
        CTRL_STAGE_STATUS => "status",
        CTRL_STAGE_COMPLETE => "complete",
        _ => "unknown",
    }
}

/// Decode an 8-byte USB SETUP packet, if `bytes` is long enough to contain one.
pub fn decode_setup(bytes: &[u8]) -> Option<Setup> {
    if bytes.len() < 8 {
        return None;
    }
    let bm = bytes[0];
    let dir = if bm & 0x80 != 0 { "in" } else { "out" };
    let req_type = match (bm >> 5) & 0x3 {
        0 => "standard",
        1 => "class",
        2 => "vendor",
        _ => "reserved",
    };
    let recipient = match bm & 0x1f {
        0 => "device",
        1 => "interface",
        2 => "endpoint",
        _ => "other",
    };
    Some(Setup {
        bm_request_type: format!("0x{bm:02x}"),
        b_request: format!("0x{:02x}", bytes[1]),
        w_value: format!("0x{:04x}", u16::from_le_bytes([bytes[2], bytes[3]])),
        w_index: format!("0x{:04x}", u16::from_le_bytes([bytes[4], bytes[5]])),
        w_length: u16::from_le_bytes([bytes[6], bytes[7]]),
        dir,
        req_type,
        recipient,
    })
}

/// A decoded USB frame, ready to render as one JSON line (DESIGN.md §8a).
#[derive(Debug, Clone, Serialize)]
pub struct UsbFrame {
    pub i: u64,
    pub ts_ns: i64,
    pub dev: u16,
    /// Endpoint address, e.g. `0x81`.
    pub ep: String,
    pub dir: &'static str,  // "in" | "out"
    pub xfer: &'static str, // "iso" | "interrupt" | "control" | "bulk"
    pub len: u32,
    pub status: u32,
    /// USBPcap control-transfer stage ("setup"/"data"/"status"/"complete"), control frames only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<&'static str>,
    /// The IRP id, rendered as `0xNN…` — pairs a SETUP frame with its later completion frame.
    /// Present for control transfers; empty otherwise.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub irp: String,
    /// Decoded SETUP packet, present on the SETUP stage of a control transfer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup: Option<Setup>,
    /// Wire captures only: the packet ID, e.g. `"IN"`, `"DATA1"`, `"NAK"`. This is the
    /// bus-level detail a USBPcap record does not have — a NAKed and retried transfer
    /// looks identical to a clean one through the Windows stack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<&'static str>,
    /// Wire captures only: device address, present on **token packets only**. The DATA and
    /// handshake packets of a transaction carry no address on the wire; joining them to
    /// their token is reassembly's job, not the frame reader's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<u8>,
    /// Wire captures only: whether the packet's CRC verifies. `None` for a handshake,
    /// which carries none. A `Some(false)` is a genuine bus error or a capture problem —
    /// nothing in a USBPcap session can report this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crc_ok: Option<bool>,
    pub hex: String,
    pub ascii: String,
    /// base64 of the raw payload — the decoder-consumable form (§8b).
    pub b64: String,
    #[serde(skip)]
    pub payload: Vec<u8>,
    #[serde(skip)]
    pub endpoint: u8,
    /// Raw control stage byte (for pairing logic); not serialized.
    #[serde(skip)]
    pub stage_raw: Option<u8>,
    /// Raw IRP id (for pairing logic); not serialized.
    #[serde(skip)]
    pub irp_id: u64,
}

/// USBPcap transfer-type encoding (USBPcap.h: `USBPCAP_TRANSFER_*`). [`crate::XFER_UNKNOWN`]
/// falls through to `"unknown"`, which is what a wire capture reports for anything that is
/// not on endpoint 0.
fn xfer_name(t: u8) -> &'static str {
    match t {
        0 => "iso",
        1 => "interrupt",
        2 => "control",
        3 => "bulk",
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
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

/// Reads decoded frames from a session's `usb.pcapng` + `frames.idx`.
pub struct UsbReader {
    pcapng: File,
    idx: IndexFile<UsbIdxRecord>,
    format: CaptureFormat,
}

impl UsbReader {
    pub fn open(pcapng_path: impl AsRef<Path>, idx_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let mut pcapng = File::open(pcapng_path)?;
        // The link type is the only record of which backend wrote this session, and it
        // decides how every packet below is decoded. Read it from the file rather than
        // taking it as an argument, so a caller cannot open a session as the wrong kind.
        let (link_type, _ns_per_unit) = crate::pcapng::read_interface_info(&mut pcapng)
            .unwrap_or((crate::pcapng::LINKTYPE_USBPCAP, 1000));
        pcapng.seek(SeekFrom::Start(0))?;
        let idx = IndexFile::<UsbIdxRecord>::open(idx_path)?;
        Ok(Self {
            pcapng,
            idx,
            format: CaptureFormat::from_link_type(link_type),
        })
    }

    /// Which backend wrote this session. Callers that render backend-specific fields —
    /// a `status` column that means `USBD_STATUS`, say — must branch on this rather than
    /// assume USBPcap.
    pub fn format(&self) -> CaptureFormat {
        self.format
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

    /// Frame `i`'s USBPcap transfer type straight from the index record (0=iso 1=int
    /// 2=control 3=bulk) — no pcapng read. Lets a control-only view skip bulk frames cheaply.
    pub fn xfer_at(&mut self, i: u64) -> anyhow::Result<u8> {
        Ok(self.idx.get(i)?.xfer)
    }

    /// Frame `i`'s timestamp straight from the index record (for timeline density bucketing).
    pub fn ts_at(&mut self, i: u64) -> anyhow::Result<i64> {
        use reveng_core::index::FixedRecord;
        Ok(self.idx.get(i)?.ts_ns())
    }

    /// Frame `i`'s on-wire transfer length (`dataLength`) from the index record — no pcapng read.
    pub fn len_at(&mut self, i: u64) -> anyhow::Result<u32> {
        Ok(self.idx.get(i)?.data_length)
    }

    /// Frame `i`'s direction straight from the index record — no pcapng read. True for IN.
    ///
    /// Honest in both formats, unlike testing bit 7 of the endpoint: on the wire the
    /// endpoint number carries no direction bit, and the index took the direction from the
    /// transaction's token.
    pub fn dir_in_at(&mut self, i: u64) -> anyhow::Result<bool> {
        Ok(self.idx.get(i)?.dir == 1)
    }

    /// Frame `i`'s packet ID, straight from the index record — no pcapng read. Meaningful
    /// only for a wire capture; `None` for USBPcap, whose records are whole transfers with
    /// no PID. Lets a caller skip SOF or handshake packets cheaply, which matters because
    /// a wire capture holds 10–100× more records than a USBPcap one of the same traffic.
    pub fn pid_at(&mut self, i: u64) -> anyhow::Result<Option<u8>> {
        Ok(match self.format {
            CaptureFormat::Wire => Some(self.idx.get(i)?.status),
            CaptureFormat::UsbPcap => None,
        })
    }

    /// Frame `i`'s stored bytes, exactly as the backend produced them — a USBPcap record
    /// (header + payload) or a whole wire packet (PID + fields + CRC).
    ///
    /// Reassembly needs this rather than [`Self::payload_at`]: a token or handshake has no
    /// payload at all, yet they are what delimit a transfer.
    pub fn raw_packet_bytes(&mut self, i: u64) -> anyhow::Result<Vec<u8>> {
        Ok(self.raw_packet(i)?.1)
    }

    /// Just the raw payload bytes of frame `i` (no hex/ascii/base64 rendering).
    ///
    /// "Payload" means the same thing in both formats — the bytes a protocol decoder wants
    /// — but is reached differently: past the USBPcap header, or between a DATA packet's
    /// PID and its CRC. A wire token or handshake carries no payload and yields empty.
    pub fn payload_at(&mut self, i: u64) -> anyhow::Result<Vec<u8>> {
        let (_rec, packet) = self.raw_packet(i)?;
        Ok(self.payload_of(&packet))
    }

    fn payload_of(&self, packet: &[u8]) -> Vec<u8> {
        match self.format {
            CaptureFormat::UsbPcap => {
                let header_len = if packet.len() >= 2 {
                    u16::from_le_bytes([packet[0], packet[1]]) as usize
                } else {
                    0
                };
                if header_len >= crate::parse::USBPCAP_HEADER_LEN && header_len <= packet.len() {
                    packet[header_len..].to_vec()
                } else {
                    Vec::new()
                }
            }
            CaptureFormat::Wire => crate::wire::decode(packet)
                .map(|p| p.data.to_vec())
                .unwrap_or_default(),
        }
    }

    /// Read the raw USBPcap packet (header + payload) for frame `i` out of the pcapng.
    fn raw_packet(&mut self, i: u64) -> anyhow::Result<(UsbIdxRecord, Vec<u8>)> {
        let rec = self.idx.get(i)?;
        // Enhanced Packet Block layout: at byte_offset we have
        //   [0..4] block type, [4..8] total len, [8..12] iface id,
        //   [12..16] ts_high, [16..20] ts_low, [20..24] caplen, [24..28] origlen,
        //   [28..28+caplen] packet data.
        let mut header = [0u8; 28];
        self.pcapng.seek(SeekFrom::Start(rec.byte_offset))?;
        self.pcapng.read_exact(&mut header)?;
        let block_type = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let total_len = u32::from_le_bytes(header[4..8].try_into().unwrap()) as u64;
        let caplen = u32::from_le_bytes(header[20..24].try_into().unwrap()) as usize;
        let file_len = self.pcapng.metadata()?.len();
        let block_end = rec
            .byte_offset
            .checked_add(total_len)
            .filter(|&end| end <= file_len)
            .ok_or_else(|| anyhow::anyhow!("frame {i} points outside usb.pcapng"))?;
        if block_type != BT_EPB
            || total_len < 32
            || !total_len.is_multiple_of(4)
            || caplen > MAX_PACKET_LEN
            || caplen as u64 > total_len - 32
        {
            anyhow::bail!("frame {i} has an invalid pcapng Enhanced Packet Block");
        }
        self.pcapng.seek(SeekFrom::Start(
            rec.byte_offset
                .checked_add(28)
                .ok_or_else(|| anyhow::anyhow!("frame {i} packet offset overflow"))?,
        ))?;
        let mut data = vec![0u8; caplen];
        self.pcapng.read_exact(&mut data)?;
        self.pcapng.seek(SeekFrom::Start(block_end - 4))?;
        let mut trailer = [0u8; 4];
        self.pcapng.read_exact(&mut trailer)?;
        if u32::from_le_bytes(trailer) as u64 != total_len {
            anyhow::bail!("frame {i} has mismatched pcapng block lengths");
        }
        Ok((rec, data))
    }

    /// Decode frame `i` into a [`UsbFrame`], according to the session's capture format.
    pub fn frame_at(&mut self, i: u64) -> anyhow::Result<UsbFrame> {
        match self.format {
            CaptureFormat::UsbPcap => self.usbpcap_frame_at(i),
            CaptureFormat::Wire => self.wire_frame_at(i),
        }
    }

    /// Decode one raw USB 2.0 wire packet.
    ///
    /// Endpoint, direction and transfer type come from the index (the [`crate::wire`]
    /// indexer carried them forward from the transaction's token); everything else is
    /// decoded from the packet here.
    fn wire_frame_at(&mut self, i: u64) -> anyhow::Result<UsbFrame> {
        use crate::wire;
        let (rec, packet) = self.raw_packet(i)?;
        let decoded = wire::decode(&packet);
        let payload = decoded
            .as_ref()
            .map(|p| p.data.to_vec())
            .unwrap_or_default();

        // A control transfer's SETUP data is the DATA0 packet immediately after a SETUP
        // token — the wire equivalent of USBPcap's setup stage. One index read back is
        // enough to recognise it, and it is what makes a control transfer readable as a
        // command rather than as three anonymous packets.
        let follows_setup_token = i > 0
            && matches!(
                decoded.as_ref().map(|p| p.kind),
                Some(wire::PacketKind::Data)
            )
            && self.idx.get(i - 1)?.status == wire::PID_SETUP;
        let setup = if follows_setup_token {
            decode_setup(&payload)
        } else {
            None
        };

        Ok(UsbFrame {
            i,
            ts_ns: rec.ts_ns,
            // The wire carries an address only on tokens; see `UsbFrame::addr`.
            dev: 0,
            ep: format!("0x{:02x}", rec.endpoint),
            dir: match &setup {
                Some(s) => s.dir,
                None if rec.dir == 1 => "in",
                None => "out",
            },
            xfer: xfer_name(rec.xfer),
            len: rec.data_length,
            // A wire capture has no host status code. The outcome of a transaction is its
            // final handshake, which is a packet of its own — see `pid`.
            status: 0,
            stage: setup.as_ref().map(|_| ctrl_stage_name(CTRL_STAGE_SETUP)),
            irp: String::new(),
            pid: decoded.as_ref().map(|p| wire::pid_name(p.pid)),
            addr: decoded.as_ref().and_then(|p| p.addr),
            crc_ok: decoded.as_ref().and_then(|p| p.crc_ok),
            setup,
            hex: hexdump(&payload),
            ascii: asciidump(&payload),
            b64: base64::engine::general_purpose::STANDARD.encode(&payload),
            endpoint: rec.endpoint,
            stage_raw: if follows_setup_token {
                Some(CTRL_STAGE_SETUP)
            } else {
                None
            },
            irp_id: 0,
            payload,
        })
    }

    /// Decode one USBPcap record: a `USBPCAP_BUFFER_PACKET_HEADER` plus payload.
    fn usbpcap_frame_at(&mut self, i: u64) -> anyhow::Result<UsbFrame> {
        let (rec, packet) = self.raw_packet(i)?;
        let header = parse_packet_header(&packet);
        // headerLen is the first u16 of the USBPcap header; payload follows it.
        let header_len = if packet.len() >= 2 {
            u16::from_le_bytes([packet[0], packet[1]]) as usize
        } else {
            0
        };
        let payload =
            if header_len >= crate::parse::USBPCAP_HEADER_LEN && header_len <= packet.len() {
                packet[header_len..].to_vec()
            } else {
                Vec::new()
            };
        let (dev, status) = header
            .as_ref()
            .map(|h| (h.device, h.status))
            .unwrap_or((0, 0));

        // Control transfers carry an IRP id (base header offset 2) and, after the base
        // header, a 1-byte stage code. USBPcap splits one control transfer into a SETUP
        // frame (payload = the 8-byte setup packet, plus any OUT data) and a later
        // completion frame sharing the same IRP id (payload = returned IN data). Decode
        // both so a caller can pair them and read the command layer.
        let is_control = rec.xfer == crate::XFER_CONTROL;
        let irp_id = if is_control && packet.len() >= 10 {
            u64::from_le_bytes(packet[2..10].try_into().unwrap())
        } else {
            0
        };
        let stage_raw = if is_control && header_len > crate::parse::USBPCAP_HEADER_LEN {
            packet.get(crate::parse::USBPCAP_HEADER_LEN).copied()
        } else {
            None
        };
        let setup = if is_control && stage_raw == Some(CTRL_STAGE_SETUP) {
            decode_setup(&payload)
        } else {
            None
        };
        // Direction: for control transfers the endpoint address (0x00) never carries the
        // direction — it lives in bmRequestType bit 7. Use the decoded setup when present.
        let dir = match &setup {
            Some(s) => s.dir,
            None => {
                if rec.endpoint & 0x80 != 0 {
                    "in"
                } else {
                    "out"
                }
            }
        };
        Ok(UsbFrame {
            i,
            ts_ns: rec.ts_ns,
            dev,
            ep: format!("0x{:02x}", rec.endpoint),
            dir,
            xfer: xfer_name(rec.xfer),
            len: rec.data_length,
            status,
            stage: stage_raw.map(ctrl_stage_name),
            irp: if is_control {
                format!("0x{irp_id:x}")
            } else {
                String::new()
            },
            // Wire-only fields; a USBPcap record is a whole transfer with no PID, no
            // bus-level address and no CRC to check.
            pid: None,
            addr: None,
            crc_ok: None,
            setup,
            hex: hexdump(&payload),
            ascii: asciidump(&payload),
            b64: base64::engine::general_purpose::STANDARD.encode(&payload),
            endpoint: rec.endpoint,
            stage_raw,
            irp_id,
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
            let (i, _off) = w
                .append_packet(2_000_000, &packet(0x81, 3, &payload))
                .unwrap();
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

    /// The point of P2: a wire session and a USBPcap session open through the *same*
    /// reader, and the reader works out which is which from the file. Nothing above this
    /// layer — `frames`, `payload`, `grep`, `diff`, the viewer — needs to know.
    #[test]
    fn a_wire_session_round_trips_through_the_same_reader() {
        let dir = std::env::temp_dir();
        let pcapng = dir.join("reveng_wire_rw_test.pcapng");
        let idx = dir.join("reveng_wire_rw_test.idx");
        let _ = std::fs::remove_file(&pcapng);
        let _ = std::fs::remove_file(&idx);

        // A Low-speed control transaction: SETUP token, the 8 setup bytes as DATA0, then
        // the device's ACK. GET_DESCRIPTOR(Device), 18 bytes, to address 1. Built with the
        // wire module's own CRC helpers, which are anchored against captured packets in
        // `wire::tests` — so this test exercises the reader, not the CRC.
        let tf = crate::wire::token_field(crate::wire::token_payload(1, 0));
        let setup_token = [0x2du8, tf[0], tf[1]];
        let mut setup_data = vec![0xc3u8, 0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00];
        setup_data.extend_from_slice(&crate::wire::crc16(&setup_data[1..]).to_le_bytes());
        let ack = [0xd2u8];

        {
            let mut w =
                UsbWriter::create_wire(&pcapng, &idx, crate::pcapng::LINKTYPE_USB_2_0_LOW_SPEED)
                    .unwrap();
            w.append_packet(1_000, &setup_token).unwrap();
            w.append_packet(2_000, &setup_data).unwrap();
            w.append_packet(3_000, &ack).unwrap();
            w.flush().unwrap();
        }

        let mut r = UsbReader::open(&pcapng, &idx).unwrap();
        assert_eq!(r.format(), crate::CaptureFormat::Wire);
        assert_eq!(r.len(), 3);

        let token = r.frame_at(0).unwrap();
        assert_eq!(token.pid, Some("SETUP"));
        assert_eq!(token.addr, Some(1), "address is on the token");
        assert_eq!(token.endpoint, 0);
        assert_eq!(token.xfer, "control");
        assert_eq!(token.crc_ok, Some(true));

        let data = r.frame_at(1).unwrap();
        assert_eq!(data.pid, Some("DATA0"));
        assert_eq!(data.addr, None, "a DATA packet carries no address");
        assert_eq!(data.endpoint, 0, "carried forward from the token");
        assert_eq!(data.crc_ok, Some(true));
        // The whole reason to decode the packet after a SETUP token: it reads as a command.
        let s = data
            .setup
            .expect("DATA0 after a SETUP token is the setup packet");
        assert_eq!(s.b_request, "0x06");
        assert_eq!(s.w_value, "0x0100");
        assert_eq!(s.w_length, 18);
        assert_eq!(s.dir, "in");
        assert_eq!(
            data.dir, "in",
            "direction comes from bmRequestType, not the token"
        );
        assert_eq!(data.stage, Some("setup"));

        let handshake = r.frame_at(2).unwrap();
        assert_eq!(handshake.pid, Some("ACK"));
        assert_eq!(handshake.crc_ok, None, "a handshake carries no CRC");
        assert!(handshake.payload.is_empty());

        // Payload means the same thing in both formats: the bytes a decoder wants.
        assert_eq!(r.payload_at(1).unwrap().len(), 8);
        assert!(r.payload_at(0).unwrap().is_empty());
        assert_eq!(r.pid_at(2).unwrap(), Some(crate::wire::PID_ACK));

        let _ = std::fs::remove_file(&pcapng);
        let _ = std::fs::remove_file(&idx);
    }

    /// A USBPcap session must keep reporting USBPcap fields once the reader can also read
    /// wire captures — the regression that a format switch invites.
    #[test]
    fn a_usbpcap_session_is_not_read_as_wire() {
        let dir = std::env::temp_dir();
        let pcapng = dir.join("reveng_fmt_guard.pcapng");
        let idx = dir.join("reveng_fmt_guard.idx");
        let _ = std::fs::remove_file(&pcapng);
        let _ = std::fs::remove_file(&idx);
        {
            let mut w = UsbWriter::create(&pcapng, &idx).unwrap();
            w.append_packet(1_000, &packet(0x81, 3, &[1, 2, 3]))
                .unwrap();
            w.flush().unwrap();
        }
        let mut r = UsbReader::open(&pcapng, &idx).unwrap();
        assert_eq!(r.format(), crate::CaptureFormat::UsbPcap);
        let f = r.frame_at(0).unwrap();
        assert_eq!(f.pid, None);
        assert_eq!(f.crc_ok, None);
        assert_eq!(f.xfer, "bulk");
        assert_eq!(f.payload, vec![1, 2, 3]);
        assert_eq!(r.pid_at(0).unwrap(), None);
        let _ = std::fs::remove_file(&pcapng);
        let _ = std::fs::remove_file(&idx);
    }

    #[test]
    fn refuses_to_write_wire_packets_under_a_non_wire_link_type() {
        let dir = std::env::temp_dir();
        // Writing wire packets under LINKTYPE_USBPCAP would produce a session that reads
        // back as USBPcap records — garbage that decodes without erroring.
        let err = UsbWriter::create_wire(
            dir.join("reveng_bad_lt.pcapng"),
            dir.join("reveng_bad_lt.idx"),
            crate::pcapng::LINKTYPE_USBPCAP,
        );
        assert!(err.is_err());
        let _ = std::fs::remove_file(dir.join("reveng_bad_lt.pcapng"));
        let _ = std::fs::remove_file(dir.join("reveng_bad_lt.idx"));
    }

    #[test]
    fn rejects_index_pointing_at_a_non_packet_block() {
        let dir = std::env::temp_dir();
        let pcapng = dir.join("reveng_usbrw_bad_offset.pcapng");
        let idx = dir.join("reveng_usbrw_bad_offset.idx");
        let _ = std::fs::remove_file(&pcapng);
        let _ = std::fs::remove_file(&idx);
        {
            let mut w = UsbWriter::create(&pcapng, &idx).unwrap();
            w.append_packet(1_000, &packet(0x81, 3, &[1])).unwrap();
            w.flush().unwrap();
        }
        let mut index = IndexFile::<UsbIdxRecord>::open(&idx).unwrap();
        let mut rec = index.get(0).unwrap();
        rec.byte_offset = 0; // Section Header Block, not an Enhanced Packet Block.
        drop(index);
        let mut replacement = IndexFile::<UsbIdxRecord>::create(&idx).unwrap();
        replacement.append(&rec).unwrap();
        drop(replacement);

        let mut reader = UsbReader::open(&pcapng, &idx).unwrap();
        assert!(reader.frame_at(0).is_err());
        let _ = std::fs::remove_file(pcapng);
        let _ = std::fs::remove_file(idx);
    }
}
