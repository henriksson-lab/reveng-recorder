//! USB 2.0 **wire packet** decoding — the bus-level counterpart to [`crate::parse`].
//!
//! A USBPcap record is a whole transfer as the Windows stack saw it. A hardware analyzer
//! records what was physically on the bus: individual tokens, data packets and handshakes.
//! This module decodes one such packet, and derives the `frames.idx` record for it.
//!
//! # Packet layout (USB 2.0 §8)
//!
//! Every packet starts with a **PID byte**: the 4-bit packet ID in the low nibble and its
//! ones-complement in the high nibble. A byte failing that check is not a packet.
//!
//! ```text
//! token      PID  addr[6:0] endp[3:0] crc5[4:0]          3 bytes
//! SOF        PID  frame[10:0]         crc5[4:0]          3 bytes
//! data       PID  payload…            crc16[15:0]        3 + n bytes
//! handshake  PID                                         1 byte
//! ```
//!
//! Token address/endpoint are packed LSB-first across the two bytes after the PID, so the
//! endpoint straddles the byte boundary — bit 0 is the top bit of the first byte.
//!
//! # Why a state machine is needed for indexing
//!
//! Only a **token** carries an address and endpoint. The DATA and handshake packets that
//! follow it identify themselves by nothing at all — they belong to whichever transaction
//! is in progress. Indexing therefore has to carry the last token forward
//! ([`WireIndexer`]), or every payload on the bus ends up unattributed.

use crate::{UsbIdxRecord, XFER_CONTROL, XFER_UNKNOWN};

/// 4-bit packet IDs (USB 2.0 table 8-1). These are the low nibble of the PID byte.
pub const PID_OUT: u8 = 0b0001;
pub const PID_IN: u8 = 0b1001;
pub const PID_SOF: u8 = 0b0101;
pub const PID_SETUP: u8 = 0b1101;
pub const PID_DATA0: u8 = 0b0011;
pub const PID_DATA1: u8 = 0b1011;
pub const PID_DATA2: u8 = 0b0111;
pub const PID_MDATA: u8 = 0b1111;
pub const PID_ACK: u8 = 0b0010;
pub const PID_NAK: u8 = 0b1010;
pub const PID_STALL: u8 = 0b1110;
pub const PID_NYET: u8 = 0b0110;
pub const PID_PRE: u8 = 0b1100;
pub const PID_SPLIT: u8 = 0b1000;
pub const PID_PING: u8 = 0b0100;

/// What a PID means structurally — which fields the rest of the packet has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    /// IN/OUT/SETUP/PING — carries address and endpoint.
    Token,
    /// Start of Frame — carries a frame number, no address.
    Sof,
    /// DATA0/1/2/MDATA — carries a payload and CRC16.
    Data,
    /// ACK/NAK/STALL/NYET — the PID is the whole packet.
    Handshake,
    /// PRE/ERR/SPLIT, and anything with a valid PID we do not model.
    Special,
}

/// Human name for a PID, or `"?"`.
pub fn pid_name(pid: u8) -> &'static str {
    match pid {
        PID_OUT => "OUT",
        PID_IN => "IN",
        PID_SOF => "SOF",
        PID_SETUP => "SETUP",
        PID_DATA0 => "DATA0",
        PID_DATA1 => "DATA1",
        PID_DATA2 => "DATA2",
        PID_MDATA => "MDATA",
        PID_ACK => "ACK",
        PID_NAK => "NAK",
        PID_STALL => "STALL",
        PID_NYET => "NYET",
        PID_PRE => "PRE/ERR",
        PID_SPLIT => "SPLIT",
        PID_PING => "PING",
        _ => "?",
    }
}

/// The on-wire PID byte for a 4-bit packet ID: the ID in the low nibble, its
/// ones-complement in the high nibble. Inverse of the check in [`decode`].
pub fn pid_byte(pid: u8) -> u8 {
    (pid & 0x0f) | ((!pid & 0x0f) << 4)
}

/// Structural class of a PID.
pub fn pid_kind(pid: u8) -> PacketKind {
    match pid {
        PID_OUT | PID_IN | PID_SETUP | PID_PING => PacketKind::Token,
        PID_SOF => PacketKind::Sof,
        PID_DATA0 | PID_DATA1 | PID_DATA2 | PID_MDATA => PacketKind::Data,
        PID_ACK | PID_NAK | PID_STALL | PID_NYET => PacketKind::Handshake,
        _ => PacketKind::Special,
    }
}

/// A decoded wire packet, borrowing its payload from the captured bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WirePacket<'a> {
    /// The 4-bit packet ID (low nibble of the PID byte).
    pub pid: u8,
    pub kind: PacketKind,
    /// Device address, for tokens only.
    pub addr: Option<u8>,
    /// Endpoint number, for tokens only.
    pub endpoint: Option<u8>,
    /// Frame number, for SOF only.
    pub frame_number: Option<u16>,
    /// The data field of a DATA packet — PID and CRC16 stripped. Empty otherwise.
    pub data: &'a [u8],
    /// Whether the packet's CRC checks out. `None` when the packet carries no CRC
    /// (handshakes) or is too short to hold one.
    pub crc_ok: Option<bool>,
}

/// Decode one wire packet. Returns `None` when the PID byte fails its complement check,
/// which is how framing garbage — the signature of a wrong capture speed — is rejected.
pub fn decode(bytes: &[u8]) -> Option<WirePacket<'_>> {
    let b0 = *bytes.first()?;
    let pid = b0 & 0x0f;
    if (!b0 >> 4) & 0x0f != pid {
        return None;
    }
    let kind = pid_kind(pid);
    let mut p = WirePacket {
        pid,
        kind,
        addr: None,
        endpoint: None,
        frame_number: None,
        data: &[],
        crc_ok: None,
    };
    match kind {
        PacketKind::Token if bytes.len() >= 3 => {
            let field = u16::from_le_bytes([bytes[1], bytes[2]]);
            p.addr = Some((field & 0x7f) as u8);
            p.endpoint = Some(((field >> 7) & 0x0f) as u8);
            p.crc_ok = Some(crc5_ok(field));
        }
        PacketKind::Sof if bytes.len() >= 3 => {
            let field = u16::from_le_bytes([bytes[1], bytes[2]]);
            p.frame_number = Some(field & 0x07ff);
            p.crc_ok = Some(crc5_ok(field));
        }
        PacketKind::Data if bytes.len() >= 3 => {
            let body = &bytes[1..];
            let (data, crc) = body.split_at(body.len() - 2);
            p.data = data;
            p.crc_ok = Some(crc16(data) == u16::from_le_bytes([crc[0], crc[1]]));
        }
        _ => {}
    }
    Some(p)
}

/// USB CRC5 over an 11-bit token field: x^5 + x^2 + 1, LSB-first, initial value all-ones,
/// result complemented.
pub fn crc5(payload: u16) -> u8 {
    let mut rem: u8 = 0x1f;
    for i in 0..11 {
        let bit = ((payload >> i) & 1) as u8;
        let xor = (rem & 0x01) ^ bit;
        rem >>= 1;
        if xor != 0 {
            rem ^= 0x14;
        }
    }
    rem ^ 0x1f
}

/// Build the two bytes that follow a token PID: an 11-bit field plus its CRC5, as they go
/// on the wire (little-endian). Inverse of the split done in [`decode`].
pub fn token_field(payload: u16) -> [u8; 2] {
    let payload = payload & 0x07ff;
    (payload | ((crc5(payload) as u16) << 11)).to_le_bytes()
}

/// The 11-bit token field packs `addr[6:0]` then `endp[3:0]`, LSB-first.
pub fn token_payload(addr: u8, endpoint: u8) -> u16 {
    ((addr as u16) & 0x7f) | (((endpoint as u16) & 0x0f) << 7)
}

/// `field` is the two bytes after the PID read little-endian: 11 payload bits then the
/// 5 CRC bits. Verifying is a plain recompute — the residue trick buys nothing here and
/// reads worse.
fn crc5_ok(field: u16) -> bool {
    crc5(field & 0x07ff) == (field >> 11) as u8
}

/// USB CRC16 over a data packet's payload: x^16 + x^15 + x^2 + 1, LSB-first, initial value
/// all-ones, result complemented. Transmitted little-endian after the payload.
pub fn crc16(data: &[u8]) -> u16 {
    let mut rem: u16 = 0xffff;
    for &byte in data {
        for i in 0..8 {
            let bit = ((byte >> i) & 1) as u16;
            let xor = (rem & 0x0001) ^ bit;
            rem >>= 1;
            if xor != 0 {
                rem ^= 0xa001;
            }
        }
    }
    rem ^ 0xffff
}

/// Derives `frames.idx` records from a stream of wire packets.
///
/// Carries the current transaction's token forward so that DATA and handshake packets are
/// attributed to the right endpoint. A capture that starts mid-transaction therefore has
/// its first few packets attributed to address 0 endpoint 0 — unavoidable, and harmless
/// next to the alternative of leaving every payload on the bus unaddressed.
#[derive(Debug, Default, Clone)]
pub struct WireIndexer {
    addr: u8,
    endpoint: u8,
    /// Direction of the transaction in progress, as `UsbIdxRecord::dir` encodes it.
    dir: u8,
    /// Set by a SETUP token, cleared by the next non-SETUP token.
    control: bool,
}

impl WireIndexer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Index one wire packet captured at `ts_ns` and stored at `byte_offset`.
    ///
    /// Field meanings differ from the USBPcap backend, deliberately:
    ///
    /// - `endpoint` — from the current transaction's token, not this packet.
    /// - `dir` — the **transaction's** direction. An ACK to an IN transaction is indexed
    ///   `in` even though the handshake itself travels host→device, because filtering by
    ///   direction means "which way is this transaction's data going".
    /// - `xfer` — [`XFER_CONTROL`] for endpoint 0 or a SETUP-initiated transaction,
    ///   [`XFER_UNKNOWN`] otherwise. Bulk, interrupt and isochronous are indistinguishable
    ///   on the wire without the endpoint descriptors; claiming one would be invention.
    /// - `status` — the **PID**, not a host status code. A wire capture has no host status;
    ///   the PID is what makes a handshake or SOF filterable without reading the pcapng.
    /// - `data_length` — the data field's length, CRC excluded.
    pub fn index(&mut self, ts_ns: i64, byte_offset: u64, packet: &[u8]) -> UsbIdxRecord {
        let decoded = decode(packet);
        let (pid, data_length) = match &decoded {
            Some(p) => (p.pid, p.data.len() as u32),
            // Undecodable bytes still get a record: dropping them would make a capture with
            // a framing problem look merely sparse.
            None => (0xff, 0),
        };

        if let Some(p) = &decoded {
            match p.kind {
                PacketKind::Token => {
                    self.addr = p.addr.unwrap_or(0);
                    self.endpoint = p.endpoint.unwrap_or(0);
                    self.dir = u8::from(pid == PID_IN);
                    self.control = pid == PID_SETUP;
                }
                PacketKind::Sof => {
                    // SOF belongs to no transaction and must not overwrite one.
                    return UsbIdxRecord {
                        ts_ns,
                        byte_offset,
                        endpoint: 0,
                        dir: 0,
                        xfer: XFER_UNKNOWN,
                        status: PID_SOF,
                        data_length: 0,
                    };
                }
                _ => {}
            }
        }

        UsbIdxRecord {
            ts_ns,
            byte_offset,
            endpoint: self.endpoint,
            dir: self.dir,
            xfer: if self.control || self.endpoint == 0 {
                XFER_CONTROL
            } else {
                XFER_UNKNOWN
            },
            status: pid,
            data_length,
        }
    }

    /// The device address of the transaction in progress.
    pub fn address(&self) -> u8 {
        self.addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes captured from a Low-speed keyboard through a Cynthion. Every assertion here
    /// is against real bus traffic, not a constructed packet.
    const IN_TOKEN: [u8; 3] = [0x69, 0x8f, 0xa8];
    const NAK: [u8; 1] = [0x5a];
    const DATA1_EMPTY_REPORT: [u8; 11] = [
        0x4b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbf, 0xf4,
    ];

    #[test]
    fn decodes_a_captured_in_token() {
        let p = decode(&IN_TOKEN).unwrap();
        assert_eq!(p.pid, PID_IN);
        assert_eq!(p.kind, PacketKind::Token);
        assert_eq!(p.addr, Some(0x0f));
        assert_eq!(p.endpoint, Some(1));
        assert_eq!(p.crc_ok, Some(true), "CRC5 of a real token must verify");
    }

    #[test]
    fn decodes_a_captured_handshake() {
        let p = decode(&NAK).unwrap();
        assert_eq!(p.pid, PID_NAK);
        assert_eq!(p.kind, PacketKind::Handshake);
        assert!(p.data.is_empty());
        assert_eq!(p.crc_ok, None);
    }

    #[test]
    fn decodes_a_captured_data_packet_and_checks_its_crc() {
        let p = decode(&DATA1_EMPTY_REPORT).unwrap();
        assert_eq!(p.pid, PID_DATA1);
        assert_eq!(p.kind, PacketKind::Data);
        assert_eq!(p.data, &[0u8; 8]);
        assert_eq!(
            p.crc_ok,
            Some(true),
            "CRC16 of a real HID report must verify"
        );
    }

    #[test]
    fn rejects_a_bad_pid_byte() {
        // Framing garbage — which is what a wrong --speed produces — must not decode.
        assert!(decode(&[0x69 ^ 0x01]).is_none());
        assert!(decode(&[]).is_none());
    }

    #[test]
    fn flags_a_corrupted_crc() {
        let mut bad = DATA1_EMPTY_REPORT;
        bad[4] ^= 0x01;
        assert_eq!(decode(&bad).unwrap().crc_ok, Some(false));
        let mut bad_token = IN_TOKEN;
        bad_token[1] ^= 0x01;
        assert_eq!(decode(&bad_token).unwrap().crc_ok, Some(false));
    }

    #[test]
    fn attributes_data_and_handshake_to_the_preceding_token() {
        let mut ix = WireIndexer::new();
        let token = ix.index(10, 0, &IN_TOKEN);
        let data = ix.index(20, 32, &DATA1_EMPTY_REPORT);
        let ack = ix.index(30, 64, &NAK);

        for r in [token, data, ack] {
            assert_eq!(r.endpoint, 1, "inherited from the IN token");
            assert_eq!(r.dir, 1, "the transaction is IN");
            assert_eq!(
                r.xfer, XFER_UNKNOWN,
                "not endpoint 0, so not knowably control"
            );
        }
        assert_eq!(token.status, PID_IN);
        assert_eq!(data.status, PID_DATA1);
        assert_eq!(data.data_length, 8, "CRC excluded");
        assert_eq!(ack.status, PID_NAK);
        assert_eq!(ix.address(), 0x0f);
    }

    #[test]
    fn sof_does_not_disturb_the_transaction_in_progress() {
        // A SOF lands every 1 ms (125 µs at high speed) and can fall between a token and
        // its data. Letting it clear the endpoint would misattribute the payload.
        let mut ix = WireIndexer::new();
        ix.index(10, 0, &IN_TOKEN);
        let sof = ix.index(15, 32, &[0xa5, 0x00, 0x10]);
        assert_eq!(sof.status, PID_SOF);
        let data = ix.index(20, 64, &DATA1_EMPTY_REPORT);
        assert_eq!(data.endpoint, 1);
        assert_eq!(data.status, PID_DATA1);
    }

    /// The token builders must reproduce a packet captured off real hardware — otherwise
    /// tests that construct tokens with them would be checking the decoder against itself.
    #[test]
    fn token_builders_reproduce_a_captured_token() {
        let field = token_field(token_payload(0x0f, 1));
        assert_eq!([0x69, field[0], field[1]], IN_TOKEN);
    }

    #[test]
    fn a_setup_token_marks_the_transaction_control() {
        let mut ix = WireIndexer::new();
        // SETUP to address 1 endpoint 0.
        let f = token_field(token_payload(1, 0));
        let setup = ix.index(10, 0, &[0x2d, f[0], f[1]]);
        assert_eq!(setup.xfer, XFER_CONTROL);
        assert_eq!(setup.dir, 0, "SETUP is host->device");
        let data = ix.index(20, 32, &DATA1_EMPTY_REPORT);
        assert_eq!(data.xfer, XFER_CONTROL, "still the control transaction");
    }

    #[test]
    fn undecodable_bytes_still_produce_a_record() {
        let mut ix = WireIndexer::new();
        let r = ix.index(10, 0, &[0x00, 0x01]);
        assert_eq!(r.status, 0xff, "marked unknown rather than dropped");
        assert_eq!(r.data_length, 0);
    }
}
