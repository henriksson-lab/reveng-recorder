//! Parsing of the `USBPCAP_BUFFER_PACKET_HEADER` (DESIGN.md §4).
//!
//! Layout (little-endian, packed — 27 bytes before payload):
//! ```text
//!   off  size  field
//!   0    2     headerLen (u16)
//!   2    8     irpId     (u64)
//!   10   4     status    (u32, USBD_STATUS)
//!   14   2     function  (u16)
//!   16   1     info      (u8)
//!   17   2     bus       (u16)
//!   19   2     device    (u16)
//!   21   1     endpoint  (u8)
//!   22   1     transfer  (u8)
//!   23   4     dataLength(u32)
//! ```
//! This logic is pure and cross-platform, so it is unit-tested off Windows.

use reveng_core::event::UsbFrameHeader;

pub const USBPCAP_HEADER_LEN: usize = 27;

/// Parse the fixed USBPcap packet header. Returns `None` if the slice is too short.
pub fn parse_packet_header(buf: &[u8]) -> Option<UsbFrameHeader> {
    if buf.len() < USBPCAP_HEADER_LEN {
        return None;
    }
    let u16le = |o: usize| u16::from_le_bytes([buf[o], buf[o + 1]]);
    let u32le = |o: usize| u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
    Some(UsbFrameHeader {
        status: u32le(10),
        bus: u16le(17),
        device: u16le(19),
        endpoint: buf[21],
        transfer: buf[22],
        data_length: u32le(23),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_fields() {
        let mut b = [0u8; USBPCAP_HEADER_LEN];
        b[0..2].copy_from_slice(&27u16.to_le_bytes()); // headerLen
        b[10..14].copy_from_slice(&0u32.to_le_bytes()); // status
        b[17..19].copy_from_slice(&1u16.to_le_bytes()); // bus
        b[19..21].copy_from_slice(&5u16.to_le_bytes()); // device
        b[21] = 0x81; // endpoint (IN)
        b[22] = 2; // transfer = control
        b[23..27].copy_from_slice(&64u32.to_le_bytes()); // dataLength

        let h = parse_packet_header(&b).unwrap();
        assert_eq!(h.bus, 1);
        assert_eq!(h.device, 5);
        assert_eq!(h.endpoint, 0x81);
        assert_eq!(h.transfer, 2);
        assert_eq!(h.data_length, 64);
    }

    #[test]
    fn rejects_short() {
        assert!(parse_packet_header(&[0u8; 10]).is_none());
    }
}
