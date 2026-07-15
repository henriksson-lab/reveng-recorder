//! Text/binary heuristics for choosing how to render a payload (DESIGN.md §8b).
//!
//! Capture always stores raw bytes; this only decides *presentation* — some USB endpoints
//! carry text (CDC-ACM serial, NMEA, AT commands, debug logs), most carry binary.

/// Fraction of bytes that are printable ASCII or common whitespace, in `0.0..=1.0`.
pub fn printable_ratio(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let printable = bytes
        .iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b) || matches!(b, b'\n' | b'\r' | b'\t'))
        .count();
    printable as f64 / bytes.len() as f64
}

/// Is this payload "texty" enough to render as text? Threshold 0.85; empty is not text.
pub fn is_texty(bytes: &[u8]) -> bool {
    !bytes.is_empty() && printable_ratio(bytes) >= 0.85
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_text_vs_binary() {
        assert!(is_texty(b"$GPGGA,123519,4807.038,N*47\r\n"));
        assert!(is_texty(b"AT+CGMR\r\nOK\r\n"));
        assert!(!is_texty(&[0x00, 0x01, 0x02, 0xff, 0x80, 0x7f, 0x00, 0x13]));
        assert!(!is_texty(b"")); // empty is not text
        // mostly-text with a couple of control bytes still reads as text
        assert!(is_texty(b"hello world\x00\x01 this is mostly text and readable"));
    }

    #[test]
    fn ratio_bounds() {
        assert_eq!(printable_ratio(b""), 0.0);
        assert_eq!(printable_ratio(b"ABCD"), 1.0);
        assert_eq!(printable_ratio(&[0x00, 0x00]), 0.0);
    }
}
