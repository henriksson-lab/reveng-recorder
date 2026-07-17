//! Minimal pcapng writer/reader for USB captures (DESIGN.md §4, §8).
//!
//! We own the pcapng writer so we can preserve frame timestamps, return the byte offset
//! of every packet block (for `frames.idx`), and later inject checkpoint comments. Blocks
//! are written without options for compactness. Link type is `LINKTYPE_USBPCAP` (249).
//! Timestamps are stored in microseconds (the pcapng default resolution).

use std::io::Write;

pub const LINKTYPE_USBPCAP: u16 = 249;

const BT_SHB: u32 = 0x0A0D_0D0A;
const BT_IDB: u32 = 0x0000_0001;
const BT_EPB: u32 = 0x0000_0006;
const SHB_MAGIC: u32 = 0x1A2B_3C4D;

fn pad4(n: usize) -> usize {
    (4 - (n % 4)) % 4
}

/// Streaming pcapng writer that tracks byte offsets.
pub struct PcapngWriter<W: Write> {
    w: W,
    offset: u64,
}

impl<W: Write> PcapngWriter<W> {
    /// Write the Section Header + Interface Description blocks and return the writer.
    pub fn new(mut w: W) -> std::io::Result<Self> {
        let mut offset = 0u64;

        // --- SHB (no options), total length 28 ---
        let mut shb = Vec::new();
        shb.extend_from_slice(&BT_SHB.to_le_bytes());
        shb.extend_from_slice(&28u32.to_le_bytes());
        shb.extend_from_slice(&SHB_MAGIC.to_le_bytes());
        shb.extend_from_slice(&1u16.to_le_bytes()); // major
        shb.extend_from_slice(&0u16.to_le_bytes()); // minor
        shb.extend_from_slice(&(-1i64).to_le_bytes()); // section length: unknown
        shb.extend_from_slice(&28u32.to_le_bytes());
        w.write_all(&shb)?;
        offset += shb.len() as u64;

        // --- IDB (no options), total length 20 ---
        let mut idb = Vec::new();
        idb.extend_from_slice(&BT_IDB.to_le_bytes());
        idb.extend_from_slice(&20u32.to_le_bytes());
        idb.extend_from_slice(&LINKTYPE_USBPCAP.to_le_bytes());
        idb.extend_from_slice(&0u16.to_le_bytes()); // reserved
        idb.extend_from_slice(&0u32.to_le_bytes()); // snaplen: no limit
        idb.extend_from_slice(&20u32.to_le_bytes());
        w.write_all(&idb)?;
        offset += idb.len() as u64;

        Ok(Self { w, offset })
    }

    /// Append one packet (an Enhanced Packet Block). Returns the block's byte offset —
    /// this is exactly what goes into `frames.idx` for O(1) seeking.
    pub fn write_packet(&mut self, ts_ns: i64, data: &[u8]) -> std::io::Result<u64> {
        if ts_ns < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "pcapng packet timestamp must be non-negative",
            ));
        }
        let data_len = u32::try_from(data.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "packet is too large for pcapng",
            )
        })?;
        let block_offset = self.offset;
        let ts_us = (ts_ns / 1000) as u64;
        let ts_high = (ts_us >> 32) as u32;
        let ts_low = (ts_us & 0xFFFF_FFFF) as u32;
        let pad = pad4(data.len());
        let total = 32usize
            .checked_add(data.len())
            .and_then(|n| n.checked_add(pad))
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "packet is too large for a pcapng block",
                )
            })?;

        let mut b = Vec::with_capacity(total as usize);
        b.extend_from_slice(&BT_EPB.to_le_bytes());
        b.extend_from_slice(&total.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // interface id
        b.extend_from_slice(&ts_high.to_le_bytes());
        b.extend_from_slice(&ts_low.to_le_bytes());
        b.extend_from_slice(&data_len.to_le_bytes()); // captured len
        b.extend_from_slice(&data_len.to_le_bytes()); // original len
        b.extend_from_slice(data);
        b.extend(std::iter::repeat_n(0u8, pad));
        b.extend_from_slice(&total.to_le_bytes());

        self.w.write_all(&b)?;
        self.offset += b.len() as u64;
        Ok(block_offset)
    }

    pub fn into_inner(self) -> W {
        self.w
    }

    /// Current byte length written (== the offset the next block will start at).
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> std::io::Result<()> {
        self.w.flush()
    }
}

/// A parsed block descriptor.
#[derive(Debug, Clone, Copy)]
pub struct Block {
    pub offset: usize,
    pub len: usize,
    pub block_type: u32,
}

/// Scan a pcapng buffer into its blocks (no allocation of packet data).
pub fn scan_blocks(data: &[u8]) -> anyhow::Result<Vec<Block>> {
    let mut blocks = Vec::new();
    let mut off = 0usize;
    while data.len().saturating_sub(off) >= 8 {
        let block_type = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let len = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;
        let Some(end) = off.checked_add(len) else {
            anyhow::bail!("pcapng block length overflows at offset {off}");
        };
        if len < 12 || !len.is_multiple_of(4) || end > data.len() {
            anyhow::bail!("corrupt pcapng block at offset {off} (len {len})");
        }
        let trailing_len = u32::from_le_bytes(data[off + len - 4..off + len].try_into().unwrap()) as usize;
        if trailing_len != len {
            anyhow::bail!("pcapng block at offset {off} has mismatched trailing length");
        }
        blocks.push(Block {
            offset: off,
            len,
            block_type,
        });
        off += len;
    }
    if off != data.len() {
        anyhow::bail!("trailing {} byte(s) after final pcapng block", data.len() - off);
    }
    Ok(blocks)
}

/// A packet extracted from a pcapng buffer.
pub struct Packet<'a> {
    pub frame_index: u64,
    pub offset: usize,
    pub ts_ns: i64,
    pub data: &'a [u8],
}

/// Iterate the Enhanced Packet Blocks (the USB frames), in order.
pub fn packets(data: &[u8]) -> anyhow::Result<Vec<Packet<'_>>> {
    let mut out = Vec::new();
    let mut frame_index = 0u64;
    for b in scan_blocks(data)? {
        if b.block_type != BT_EPB {
            continue;
        }
        let o = b.offset;
        if b.len < 32 {
            anyhow::bail!("Enhanced Packet Block at offset {o} is too short");
        }
        let ts_high = u32::from_le_bytes(data[o + 12..o + 16].try_into().unwrap()) as u64;
        let ts_low = u32::from_le_bytes(data[o + 16..o + 20].try_into().unwrap()) as u64;
        let caplen = u32::from_le_bytes(data[o + 20..o + 24].try_into().unwrap()) as usize;
        let ts_us = (ts_high << 32) | ts_low;
        let ts_ns = ts_us
            .checked_mul(1000)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(|| anyhow::anyhow!("packet timestamp at offset {o} is out of range"))?;
        let data_start = o + 28;
        let data_end = data_start
            .checked_add(caplen)
            .filter(|&end| end <= o + b.len - 4)
            .ok_or_else(|| {
                anyhow::anyhow!("corrupt Enhanced Packet Block at offset {o} (caplen {caplen})")
            })?;
        out.push(Packet {
            frame_index,
            offset: o,
            ts_ns,
            data: &data[data_start..data_end],
        });
        frame_index += 1;
    }
    Ok(out)
}

/// Produce a new pcapng containing only frames `[start, end]` (inclusive), preserving the
/// section/interface headers. Used by "export slice around checkpoint" (DESIGN.md §10).
pub fn slice(data: &[u8], start_frame: u64, end_frame: u64) -> anyhow::Result<Vec<u8>> {
    let blocks = scan_blocks(data)?;
    let first_epb = blocks
        .iter()
        .position(|b| b.block_type == BT_EPB)
        .unwrap_or(blocks.len());

    let mut out = Vec::new();
    // Copy the header blocks (SHB, IDB, …) verbatim.
    for b in &blocks[..first_epb] {
        out.extend_from_slice(&data[b.offset..b.offset + b.len]);
    }
    // Copy the selected packet blocks.
    let mut frame_index = 0u64;
    for b in &blocks[first_epb..] {
        if b.block_type != BT_EPB {
            continue;
        }
        if frame_index >= start_frame && frame_index <= end_frame {
            out.extend_from_slice(&data[b.offset..b.offset + b.len]);
        }
        frame_index += 1;
    }
    Ok(out)
}

/// Rewrite a pcapng, injecting an `opt_comment` into the Enhanced Packet Blocks named in
/// `comments` (keyed by frame index). Checkpoint comments show up natively in Wireshark
/// (DESIGN.md §4). Returns the new bytes and the new byte-offset of every frame (in order)
/// so `frames.idx` can be updated — injecting a comment changes downstream offsets.
pub fn inject_comments(data: &[u8], comments: &[(u64, String)]) -> anyhow::Result<(Vec<u8>, Vec<u64>)> {
    use std::collections::HashMap;
    let map: HashMap<u64, &str> = comments.iter().map(|(i, s)| (*i, s.as_str())).collect();

    let blocks = scan_blocks(data)?;
    let mut out = Vec::with_capacity(data.len() + 64 * comments.len());
    let mut new_offsets = Vec::new();
    let mut frame_index = 0u64;

    for b in blocks {
        if b.block_type != BT_EPB {
            out.extend_from_slice(&data[b.offset..b.offset + b.len]);
            continue;
        }
        let o = b.offset;
        if b.len < 32 {
            anyhow::bail!("Enhanced Packet Block at offset {o} is too short");
        }
        let caplen = u32::from_le_bytes(data[o + 20..o + 24].try_into().unwrap()) as usize;
        let ts_high = u32::from_le_bytes(data[o + 12..o + 16].try_into().unwrap());
        let ts_low = u32::from_le_bytes(data[o + 16..o + 20].try_into().unwrap());
        let orig_len = u32::from_le_bytes(data[o + 24..o + 28].try_into().unwrap());
        let packet_end = (o + 28)
            .checked_add(caplen)
            .filter(|&end| end <= o + b.len - 4)
            .ok_or_else(|| anyhow::anyhow!("corrupt Enhanced Packet Block at offset {o}"))?;
        let pkt = &data[o + 28..packet_end];

        new_offsets.push(out.len() as u64);

        match map.get(&frame_index) {
            None => out.extend_from_slice(&data[o..o + b.len]), // unchanged
            Some(comment) => {
                let cbytes = comment.as_bytes();
                let comment_len = u16::try_from(cbytes.len())
                    .map_err(|_| anyhow::anyhow!("pcapng comment exceeds 65535 bytes"))?;
                let cpad = pad4(cbytes.len());
                let data_pad = pad4(caplen);
                // options: opt_comment (4 + clen + cpad) + opt_endofopt (4)
                let opts_len = 4 + cbytes.len() + cpad + 4;
                let total = 32usize
                    .checked_add(caplen)
                    .and_then(|n| n.checked_add(data_pad))
                    .and_then(|n| n.checked_add(opts_len))
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| anyhow::anyhow!("commented pcapng block is too large"))?;

                out.extend_from_slice(&BT_EPB.to_le_bytes());
                out.extend_from_slice(&total.to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes()); // interface id
                out.extend_from_slice(&ts_high.to_le_bytes());
                out.extend_from_slice(&ts_low.to_le_bytes());
                out.extend_from_slice(&(caplen as u32).to_le_bytes());
                out.extend_from_slice(&orig_len.to_le_bytes());
                out.extend_from_slice(pkt);
                out.extend(std::iter::repeat_n(0u8, data_pad));
                // opt_comment (code 1)
                out.extend_from_slice(&1u16.to_le_bytes());
                out.extend_from_slice(&comment_len.to_le_bytes());
                out.extend_from_slice(cbytes);
                out.extend(std::iter::repeat_n(0u8, cpad));
                // opt_endofopt (code 0, len 0)
                out.extend_from_slice(&0u16.to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes());
                out.extend_from_slice(&total.to_le_bytes());
            }
        }
        frame_index += 1;
    }
    Ok((out, new_offsets))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_comment_preserves_packets_and_reports_offsets() {
        let mut buf = Vec::new();
        {
            let mut w = PcapngWriter::new(&mut buf).unwrap();
            for i in 0..3u8 {
                w.write_packet((i as i64 + 1) * 1_000_000, &[i, i, i]).unwrap();
            }
        }
        let (out, offsets) = inject_comments(&buf, &[(1, "CHECKPOINT #7 — click".into())]).unwrap();
        // Same packets, same timestamps, intact order.
        let pkts = packets(&out).unwrap();
        assert_eq!(pkts.len(), 3);
        assert_eq!(pkts[0].data, &[0, 0, 0]);
        assert_eq!(pkts[1].data, &[1, 1, 1]);
        assert_eq!(pkts[2].data, &[2, 2, 2]);
        assert_eq!(pkts[1].ts_ns, 2_000_000);
        // Reported offsets match the parser's block offsets (frames.idx contract).
        assert_eq!(pkts[0].offset as u64, offsets[0]);
        assert_eq!(pkts[1].offset as u64, offsets[1]);
        assert_eq!(pkts[2].offset as u64, offsets[2]);
        // The comment bytes are present.
        assert!(out.windows(5).any(|w| w == b"click"));
    }

    #[test]
    fn write_then_read_roundtrips() {
        let mut buf = Vec::new();
        let mut offsets = Vec::new();
        {
            let mut w = PcapngWriter::new(&mut buf).unwrap();
            offsets.push(w.write_packet(1_000_000, &[0xAA, 0xBB, 0xCC]).unwrap());
            offsets.push(w.write_packet(2_000_000, &[0x01]).unwrap());
            offsets.push(w.write_packet(3_000_000, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap());
        }
        let pkts = packets(&buf).unwrap();
        assert_eq!(pkts.len(), 3);
        assert_eq!(pkts[0].data, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(pkts[0].ts_ns, 1_000_000);
        assert_eq!(pkts[1].data, &[0x01]);
        assert_eq!(pkts[2].data, &[0xDE, 0xAD, 0xBE, 0xEF]);
        // reported offsets match the parser's block offsets (frames.idx contract)
        assert_eq!(pkts[0].offset as u64, offsets[0]);
        assert_eq!(pkts[2].offset as u64, offsets[2]);
    }

    #[test]
    fn slice_keeps_headers_and_selected_frames() {
        let mut buf = Vec::new();
        {
            let mut w = PcapngWriter::new(&mut buf).unwrap();
            for i in 0..5u8 {
                w.write_packet((i as i64 + 1) * 1_000_000, &[i, i, i]).unwrap();
            }
        }
        let sliced = slice(&buf, 1, 3).unwrap();
        let pkts = packets(&sliced).unwrap();
        assert_eq!(pkts.len(), 3);
        assert_eq!(pkts[0].data, &[1, 1, 1]);
        assert_eq!(pkts[2].data, &[3, 3, 3]);
    }

    #[test]
    fn malformed_epb_returns_error_instead_of_panicking() {
        let mut short = Vec::new();
        short.extend_from_slice(&BT_EPB.to_le_bytes());
        short.extend_from_slice(&12u32.to_le_bytes());
        short.extend_from_slice(&12u32.to_le_bytes());
        assert!(packets(&short).is_err());
        assert!(inject_comments(&short, &[(0, "note".into())]).is_err());

        let mut oversized_caplen = Vec::new();
        {
            let mut w = PcapngWriter::new(&mut oversized_caplen).unwrap();
            w.write_packet(1_000, &[1, 2, 3]).unwrap();
        }
        // First EPB begins after the 28-byte SHB and 20-byte IDB.
        oversized_caplen[68..72].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(packets(&oversized_caplen).is_err());
        assert!(inject_comments(&oversized_caplen, &[(0, "note".into())]).is_err());
    }
}
