//! Writing a USB session: `usb.pcapng` (the Wireshark-openable truth) plus the
//! fixed-width `frames.idx` seek sidecar, appended together on the hot capture path
//! (DESIGN.md §4, §8.2). We own the pcapng writer so every frame's block byte-offset is
//! known (for `frames.idx` and later checkpoint-comment injection).

use crate::parse::parse_packet_header;
use crate::pcapng::PcapngWriter;
use crate::UsbIdxRecord;
use reveng_core::index::IndexFile;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

pub struct UsbWriter {
    pcapng: PcapngWriter<BufWriter<File>>,
    idx: IndexFile<UsbIdxRecord>,
}

impl UsbWriter {
    /// Create a fresh `usb.pcapng` + `frames.idx`.
    pub fn create(pcapng_path: impl AsRef<Path>, idx_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let file = File::create(pcapng_path)?;
        let pcapng = PcapngWriter::new(BufWriter::new(file))?;
        let idx = IndexFile::<UsbIdxRecord>::create(idx_path)?;
        Ok(Self { pcapng, idx })
    }

    pub fn len(&self) -> u64 {
        self.idx.len()
    }
    pub fn is_empty(&self) -> bool {
        self.idx.is_empty()
    }

    /// Append one raw USBPcap packet (header + payload, exactly as USBPcap emits it) at
    /// session time `ts_ns`. Parses the fixed header for the index; returns
    /// `(frame_index, byte_offset)`.
    pub fn append_packet(&mut self, ts_ns: i64, packet: &[u8]) -> anyhow::Result<(u64, u64)> {
        let offset = self.pcapng.write_packet(ts_ns, packet)?;
        let h = parse_packet_header(packet);
        let (endpoint, xfer, status, data_length) = h
            .map(|h| (h.endpoint, h.transfer, h.status, h.data_length))
            .unwrap_or((0, 0xff, 0, 0));
        let dir = if endpoint & 0x80 != 0 { 1 } else { 0 };
        let rec = UsbIdxRecord {
            ts_ns,
            byte_offset: offset,
            endpoint,
            dir,
            xfer,
            status: (status & 0xff) as u8,
            data_length,
        };
        let index = self.idx.append(&rec)?;
        Ok((index, offset))
    }

    /// Flush the pcapng writer to disk (call before finalize / comment injection).
    pub fn flush(&mut self) -> anyhow::Result<()> {
        self.pcapng.flush()?;
        Ok(())
    }
}
