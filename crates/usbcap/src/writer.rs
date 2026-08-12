//! Writing a USB session: `usb.pcapng` (the Wireshark-openable truth) plus the
//! fixed-width `frames.idx` seek sidecar, appended together on the hot capture path
//! (DESIGN.md §4, §8.2). We own the pcapng writer so every frame's block byte-offset is
//! known (for `frames.idx` and later checkpoint-comment injection).

use crate::parse::parse_packet_header;
use crate::pcapng::{PcapngWriter, TsResolution};
use crate::wire::WireIndexer;
use crate::{CaptureFormat, UsbIdxRecord};
use reveng_core::index::IndexFile;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

pub struct UsbWriter {
    pcapng: PcapngWriter<BufWriter<File>>,
    idx: IndexFile<UsbIdxRecord>,
    format: CaptureFormat,
    /// Carries the current transaction's token across packets. Only used in
    /// [`CaptureFormat::Wire`]; a USBPcap record is self-describing.
    wire: WireIndexer,
}

impl UsbWriter {
    /// Create a fresh `usb.pcapng` + `frames.idx` for a USBPcap capture.
    pub fn create(
        pcapng_path: impl AsRef<Path>,
        idx_path: impl AsRef<Path>,
    ) -> anyhow::Result<Self> {
        let file = File::create(pcapng_path)?;
        let pcapng = PcapngWriter::new(BufWriter::new(file))?;
        let idx = IndexFile::<UsbIdxRecord>::create(idx_path)?;
        Ok(Self {
            pcapng,
            idx,
            format: CaptureFormat::UsbPcap,
            wire: WireIndexer::new(),
        })
    }

    /// Create a fresh `usb.pcapng` + `frames.idx` for raw wire packets from a hardware
    /// analyzer, declaring `link_type` (which carries the capture speed) and nanosecond
    /// timestamps — sub-microsecond bus timing being the point of using such hardware.
    ///
    /// `link_type` must be one the reader maps to [`CaptureFormat::Wire`], or the session
    /// would be written as wire packets and read back as USBPcap records.
    pub fn create_wire(
        pcapng_path: impl AsRef<Path>,
        idx_path: impl AsRef<Path>,
        link_type: u16,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            CaptureFormat::from_link_type(link_type) == CaptureFormat::Wire,
            "link type {link_type} is not a raw USB 2.0 wire type; a session written with \
             it would be read back as USBPcap records"
        );
        let file = File::create(pcapng_path)?;
        let pcapng =
            PcapngWriter::with_link_type(BufWriter::new(file), link_type, TsResolution::Nanos)?;
        let idx = IndexFile::<UsbIdxRecord>::create(idx_path)?;
        Ok(Self {
            pcapng,
            idx,
            format: CaptureFormat::Wire,
            wire: WireIndexer::new(),
        })
    }

    pub fn format(&self) -> CaptureFormat {
        self.format
    }

    pub fn len(&self) -> u64 {
        self.idx.len()
    }
    pub fn is_empty(&self) -> bool {
        self.idx.is_empty()
    }

    /// Append one packet exactly as the backend produced it — a USBPcap record (header +
    /// payload) or a raw wire packet — at session time `ts_ns`, deriving its index record.
    /// Returns `(frame_index, byte_offset)`.
    ///
    /// The stored bytes are never rewritten: the pcapng is the truth and reassembly is a
    /// view over it (DESIGN.md §8b). Only the index derivation differs by format.
    pub fn append_packet(&mut self, ts_ns: i64, packet: &[u8]) -> anyhow::Result<(u64, u64)> {
        let offset = self.pcapng.write_packet(ts_ns, packet)?;
        let rec = match self.format {
            CaptureFormat::UsbPcap => {
                let h = parse_packet_header(packet);
                let (endpoint, xfer, status, data_length) = h
                    .map(|h| (h.endpoint, h.transfer, h.status, h.data_length))
                    .unwrap_or((0, 0xff, 0, 0));
                UsbIdxRecord {
                    ts_ns,
                    byte_offset: offset,
                    endpoint,
                    dir: u8::from(endpoint & 0x80 != 0),
                    xfer,
                    status: (status & 0xff) as u8,
                    data_length,
                }
            }
            CaptureFormat::Wire => self.wire.index(ts_ns, offset, packet),
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
