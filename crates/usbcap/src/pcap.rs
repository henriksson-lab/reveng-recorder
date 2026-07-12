//! Reading the classic libpcap stream that `USBPcapCMD.exe -o -` writes to stdout
//! (DESIGN.md §4). This is *input* parsing — we re-emit frames into our own pcapng
//! (see [`crate::pcapng`]); it is not the on-disk format.
//!
//! libpcap layout (little-endian for the magics we accept):
//! ```text
//!   Global header (24 bytes):
//!     magic (u32)  0xa1b2c3d4 = microsecond ts, 0xa1b23c4d = nanosecond ts
//!     ver_major(u16) ver_minor(u16) thiszone(i32) sigfigs(u32) snaplen(u32) linktype(u32)
//!   Record header (16 bytes), repeated:
//!     ts_sec(u32) ts_frac(u32) incl_len(u32) orig_len(u32)  then incl_len bytes of data
//! ```

use std::io::Read;

pub const DLT_USBPCAP: u32 = 249;
const MAGIC_USEC: u32 = 0xa1b2_c3d4;
const MAGIC_NSEC: u32 = 0xa1b2_3c4d;
/// Upper bound on a single record's captured length (64 MiB) — a corruption guard.
const MAX_RECORD_LEN: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct GlobalHeader {
    pub linktype: u32,
    /// True if record `ts_frac` is nanoseconds, false if microseconds.
    pub nanos: bool,
}

/// One captured record: a wall-clock timestamp plus the raw packet bytes (which, for
/// `DLT_USBPCAP`, are a `USBPCAP_BUFFER_PACKET_HEADER` + payload).
#[derive(Debug, Clone)]
pub struct PcapRecord {
    /// Wall-clock time as Unix nanoseconds.
    pub unix_ns: i64,
    pub data: Vec<u8>,
}

/// Streaming libpcap reader over any byte source (a child's stdout, a file, …).
pub struct PcapReader<R: Read> {
    r: R,
    header: GlobalHeader,
}

fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(false); // clean EOF at a record boundary
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated pcap record",
                ));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

impl<R: Read> PcapReader<R> {
    /// Consume and validate the 24-byte global header.
    pub fn new(mut r: R) -> anyhow::Result<Self> {
        let mut gh = [0u8; 24];
        if !read_exact_or_eof(&mut r, &mut gh)? {
            anyhow::bail!("pcap stream ended before the global header");
        }
        let magic = u32::from_le_bytes(gh[0..4].try_into().unwrap());
        let nanos = match magic {
            MAGIC_USEC => false,
            MAGIC_NSEC => true,
            other => anyhow::bail!("unexpected pcap magic 0x{other:08x} (not little-endian libpcap)"),
        };
        let linktype = u32::from_le_bytes(gh[20..24].try_into().unwrap());
        Ok(Self {
            r,
            header: GlobalHeader { linktype, nanos },
        })
    }

    pub fn header(&self) -> GlobalHeader {
        self.header
    }

    /// Read the next record, or `Ok(None)` at a clean end of stream.
    pub fn next_record(&mut self) -> anyhow::Result<Option<PcapRecord>> {
        let mut rh = [0u8; 16];
        if !read_exact_or_eof(&mut self.r, &mut rh)? {
            return Ok(None);
        }
        let ts_sec = u32::from_le_bytes(rh[0..4].try_into().unwrap()) as i64;
        let ts_frac = u32::from_le_bytes(rh[4..8].try_into().unwrap()) as i64;
        let incl_len = u32::from_le_bytes(rh[8..12].try_into().unwrap()) as usize;

        // Sanity-cap the record length so a corrupt/garbage stream can't request a huge
        // allocation. USB URBs are far below this; a real frame never approaches it.
        if incl_len > MAX_RECORD_LEN {
            anyhow::bail!("pcap record length {incl_len} exceeds sane maximum ({MAX_RECORD_LEN})");
        }

        let mut data = vec![0u8; incl_len];
        if incl_len > 0 && !read_exact_or_eof(&mut self.r, &mut data)? {
            anyhow::bail!("pcap record header promised {incl_len} bytes but stream ended");
        }
        let frac_ns = if self.header.nanos { ts_frac } else { ts_frac * 1000 };
        Ok(Some(PcapRecord {
            unix_ns: ts_sec * 1_000_000_000 + frac_ns,
            data,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn global_header(magic: u32, linktype: u32) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&magic.to_le_bytes());
        h.extend_from_slice(&2u16.to_le_bytes()); // ver major
        h.extend_from_slice(&4u16.to_le_bytes()); // ver minor
        h.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        h.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        h.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        h.extend_from_slice(&linktype.to_le_bytes());
        h
    }

    fn record(ts_sec: u32, ts_frac: u32, data: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&ts_sec.to_le_bytes());
        r.extend_from_slice(&ts_frac.to_le_bytes());
        r.extend_from_slice(&(data.len() as u32).to_le_bytes());
        r.extend_from_slice(&(data.len() as u32).to_le_bytes());
        r.extend_from_slice(data);
        r
    }

    #[test]
    fn parses_microsecond_stream() {
        let mut buf = global_header(MAGIC_USEC, DLT_USBPCAP);
        buf.extend(record(2, 500_000, &[0xaa, 0xbb])); // 2.5s
        buf.extend(record(3, 0, &[0x01]));

        let mut r = PcapReader::new(std::io::Cursor::new(buf)).unwrap();
        assert_eq!(r.header().linktype, DLT_USBPCAP);
        assert!(!r.header().nanos);
        let a = r.next_record().unwrap().unwrap();
        assert_eq!(a.unix_ns, 2_500_000_000);
        assert_eq!(a.data, vec![0xaa, 0xbb]);
        let b = r.next_record().unwrap().unwrap();
        assert_eq!(b.unix_ns, 3_000_000_000);
        assert!(r.next_record().unwrap().is_none());
    }

    #[test]
    fn parses_nanosecond_stream() {
        let mut buf = global_header(MAGIC_NSEC, DLT_USBPCAP);
        buf.extend(record(1, 250, &[0x99]));
        let mut r = PcapReader::new(std::io::Cursor::new(buf)).unwrap();
        assert!(r.header().nanos);
        let a = r.next_record().unwrap().unwrap();
        assert_eq!(a.unix_ns, 1_000_000_250);
    }

    #[test]
    fn rejects_bad_magic() {
        let buf = global_header(0xdead_beef, DLT_USBPCAP);
        assert!(PcapReader::new(std::io::Cursor::new(buf)).is_err());
    }

    #[test]
    fn rejects_oversized_record_len() {
        let mut buf = global_header(MAGIC_USEC, DLT_USBPCAP);
        // A record header claiming ~4 GiB of payload, with no payload following.
        buf.extend_from_slice(&1u32.to_le_bytes()); // ts_sec
        buf.extend_from_slice(&0u32.to_le_bytes()); // ts_frac
        buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // incl_len
        buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // orig_len
        let mut r = PcapReader::new(std::io::Cursor::new(buf)).unwrap();
        assert!(r.next_record().is_err()); // capped, not a 4 GB allocation
    }
}
