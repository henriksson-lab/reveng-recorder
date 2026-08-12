//! [`CaptureSource`] implementation over the Cynthion analyzer.
//!
//! Shape follows the USBPcap backend: a reader thread drains the hardware into a channel,
//! `next()` is a blocking pull off that channel, and a separate stop handle exists because
//! [`CaptureSource`] has no cancellation method — a source parked in `next()` can only be
//! released from outside.
//!
//! What is different is the abstraction level. USBPcap hands over whole transfers as the
//! Windows stack saw them; this hands over **wire packets**, plus bus events the host
//! stack never sees at all. See the crate docs for the framing.

use crate::{
    capture_state, Speed, ANALYZER_INTERFACE, EP_CAPTURE, GATEWARE_PROTOCOL, PID, REQ_STATE, VID,
};
use anyhow::{bail, Context, Result};
use futures_lite::future::block_on;
use reveng_core::clock::Clock;
use reveng_core::event::{SourceKind, TrafficKind, TrafficRecord, UsbFrameHeader};
use reveng_core::source::CaptureSource;
use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

/// Transfers kept in flight, and the size of each. Enough that a burst is not lost while
/// a completion is being handled.
const NUM_TRANSFERS: usize = 8;
/// Read-buffer size, chosen by capture speed — the two ends of the bus want opposite things.
///
/// A bulk IN completes only when it fills or the device sends a short packet, so buffer size
/// *is* capture latency. On a Low-speed bus (~8 KB/s of wire data) a 16 KiB buffer takes two
/// seconds to fill; measured, that lost the last 2 s of every 6 s capture. On a High-speed
/// bus a camera can produce tens of MB/s, where a small buffer means tens of thousands of
/// completions a second and an analyzer that overflows the moment the host hiccups.
///
/// So: small at Low speed for latency, large at High speed for headroom. (Packetry uses a
/// flat 16 KiB × 4 = 64 KiB in flight; at High speed this gives 128 KiB.)
const fn read_len(speed: Speed) -> usize {
    match speed {
        Speed::Low => 4 * 1024,
        // Full is ~1.5 MB/s at most, so 16 KiB still fills in ~11 ms.
        Speed::Full => 16 * 1024,
        // Auto included: it may resolve to High, and under-buffering there is the costlier
        // mistake — a slow capture is recoverable, a dropped one is not.
        Speed::High | Speed::Auto => 16 * 1024,
    }
}

/// One decoded record off the analyzer stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// A packet seen on the target bus.
    Packet { ts_ns: i64, bytes: Vec<u8> },
    /// A bus event: capture start/stop, speed change, line state, reset, keepalive…
    Event { ts_ns: i64, code: u8 },
}

/// Incremental decoder for the analyzer's byte stream.
///
/// Kept separate from the USB plumbing so it can be tested on canned bytes with no
/// hardware — which is the only way the framing gets covered on Linux and macOS CI.
#[derive(Default)]
pub struct StreamDecoder {
    buffer: VecDeque<u8>,
    /// Running total of clock cycles; timestamps are deltas against it.
    cycles: u64,
    /// A packet of odd length is followed by one padding byte.
    padding_due: bool,
}

impl StreamDecoder {
    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend(data);
    }

    /// Pull the next complete record, or `None` when more bytes are needed.
    pub fn next_record(&mut self) -> Option<Record> {
        if self.padding_due {
            if self.buffer.is_empty() {
                return None;
            }
            self.buffer.pop_front();
            self.padding_due = false;
        }

        if self.buffer.len() < 4 {
            return None;
        }

        let head = u16::from_be_bytes([self.buffer[0], self.buffer[1]]);
        let delta = u16::from_be_bytes([self.buffer[2], self.buffer[3]]) as u64;

        // `0xFF` in the high byte marks an event; anything else is a packet length.
        if self.buffer[0] == 0xFF {
            let code = self.buffer[1];
            self.cycles += delta;
            self.buffer.drain(0..4);
            return Some(Record::Event {
                ts_ns: clk_to_ns(self.cycles),
                code,
            });
        }

        let len = head as usize;
        // Wait for the body before consuming the header, so a short read is resumable.
        if self.buffer.len() < 4 + len {
            return None;
        }
        self.cycles += delta;
        self.buffer.drain(0..4);
        let bytes: Vec<u8> = self.buffer.drain(0..len).collect();
        if len % 2 == 1 {
            self.padding_due = true;
        }
        Some(Record::Packet {
            ts_ns: clk_to_ns(self.cycles),
            bytes,
        })
    }
}

/// Convert analyzer clock cycles to nanoseconds.
///
/// The clock is 60 MHz, so a cycle is 16⅔ ns — not representable. Three cycles are
/// exactly 50 ns, so converting whole groups of three and looking up the remainder keeps
/// the result exact instead of accumulating rounding error across a long capture.
pub fn clk_to_ns(cycles: u64) -> i64 {
    const REMAINDER: [u64; 3] = [0, 16, 33];
    ((cycles / 3) * 50 + REMAINDER[(cycles % 3) as usize]) as i64
}

/// pcapng link types for raw USB 2.0 packets, from the tcpdump registry.
///
/// Defined in `reveng_usbcap::pcapng` rather than here, because the reader has to map the
/// same values back to a capture format — two lists would be two chances to disagree.
pub use reveng_usbcap::pcapng::{
    LINKTYPE_USB_2_0, LINKTYPE_USB_2_0_FULL_SPEED, LINKTYPE_USB_2_0_HIGH_SPEED,
    LINKTYPE_USB_2_0_LOW_SPEED,
};

impl Speed {
    /// The link type that records this capture speed. `Auto` cannot claim a speed it has
    /// not resolved, so it falls back to the generic type.
    pub const fn link_type(self) -> u16 {
        match self {
            Speed::Low => LINKTYPE_USB_2_0_LOW_SPEED,
            Speed::Full => LINKTYPE_USB_2_0_FULL_SPEED,
            Speed::High => LINKTYPE_USB_2_0_HIGH_SPEED,
            Speed::Auto => LINKTYPE_USB_2_0,
        }
    }
}

/// Handle that stops a running capture from another thread.
#[derive(Clone)]
pub struct Stopper(Arc<Mutex<Option<futures_channel::oneshot::Sender<()>>>>);

impl Stopper {
    pub fn stop(&self) {
        if let Some(tx) = self.0.lock().unwrap().take() {
            let _ = tx.send(());
        }
    }
}

pub struct CynthionSource {
    clock: Clock,
    speed: Speed,
    iface: Option<nusb::Interface>,
    data_rx: Option<mpsc::Receiver<Vec<u8>>>,
    reader: Option<std::thread::JoinHandle<()>>,
    stopper: Stopper,
    decoder: StreamDecoder,
    /// Session time at which the hardware capture began; analyzer timestamps are
    /// relative to that instant.
    capture_start_ns: i64,
    /// Events seen so far, by code — reported in session metadata. Events carry real
    /// information (bus reset, speed change) but have no representation in a USB 2.0
    /// pcapng, so for now they are counted rather than stored. See the crate docs.
    pub event_counts: std::collections::BTreeMap<u8, u64>,
    /// Sidecar for the bus events. Install with [`Self::log_events_to`] before `start()`;
    /// without it the events are counted and then lost.
    event_log: Option<crate::events::EventLog>,
    event_log_failed: bool,
    packets: u64,
}

impl CynthionSource {
    pub fn new(clock: Clock, speed: Speed) -> Self {
        Self {
            clock,
            speed,
            iface: None,
            data_rx: None,
            reader: None,
            stopper: Stopper(Arc::new(Mutex::new(None))),
            decoder: StreamDecoder::default(),
            capture_start_ns: 0,
            event_counts: Default::default(),
            event_log: None,
            event_log_failed: false,
            packets: 0,
        }
    }

    /// Write bus events to a sidecar at `path` as they arrive. Call before [`Self::start`].
    ///
    /// Without this the events are counted and discarded, and the capture loses the only
    /// evidence that distinguishes an idle bus from a mis-sampled one, or that the analyzer
    /// dropped data. See [`crate::events`].
    pub fn log_events_to(&mut self, path: impl AsRef<std::path::Path>) -> Result<()> {
        self.event_log = Some(crate::events::EventLog::create(path)?);
        Ok(())
    }

    /// A handle that stops this capture from another thread. Valid after [`Self::start`].
    pub fn stopper(&self) -> Stopper {
        self.stopper.clone()
    }

    pub fn packets(&self) -> u64 {
        self.packets
    }

    /// True when the capture produced bus events but never a packet — the signature of a
    /// speed mismatch, which otherwise looks exactly like a successful empty capture.
    pub fn looks_like_speed_mismatch(&self) -> bool {
        self.packets == 0 && self.event_counts.values().sum::<u64>() > 0
    }
}

/// Find the analyzer and claim its interface, checking the gateware version first.
fn open_analyzer() -> Result<nusb::Interface> {
    let info = nusb::list_devices()?
        .find(|d| d.vendor_id() == VID && d.product_id() == PID)
        .context("no Cynthion analyzer found on USB")?;
    let device = info.open().context("opening the Cynthion")?;

    // The protocol byte is the gateware's API version. Saying so plainly matters: an
    // out-of-date board fails in a way that looks like broken hardware — capture arms,
    // the endpoint streams, and no packet ever appears.
    let protocol = device
        .configurations()
        .flat_map(|c| {
            c.interfaces()
                .flat_map(|i| i.alt_settings().map(|a| a.protocol()).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        })
        .next()
        .unwrap_or(0);
    if protocol != GATEWARE_PROTOCOL {
        bail!(
            "Cynthion analyzer gateware is v{protocol}, this backend speaks v{GATEWARE_PROTOCOL}. \
             Update the board with `cynthion update` (see crates/cynthion docs)."
        );
    }

    device
        .claim_interface(ANALYZER_INTERFACE)
        .context("claiming the Cynthion analyzer interface")
}

fn write_state(iface: &nusb::Interface, state: u8) -> Result<()> {
    let control = nusb::transfer::Control {
        control_type: nusb::transfer::ControlType::Vendor,
        recipient: nusb::transfer::Recipient::Interface,
        request: REQ_STATE,
        value: state as u16,
        index: ANALYZER_INTERFACE as u16,
    };
    iface
        .control_out_blocking(control, &[], std::time::Duration::from_secs(1))
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("Cynthion state write {state:#04x} failed: {e}"))
}

impl CaptureSource for CynthionSource {
    fn kind(&self) -> SourceKind {
        // Deliberately `Usb`, not a new variant: `SourceKind` is matched exhaustively in
        // the query layer and the viewer, and this is USB traffic by any useful measure.
        SourceKind::Usb
    }

    fn start(&mut self) -> Result<()> {
        let iface = open_analyzer()?;

        // The first control transfer after a claim fails; spend it deliberately rather
        // than letting it look like a broken device.
        let _ = write_state(&iface, 0);
        write_state(&iface, capture_state(self.speed)).context("starting capture")?;
        self.capture_start_ns = self.clock.now_ns();

        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>();
        let (stop_tx, stop_rx) = futures_channel::oneshot::channel::<()>();
        *self.stopper.0.lock().unwrap() = Some(stop_tx);

        let reader_iface = iface.clone();
        let read_len = read_len(self.speed);
        let reader = std::thread::Builder::new()
            .name("cynthion-reader".into())
            .spawn(move || {
                let mut queue = reader_iface.bulk_in_queue(EP_CAPTURE);
                for _ in 0..NUM_TRANSFERS {
                    queue.submit(nusb::transfer::RequestBuffer::new(read_len));
                }
                let mut stop_rx = stop_rx;
                let mut stopping = false;
                loop {
                    if stopping && queue.pending() == 0 {
                        break;
                    }
                    // Race the stop signal against the next completion. Without this a
                    // silent bus parks the thread in `next_complete()` forever and the
                    // session can never finalize.
                    enum Wake {
                        Stop,
                        Data(nusb::transfer::Completion<Vec<u8>>),
                    }
                    let wake = block_on(futures_lite::future::or(
                        async {
                            if stopping {
                                std::future::pending::<()>().await;
                            }
                            let _ = (&mut stop_rx).await;
                            Wake::Stop
                        },
                        async { Wake::Data(queue.next_complete().await) },
                    ));
                    match wake {
                        Wake::Stop => {
                            stopping = true;
                            queue.cancel_all();
                        }
                        Wake::Data(completion) => {
                            // Keep whatever arrived, even from a cancelled transfer. A
                            // bulk IN completes partially all the time, and on a slow bus
                            // an in-flight buffer can hold seconds of real capture —
                            // discarding it because the *status* is `Cancelled` silently
                            // truncates the tail of every session.
                            if !completion.data.is_empty() {
                                // A closed receiver means the consumer is gone; stop.
                                if data_tx.send(completion.data.clone()).is_err() {
                                    stopping = true;
                                    queue.cancel_all();
                                    continue;
                                }
                            }
                            if !stopping {
                                queue.submit(nusb::transfer::RequestBuffer::new(read_len));
                            }
                        }
                    }
                }
            })?;

        self.iface = Some(iface);
        self.data_rx = Some(data_rx);
        self.reader = Some(reader);
        Ok(())
    }

    fn next(&mut self) -> Result<Option<TrafficRecord>> {
        loop {
            while let Some(record) = self.decoder.next_record() {
                match record {
                    Record::Event { ts_ns, code } => {
                        *self.event_counts.entry(code).or_default() += 1;
                        // Persist as well as count. Events have no representation in a USB
                        // 2.0 pcapng, and they are the only record of a bus reset, a speed
                        // change, or the analyzer overflowing its own buffer — see
                        // [`crate::events`]. A write failure must not kill the capture, so
                        // it is reported once and the packet stream carries on.
                        if let Some(log) = &mut self.event_log {
                            if let Err(e) = log.append(self.capture_start_ns + ts_ns, code) {
                                if !self.event_log_failed {
                                    self.event_log_failed = true;
                                    eprintln!("bus-event log write failed: {e}");
                                }
                            }
                        }
                    }
                    Record::Packet { ts_ns, bytes } => {
                        self.packets += 1;
                        // Wire packets carry no URB metadata. The header is filled with
                        // what a packet actually determines — its length — and left
                        // zeroed elsewhere rather than inventing endpoint or transfer
                        // values that only reassembly can establish.
                        let header = UsbFrameHeader {
                            bus: 0,
                            device: 0,
                            endpoint: 0,
                            transfer: 0xff,
                            status: 0,
                            data_length: bytes.len() as u32,
                        };
                        return Ok(Some(TrafficRecord {
                            // The analyzer's timestamp is relative to *its* capture
                            // start, so anchor it to the session clock rather than
                            // mixing the two scales. This keeps the hardware's precise
                            // inter-packet timing while landing every record on the one
                            // master timeline the whole session is normalised to.
                            ts_ns: self.capture_start_ns + ts_ns,
                            source: SourceKind::Usb,
                            kind: TrafficKind::Usb(header),
                            payload: bytes,
                        }));
                    }
                }
            }
            let Some(rx) = &self.data_rx else {
                return Ok(None);
            };
            match rx.recv() {
                Ok(chunk) => self.decoder.push(&chunk),
                // Reader thread finished and dropped the sender: end of stream.
                Err(_) => return Ok(None),
            }
        }
    }

    fn stop(&mut self) -> Result<()> {
        self.stopper.stop();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        self.data_rx = None;
        // Flush before the state write below, which can fail: the events are evidence and
        // must survive a failed teardown.
        if let Some(log) = &mut self.event_log {
            let _ = log.flush();
        }
        if let Some(iface) = &self.iface {
            // Report a failed stop rather than swallowing it — a silently failed restore
            // is how the board gets left capturing, and it then refuses to be stopped.
            write_state(iface, 0).context("stopping capture")?;
        }
        Ok(())
    }
}

impl Drop for CynthionSource {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Framing, exercised without hardware — the only way this is covered on Linux/macOS.
    #[test]
    fn decodes_events_and_packets_with_odd_length_padding() {
        let mut d = StreamDecoder::default();
        d.push(&[
            // event: code 5 (CaptureStart(Full)), delta 0
            0xFF, 0x05, 0x00, 0x00, //
            // packet: length 3, delta 0x0003, body, then one pad byte
            0x00, 0x03, 0x00, 0x03, 0x69, 0x8f, 0xa8, 0x00, //
            // packet: length 1, delta 0x0003, body, then one pad byte
            0x00, 0x01, 0x00, 0x03, 0x5a, 0x00,
        ]);

        assert_eq!(d.next_record(), Some(Record::Event { ts_ns: 0, code: 5 }));
        // 3 cycles == exactly 50 ns, which is the reason for the group-of-three maths.
        assert_eq!(
            d.next_record(),
            Some(Record::Packet {
                ts_ns: 50,
                bytes: vec![0x69, 0x8f, 0xa8]
            })
        );
        assert_eq!(
            d.next_record(),
            Some(Record::Packet {
                ts_ns: 100,
                bytes: vec![0x5a]
            })
        );
        assert_eq!(d.next_record(), None);
    }

    /// A record split across two reads must resume, not corrupt.
    #[test]
    fn resumes_across_a_split_transfer() {
        let mut d = StreamDecoder::default();
        d.push(&[0x00, 0x03, 0x00, 0x03, 0x69]);
        assert_eq!(d.next_record(), None, "must wait for the whole body");
        d.push(&[0x8f, 0xa8, 0x00]);
        assert_eq!(
            d.next_record(),
            Some(Record::Packet {
                ts_ns: 50,
                bytes: vec![0x69, 0x8f, 0xa8]
            })
        );
    }

    #[test]
    fn cycle_conversion_is_exact_at_multiples_of_three() {
        assert_eq!(clk_to_ns(0), 0);
        assert_eq!(clk_to_ns(3), 50);
        assert_eq!(clk_to_ns(60_000_000), 1_000_000_000, "one second of cycles");
    }
}
