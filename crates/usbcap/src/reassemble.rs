//! Rebuilding whole transfers from raw USB 2.0 wire packets.
//!
//! A hardware analyzer records tokens, DATA and handshakes. The analysis toolchain — `ctrl`,
//! `ctrl-diff`, `sweep`, `reg-state`, `annotate` — reasons about *control transfers*. This
//! module is the bridge, and it is a **read-side view**: the stored packets are never
//! rewritten (DESIGN.md §8b).
//!
//! # A control transfer on the wire
//!
//! ```text
//! setup    SETUP token → DATA0 (8 bytes) → ACK
//! data     IN/OUT token → DATA0/DATA1 → ACK        repeated, toggling, optional
//! status   token in the OPPOSITE direction → zero-length DATA1 → ACK
//! ```
//!
//! Two consequences shape the state machine below.
//!
//! **The status stage is what ends a transfer, and it is recognised by direction.** A token
//! whose direction differs from the SETUP's is the status stage — uniformly, including for
//! a zero-length request where there is no data stage at all.
//!
//! **A NAK is a retry, not an outcome.** On an OUT transaction the host re-sends the same
//! DATA after a NAK, so data must be held until its handshake arrives and only committed on
//! ACK — otherwise every retried packet is counted twice. This is the whole reason
//! reassembly cannot be a simple filter over DATA packets.
//!
//! # Deliberately out of scope
//!
//! **Split transactions.** A low- or full-speed device behind a high-speed hub has its
//! traffic wrapped in SPLIT tokens; those are not modelled, and such a transfer will not
//! reassemble. Left until a target needs it, rather than guessed at. In the usual topology
//! it does not arise: the analyzer taps the hub↔device segment, which runs at the device's
//! own speed.
//!
//! **PING/NYET** (high-speed bulk OUT flow control) and **DATA2/MDATA** (high-bandwidth
//! isochronous) decode as PIDs but carry no reassembly semantics here.
//!
//! # What this means for streaming devices (cameras)
//!
//! Everything here is verified at Low speed. Before pointing it at a camera:
//!
//! - **Bulk streams work.** [`DataStream`] ACK-gates and coalesces retries, which is exactly
//!   right for a bulk image endpoint, and `frame-extract` uses it.
//! - **Isochronous streams yield nothing** — an iso transfer has no handshake at all, so
//!   nothing is ever committed, and the discard is silent. Pinned by
//!   `isochronous_gap_tests`. Most UVC webcams are isochronous. The fix needs the endpoint
//!   *type*, which is not on the wire but is in the configuration descriptor — which a
//!   capture including enumeration now contains, and [`ControlReassembler`] can already
//!   recover.
//! - **The analyzer's own uplink is USB 2.0.** A high-speed camera saturating the bus
//!   produces *more* analyzer data than the target's payload — every packet gains a 4-byte
//!   header, plus tokens, handshakes and SOF — so overflow is expected, not unlikely. It is
//!   at least visible: `CaptureStop(BufferFull)` is persisted and `verify` reports it.
//! - **Volume is unprofiled at that rate.** A 2.8 MB frame at 512-byte packets is ~17 000
//!   wire packets; at 30 fps that is ~500 k packets/s and ~12 MB/s of index alone, through a
//!   per-packet mutex. `frame-extract` also does one seek+read per packet — fine at 10⁵,
//!   painful at 10⁷.

use crate::wire::{self, PacketKind};
use std::collections::HashMap;

/// How a control transfer ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlOutcome {
    /// The status stage was acknowledged — the transfer succeeded.
    Ack,
    /// The device stalled. On the wire this is the endpoint saying "no", and it is the
    /// normal answer to an unsupported request — evidence, not necessarily an error.
    Stall,
    /// The capture ended, or a new SETUP pre-empted this one, before a status stage.
    Incomplete,
}

impl ControlOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            ControlOutcome::Ack => "ok",
            ControlOutcome::Stall => "STALL",
            ControlOutcome::Incomplete => "incomplete",
        }
    }
}

/// One control transfer rebuilt from the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlTransfer {
    /// Frame index of the SETUP token — the transfer's identity in the capture.
    pub frame: u64,
    pub ts_ns: i64,
    pub addr: u8,
    pub endpoint: u8,
    /// The 8 raw setup bytes, for [`crate::reader::decode_setup`].
    pub setup: [u8; 8],
    /// Data-stage bytes: written by the host on an OUT, returned by the device on an IN.
    /// Retried (NAKed) transactions are coalesced — each byte appears once.
    pub data: Vec<u8>,
    pub outcome: ControlOutcome,
    /// Transactions the device NAKed before answering. Invisible to a host-stack capture,
    /// and the main reason a hardware analyzer is worth the trouble.
    pub naks: u32,
}

/// What the DATA packet currently in flight belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    Nothing,
    /// The 8 setup bytes, not yet acknowledged.
    Setup,
    /// Data-stage bytes, held until a handshake says whether they landed.
    Data,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// SETUP token seen; waiting for the DATA that carries the 8 setup bytes.
    AwaitSetup,
    Data,
    Status,
}

#[derive(Debug, Clone)]
struct InProgress {
    frame: u64,
    ts_ns: i64,
    addr: u8,
    endpoint: u8,
    setup: [u8; 8],
    /// Direction from `bmRequestType` bit 7. Known only once the setup bytes arrive.
    dir_in: bool,
    data: Vec<u8>,
    stage: Stage,
    pending: Pending,
    pending_bytes: Vec<u8>,
    naks: u32,
}

/// Rebuilds control transfers from a stream of wire packets.
///
/// Feed every packet in capture order; completed transfers come back as they finish. State
/// is kept per `(address, endpoint)`, because the host can interleave control transfers
/// across devices even though it runs only one at a time per device.
#[derive(Debug, Default)]
pub struct ControlReassembler {
    live: HashMap<(u8, u8), InProgress>,
    /// The transaction's token: `(addr, endpoint, dir_in)`. DATA and handshake packets
    /// carry no address of their own, so they are attributed to this.
    token: Option<(u8, u8, bool)>,
}

impl ControlReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one wire packet. Returns a transfer when this packet completed one.
    pub fn push(&mut self, frame: u64, ts_ns: i64, packet: &[u8]) -> Option<ControlTransfer> {
        let p = wire::decode(packet)?;
        match p.kind {
            PacketKind::Token => self.on_token(frame, ts_ns, p.pid, p.addr?, p.endpoint?),
            PacketKind::Data => {
                self.on_data(p.data);
                None
            }
            PacketKind::Handshake => self.on_handshake(p.pid),
            // SOF and specials belong to no transaction and must not disturb one.
            _ => None,
        }
    }

    fn on_token(
        &mut self,
        frame: u64,
        ts_ns: i64,
        pid: u8,
        addr: u8,
        endpoint: u8,
    ) -> Option<ControlTransfer> {
        let dir_in = pid == wire::PID_IN;
        self.token = Some((addr, endpoint, dir_in));

        if pid == wire::PID_SETUP {
            // A SETUP arriving while a transfer is live means the previous one never
            // finished — report it rather than dropping it silently, so a truncated
            // capture shows as truncated.
            let orphan = self.live.remove(&(addr, endpoint)).map(finish_incomplete);
            self.live.insert(
                (addr, endpoint),
                InProgress {
                    frame,
                    ts_ns,
                    addr,
                    endpoint,
                    setup: [0; 8],
                    dir_in: false,
                    data: Vec::new(),
                    stage: Stage::AwaitSetup,
                    pending: Pending::Nothing,
                    pending_bytes: Vec::new(),
                    naks: 0,
                },
            );
            return orphan;
        }

        if let Some(t) = self.live.get_mut(&(addr, endpoint)) {
            // A token in the opposite direction to the request is the status stage — the
            // one rule that ends a transfer, and it holds even when there is no data stage.
            if t.stage == Stage::Data && dir_in != t.dir_in {
                t.stage = Stage::Status;
            }
        }
        None
    }

    fn on_data(&mut self, data: &[u8]) {
        let Some((addr, endpoint, _)) = self.token else {
            return;
        };
        let Some(t) = self.live.get_mut(&(addr, endpoint)) else {
            return;
        };
        match t.stage {
            Stage::AwaitSetup => {
                if data.len() == 8 {
                    t.setup.copy_from_slice(data);
                    t.dir_in = data[0] & 0x80 != 0;
                    t.pending = Pending::Setup;
                }
            }
            // Held, not committed: an OUT that gets NAKed is re-sent verbatim, and counting
            // it twice would corrupt every retried transfer.
            Stage::Data | Stage::Status => {
                t.pending = Pending::Data;
                t.pending_bytes = data.to_vec();
            }
        }
    }

    fn on_handshake(&mut self, pid: u8) -> Option<ControlTransfer> {
        let (addr, endpoint, _) = self.token?;
        let t = self.live.get_mut(&(addr, endpoint))?;
        match pid {
            wire::PID_ACK => {
                match std::mem::replace(&mut t.pending, Pending::Nothing) {
                    Pending::Setup => t.stage = Stage::Data,
                    Pending::Data => t.data.append(&mut t.pending_bytes),
                    Pending::Nothing => {}
                }
                t.pending_bytes.clear();
                if t.stage == Stage::Status {
                    let done = self.live.remove(&(addr, endpoint))?;
                    return Some(finish(done, ControlOutcome::Ack));
                }
                None
            }
            wire::PID_NAK => {
                // Not an outcome: the transaction will be retried. Drop the held bytes so
                // the retry's copy is the only one counted.
                t.naks += 1;
                t.pending = Pending::Nothing;
                t.pending_bytes.clear();
                None
            }
            wire::PID_STALL => {
                let done = self.live.remove(&(addr, endpoint))?;
                Some(finish(done, ControlOutcome::Stall))
            }
            _ => None,
        }
    }

    /// Transfers still open when the capture ended — reported as
    /// [`ControlOutcome::Incomplete`] rather than dropped, so a truncated capture is
    /// visibly truncated.
    pub fn finish(self) -> Vec<ControlTransfer> {
        let mut out: Vec<ControlTransfer> =
            self.live.into_values().map(finish_incomplete).collect();
        out.sort_by_key(|t| t.frame);
        out
    }
}

fn finish(t: InProgress, outcome: ControlOutcome) -> ControlTransfer {
    ControlTransfer {
        frame: t.frame,
        ts_ns: t.ts_ns,
        addr: t.addr,
        endpoint: t.endpoint,
        setup: t.setup,
        data: t.data,
        outcome,
        naks: t.naks,
    }
}

fn finish_incomplete(t: InProgress) -> ControlTransfer {
    finish(t, ControlOutcome::Incomplete)
}

/// One acknowledged data packet, attributed to its transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckedData {
    pub addr: u8,
    pub endpoint: u8,
    pub dir_in: bool,
    pub data: Vec<u8>,
}

/// Yields the payload of every DATA packet the device (or host) **acknowledged**.
///
/// This is the non-control counterpart to [`ControlReassembler`], and exists for the same
/// reason: a NAKed transaction is retried with identical bytes, so concatenating every DATA
/// packet on an endpoint duplicates data. For a bulk image stream that silently corrupts the
/// frame — the payload is the right length, so nothing looks wrong until the image does.
#[derive(Debug, Default)]
pub struct DataStream {
    token: Option<(u8, u8, bool)>,
    open: Option<Vec<u8>>,
}

impl DataStream {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one wire packet in capture order; returns a payload when this packet
    /// acknowledged one.
    pub fn push(&mut self, packet: &[u8]) -> Option<AckedData> {
        let p = wire::decode(packet)?;
        match p.kind {
            PacketKind::Token => {
                self.token = Some((p.addr?, p.endpoint?, p.pid == wire::PID_IN));
                self.open = None;
                None
            }
            PacketKind::Data => {
                self.open = Some(p.data.to_vec());
                None
            }
            PacketKind::Handshake => {
                let data = self.open.take()?;
                if p.pid != wire::PID_ACK {
                    return None; // NAK/STALL: these bytes did not land.
                }
                let (addr, endpoint, dir_in) = self.token?;
                Some(AckedData {
                    addr,
                    endpoint,
                    dir_in,
                    data,
                })
            }
            // SOF must not clear the DATA awaiting its handshake.
            _ => None,
        }
    }
}

/// Bus-level integrity findings over a wire capture — what `verify` reports for a session a
/// hardware analyzer produced.
///
/// None of these have a USBPcap equivalent, and none of USBPcap's checks apply here: there is
/// no IRP to leave unpaired and no `USBD_STATUS` to be non-zero. What can go wrong on a wire
/// capture is that packets were mis-sampled, corrupted, or lost.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WireIntegrity {
    pub packets: u64,
    /// Bytes whose PID failed its ones-complement check — not USB packets at all. A capture
    /// full of these is the signature of a **wrong capture speed**, which otherwise looks
    /// exactly like a successful capture of an idle bus.
    pub undecodable: u64,
    /// Packets whose CRC5 or CRC16 did not verify: a genuine bus error, or a sampling
    /// problem in the analyzer.
    pub crc_errors: u64,
    /// DATA packets with no handshake after them. Either the handshake was lost, or the
    /// endpoint is isochronous — which has none by design, so this is a hint, not a verdict.
    pub data_without_handshake: u64,
    /// ACKed DATA packets whose toggle was not the expected one. The toggle only advances on
    /// ACK, so a legitimate retransmission after a lost ACK does *not* count here.
    pub toggle_anomalies: u64,
    /// Transactions the device NAKed. Normal traffic, not an error — reported because the
    /// rate is diagnostic, and because a host-stack capture cannot show it at all.
    pub naks: u64,
    /// SOF packets, which dominate a full/high-speed capture's volume.
    pub sofs: u64,
}

/// One item of the capture stream, as the integrity check sees it.
#[derive(Debug, Clone, Copy)]
pub enum StreamItem<'a> {
    Packet(&'a [u8]),
    /// A bus reset, from the analyzer's event sidecar rather than the packet file.
    ///
    /// It has to be interleaved here in timestamp order because a reset sets **every**
    /// endpoint's data toggle back to DATA0 (USB 2.0 §8.6.1). Without it, the first packet
    /// on each endpoint after a reset reads as a toggle violation — measured, a single
    /// replug produced 13 such false positives.
    BusReset,
}

/// Scan wire packets for bus-level integrity problems.
///
/// Takes an iterator so it can run over a capture without loading it, and be tested on canned
/// packets with no session on disk.
pub fn check_wire_integrity<'a>(items: impl Iterator<Item = StreamItem<'a>>) -> WireIntegrity {
    let mut r = WireIntegrity::default();
    // Expected toggle per (address, endpoint, direction). `None` until the first ACKed DATA
    // establishes one — guessing an initial toggle would manufacture an anomaly on any
    // capture that started mid-stream.
    let mut expect: HashMap<(u8, u8, bool), u8> = HashMap::new();
    let mut token: Option<(u8, u8, bool)> = None;
    // The DATA awaiting a handshake, and what toggle it carried.
    let mut open_data: Option<u8> = None;

    for item in items {
        let packet = match item {
            StreamItem::BusReset => {
                // Every endpoint restarts at DATA0, so no expectation survives a reset.
                expect.clear();
                open_data = None;
                continue;
            }
            StreamItem::Packet(p) => p,
        };
        r.packets += 1;
        let Some(p) = wire::decode(packet) else {
            r.undecodable += 1;
            continue;
        };
        // A valid PID byte is not enough: a token or DATA cut short still has one. `crc_ok`
        // is set only when the packet was long enough to hold its CRC, so `None` on anything
        // but a handshake means truncated — equally unusable, and equally a sign of a
        // sampling problem.
        if p.kind != PacketKind::Handshake && p.kind != PacketKind::Special && p.crc_ok.is_none() {
            r.undecodable += 1;
            continue;
        }
        if p.crc_ok == Some(false) {
            r.crc_errors += 1;
        }
        match p.kind {
            PacketKind::Sof => {
                r.sofs += 1;
                // A SOF can fall anywhere, including between DATA and its handshake.
                continue;
            }
            PacketKind::Token => {
                if open_data.take().is_some() {
                    r.data_without_handshake += 1;
                }
                let key = (
                    p.addr.unwrap_or(0),
                    p.endpoint.unwrap_or(0),
                    p.pid == wire::PID_IN,
                );
                // A SETUP restarts its endpoint's toggle sequence in both directions, so any
                // prior expectation for it is stale rather than violated.
                if p.pid == wire::PID_SETUP {
                    expect.remove(&(key.0, key.1, true));
                    expect.remove(&(key.0, key.1, false));
                }
                token = Some(key);
            }
            PacketKind::Data => {
                if open_data.replace(p.pid).is_some() {
                    r.data_without_handshake += 1;
                }
            }
            PacketKind::Handshake => {
                let toggle = open_data.take();
                match p.pid {
                    wire::PID_ACK => {
                        if let (Some(t), Some(key)) = (toggle, token) {
                            // Only an ACKed DATA advances the toggle, so this comparison is
                            // exactly the rule the device itself follows.
                            match expect.get(&key) {
                                Some(&want) if want != t => r.toggle_anomalies += 1,
                                _ => {}
                            }
                            expect.insert(key, next_toggle(t));
                        }
                    }
                    wire::PID_NAK => r.naks += 1,
                    _ => {}
                }
            }
            PacketKind::Special => {}
        }
    }
    if open_data.is_some() {
        // The capture simply ended here; not counted as a fault.
    }
    r
}

fn next_toggle(pid: u8) -> u8 {
    if pid == wire::PID_DATA0 {
        wire::PID_DATA1
    } else {
        wire::PID_DATA0
    }
}

/// Packet builders shared by the test modules below. Each produces a byte sequence that
/// [`wire::decode`] accepts, CRCs included — the builders themselves are checked against
/// packets captured off real hardware in `wire::tests`.
#[cfg(test)]
mod tests_support {
    use super::wire;

    pub fn token(pid: u8, addr: u8, ep: u8) -> Vec<u8> {
        let f = wire::token_field(wire::token_payload(addr, ep));
        vec![wire::pid_byte(pid), f[0], f[1]]
    }

    pub fn data(pid: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![wire::pid_byte(pid)];
        v.extend_from_slice(payload);
        v.extend_from_slice(&wire::crc16(payload).to_le_bytes());
        v
    }

    pub fn handshake(pid: u8) -> Vec<u8> {
        vec![wire::pid_byte(pid)]
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::*;
    use super::*;

    const ACK: u8 = wire::PID_ACK;
    const NAK: u8 = wire::PID_NAK;
    const STALL: u8 = wire::PID_STALL;

    /// GET_DESCRIPTOR(Device): IN request, 8 bytes of setup, an 8-byte data stage, status.
    fn get_descriptor_setup() -> [u8; 8] {
        [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x08, 0x00]
    }

    /// Drive a packet sequence and return everything that completed.
    fn run(packets: &[Vec<u8>]) -> Vec<ControlTransfer> {
        let mut r = ControlReassembler::new();
        let mut out = Vec::new();
        for (i, p) in packets.iter().enumerate() {
            if let Some(t) = r.push(i as u64, (i as i64) * 1000, p) {
                out.push(t);
            }
        }
        out.extend(r.finish());
        out
    }

    #[test]
    fn rebuilds_an_in_control_transfer() {
        let s = get_descriptor_setup();
        let payload = [0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40];
        let t = run(&[
            token(wire::PID_SETUP, 1, 0),
            data(wire::PID_DATA0, &s),
            handshake(ACK),
            token(wire::PID_IN, 1, 0),
            data(wire::PID_DATA1, &payload),
            handshake(ACK),
            // Status stage: opposite direction, zero-length.
            token(wire::PID_OUT, 1, 0),
            data(wire::PID_DATA1, &[]),
            handshake(ACK),
        ]);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].setup, s);
        assert_eq!(t[0].data, payload);
        assert_eq!(t[0].outcome, ControlOutcome::Ack);
        assert_eq!(t[0].frame, 0, "identified by its SETUP token");
        assert_eq!(t[0].addr, 1);
        assert_eq!(t[0].naks, 0);
    }

    #[test]
    fn rebuilds_a_zero_length_out_control_transfer() {
        // SET_CONFIGURATION(1): no data stage at all, so the status stage is the only thing
        // that can end it. This is the case a "wait for the data stage" model gets wrong.
        let s = [0x00u8, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        let t = run(&[
            token(wire::PID_SETUP, 3, 0),
            data(wire::PID_DATA0, &s),
            handshake(ACK),
            token(wire::PID_IN, 3, 0),
            data(wire::PID_DATA1, &[]),
            handshake(ACK),
        ]);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].outcome, ControlOutcome::Ack);
        assert!(t[0].data.is_empty());
    }

    #[test]
    fn coalesces_a_naked_and_retried_out_transaction() {
        // The bug this exists to prevent: the host re-sends identical DATA after a NAK, so
        // a naive "collect every DATA packet" yields the payload twice.
        let s = [0x00u8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00];
        let payload = [0xaa, 0xbb, 0xcc, 0xdd];
        let t = run(&[
            token(wire::PID_SETUP, 2, 0),
            data(wire::PID_DATA0, &s),
            handshake(ACK),
            token(wire::PID_OUT, 2, 0),
            data(wire::PID_DATA1, &payload),
            handshake(NAK),
            token(wire::PID_OUT, 2, 0),
            data(wire::PID_DATA1, &payload),
            handshake(ACK),
            token(wire::PID_IN, 2, 0),
            data(wire::PID_DATA1, &[]),
            handshake(ACK),
        ]);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].data, payload, "the retry must not be counted twice");
        assert_eq!(t[0].naks, 1, "and the retry is still reported");
        assert_eq!(t[0].outcome, ControlOutcome::Ack);
    }

    #[test]
    fn joins_a_multi_packet_in_data_stage() {
        let s = [0x80u8, 0x06, 0x00, 0x02, 0x00, 0x00, 0x10, 0x00];
        let t = run(&[
            token(wire::PID_SETUP, 1, 0),
            data(wire::PID_DATA0, &s),
            handshake(ACK),
            token(wire::PID_IN, 1, 0),
            data(wire::PID_DATA1, &[1, 2, 3, 4, 5, 6, 7, 8]),
            handshake(ACK),
            token(wire::PID_IN, 1, 0),
            data(wire::PID_DATA0, &[9, 10, 11, 12]),
            handshake(ACK),
            token(wire::PID_OUT, 1, 0),
            data(wire::PID_DATA1, &[]),
            handshake(ACK),
        ]);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].data, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    }

    #[test]
    fn a_stall_ends_the_transfer_and_is_reported() {
        // Probing an unsupported request is exactly this shape, and the STALL is the
        // finding — not an error to hide.
        let s = [0xc0u8, 0x42, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
        let t = run(&[
            token(wire::PID_SETUP, 5, 0),
            data(wire::PID_DATA0, &s),
            handshake(ACK),
            token(wire::PID_IN, 5, 0),
            handshake(STALL),
        ]);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].outcome, ControlOutcome::Stall);
        assert!(t[0].data.is_empty());
    }

    #[test]
    fn interleaved_devices_do_not_mix() {
        let a = [0x80u8, 0x06, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00];
        let b = [0x80u8, 0x06, 0x00, 0x02, 0x00, 0x00, 0x02, 0x00];
        let t = run(&[
            token(wire::PID_SETUP, 1, 0),
            data(wire::PID_DATA0, &a),
            handshake(ACK),
            token(wire::PID_SETUP, 2, 0),
            data(wire::PID_DATA0, &b),
            handshake(ACK),
            token(wire::PID_IN, 1, 0),
            data(wire::PID_DATA1, &[0xa1, 0xa2]),
            handshake(ACK),
            token(wire::PID_IN, 2, 0),
            data(wire::PID_DATA1, &[0xb1, 0xb2]),
            handshake(ACK),
            token(wire::PID_OUT, 1, 0),
            data(wire::PID_DATA1, &[]),
            handshake(ACK),
            token(wire::PID_OUT, 2, 0),
            data(wire::PID_DATA1, &[]),
            handshake(ACK),
        ]);
        assert_eq!(t.len(), 2);
        let one = t.iter().find(|x| x.addr == 1).unwrap();
        let two = t.iter().find(|x| x.addr == 2).unwrap();
        assert_eq!(one.data, vec![0xa1, 0xa2]);
        assert_eq!(one.setup, a);
        assert_eq!(two.data, vec![0xb1, 0xb2]);
        assert_eq!(two.setup, b);
    }

    #[test]
    fn an_unfinished_transfer_is_reported_not_dropped() {
        let s = get_descriptor_setup();
        let t = run(&[
            token(wire::PID_SETUP, 1, 0),
            data(wire::PID_DATA0, &s),
            handshake(ACK),
            token(wire::PID_IN, 1, 0),
            // Capture ends mid-transfer.
        ]);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].outcome, ControlOutcome::Incomplete);
        assert_eq!(t[0].setup, s);
    }

    #[test]
    fn sof_between_stages_is_ignored() {
        // A SOF lands every 1 ms and will fall inside a control transfer. Letting it clear
        // the token would strand the DATA that follows.
        let s = get_descriptor_setup();
        let sof = vec![0xa5, 0x00, 0x10];
        let t = run(&[
            token(wire::PID_SETUP, 1, 0),
            sof.clone(),
            data(wire::PID_DATA0, &s),
            handshake(ACK),
            token(wire::PID_IN, 1, 0),
            sof,
            data(wire::PID_DATA1, &[0x77]),
            handshake(ACK),
            token(wire::PID_OUT, 1, 0),
            data(wire::PID_DATA1, &[]),
            handshake(ACK),
        ]);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].data, vec![0x77]);
        assert_eq!(t[0].outcome, ControlOutcome::Ack);
    }

    #[test]
    fn a_naked_in_transaction_yields_no_data_and_is_counted() {
        // The common idle case: the device is not ready, NAKs, and the host polls again.
        let s = get_descriptor_setup();
        let t = run(&[
            token(wire::PID_SETUP, 1, 0),
            data(wire::PID_DATA0, &s),
            handshake(ACK),
            token(wire::PID_IN, 1, 0),
            handshake(NAK),
            token(wire::PID_IN, 1, 0),
            handshake(NAK),
            token(wire::PID_IN, 1, 0),
            data(wire::PID_DATA1, &[0x5a]),
            handshake(ACK),
            token(wire::PID_OUT, 1, 0),
            data(wire::PID_DATA1, &[]),
            handshake(ACK),
        ]);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].data, vec![0x5a]);
        assert_eq!(t[0].naks, 2);
    }
}

#[cfg(test)]
mod integrity_tests {
    use super::tests_support::*;
    use super::*;

    fn scan(packets: &[Vec<u8>]) -> WireIntegrity {
        check_wire_integrity(packets.iter().map(|p| StreamItem::Packet(p.as_slice())))
    }

    /// A clean IN transaction with alternating toggles must report nothing at all.
    #[test]
    fn clean_traffic_reports_no_problems() {
        let p = vec![
            token(wire::PID_IN, 1, 1),
            data(wire::PID_DATA0, &[1, 2]),
            handshake(wire::PID_ACK),
            token(wire::PID_IN, 1, 1),
            data(wire::PID_DATA1, &[3, 4]),
            handshake(wire::PID_ACK),
        ];
        let r = scan(&p);
        assert_eq!(r.packets, 6);
        assert_eq!(r.crc_errors, 0);
        assert_eq!(r.toggle_anomalies, 0);
        assert_eq!(r.data_without_handshake, 0);
        assert_eq!(r.undecodable, 0);
    }

    #[test]
    fn framing_garbage_is_counted_not_decoded() {
        // What a wrong --speed produces: bytes that are not packets. This is the check that
        // tells a mis-sampled capture from a genuinely quiet bus.
        //
        // The second entry is the subtle one: 0x69 is a *valid* IN PID byte, so the PID
        // check alone passes it. Truncated to two bytes it is still garbage, and counting it
        // as a token would attribute everything after it to address 0.
        let p = vec![
            vec![0x00, 0x11],
            vec![0x69, 0x01],
            token(wire::PID_IN, 1, 1),
        ];
        let r = scan(&p);
        assert_eq!(r.undecodable, 2);
        assert_eq!(r.packets, 3);
    }

    #[test]
    fn a_corrupted_payload_is_reported() {
        let mut bad = data(wire::PID_DATA0, &[0xaa, 0xbb]);
        bad[1] ^= 0x01;
        let r = scan(&[token(wire::PID_IN, 1, 1), bad, handshake(wire::PID_ACK)]);
        assert_eq!(r.crc_errors, 1);
    }

    #[test]
    fn a_repeated_toggle_after_an_ack_is_an_anomaly() {
        let p = vec![
            token(wire::PID_IN, 1, 1),
            data(wire::PID_DATA0, &[1]),
            handshake(wire::PID_ACK),
            token(wire::PID_IN, 1, 1),
            data(wire::PID_DATA0, &[2]), // should have been DATA1
            handshake(wire::PID_ACK),
        ];
        assert_eq!(scan(&p).toggle_anomalies, 1);
    }

    /// The false-positive this check must not produce: after a NAK the host re-sends the
    /// same DATA with the same toggle, which is correct behaviour.
    #[test]
    fn a_retry_after_a_nak_is_not_a_toggle_anomaly() {
        let p = vec![
            token(wire::PID_OUT, 1, 1),
            data(wire::PID_DATA0, &[1]),
            handshake(wire::PID_ACK),
            token(wire::PID_OUT, 1, 1),
            data(wire::PID_DATA1, &[2]),
            handshake(wire::PID_NAK),
            token(wire::PID_OUT, 1, 1),
            data(wire::PID_DATA1, &[2]), // same toggle, correctly
            handshake(wire::PID_ACK),
        ];
        let r = scan(&p);
        assert_eq!(r.toggle_anomalies, 0);
        assert_eq!(r.naks, 1);
    }

    /// Two endpoints toggle independently; sharing one counter would invent anomalies.
    #[test]
    fn endpoints_toggle_independently() {
        let p = vec![
            token(wire::PID_IN, 1, 1),
            data(wire::PID_DATA0, &[1]),
            handshake(wire::PID_ACK),
            token(wire::PID_IN, 1, 2),
            data(wire::PID_DATA0, &[2]),
            handshake(wire::PID_ACK),
            token(wire::PID_IN, 1, 1),
            data(wire::PID_DATA1, &[3]),
            handshake(wire::PID_ACK),
            token(wire::PID_IN, 1, 2),
            data(wire::PID_DATA1, &[4]),
            handshake(wire::PID_ACK),
        ];
        assert_eq!(scan(&p).toggle_anomalies, 0);
    }

    #[test]
    fn a_lost_handshake_is_reported() {
        let p = vec![
            token(wire::PID_IN, 1, 1),
            data(wire::PID_DATA0, &[1]),
            // handshake missing — next token starts a new transaction
            token(wire::PID_IN, 1, 1),
            data(wire::PID_DATA1, &[2]),
            handshake(wire::PID_ACK),
        ];
        assert_eq!(scan(&p).data_without_handshake, 1);
    }

    #[test]
    fn a_trailing_data_packet_is_not_a_fault() {
        // The capture simply stopped; that is not a lost handshake.
        let p = vec![token(wire::PID_IN, 1, 1), data(wire::PID_DATA0, &[1])];
        assert_eq!(scan(&p).data_without_handshake, 0);
    }

    #[test]
    fn sof_between_data_and_its_handshake_is_ignored() {
        let p = vec![
            token(wire::PID_IN, 1, 1),
            data(wire::PID_DATA0, &[1]),
            vec![wire::pid_byte(wire::PID_SOF), 0x00, 0x10],
            handshake(wire::PID_ACK),
        ];
        let r = scan(&p);
        assert_eq!(r.data_without_handshake, 0);
        assert_eq!(r.sofs, 1);
    }
}

#[cfg(test)]
mod data_stream_tests {
    use super::tests_support::*;
    use super::*;

    /// The corruption this exists to prevent: on the wire a NAKed bulk OUT is re-sent with
    /// identical bytes, so concatenating every DATA packet yields a payload of the right
    /// length that is silently wrong.
    #[test]
    fn a_retried_bulk_write_is_not_duplicated() {
        let mut s = DataStream::new();
        let packets = [
            token(wire::PID_OUT, 4, 8),
            data(wire::PID_DATA0, &[0xaa, 0xbb]),
            handshake(wire::PID_NAK),
            token(wire::PID_OUT, 4, 8),
            data(wire::PID_DATA0, &[0xaa, 0xbb]),
            handshake(wire::PID_ACK),
        ];
        let got: Vec<u8> = packets
            .iter()
            .filter_map(|p| s.push(p))
            .flat_map(|a| a.data)
            .collect();
        assert_eq!(got, vec![0xaa, 0xbb]);
    }

    #[test]
    fn acked_data_carries_its_endpoint_and_direction() {
        let mut s = DataStream::new();
        let packets = [
            token(wire::PID_IN, 4, 6),
            data(wire::PID_DATA1, &[1, 2, 3]),
            handshake(wire::PID_ACK),
        ];
        let got: Vec<AckedData> = packets.iter().filter_map(|p| s.push(p)).collect();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].endpoint, 6);
        assert_eq!(got[0].addr, 4);
        assert!(got[0].dir_in);
        assert_eq!(got[0].data, vec![1, 2, 3]);
    }

    #[test]
    fn a_stalled_transaction_contributes_nothing() {
        let mut s = DataStream::new();
        let packets = [
            token(wire::PID_OUT, 4, 8),
            data(wire::PID_DATA0, &[9, 9]),
            handshake(wire::PID_STALL),
        ];
        assert_eq!(packets.iter().filter_map(|p| s.push(p)).count(), 0);
    }

    #[test]
    fn a_sof_does_not_strand_data_awaiting_its_handshake() {
        let mut s = DataStream::new();
        let packets = [
            token(wire::PID_IN, 4, 6),
            data(wire::PID_DATA1, &[7]),
            vec![wire::pid_byte(wire::PID_SOF), 0x00, 0x10],
            handshake(wire::PID_ACK),
        ];
        let got: Vec<u8> = packets
            .iter()
            .filter_map(|p| s.push(p))
            .flat_map(|a| a.data)
            .collect();
        assert_eq!(got, vec![7]);
    }
}

#[cfg(test)]
mod reset_toggle_tests {
    use super::tests_support::*;
    use super::*;

    /// A bus reset sets every endpoint's toggle back to DATA0 (USB 2.0 §8.6.1). Without
    /// feeding resets into the check, the first packet on each endpoint after one reads as a
    /// violation — a real replug produced 13 such false positives before this was handled.
    #[test]
    fn a_bus_reset_clears_the_expected_toggle() {
        let items = vec![
            StreamItem::Packet(&[]), // placeholder, replaced below
        ];
        drop(items);

        let t_in = token(wire::PID_IN, 1, 1);
        let d0 = data(wire::PID_DATA0, &[1]);
        let d1 = data(wire::PID_DATA1, &[2]);
        let ack = handshake(wire::PID_ACK);

        // DATA0 → ACK sets the expectation to DATA1. A reset then returns it to DATA0, so
        // the DATA0 that follows is correct, not an anomaly.
        let with_reset = check_wire_integrity(
            [
                StreamItem::Packet(&t_in),
                StreamItem::Packet(&d0),
                StreamItem::Packet(&ack),
                StreamItem::BusReset,
                StreamItem::Packet(&t_in),
                StreamItem::Packet(&d0),
                StreamItem::Packet(&ack),
            ]
            .into_iter(),
        );
        assert_eq!(with_reset.toggle_anomalies, 0);

        // The same sequence without the reset is a genuine violation — the check must not
        // have been defanged into never reporting anything.
        let without_reset = check_wire_integrity(
            [
                StreamItem::Packet(&t_in),
                StreamItem::Packet(&d0),
                StreamItem::Packet(&ack),
                StreamItem::Packet(&t_in),
                StreamItem::Packet(&d0),
                StreamItem::Packet(&ack),
            ]
            .into_iter(),
        );
        assert_eq!(without_reset.toggle_anomalies, 1);

        // And a correctly toggling pair stays clean either way.
        let clean = check_wire_integrity(
            [
                StreamItem::Packet(&t_in),
                StreamItem::Packet(&d0),
                StreamItem::Packet(&ack),
                StreamItem::Packet(&t_in),
                StreamItem::Packet(&d1),
                StreamItem::Packet(&ack),
            ]
            .into_iter(),
        );
        assert_eq!(clean.toggle_anomalies, 0);
    }

    /// A SETUP restarts its endpoint's toggle sequence, so a stale expectation from before
    /// the control transfer must not be reported against it.
    #[test]
    fn a_setup_token_clears_its_endpoints_expectation() {
        let t_out = token(wire::PID_OUT, 1, 0);
        let t_setup = token(wire::PID_SETUP, 1, 0);
        let d0 = data(wire::PID_DATA0, &[1]);
        let ack = handshake(wire::PID_ACK);
        let r = check_wire_integrity(
            [
                StreamItem::Packet(&t_out),
                StreamItem::Packet(&d0),
                StreamItem::Packet(&ack),
                StreamItem::Packet(&t_setup),
                StreamItem::Packet(&d0),
                StreamItem::Packet(&ack),
            ]
            .into_iter(),
        );
        assert_eq!(r.toggle_anomalies, 0);
    }
}

#[cfg(test)]
mod isochronous_gap_tests {
    use super::tests_support::*;
    use super::*;

    /// **Known limitation, pinned deliberately.** An isochronous transfer has no handshake by
    /// design (USB 2.0 §5.10) — the host sends a token, the device sends DATA, and nothing
    /// acknowledges it. [`DataStream`] commits only on ACK, so an isochronous stream yields
    /// **nothing at all**, and the discard is silent: the next token clears the pending DATA.
    ///
    /// This is why `frame-extract` cannot yet pull frames from an isochronous camera on a wire
    /// capture. Fixing it needs the endpoint's *type*, which is not on the wire — it is in the
    /// configuration descriptor, which a capture that includes enumeration now contains and
    /// `ControlReassembler` can already recover. Until that is wired up, this test exists so
    /// the gap is a recorded fact rather than a surprise.
    #[test]
    fn isochronous_data_is_dropped_because_it_has_no_handshake() {
        let mut s = DataStream::new();
        let packets = vec![
            token(wire::PID_IN, 7, 3),
            data(wire::PID_DATA0, &[0x11, 0x22, 0x33]),
            // no handshake — isochronous
            token(wire::PID_IN, 7, 3),
            data(wire::PID_DATA1, &[0x44, 0x55, 0x66]),
        ];
        let got: Vec<AckedData> = packets.iter().filter_map(|p| s.push(p)).collect();
        assert!(
            got.is_empty(),
            "documents the gap: isochronous payloads are currently lost, not extracted"
        );
    }

    /// The integrity scan *does* see it, which is the one signal a user gets today: an
    /// isochronous endpoint shows up as DATA-without-handshake.
    #[test]
    fn the_integrity_scan_at_least_notices_isochronous_traffic() {
        let items = vec![
            token(wire::PID_IN, 7, 3),
            data(wire::PID_DATA0, &[1, 2, 3]),
            token(wire::PID_IN, 7, 3),
            data(wire::PID_DATA1, &[4, 5, 6]),
            token(wire::PID_IN, 7, 3),
            data(wire::PID_DATA0, &[7, 8, 9]),
        ];
        let r = check_wire_integrity(items.iter().map(|p| StreamItem::Packet(p.as_slice())));
        // Two of the three DATA packets are followed by a token rather than a handshake; the
        // last is simply the end of the capture and is not counted.
        assert_eq!(r.data_without_handshake, 2);
    }
}
