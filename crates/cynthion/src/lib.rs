//! Cynthion hardware USB 2.0 analyzer capture backend.
//!
//! Unlike the USBPcap backend this needs no kernel driver and no vendor SDK — it talks to
//! the board over `nusb`, so capture works on Linux, macOS and Windows alike. That is the
//! whole point: USBPcap is what confines live capture to Windows.
//!
//! # What the board says about itself
//!
//! Everything below was read from the hardware (Cynthion, `bcdDevice` 1.04) with
//! `cynthion-probe`, not from a vendor package. Standard descriptor reads are
//! **[confirmed]**. The control protocol was read from Packetry's own source and then
//! **[confirmed]** on this unit: the state write is accepted, capture starts, and the
//! stream decodes with the documented framing.
//!
//! ## Identity — [confirmed]
//!
//! | | |
//! |---|---|
//! | VID:PID | `1d50:615b` (Great Scott Gadgets ship under the OpenMoko shared VID) |
//! | Strings | `Cynthion Project` / `USB Analyzer` |
//! | `bcdUSB` | 2.00 |
//!
//! ## Interfaces — [confirmed]
//!
//! ```text
//! 09 02 22 00 02 01 00 80 fa    config: 2 interfaces, 500 mA
//! 09 04 00 00 01 ff 10 01 00    interface 0, vendor ff/10, protocol 01 = gateware API v1
//! 07 05 81 02 00 02 ff          endpoint 0x81, bulk, wMaxPacketSize 512
//! 09 04 01 00 00 ff 00 00 00    interface 1, vendor class ff, subclass 00, no endpoints
//! ```
//!
//! Interface 0 carries the capture stream on **bulk IN `0x81`, 512-byte packets**.
//! Interface 1 has no endpoints at all — a control-only surface that answers nothing we
//! have found, so nothing here uses it.
//!
//! ## The control surface — from Packetry's source
//!
//! Capture is armed by writing a **state byte** as `wValue`:
//!
//! ```text
//! bRequest 1, recipient = Interface, wValue = state, wIndex = interface number, no data
//! ```
//!
//! The state byte is a bitfield, not a scalar:
//!
//! | bit | meaning |
//! |---|---|
//! | 0 | capture enable |
//! | 1–2 | speed: `0` High, `1` Full, `2` Low, `3` Auto |
//! | 3 | TARGET-C VBUS enable |
//! | 4 | CONTROL VBUS enable |
//! | 5 | AUX VBUS enable |
//! | 6 | TARGET-A discharge |
//! | 7 | power-control enable |
//!
//! So "capture, auto-detect speed" is `0b0000_0111` = `0x07`; stopping writes the same
//! byte with bit 0 cleared.
//!
//! ### Why probing alone could not find this
//!
//! A read-only sweep of all 256 request numbers found only `bRequest 0x00` answering, and
//! concluded the register was a boolean because `wValue` 2–4 STALLed. Both observations
//! were real and both conclusions were wrong: the sweep issued **IN transfers only**, so
//! an OUT-only request was invisible to it by construction, and the values it tried
//! happened to be invalid bit patterns rather than points on a scale.
//!
//! Read-only probing maps what a device *answers*. It cannot map what a device *accepts*,
//! and inferring a value space from which pokes STALL will mislead whenever the field is
//! a bitfield. Worth remembering before trusting a scan like that again.
//!
//! ## Readable registers — [confirmed] on hardware
//!
//! | request | returns |
//! |---|---|
//! | 0 | current state byte |
//! | 2 | supported-speeds mask (this board: `0b1111`, all four) |
//! | 4 | protocol minor version (this board: 1) |
//!
//! Request 1 sets the state; request 3 configures the built-in test device. Both are
//! **OUT-only** — probing them with an IN transfer STALLs, which is what made a
//! read-only sweep miss them.
//!
//! ## Stream framing — [confirmed] on hardware
//!
//! The capture endpoint delivers a flat byte stream of variable-length records, each
//! with a 4-byte header:
//!
//! ```text
//! [0]     0xFF  -> this record is an EVENT, [1] is the event code, no body
//!         else  -> [0..2] is a big-endian packet LENGTH
//! [2..4]  big-endian clock-cycle delta since the previous record
//! [4..]   packet body, present only for packets
//!         + one padding byte when the length is odd
//! ```
//!
//! Timestamps are a running sum of those deltas. The clock is 60 MHz, and three cycles
//! are exactly 50 ns — so converting in whole groups of three avoids the rounding drift
//! a per-cycle constant would accumulate over a long capture. See `clk_to_ns`.
//!
//! Event codes cover capture start/stop, speed changes, line-state transitions
//! (`SE0`/`FsJ`/`FsK`/`LsJ`/`LsK`/chirps), VBUS validity, attach, bus reset and suspend
//! or resume. A capture therefore carries **bus events interleaved with packets**, which
//! is strictly more than a host-stack capture can see.
//!
//! ## Gateware version — the board must be current
//!
//! The interface protocol byte is the analyzer's **gateware API version**. Packetry
//! checks it exactly and refuses a mismatch in either direction:
//!
//! > Analyzer gateware is older (v0) than supported by this version of Packetry (v1).
//! > Please update gateware.
//!
//! This unit first reported protocol `0x00`, which explained every symptom seen while
//! probing: `bRequest 1` does not exist on v0, so capture could never be armed and the
//! endpoint stayed silent whatever was written. After `cynthion update` it reports
//! `0x01` and captures normally. A backend must check this byte and say plainly that the
//! gateware needs updating, rather than failing as though the hardware were broken.
//!
//! ## Two behaviours a driver has to handle — [confirmed]
//!
//! 1. **The first control transfer after claiming the interface fails**; the next one
//!    succeeds. Reproduced on every run. Open must therefore tolerate one failure — a
//!    discarded warm-up read, or a retry — rather than reporting the device broken.
//!
//! 2. **A STALLed control request halts the endpoint for subsequent ones.** After
//!    probing an unsupported `wValue`, later writes on that handle fail until the halt is
//!    cleared. This is how an earlier probe run left the board enabled when its restore
//!    silently failed: the restore was issued, and rejected, and the error swallowed.
//!    Anything that writes this register must check the result.
//!
//! ## Speed auto-detection is not trustworthy — [confirmed]
//!
//! Capturing a Low-speed keyboard with the speed field set to `Auto` produced
//! `CaptureStart(Full)` and then **3072 events and zero packets** — nothing but
//! `SE0`/`FsJ`/`FsK` line-state transitions. Setting the field to `Low` explicitly on the
//! same hardware, unchanged otherwise, produced **815 packets**:
//!
//! ```text
//! CaptureStart(Low)
//! LsKeepalive                      every ~1 ms
//! packet 3 bytes  69 8f a8         IN token, address 0x0f, endpoint 1
//! packet 1 bytes  5a               NAK
//! ```
//!
//! **The failure is silent.** Capture starts, the endpoint streams at full rate, and
//! every transfer succeeds — it simply never frames a packet, because the analyzer is
//! sampling at the wrong bit rate. The giveaway is timing: those transitions were 667 ns
//! apart, which is the Low-speed bit time, not Full speed's 83 ns.
//!
//! So a backend must not default to `Auto` and must not report an all-events, no-packets
//! capture as success. That combination is the signature of a speed mismatch and should
//! be surfaced as one.
//!
//! ## Transfer size is capture latency, not throughput — [confirmed]
//!
//! The endpoint streams only what the bus produces. A Low-speed keyboard generates roughly
//! 8 KB/s, so a 16 KiB read buffer takes about two seconds to fill — and a bulk IN does not
//! complete until it fills or the device sends a short packet. Sizing reads for bandwidth
//! therefore *delays* every record by the fill time, and a capture stopped mid-buffer loses
//! however much was in flight.
//!
//! Measured: a 6-second capture with 16 KiB reads yielded 4016 keepalives (~4 s of a
//! 1 kHz event) and a 4-second span. With 4 KiB reads and in-flight data kept on cancel,
//! the same capture yields 6048 keepalives and a 5983.8 ms span.
//!
//! Two rules follow. Keep the buffer small enough that a quiet bus still completes
//! transfers several times a second, and **keep the bytes from a cancelled transfer** — a
//! bulk IN completes partially as a matter of course, and a `Cancelled` status says the
//! host stopped waiting, not that the data is invalid.
//!
//! # Still unknown
//!
//! - Whether interface 1 does anything. It has no endpoints and answered no request.
//! - Whether `Auto` is reliable for Full- and High-speed targets, or only misdetects
//!   Low speed. Only the Low-speed case has been tested.

/// USB identity of the analyzer, as read from the board.
pub const VID: u16 = 0x1d50;
pub const PID: u16 = 0x615b;

/// The analyzer interface and its capture endpoint.
pub const ANALYZER_INTERFACE: u8 = 0;
pub const EP_CAPTURE: u8 = 0x81;
/// `wMaxPacketSize` of [`EP_CAPTURE`], from the endpoint descriptor.
pub const CAPTURE_MAX_PACKET: usize = 512;

/// Interface protocol byte = the analyzer gateware's API version. Checked exactly:
/// an older board does not implement [`REQ_STATE`] and can never be armed.
pub const GATEWARE_PROTOCOL: u8 = 0x01;

/// Write the capture state byte as `wValue`, recipient Interface, no data stage.
pub const REQ_STATE: u8 = 1;

/// Bit 0 of the state byte.
pub const STATE_ENABLE: u8 = 1 << 0;

/// Bus speed, encoded in bits 1–2 of the state byte.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Speed {
    High = 0,
    Full = 1,
    Low = 2,
    /// Let the analyzer detect the target's speed.
    Auto = 3,
}

impl Speed {
    /// This speed positioned in the state byte.
    pub const fn bits(self) -> u8 {
        (self as u8) << 1
    }
}

/// The state byte that starts a capture at `speed`, leaving all VBUS control off.
pub const fn capture_state(speed: Speed) -> u8 {
    STATE_ENABLE | speed.bits()
}

pub mod events;
pub mod source;
pub use events::{event_name, EventLog, EventSummary};
pub use source::{clk_to_ns, CynthionSource, Record, Stopper, StreamDecoder};
