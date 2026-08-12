//! Skeleton for a clean-room userspace USB driver, cross-platform via `nusb` (WinUSB on Windows,
//! usbfs on Linux, IOKit on macOS). Copy into a new crate; `cargo add nusb futures-lite anyhow`.
//!
//! It encodes the two bring-up gotchas that cost the most time when reverse-engineering a device:
//!
//!   1. BULK STREAMING NEEDS A QUEUE. Many devices (esp. Cypress FX2/FX3 cameras) only stream while
//!      SEVERAL bulk-IN requests are outstanding — the DMA won't start for a single read, which
//!      just NAKs forever (looks like "silent endpoint"). Keep ~16 requests in flight.
//!
//!   2. ABORTED ATTEMPTS WEDGE THE DEVICE. Half-finished init/stream attempts can leave the
//!      firmware stuck (every read NAKs regardless of what you send). A USB reset — or, failing
//!      that, a physical replug — returns it to a clean state. Reset on open.
//!
//! Bonus: on Linux a kernel driver may hold the interface — `detach_and_claim_interface` detaches
//! it. On Linux you also need device permissions (a udev rule, or run as root).

use anyhow::{Context, Result};
use futures_lite::future::block_on;
use nusb::transfer::{ControlIn, ControlOut, ControlType, Recipient, RequestBuffer};
use nusb::Interface;

const VID: u16 = 0x0000; // <-- your device
const PID: u16 = 0x0000;
const IMAGE_EP: u8 = 0x81; // <-- your bulk-IN endpoint
const FRAME_BYTES: usize = 0; // <-- bytes per frame (e.g. width*height)

pub struct Device {
    iface: Interface,
}

impl Device {
    pub fn open() -> Result<Device> {
        let di = nusb::list_devices()?
            .find(|d| d.vendor_id() == VID && d.product_id() == PID)
            .context("device not found")?;
        let dev = di.open().context("open failed (in use? permissions?)")?;
        let _ = dev.reset(); // gotcha #2: clean state (Linux/macOS; no-op on Windows)
        let iface = dev
            .detach_and_claim_interface(0) // detaches a kernel driver on Linux
            .context("claim interface 0 failed (Linux: udev rule or root?)")?;
        let _ = iface.set_alt_setting(0);
        Ok(Device { iface })
    }

    pub fn control_out(&self, request: u8, value: u16, index: u16, data: &[u8]) -> Result<()> {
        block_on(self.iface.control_out(ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request,
            value,
            index,
            data,
        }))
        .into_result()
        .map_err(|e| anyhow::anyhow!("control_out: {e}"))?;
        Ok(())
    }

    pub fn control_in(&self, request: u8, value: u16, index: u16, length: u16) -> Result<Vec<u8>> {
        Ok(block_on(self.iface.control_in(ControlIn {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request,
            value,
            index,
            length,
        }))
        .into_result()
        .map_err(|e| anyhow::anyhow!("control_in: {e}"))?)
    }

    /// Read one frame with a QUEUED bulk read (gotcha #1). Runs the queue on a worker thread and
    /// accumulates `FRAME_BYTES`, with an overall timeout.
    pub fn read_frame(&self, timeout_ms: u64) -> Result<Vec<u8>> {
        use std::sync::mpsc::{channel, RecvTimeoutError};
        use std::time::{Duration, Instant};
        let iface = self.iface.clone();
        let (tx, rx) = channel::<std::result::Result<Vec<u8>, String>>();
        std::thread::spawn(move || {
            let mut q = iface.bulk_in_queue(IMAGE_EP);
            for _ in 0..16 {
                q.submit(RequestBuffer::new(512 * 1024));
            }
            loop {
                let c = block_on(q.next_complete());
                let msg = c.status.map(|_| c.data.clone()).map_err(|e| e.to_string());
                let stop = msg.is_err();
                if tx.send(msg).is_err() || stop {
                    return;
                }
                q.submit(RequestBuffer::new(512 * 1024));
            }
        });
        let mut frame = Vec::with_capacity(FRAME_BYTES + (1 << 20));
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        while frame.len() < FRAME_BYTES {
            let now = Instant::now();
            if now >= deadline {
                anyhow::bail!("frame timeout ({} of {FRAME_BYTES} bytes)", frame.len());
            }
            match rx.recv_timeout(deadline - now) {
                Ok(Ok(d)) => frame.extend_from_slice(&d),
                Ok(Err(e)) => anyhow::bail!("bulk error: {e}"),
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => anyhow::bail!("stream thread ended"),
            }
        }
        frame.truncate(FRAME_BYTES);
        Ok(frame)
    }
}
