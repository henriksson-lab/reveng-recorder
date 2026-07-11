//! The master session clock (DESIGN.md §2).
//!
//! All session timestamps are nanoseconds since [`Clock::start`]. On Windows
//! `std::time::Instant` is backed by `QueryPerformanceCounter` — exactly the master
//! clock the design specifies — so using `Instant` keeps the scaffold cross-platform
//! for development while remaining correct on the target platform.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct Clock {
    origin: Instant,
    wall_ns_at_origin: i64,
}

impl Clock {
    /// Anchor the timeline at "now".
    pub fn start() -> Self {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        Self {
            origin: Instant::now(),
            wall_ns_at_origin: wall,
        }
    }

    /// Monotonic nanoseconds since session start.
    pub fn now_ns(&self) -> i64 {
        self.origin.elapsed().as_nanos() as i64
    }

    /// Unix-epoch wall-clock ns at session start. This is the anchor used to fold a
    /// capture source's wall-clock timestamps (e.g. USBPcap's pcap record time) onto
    /// this monotonic timeline.
    pub fn wall_ns_at_origin(&self) -> i64 {
        self.wall_ns_at_origin
    }

    /// Convert a source wall-clock timestamp (unix ns) into session ns.
    pub fn wall_to_session_ns(&self, wall_unix_ns: i64) -> i64 {
        wall_unix_ns - self.wall_ns_at_origin
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_is_monotonic() {
        let c = Clock::start();
        let a = c.now_ns();
        let b = c.now_ns();
        assert!(b >= a);
    }

    #[test]
    fn wall_conversion_roundtrips_offset() {
        let c = Clock::start();
        let origin = c.wall_ns_at_origin();
        assert_eq!(c.wall_to_session_ns(origin + 1_000), 1_000);
    }
}
