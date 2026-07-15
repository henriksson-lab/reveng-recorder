//! Checkpoints and the rules that generate them (DESIGN.md §7, §11.2).

use crate::event::TrafficAnchor;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointType {
    Click,
    KeyDown,
    Interval,
    Manual,
    SessionStart,
    SessionStop,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub id: u64,
    pub ts_ns: i64,
    pub kind: CheckpointType,
    pub cause: String,
    /// Nearest preceding traffic event in the primary log — source-agnostic (DESIGN.md §7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor: Option<TrafficAnchor>,
    /// Additional anchors into other logs captured concurrently — e.g. the nearest preceding
    /// PCIe event when USB + PCIe are co-logged. `anchor` stays the base (USB) source; this
    /// carries the rest, so one checkpoint reaches both wires. Empty for single-source sessions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchors: Vec<TrafficAnchor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screenshot_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fg_process: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fg_window: Option<String>,
    pub cursor: (i32, i32),
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Which user events generate checkpoints (mirrors the `--checkpoint-*` flags, §11.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckpointConfig {
    pub on_any_key: bool,
    pub special_keys: Vec<String>,
    pub key_combos: Vec<String>,
    pub mouse_buttons: Vec<String>,
    pub on_mouseup: bool,
    pub on_wheel: bool,
    /// Interval-checkpoint period in ms; `0` disables.
    pub interval_ms: u64,
    /// Minimum traffic bytes since the last checkpoint to emit an interval one.
    pub interval_bytes: u64,
}

impl Default for CheckpointConfig {
    fn default() -> Self {
        Self {
            on_any_key: false,
            special_keys: ["Return", "Escape", "Tab", "Back", "Delete"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            key_combos: Vec::new(),
            mouse_buttons: ["L", "R", "M"].iter().map(|s| s.to_string()).collect(),
            on_mouseup: false,
            on_wheel: false,
            interval_ms: 1000,
            interval_bytes: 4096,
        }
    }
}

impl CheckpointConfig {
    /// Does a key-down on `key_name` (e.g. "Return") produce a checkpoint?
    pub fn key_triggers(&self, key_name: &str) -> bool {
        self.on_any_key
            || self
                .special_keys
                .iter()
                .any(|k| k.eq_ignore_ascii_case(key_name))
    }

    /// Does pressing mouse `button` (e.g. "L") produce a checkpoint?
    pub fn mouse_triggers(&self, button: &str) -> bool {
        self.mouse_buttons
            .iter()
            .any(|b| b.eq_ignore_ascii_case(button))
    }
}

/// Tracks traffic since the last checkpoint so interval checkpoints fire only during
/// continuous traffic, and reset whenever any real checkpoint fires (DESIGN.md §7).
#[derive(Debug, Default)]
pub struct IntervalTracker {
    bytes_since: u64,
}

impl IntervalTracker {
    pub fn add_bytes(&mut self, n: u64) {
        self.bytes_since = self.bytes_since.saturating_add(n);
    }

    pub fn reset(&mut self) {
        self.bytes_since = 0;
    }

    /// Given the timer has ticked, should an interval checkpoint fire now?
    pub fn should_fire(&self, cfg: &CheckpointConfig) -> bool {
        cfg.interval_ms > 0 && self.bytes_since >= cfg.interval_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_and_mouse_triggers() {
        let cfg = CheckpointConfig::default();
        assert!(cfg.key_triggers("Return"));
        assert!(cfg.key_triggers("escape")); // case-insensitive
        assert!(!cfg.key_triggers("A"));
        assert!(cfg.mouse_triggers("L"));
        assert!(!cfg.mouse_triggers("X1"));
    }

    #[test]
    fn any_key_overrides() {
        let mut cfg = CheckpointConfig::default();
        cfg.on_any_key = true;
        assert!(cfg.key_triggers("A"));
    }

    #[test]
    fn interval_only_with_enough_traffic() {
        let cfg = CheckpointConfig::default();
        let mut t = IntervalTracker::default();
        assert!(!t.should_fire(&cfg)); // idle: no interval checkpoint
        t.add_bytes(5000);
        assert!(t.should_fire(&cfg));
        t.reset();
        assert!(!t.should_fire(&cfg));
    }
}
