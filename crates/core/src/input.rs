//! Input-event schema (DESIGN.md §5). Lives in `core` so the session layer and the
//! Windows hook layer (`reveng-winput`) share one type.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    MouseDown,
    MouseUp,
    Wheel,
    KeyDown,
    KeyUp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputEvent {
    pub ts_ns: i64,
    pub kind: InputKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub button: Option<String>, // "L","R","M","X1","X2"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vk: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scancode: Option<u16>,
    pub x: i32,
    pub y: i32,
    pub injected: bool,
}
