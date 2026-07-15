//! M2 interrupt capture via ETW (Windows only) — the low-risk tier of DESIGN.md §4a M2.
//!
//! Instead of attaching an ISR-sharing filter into the target's device stack (a PnP rewrite
//! with real BSOD/hang risk on re-enumeration), we consume the **NT Kernel Logger**'s ISR
//! events. The kernel already traces every interrupt-service-routine entry with its IDT
//! `Vector`, ISR `Routine` address, and a QPC timestamp; we subscribe in real time, fold the
//! QPC onto the session clock, and emit [`PcieEvent::Irq`]. Pure user-mode, no driver changes,
//! nothing re-enumerated — so this is safe to run against a live USB/xHCI controller.
//!
//! Attribution: the ETW ISR event carries the IDT vector, not a BDF. `vectors` (if set) filters
//! to a device's vector(s); with no filter every ISR is captured (an offline histogram of the
//! session then reveals which vector is the target — wiggle the device and watch the count
//! spike). The higher-fidelity ISR-sharing filter driver is the future upgrade (README M2.5).

#![cfg(windows)]

use reveng_core::clock::Clock;
use reveng_core::event::{PcieEvent, SourceKind, TrafficKind, TrafficRecord};
use reveng_core::source::CaptureSource;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::ERROR_ALREADY_EXISTS;
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, OpenTraceW, ProcessTrace, StartTraceW, CONTROLTRACE_HANDLE,
    EVENT_HEADER_FLAG_64_BIT_HEADER, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP,
    EVENT_TRACE_FLAG_DPC, EVENT_TRACE_FLAG_INTERRUPT, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, WNODE_FLAG_TRACED_GUID,
};
use windows::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};

/// "NT Kernel Logger" — the fixed name/GUID of the classic kernel trace session.
const KERNEL_LOGGER_NAME: &str = "NT Kernel Logger";
/// `SystemTraceControlGuid` {9e814aad-3204-11d2-9a82-006008a86939}.
const SYSTEM_TRACE_CONTROL_GUID: GUID = GUID::from_u128(0x9e814aad_3204_11d2_9a82_006008a86939);
/// PerfInfo provider {ce1dbfb4-137e-4da6-87b0-3f59aa102cbc} — carries ISR/DPC events.
const PERFINFO_GUID: GUID = GUID::from_u128(0xce1dbfb4_137e_4da6_87b0_3f59aa102cbc);
/// PerfInfo opcode for an ISR-entry event.
const OPCODE_ISR: u8 = 67;

/// One captured interrupt-service-routine entry.
#[derive(Clone, Copy)]
struct IrqSample {
    qpc: i64,
    vector: u16,
    #[allow(dead_code)]
    routine: u64,
}

/// Tunables for [`EtwIrqSource`].
#[derive(Clone, Default)]
pub struct EtwIrqOpts {
    /// If non-empty, only ISRs on these IDT vectors are emitted. Empty = capture every ISR.
    pub vectors: Vec<u16>,
    /// Stop after this long (the ETW stream is otherwise unbounded).
    pub max_duration: Option<Duration>,
}

/// Interrupt CaptureSource backed by the NT Kernel Logger's ISR events.
pub struct EtwIrqSource {
    clock: Clock,
    opts: EtwIrqOpts,
    // Live state (populated by `start`).
    rx: Option<Receiver<IrqSample>>,
    consumer: Option<std::thread::JoinHandle<()>>,
    session: Option<CONTROLTRACE_HANDLE>,
    trace: Option<PROCESSTRACE_HANDLE>,
    // Held so the callback's `Context` pointer stays valid for the trace's lifetime.
    _tx: Option<Box<Sender<IrqSample>>>,
    // QPC → session-ns fold, anchored at `start`.
    qpc_anchor: i64,
    ns_anchor: i64,
    qpc_freq: i64,
    deadline: Option<Instant>,
    /// Set by [`stop_handle`] to end an unbounded stream promptly (used when ETW is a
    /// concurrent PCIe secondary with no deadline). Checked in `next`'s poll loop.
    stop: Arc<AtomicBool>,
}

impl EtwIrqSource {
    pub fn new(clock: Clock, opts: EtwIrqOpts) -> Self {
        Self {
            clock,
            opts,
            rx: None,
            consumer: None,
            session: None,
            trace: None,
            _tx: None,
            qpc_anchor: 0,
            ns_anchor: 0,
            qpc_freq: 1,
            deadline: None,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A flag another thread can set to stop this source (for finalize when it's a concurrent
    /// secondary). Setting it makes `next` return `Ok(None)` within one poll (~200 ms).
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }

    fn fold_qpc(&self, qpc: i64) -> i64 {
        let delta = (qpc - self.qpc_anchor) as i128;
        let ns = delta * 1_000_000_000i128 / (self.qpc_freq.max(1) as i128);
        self.ns_anchor + ns as i64
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A heap buffer holding an `EVENT_TRACE_PROPERTIES` followed by room for the logger name,
/// as the ETW ABI requires (the name is written in-line at `LoggerNameOffset`).
struct TraceProps {
    buf: Vec<u8>,
}

impl TraceProps {
    fn new() -> Self {
        // Space for the fixed struct + a generous logger-name tail.
        let size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 2 * (KERNEL_LOGGER_NAME.len() + 1) * 2;
        Self { buf: vec![0u8; size] }
    }

    fn as_mut(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES
    }

    /// Fill the header for a real-time kernel (ISR) session.
    fn init_kernel_isr(&mut self) {
        let total = self.buf.len() as u32;
        unsafe {
            let p = &mut *self.as_mut();
            p.Wnode.BufferSize = total;
            p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            p.Wnode.ClientContext = 1; // timestamps in QPC ticks
            p.Wnode.Guid = SYSTEM_TRACE_CONTROL_GUID;
            p.EnableFlags = EVENT_TRACE_FLAG_INTERRUPT | EVENT_TRACE_FLAG_DPC; // ISR + DPC
            p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            p.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        }
    }

    /// A minimal header for a `ControlTraceW(STOP)` call.
    fn init_for_stop(&mut self) {
        let total = self.buf.len() as u32;
        unsafe {
            let p = &mut *self.as_mut();
            p.Wnode.BufferSize = total;
            p.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        }
    }
}

/// ETW real-time callback: parse ISR events and forward samples over the channel stashed in
/// `UserContext`. Runs on the trace's `ProcessTrace` thread.
unsafe extern "system" fn event_callback(record: *mut EVENT_RECORD) {
    let rec = match record.as_ref() {
        Some(r) => r,
        None => return,
    };
    let hdr = &rec.EventHeader;
    let opcode = hdr.EventDescriptor.Opcode;
    if hdr.ProviderId != PERFINFO_GUID {
        return;
    }
    // Diagnostic: also observe DPC (66) + TimerDPC (68) to gauge per-device granularity.
    let debug = std::env::var_os("REVENG_ETW_DEBUG").is_some();
    if opcode != OPCODE_ISR && !(debug && (opcode == 66 || opcode == 68)) {
        return;
    }
    let ctx = rec.UserContext as *const Sender<IrqSample>;
    let tx = match ctx.as_ref() {
        Some(t) => t,
        None => return,
    };

    let data = rec.UserData as *const u8;
    let len = rec.UserDataLength as usize;
    let ptr_size = if (hdr.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER as u16) != 0 {
        8
    } else {
        4
    };

    // Bring-up diagnostic: dump distinct (opcode, routine, vector) tuples to gauge granularity.
    if debug {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        if N.fetch_add(1, Ordering::Relaxed) < 60 {
            let routine = if len >= 16 {
                let mut b = [0u8; 8];
                std::ptr::copy_nonoverlapping(data.add(8), b.as_mut_ptr(), 8);
                u64::from_le_bytes(b)
            } else {
                0
            };
            let vec = if opcode == OPCODE_ISR && len >= 18 { *data.add(17) } else { 0 };
            eprintln!("[etw] op={opcode} routine={routine:#018x} vec={vec:#04x} len={len}");
        }
    }
    if opcode != OPCODE_ISR {
        return;
    }
    // Layout: InitialTime(u64) | Routine(ptr) | ReturnValue(u8) | Vector | Reserved.
    let routine_off = 8usize;
    let vector_off = 8 + ptr_size + 1; // after InitialTime, Routine, ReturnValue
    if len < vector_off + 1 {
        return;
    }
    let routine = if ptr_size == 8 {
        let mut b = [0u8; 8];
        std::ptr::copy_nonoverlapping(data.add(routine_off), b.as_mut_ptr(), 8);
        u64::from_le_bytes(b)
    } else {
        let mut b = [0u8; 4];
        std::ptr::copy_nonoverlapping(data.add(routine_off), b.as_mut_ptr(), 4);
        u32::from_le_bytes(b) as u64
    };
    // IDT vectors fit in a byte; read one to be layout-agnostic (Vector is u8-or-u16).
    let vector = *data.add(vector_off) as u16;
    let qpc = hdr.TimeStamp;

    let _ = tx.send(IrqSample {
        qpc,
        vector,
        routine,
    });
}

impl CaptureSource for EtwIrqSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Pcie
    }

    fn start(&mut self) -> anyhow::Result<()> {
        // Anchor QPC → session-ns.
        let mut freq = 0i64;
        let mut qpc = 0i64;
        unsafe {
            let _ = QueryPerformanceFrequency(&mut freq);
            let _ = QueryPerformanceCounter(&mut qpc);
        }
        self.qpc_freq = freq;
        self.qpc_anchor = qpc;
        self.ns_anchor = self.clock.now_ns();

        // Start (or restart) the NT Kernel Logger with ISR tracing.
        let name = wide(KERNEL_LOGGER_NAME);
        let mut session = CONTROLTRACE_HANDLE::default();
        let mut props = TraceProps::new();
        props.init_kernel_isr();
        let mut err = unsafe { StartTraceW(&mut session, PCWSTR(name.as_ptr()), props.as_mut()) };
        if err == ERROR_ALREADY_EXISTS {
            // A stale kernel logger is running — stop it and try once more.
            let mut stopper = TraceProps::new();
            stopper.init_for_stop();
            unsafe {
                let _ = ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    PCWSTR(name.as_ptr()),
                    stopper.as_mut(),
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            let mut props2 = TraceProps::new();
            props2.init_kernel_isr();
            session = CONTROLTRACE_HANDLE::default();
            err = unsafe { StartTraceW(&mut session, PCWSTR(name.as_ptr()), props2.as_mut()) };
        }
        if err.is_err() {
            anyhow::bail!(
                "StartTrace(NT Kernel Logger) failed: {:?} (needs admin; only one kernel logger may run)",
                err
            );
        }
        self.session = Some(session);

        // Channel + a boxed Sender whose address we hand to the callback via Context.
        let (tx, rx) = std::sync::mpsc::channel::<IrqSample>();
        let boxed = Box::new(tx);
        let ctx_ptr = (&*boxed as *const Sender<IrqSample>) as *mut c_void;
        self.rx = Some(rx);

        // Open the real-time consumer.
        let mut logfile = EVENT_TRACE_LOGFILEW::default();
        logfile.LoggerName = PWSTR(name.as_ptr() as *mut _); // borrow for OpenTrace
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(event_callback);
        logfile.Context = ctx_ptr;

        let trace = unsafe { OpenTraceW(&mut logfile) };
        if trace.Value == u64::MAX {
            // INVALID_PROCESSTRACE_HANDLE
            let last = unsafe { windows::Win32::Foundation::GetLastError() };
            // Best-effort teardown of the session we just started.
            let mut stopper = TraceProps::new();
            stopper.init_for_stop();
            unsafe {
                let _ = ControlTraceW(
                    session,
                    PCWSTR(name.as_ptr()),
                    stopper.as_mut(),
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            anyhow::bail!("OpenTrace(NT Kernel Logger) failed: {:?}", last);
        }
        self.trace = Some(trace);
        self._tx = Some(boxed);

        // ProcessTrace blocks until the session is stopped; run it on its own thread.
        let consumer = std::thread::Builder::new()
            .name("etw-isr".into())
            .spawn(move || {
                let handles = [trace];
                unsafe {
                    let _ = ProcessTrace(&handles, None, None);
                }
            })?;
        self.consumer = Some(consumer);

        self.stop.store(false, Ordering::Relaxed);
        self.deadline = self.opts.max_duration.map(|d| Instant::now() + d);
        Ok(())
    }

    fn next(&mut self) -> anyhow::Result<Option<TrafficRecord>> {
        let rx = match self.rx.as_ref() {
            Some(r) => r,
            None => return Ok(None),
        };
        loop {
            if self.stop.load(Ordering::Relaxed) {
                return Ok(None);
            }
            if let Some(dl) = self.deadline {
                if Instant::now() >= dl {
                    return Ok(None);
                }
            }
            let sample = match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(s) => s,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Ok(None),
            };
            if !self.opts.vectors.is_empty() && !self.opts.vectors.contains(&sample.vector) {
                continue;
            }
            let ts_ns = self.fold_qpc(sample.qpc);
            return Ok(Some(TrafficRecord {
                ts_ns,
                source: SourceKind::Pcie,
                kind: TrafficKind::Pcie(PcieEvent::Irq {
                    ts_ns,
                    vector: sample.vector,
                }),
                payload: Vec::new(),
            }));
        }
    }

    fn stop(&mut self) -> anyhow::Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        // Stopping the session makes ProcessTrace return, which lets the consumer thread exit.
        if let Some(session) = self.session.take() {
            let name = wide(KERNEL_LOGGER_NAME);
            let mut stopper = TraceProps::new();
            stopper.init_for_stop();
            unsafe {
                let _ = ControlTraceW(
                    session,
                    PCWSTR(name.as_ptr()),
                    stopper.as_mut(),
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
        }
        if let Some(trace) = self.trace.take() {
            unsafe {
                let _ = CloseTrace(trace);
            }
        }
        if let Some(c) = self.consumer.take() {
            let _ = c.join();
        }
        self.rx = None;
        self._tx = None;
        Ok(())
    }
}
