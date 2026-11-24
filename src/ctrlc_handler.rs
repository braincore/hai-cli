use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};

pub type Handlers = Arc<SyncMutex<HashMap<u32, Box<dyn Fn() + Send + Sync>>>>;

// CtrlcHandler has two purposes:
// 1. Terminal mode: Handle real Ctrl-C signals from the terminal.
// 2. Kernel mode: Emulate Ctrl-C interrupts for kernel processes (websocket
//.   i/o).
//
// For #1, the ctrlc crate supports registering a single callback. CtrlcHandler
// uses this to implement support for multiple callbacks that can be
// dynamically registered/deregistered. Child processes (shell exec, tools) get
// the same SIGINT directly since they share the same process group.
//
// For #2, the client sends an interrupt message and CtrlcHandler emulates ^C
// ^C by running the registered handlers. It also signals the appropriate child
// process groups (spawned via `spawn_interruptible`), but not the process
// group of the kernel itself as that would signal whoever spawned the kernel
// (blowing up everything in the process).
#[derive(Clone)]
pub struct CtrlcHandler {
    handlers: Handlers,
}

impl CtrlcHandler {
    pub fn new() -> CtrlcHandler {
        let handlers: Handlers = Arc::new(SyncMutex::new(HashMap::new()));
        let handlers_clone = Arc::clone(&handlers);
        ctrlc::set_handler(move || {
            let ctrlc_handlers_unlocked = handlers_clone.lock().expect("Failed to lock mutex");
            for ctrlc_handler in ctrlc_handlers_unlocked.values() {
                ctrlc_handler();
            }
        })
        .expect("Error setting Ctrl-C handler");
        CtrlcHandler { handlers }
    }

    pub fn add_handler<F>(&mut self, handler: F) -> u32
    where
        F: Fn() + Send + Sync + 'static,
    {
        let id = next_id();
        let mut handlers = self.handlers.lock().expect("Failed to lock mutex");
        handlers.insert(id, Box::new(handler));
        id
    }

    pub fn remove_handler(&mut self, id: u32) {
        let mut handlers = self.handlers.lock().expect("Failed to lock mutex");
        handlers.remove(&id);
    }

    /// Emulates ^C for websocket i/o (kernel mode).
    ///
    /// Runs the registered handlers in-process and sends an interrupt to the
    /// process group of each child registered via `spawn_interruptible`.
    /// Never signals our own process group (see module comment).
    pub fn trigger(&self) {
        {
            // Don't panic: if the mutex is poisoned, still run handlers.
            let handlers = self
                .handlers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for handler in handlers.values() {
                handler();
            }
        }
        let pgids: Vec<u32> = CHILD_PGIDS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|(_, pgid)| *pgid)
            .collect();
        for pgid in pgids {
            interrupt_process_group(pgid);
        }
    }

    /// Registers a handler and returns a guard that unregisters it when
    /// dropped.
    pub fn add_handler_guarded<F>(&mut self, handler: F) -> CtrlcHandlerGuard
    where
        F: Fn() + Send + Sync + 'static,
    {
        let id = self.add_handler(handler);
        CtrlcHandlerGuard {
            handlers: Arc::clone(&self.handlers),
            id,
        }
    }

    /// Returns a `Notify` that's notified on interrupt (real or emulated),
    /// for use in `tokio::select!`. The permit is stored, so an interrupt
    /// that arrives before `notified()` is awaited isn't lost.
    pub fn interrupt_notify(&mut self) -> (CtrlcHandlerGuard, Arc<tokio::sync::Notify>) {
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = self.add_handler_guarded({
            let notify = notify.clone();
            move || notify.notify_one()
        });
        (guard, notify)
    }
}

impl Default for CtrlcHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Set once at startup for kernel processes.
static KERNEL_MODE: AtomicBool = AtomicBool::new(false);

/// Process-group IDs of running children that should receive emulated ^C.
/// Keyed by a unique ID so that guards remove exactly their own entry.
static CHILD_PGIDS: SyncMutex<Vec<(u32, u32)>> = SyncMutex::new(Vec::new());

fn next_id() -> u32 {
    // Use incrementing count for IDs
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Call once at startup (before spawning children) if this process is a
/// kernel whose interrupts arrive over websocket rather than from a terminal.
pub fn set_kernel_mode() {
    KERNEL_MODE.store(true, Ordering::SeqCst);
}

pub fn is_kernel_mode() -> bool {
    KERNEL_MODE.load(Ordering::SeqCst)
}

/// Puts the child process in its own process group to isolate signals.
pub fn isolate_process_group(cmd: &mut tokio::process::Command) {
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }
}

/// Spawns a child process that should be interrupted by ^C.
///
/// 1. Terminal mode: Calls ordinary `cmd.spawn()` which uses the current
///    process group and responds to ^C the ordinary way.
/// 2. Kernel mode: Child gets its own process group that's tracked so that
///    it's interruptible by `CtrlcHandler::trigger`.
///
/// # Returns
///
/// tuple[0]: Spawned child process.
/// tuple[1]: Guard to be kept alive until child has been waited on.
pub fn spawn_interruptible(
    cmd: &mut tokio::process::Command,
) -> std::io::Result<(tokio::process::Child, Option<ChildGuard>)> {
    if !is_kernel_mode() {
        return cmd.spawn().map(|child| (child, None));
    }
    isolate_process_group(cmd);
    let child = cmd.spawn()?;
    // Child may have been quickly reaped -> no ID
    let guard = child.id().map(|pid| {
        // With its own group, the child's PGID equals its PID.
        let id = next_id();
        CHILD_PGIDS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((id, pid));
        ChildGuard { id }
    });
    Ok((child, guard))
}

/// Unregisters a child spawned via `spawn_interruptible` when dropped.
#[must_use]
pub struct ChildGuard {
    id: u32,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        CHILD_PGIDS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|(id, _)| *id != self.id);
    }
}

/// Mimics ^C for a single child process group.
#[cfg(unix)]
fn interrupt_process_group(pgid: u32) {
    unsafe {
        libc::killpg(pgid as libc::pid_t, libc::SIGINT);
    }
}

/// Mimics ^C for a single child process group.
///
/// CTRL_C_EVENT can't target a specific group (it's disabled for processes
/// started with CREATE_NEW_PROCESS_GROUP), so CTRL_BREAK_EVENT is used.
#[cfg(windows)]
fn interrupt_process_group(pgid: u32) {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};
    unsafe {
        GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pgid);
    }
}

// --

/// Safer way to use CTRL-C handler. Auto-removes when dropped.
#[must_use]
pub struct CtrlcHandlerGuard {
    handlers: Handlers,
    id: u32,
}

impl Drop for CtrlcHandlerGuard {
    fn drop(&mut self) {
        // Don't panic: if the mutex is poisoned, remove handler.
        let mut handlers = self
            .handlers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        handlers.remove(&self.id);
    }
}
