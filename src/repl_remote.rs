use std::sync::{Arc, atomic::AtomicBool};
use tokio::sync::Mutex;

use crate::session::{CmdInput, CmdQueue, SessionState};

/// A remote interface to the REPL, allowing commands to be pushed and break
/// signals to be sent.
#[derive(Clone)]
pub struct ReplRemote {
    cmd_queue: Arc<Mutex<CmdQueue>>,
    break_signal: Arc<AtomicBool>,
}

impl ReplRemote {
    pub fn new(cmd_queue: Arc<Mutex<CmdQueue>>, break_signal: Arc<AtomicBool>) -> Self {
        Self {
            cmd_queue,
            break_signal,
        }
    }

    pub async fn push_cmd(&self, cmd_input: CmdInput) {
        self.cmd_queue.lock().await.push_cmd(cmd_input);
    }

    pub fn signal_break(&self) {
        self.break_signal
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn from_session(session: &SessionState) -> Self {
        Self::new(session.cmd_queue.clone(), session.repl_break_signal.clone())
    }
}
