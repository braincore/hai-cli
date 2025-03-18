use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};

pub type Handlers = Arc<SyncMutex<HashMap<u32, Box<dyn Fn() + Send + Sync>>>>;

// The ctrlc crate supports registering a single callback. CtrlcHandler uses
// this to implement support for multiple callbacks that can be dynamically
// registered/deregistered.
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
        // Use incrementing count for handler IDs
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);

        let mut handlers = self.handlers.lock().expect("Failed to lock mutex");
        handlers.insert(id, Box::new(handler));

        id
    }

    pub fn remove_handler(&mut self, id: u32) {
        let mut handlers = self.handlers.lock().expect("Failed to lock mutex");
        handlers.remove(&id);
    }
}
