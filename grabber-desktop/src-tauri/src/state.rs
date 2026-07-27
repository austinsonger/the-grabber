use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::task::AbortHandle;

use the_grabber::app_config::AppConfig;
use the_grabber::engine::Engine;

pub struct AppState {
    pub engine: Arc<Engine>,
    pub config: AppConfig,
    /// Abort handles for in-flight runs, keyed by run id, so the UI can cancel them.
    pub runs: Mutex<HashMap<String, AbortHandle>>,
}

impl AppState {
    pub fn new(engine: Arc<Engine>, config: AppConfig) -> Self {
        Self {
            engine,
            config,
            runs: Mutex::new(HashMap::new()),
        }
    }

    pub fn register_run(&self, run_id: String, handle: AbortHandle) {
        if let Ok(mut runs) = self.runs.lock() {
            runs.insert(run_id, handle);
        }
    }

    pub fn take_run(&self, run_id: &str) -> Option<AbortHandle> {
        self.runs.lock().ok().and_then(|mut r| r.remove(run_id))
    }
}
