use std::sync::Arc;

use the_grabber::app_config::AppConfig;
use the_grabber::engine::Engine;

pub struct AppState {
    pub engine: Arc<Engine>,
    pub config: AppConfig,
}

impl AppState {
    pub fn new(engine: Arc<Engine>, config: AppConfig) -> Self {
        Self { engine, config }
    }
}
