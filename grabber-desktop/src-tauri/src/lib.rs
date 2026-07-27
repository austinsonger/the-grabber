pub mod commands;
pub mod dto;
pub mod error;
pub mod state;

use std::sync::Arc;

use tauri::Manager;

use the_grabber::app_config::load_config;
use the_grabber::engine::Engine;

use crate::state::AppState;

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}!", name)
}

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            let config = load_config().unwrap_or_default();
            let engine = Arc::new(Engine::new(config.clone(), data_dir)?);
            app.manage(AppState::new(engine, config));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            greet,
            commands::config::load_app_config,
            commands::config::save_app_config,
            commands::credentials::list_credentials,
            commands::credentials::create_credential,
            commands::credentials::delete_credential,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Tauri application");
}
