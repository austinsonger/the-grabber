use std::path::PathBuf;

use tauri::{Emitter, State};
use the_grabber::engine::{CollectionRequest, ProgressEvent, ProgressSink};
use uuid::Uuid;

use crate::dto::CollectionRequestDto;
use crate::error::GuiError;
use crate::state::AppState;

pub struct TauriProgressSink {
    app: tauri::AppHandle,
    run_id: String,
}

impl TauriProgressSink {
    pub fn new(app: tauri::AppHandle, run_id: String) -> Self {
        Self { app, run_id }
    }
}

impl ProgressSink for TauriProgressSink {
    fn emit(&self, event: ProgressEvent) {
        let payload = ProgressPayload {
            run_id: self.run_id.clone(),
            account: event.account,
            region: event.region,
            collector: event.collector,
            status: event.status,
            records: event.records,
            message: event.message,
        };
        let _ = self.app.emit("collection:progress", payload);
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct ProgressPayload {
    run_id: String,
    account: String,
    region: Option<String>,
    collector: String,
    status: String,
    records: u64,
    message: Option<String>,
}

#[tauri::command]
pub async fn start_collection(
    request: CollectionRequestDto,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<String, GuiError> {
    let run_id = Uuid::new_v4().to_string();
    let engine = state.engine.clone();
    let sink = TauriProgressSink::new(app, run_id.clone());
    let req = CollectionRequest {
        run_id: run_id.clone(),
        account_name: request.account_name,
        credential_id: request.credential_id,
        regions: request.regions,
        start_date: request.start_date,
        end_date: request.end_date,
        collectors: request.collectors,
        output_dir: PathBuf::from(request.output_dir),
        zip: request.zip,
        sign: request.sign,
        include_raw: request.include_raw,
        write_run_manifest: request.write_run_manifest,
        write_chain_of_custody: request.write_chain_of_custody,
        signing_key: request.signing_key,
    };

    tokio::spawn(async move {
        let _ = engine.collect(req, Box::new(sink)).await;
    });

    Ok(run_id)
}
