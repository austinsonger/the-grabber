use std::path::PathBuf;

use tauri::{Emitter, Manager, State};
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
    let sink = TauriProgressSink::new(app.clone(), run_id.clone());
    let account_name = request.account_name.clone();
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

    let task_run_id = run_id.clone();
    let handle = tokio::spawn(async move {
        let result = engine.collect(req, Box::new(sink)).await;
        if let Err(e) = result {
            let _ = app.emit(
                "collection:progress",
                ProgressPayload {
                    run_id: task_run_id.clone(),
                    account: account_name,
                    region: None,
                    collector: "all".into(),
                    status: "failed".into(),
                    records: 0,
                    message: Some(format!("{e:#}")),
                },
            );
        }
        if let Some(state) = app.try_state::<AppState>() {
            state.take_run(&task_run_id);
        }
    });

    state.register_run(run_id.clone(), handle.abort_handle());

    Ok(run_id)
}

/// Abort an in-flight collection run. Returns `false` when the run already
/// finished (or was never registered).
#[tauri::command]
pub async fn cancel_collection(
    run_id: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<bool, GuiError> {
    match state.take_run(&run_id) {
        Some(handle) => {
            handle.abort();
            let _ = app.emit(
                "collection:progress",
                ProgressPayload {
                    run_id,
                    account: String::new(),
                    region: None,
                    collector: "all".into(),
                    status: "cancelled".into(),
                    records: 0,
                    message: Some("Collection run cancelled".into()),
                },
            );
            Ok(true)
        }
        None => Ok(false),
    }
}
