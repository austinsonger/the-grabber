use std::path::PathBuf;

use tauri::{Manager, State};
use the_grabber::engine::PoamRequest;
use uuid::Uuid;

use crate::commands::collection::{emit_failure, TauriProgressSink};
use crate::dto::PoamRequestDto;
use crate::error::GuiError;
use crate::state::AppState;

#[tauri::command]
pub async fn start_poam(
    request: PoamRequestDto,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<String, GuiError> {
    if !matches!(request.format.as_str(), "xlsx" | "oscal") {
        return Err(GuiError::Validation(format!(
            "Unsupported POA&M format '{}' (expected xlsx or oscal)",
            request.format
        )));
    }

    let run_id = Uuid::new_v4().to_string();
    let engine = state.engine.clone();
    let sink = TauriProgressSink::new(app.clone(), run_id.clone());
    let evidence_base = request.evidence_base.clone();
    let req = PoamRequest {
        run_id: run_id.clone(),
        evidence_base: request.evidence_base,
        year: request.year,
        month: request.month,
        format: request.format,
        output_dir: PathBuf::from(request.output_dir),
    };

    let task_run_id = run_id.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) = engine.poam(req, Box::new(sink)).await {
            emit_failure(&app, &task_run_id, &evidence_base, "poam", &e);
        }
        if let Some(state) = app.try_state::<AppState>() {
            state.take_run(&task_run_id);
        }
    });

    state.register_run(run_id.clone(), handle.abort_handle());
    Ok(run_id)
}
