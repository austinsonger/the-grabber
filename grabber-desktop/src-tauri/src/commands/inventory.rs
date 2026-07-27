use std::path::PathBuf;

use tauri::{Manager, State};
use the_grabber::engine::InventoryRequest;
use the_grabber::inventory_core::INVENTORY_ITEMS;
use uuid::Uuid;

use crate::commands::collection::{emit_failure, TauriProgressSink};
use crate::dto::{InventoryRequestDto, InventoryTypeDto};
use crate::error::GuiError;
use crate::state::AppState;

/// The asset types the inventory workflow can collect, for the UI checklist.
#[tauri::command]
pub async fn list_inventory_types() -> Result<Vec<InventoryTypeDto>, GuiError> {
    Ok(INVENTORY_ITEMS
        .iter()
        .map(|(key, name)| InventoryTypeDto {
            key: (*key).to_string(),
            name: (*name).to_string(),
        })
        .collect())
}

#[tauri::command]
pub async fn start_inventory(
    request: InventoryRequestDto,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<String, GuiError> {
    let run_id = Uuid::new_v4().to_string();
    let engine = state.engine.clone();
    let sink = TauriProgressSink::new(app.clone(), run_id.clone());
    let account_name = request.account_name.clone();
    let req = InventoryRequest {
        run_id: run_id.clone(),
        account_name: request.account_name,
        credential_id: request.credential_id,
        regions: request.regions,
        inventory_types: request.inventory_types,
        output_dir: PathBuf::from(request.output_dir),
        all_accounts: request.all_accounts,
        zip: request.zip,
    };

    let task_run_id = run_id.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) = engine.inventory(req, Box::new(sink)).await {
            emit_failure(&app, &task_run_id, &account_name, "inventory", &e);
        }
        if let Some(state) = app.try_state::<AppState>() {
            state.take_run(&task_run_id);
        }
    });

    state.register_run(run_id.clone(), handle.abort_handle());
    Ok(run_id)
}
