use std::path::PathBuf;

use tauri::State;
use the_grabber::engine::{StigApplyRequest, StigFinding, StigRemediationOutcome};

use crate::dto::StigApplyRequestDto;
use crate::error::GuiError;
use crate::state::AppState;

/// Evaluate every Okta STIG check against the tenant behind the credential.
#[tauri::command]
pub async fn stig_scan(
    credential_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<StigFinding>, GuiError> {
    let engine = state.engine.clone();
    Ok(engine.stig_scan(&credential_id).await?)
}

/// Apply remediation for the selected findings and append to the remediation log.
#[tauri::command]
pub async fn start_stig_remediation(
    request: StigApplyRequestDto,
    state: State<'_, AppState>,
) -> Result<Vec<StigRemediationOutcome>, GuiError> {
    if request.v_ids.is_empty() {
        return Err(GuiError::Validation(
            "Select at least one finding to remediate".into(),
        ));
    }

    let engine = state.engine.clone();
    let req = StigApplyRequest {
        credential_id: request.credential_id,
        tenant_name: request.tenant_name,
        v_ids: request.v_ids,
        text_input: request.text_input,
        output_dir: PathBuf::from(request.output_dir),
    };
    Ok(engine.stig_apply(req).await?)
}
