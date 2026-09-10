use tauri::State;

use the_grabber::app_config::load_config;

use crate::dto::{AccountDto, AppConfigDto, DefaultsDto};
use crate::error::GuiError;
use crate::state::AppState;

#[tauri::command]
pub async fn load_app_config(_state: State<'_, AppState>) -> Result<AppConfigDto, GuiError> {
    let config = load_config().ok_or_else(|| GuiError::Config("No config found".into()))?;
    Ok(AppConfigDto {
        accounts: config
            .account
            .into_iter()
            .map(|a| AccountDto {
                name: a.name,
                provider: a.provider.to_string(),
                account_id: a.account_id,
                credential_id: None,
                profile: a.profile,
                region: a.region.unwrap_or_default(),
                output_dir: a.output_dir,
            })
            .collect(),
        defaults: DefaultsDto {
            region: config.defaults.region.unwrap_or_default(),
            output_dir: config.defaults.output_dir.unwrap_or_default(),
            start_date_offset_days: config.defaults.start_date_offset_days.unwrap_or_default()
                as i64,
        },
    })
}

#[tauri::command]
pub async fn save_app_config(
    _dto: AppConfigDto,
    _state: State<'_, AppState>,
) -> Result<(), GuiError> {
    // TODO: map DTO back to the_grabber::app_config::AppConfig and persist.
    Ok(())
}
