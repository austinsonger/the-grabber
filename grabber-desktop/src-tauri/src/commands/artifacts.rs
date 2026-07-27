use std::path::{Path, PathBuf};

use crate::dto::ArtifactDto;
use crate::error::GuiError;

/// Cap on how much of an artifact the preview pane will load.
const PREVIEW_LIMIT: usize = 256 * 1024;

/// List the evidence artifacts written into `output_dir`, newest first.
#[tauri::command]
pub async fn list_run_artifacts(output_dir: String) -> Result<Vec<ArtifactDto>, GuiError> {
    let dir = PathBuf::from(&output_dir);
    if !dir.is_dir() {
        return Err(GuiError::NotFound(format!(
            "Output directory not found: {output_dir}"
        )));
    }

    let entries = std::fs::read_dir(&dir)
        .map_err(|e| GuiError::Collection(format!("Failed to read {output_dir}: {e}")))?;

    let mut artifacts: Vec<ArtifactDto> = Vec::new();
    for entry in entries.flatten() {
        let meta = match entry.metadata() {
            Ok(m) if m.is_file() => m,
            _ => continue,
        };
        let path = entry.path();
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        artifacts.push(ArtifactDto {
            name: entry.file_name().to_string_lossy().to_string(),
            path: path.to_string_lossy().to_string(),
            extension: path
                .extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default(),
            size_bytes: meta.len(),
            modified_epoch_secs: modified,
        });
    }

    artifacts.sort_by(|a, b| b.modified_epoch_secs.cmp(&a.modified_epoch_secs));
    Ok(artifacts)
}

/// Read the head of an artifact for the preview pane. Binary artifacts (zip,
/// xlsx) are rejected rather than dumped into the UI as mojibake.
#[tauri::command]
pub async fn read_artifact_preview(path: String) -> Result<String, GuiError> {
    let path = PathBuf::from(&path);
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if !matches!(
        ext.as_str(),
        "csv" | "json" | "jsonl" | "txt" | "md" | "log"
    ) {
        return Err(GuiError::Validation(format!(
            "Preview is not available for .{ext} files"
        )));
    }

    let bytes = std::fs::read(&path)
        .map_err(|e| GuiError::NotFound(format!("Failed to read {}: {e}", path.display())))?;
    let truncated = bytes.len() > PREVIEW_LIMIT;
    let slice = &bytes[..bytes.len().min(PREVIEW_LIMIT)];
    let mut text = String::from_utf8_lossy(slice).to_string();
    if truncated {
        text.push_str("\n\n… preview truncated …");
    }
    Ok(text)
}

/// Reveal a directory in the host file manager.
#[tauri::command]
pub async fn open_output_dir(path: String) -> Result<(), GuiError> {
    let dir = Path::new(&path);
    if !dir.is_dir() {
        return Err(GuiError::NotFound(format!(
            "Output directory not found: {path}"
        )));
    }

    #[cfg(target_os = "macos")]
    let program = "open";
    #[cfg(target_os = "windows")]
    let program = "explorer";
    #[cfg(all(unix, not(target_os = "macos")))]
    let program = "xdg-open";

    std::process::Command::new(program)
        .arg(dir)
        .spawn()
        .map_err(|e| GuiError::Collection(format!("Failed to open {path}: {e}")))?;
    Ok(())
}
