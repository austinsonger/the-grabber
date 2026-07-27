use serde::Serialize;

#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "error", content = "message")]
pub enum GuiError {
    #[error("Config error: {0}")]
    Config(String),
    #[error("Credential error: {0}")]
    Credential(String),
    #[error("Collection error: {0}")]
    Collection(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Validation error: {0}")]
    Validation(String),
}

impl From<anyhow::Error> for GuiError {
    fn from(e: anyhow::Error) -> Self {
        GuiError::Collection(e.to_string())
    }
}
