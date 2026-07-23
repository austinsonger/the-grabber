use thiserror::Error;

#[derive(Debug, Error)]
pub enum JamfError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("invalid header value: {0}")]
    Header(#[from] reqwest::header::InvalidHeaderValue),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Jamf API error: HTTP {status} — {message}")]
    Api { status: u16, message: String },

    #[error("invalid base URL: {0}")]
    InvalidBaseUrl(String),

    #[error("OAuth token request failed: {0}")]
    Auth(String),
}
