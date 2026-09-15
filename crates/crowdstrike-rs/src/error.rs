use thiserror::Error;

#[derive(Debug, Error)]
pub enum CrowdStrikeError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("invalid header value: {0}")]
    Header(#[from] reqwest::header::InvalidHeaderValue),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("CrowdStrike API error: HTTP {status} — {message}")]
    Api { status: u16, message: String },

    #[error("OAuth2 token request failed: HTTP {status} — {message}")]
    Auth { status: u16, message: String },

    #[error("invalid base URL: {0}")]
    InvalidBaseUrl(String),
}
