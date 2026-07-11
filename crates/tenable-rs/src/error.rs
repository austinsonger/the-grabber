use thiserror::Error;

#[derive(Debug, Error)]
pub enum TenableError {
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),

    #[error("API error {status}: {message}")]
    Api { status: u16, message: String },

    #[error("authentication failed — check access_key and secret_key")]
    Auth,

    #[error("permission denied — account lacks the required Tenable permission")]
    Forbidden,

    #[error("rate limited — retry after {retry_after_secs}s")]
    RateLimit { retry_after_secs: u64 },

    #[error("export job failed with status: {status}")]
    ExportFailed { status: String },

    #[error("JSON parse error: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("invalid header value: {0}")]
    InvalidHeader(#[from] reqwest::header::InvalidHeaderValue),
}
