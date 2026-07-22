use thiserror::Error;

#[derive(Debug, Error)]
pub enum ElasticError {
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),

    #[error("API error {status}: {message}")]
    Api { status: u16, message: String },

    #[error("invalid base URL: {0}")]
    InvalidBaseUrl(String),

    #[error("JSON parse error: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("invalid header value: {0}")]
    InvalidHeader(#[from] reqwest::header::InvalidHeaderValue),
}
