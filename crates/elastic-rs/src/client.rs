use reqwest::{header, Client};
use tokio::time::{sleep, Duration};

use crate::api::{alerts::AlertsApi, cases::CasesApi, exceptions::ExceptionsApi, rules::RulesApi};
use crate::error::ElasticError;

const MAX_RETRIES: u32 = 5;
const DEFAULT_RETRY_AFTER_SECS: u64 = 30;

/// Async HTTP client for the Elastic Security stack.
///
/// Elastic Security splits its API surface across two hosts: Kibana serves
/// the Detection Engine, Exception Lists, and Cases REST APIs; Elasticsearch
/// serves the `.alerts-security.alerts-*` index directly. The same API key
/// authenticates against both when it carries both Kibana and index
/// privileges — the normal case for a key created via Kibana's API Keys UI,
/// since those keys are Elasticsearch API keys under the hood.
///
/// `ElasticClient` is cheaply cloneable — `reqwest::Client` is arc-pooled.
#[derive(Clone)]
pub struct ElasticClient {
    pub(crate) http: Client,
    pub(crate) kibana_url: String,
    pub(crate) es_url: String,
}

impl ElasticClient {
    /// Build a client. `kibana_url` serves the Detection Engine, Exception
    /// Lists, and Cases APIs; `es_url` serves direct Elasticsearch queries
    /// against the alerts index. `api_key` must already be in the
    /// base64-encoded `id:api_key` form Elastic returns from key creation
    /// (Kibana's API Keys UI calls this the "Encoded" value).
    pub fn new(kibana_url: &str, es_url: &str, api_key: &str) -> Result<Self, ElasticError> {
        let kibana_url = kibana_url.trim().trim_end_matches('/');
        let es_url = es_url.trim().trim_end_matches('/');
        if kibana_url.is_empty() {
            return Err(ElasticError::InvalidBaseUrl("kibana_url is empty".into()));
        }
        if es_url.is_empty() {
            return Err(ElasticError::InvalidBaseUrl("es_url is empty".into()));
        }

        let auth = format!("ApiKey {api_key}");
        let mut headers = header::HeaderMap::new();
        headers.insert(header::AUTHORIZATION, header::HeaderValue::from_str(&auth)?);
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );
        // Required by Kibana on every request; harmlessly ignored by Elasticsearch.
        headers.insert("kbn-xsrf", header::HeaderValue::from_static("true"));

        let http = Client::builder().default_headers(headers).build()?;
        Ok(Self {
            http,
            kibana_url: kibana_url.to_string(),
            es_url: es_url.to_string(),
        })
    }

    pub(crate) async fn kibana_get(&self, path: &str) -> Result<reqwest::Response, ElasticError> {
        let url = format!("{}{}", self.kibana_url, path);
        self.send_with_retry(|| self.http.get(&url).send()).await
    }

    pub(crate) async fn es_post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response, ElasticError> {
        let url = format!("{}{}", self.es_url, path);
        self.send_with_retry(|| self.http.post(&url).json(body).send())
            .await
    }

    async fn send_with_retry<F, Fut>(&self, make_req: F) -> Result<reqwest::Response, ElasticError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
    {
        let mut backoff = 1u64;
        for attempt in 0..=MAX_RETRIES {
            let resp = make_req().await?;
            if resp.status() != 429 || attempt == MAX_RETRIES {
                return Ok(resp);
            }
            sleep(Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(DEFAULT_RETRY_AFTER_SECS);
        }
        unreachable!()
    }

    pub fn rules(&self) -> RulesApi<'_> {
        RulesApi(self)
    }
    pub fn exceptions(&self) -> ExceptionsApi<'_> {
        ExceptionsApi(self)
    }
    pub fn cases(&self) -> CasesApi<'_> {
        CasesApi(self)
    }
    pub fn alerts(&self) -> AlertsApi<'_> {
        AlertsApi(self)
    }
}

/// Check an HTTP response for a non-2xx status and convert to `ElasticError::Api`.
pub(crate) async fn check_response(
    resp: reqwest::Response,
) -> Result<reqwest::Response, ElasticError> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let message = resp.text().await.unwrap_or_default();
    Err(ElasticError::Api {
        status: status.as_u16(),
        message,
    })
}
