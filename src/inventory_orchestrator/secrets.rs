use anyhow::Result;
use aws_sdk_secretsmanager::Client as SecretsManagerClient;

pub(super) async fn collect_secretsmanager_secrets(
    _c: &SecretsManagerClient,
    _region: &str,
) -> Result<Vec<Vec<String>>> {
    Ok(Vec::new())
}
