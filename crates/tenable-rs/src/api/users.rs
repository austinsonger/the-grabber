use serde::Deserialize;

use crate::client::TenableClient;
use crate::error::TenableError;

#[derive(Debug, Clone, Deserialize)]
pub struct TenableUser {
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub permissions: u32,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub last_login_attempt: Option<u64>,
    #[serde(default)]
    pub login_fail_count: Option<u32>,
    #[serde(default, rename = "type")]
    pub user_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UsersResponse {
    #[serde(default)]
    users: Vec<TenableUser>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScannerPermission {
    #[serde(default)]
    pub id: Option<u64>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, rename = "type")]
    pub permission_type: Option<String>,
    #[serde(default)]
    pub permissions: Option<u32>,
}

pub struct UsersApi<'c>(pub(crate) &'c TenableClient);

impl<'c> UsersApi<'c> {
    /// GET /users — returns all Tenable users with their permission levels.
    pub async fn list(&self) -> Result<Vec<TenableUser>, TenableError> {
        let resp = self.0.get("/users").await?;
        let body: UsersResponse = resp.json().await?;
        Ok(body.users)
    }

    /// GET /permissions/{object_type}/{object_id} — ACL for a scanner or other object.
    /// `object_type` is typically "scanner".
    pub async fn permissions(
        &self,
        object_type: &str,
        object_id: u64,
    ) -> Result<Vec<ScannerPermission>, TenableError> {
        let path = format!("/permissions/{object_type}/{object_id}");
        let resp = self.0.get(&path).await?;
        let body: Vec<ScannerPermission> = resp.json().await?;
        Ok(body)
    }
}
