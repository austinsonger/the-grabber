use jumpcloud_rs::JumpCloudClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct JumpCloudProviderFactory {
    client: JumpCloudClient,
    tenant_name: String,
    org_id: String,
    selected: Vec<String>,
}

impl JumpCloudProviderFactory {
    pub fn new(
        client: JumpCloudClient,
        tenant_name: String,
        org_id: String,
        selected: Vec<String>,
    ) -> Self {
        Self {
            client,
            tenant_name,
            org_id,
            selected,
        }
    }

    fn has(&self, key: &str) -> bool {
        self.selected.iter().any(|s| s == key)
    }
}

impl ProviderFactory for JumpCloudProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::JumpCloud
    }
    fn account_id(&self) -> &str {
        &self.tenant_name
    }
    fn region(&self) -> &str {
        ""
    }

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();
        if self.has("jumpcloud-users") {
            v.push(Box::new(super::users::JumpCloudUsersCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("jumpcloud-user-groups") {
            v.push(Box::new(
                super::user_groups::JumpCloudUserGroupsCollector::new(self.client.clone()),
            ));
        }
        if self.has("jumpcloud-applications") {
            v.push(Box::new(
                super::applications::JumpCloudApplicationsCollector::new(self.client.clone()),
            ));
        }
        if self.has("jumpcloud-mfa-factors") {
            v.push(Box::new(
                super::mfa_factors::JumpCloudMfaFactorsCollector::new(self.client.clone()),
            ));
        }
        if self.has("jumpcloud-admin-roles") {
            v.push(Box::new(
                super::admin_roles::JumpCloudAdminRolesCollector::new(
                    self.client.clone(),
                    self.org_id.clone(),
                ),
            ));
        }
        if self.has("jumpcloud-systems") {
            v.push(Box::new(super::systems::JumpCloudSystemsCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("jumpcloud-disabled-users") {
            v.push(Box::new(
                super::disabled_users::JumpCloudDisabledUsersCollector::new(self.client.clone()),
            ));
        }
        if self.has("jumpcloud-system-groups") {
            v.push(Box::new(
                super::system_groups::JumpCloudSystemGroupsCollector::new(self.client.clone()),
            ));
        }
        v
    }

    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        let mut v: Vec<Box<dyn JsonCollector>> = Vec::new();
        if self.has("jumpcloud-user-group-members") {
            v.push(Box::new(
                super::user_groups::JumpCloudUserGroupMembersCollector::new(self.client.clone()),
            ));
        }
        if self.has("jumpcloud-policies") {
            v.push(Box::new(super::policies::JumpCloudPoliciesCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("jumpcloud-password-policy") {
            v.push(Box::new(
                super::password_policy::JumpCloudPasswordPolicyCollector::new(
                    self.client.clone(),
                    self.org_id.clone(),
                ),
            ));
        }
        if self.has("jumpcloud-session-policy") {
            v.push(Box::new(
                super::session_policy::JumpCloudSessionPolicyCollector::new(
                    self.client.clone(),
                    self.org_id.clone(),
                ),
            ));
        }
        if self.has("jumpcloud-system-group-members") {
            v.push(Box::new(
                super::system_groups::JumpCloudSystemGroupMembersCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.has("jumpcloud-system-user-associations") {
            v.push(Box::new(
                super::system_user_associations::JumpCloudSystemUserAssociationsCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        v
    }

    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        let mut v: Vec<Box<dyn EvidenceCollector>> = Vec::new();
        if self.has("jumpcloud-directory-insights") {
            v.push(Box::new(
                super::directory_insights::JumpCloudDirectoryInsightsCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.has("jumpcloud-directory-alerts") {
            v.push(Box::new(
                super::directory_alerts::JumpCloudDirectoryAlertsCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        v
    }
}
