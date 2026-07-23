use okta_rs::OktaClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct OktaProviderFactory {
    client: OktaClient,
    tenant_name: String,
    selected: Vec<String>,
}

impl OktaProviderFactory {
    pub fn new(client: OktaClient, tenant_name: String, selected: Vec<String>) -> Self {
        Self {
            client,
            tenant_name,
            selected,
        }
    }
}

impl ProviderFactory for OktaProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Okta
    }
    fn account_id(&self) -> &str {
        &self.tenant_name
    }
    fn region(&self) -> &str {
        ""
    }

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();
        if self.selected.iter().any(|s| s == "okta-users") {
            v.push(Box::new(super::users::OktaUsersCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "okta-groups") {
            v.push(Box::new(super::groups::OktaGroupsCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "okta-group-members") {
            v.push(Box::new(super::groups::OktaGroupMembersCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "okta-apps") {
            v.push(Box::new(super::apps::OktaAppsCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "okta-policies") {
            v.push(Box::new(super::policies::OktaPoliciesCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "okta-factors") {
            v.push(Box::new(super::factors::OktaFactorsCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "okta-system-log") {
            v.push(Box::new(super::system_log::OktaSystemLogCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "okta-access-reviews") {
            v.push(Box::new(
                super::access_certification_campaigns::OktaAccessCertificationCampaignsCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.selected.iter().any(|s| s == "okta-auto-provisioning") {
            v.push(Box::new(
                super::automated_provisioning_events::OktaAutomatedProvisioningEventsCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.selected.iter().any(|s| s == "okta-deprovisioning") {
            v.push(Box::new(
                super::deprovisioning_timeliness::OktaDeprovisioningTimelinessCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.selected.iter().any(|s| s == "okta-hris-config") {
            v.push(Box::new(
                super::lifecycle_hris_config::OktaLifecycleHrisConfigCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.selected.iter().any(|s| s == "okta-risk-suspend") {
            v.push(Box::new(
                super::risk_account_suspend_timing::OktaRiskAccountSuspendTimingCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.selected.iter().any(|s| s == "okta-shared-groups") {
            v.push(Box::new(
                super::group_inventory_shared::OktaGroupInventorySharedCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.selected.iter().any(|s| s == "okta-threat-insight") {
            v.push(Box::new(
                super::threat_insight_detections::OktaThreatInsightDetectionsCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.selected.iter().any(|s| s == "okta-signin-widget") {
            v.push(Box::new(
                super::signin_widget_config::OktaSignInWidgetConfigCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.selected.iter().any(|s| s == "okta-session-policy") {
            v.push(Box::new(
                super::session_policy::OktaSessionPolicyCollector::new(self.client.clone()),
            ));
        }
        if self.selected.iter().any(|s| s == "okta-publisher-groups") {
            v.push(Box::new(
                super::publisher_group_membership::OktaPublisherGroupMembershipCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.selected.iter().any(|s| s == "okta-prod-recert") {
            v.push(Box::new(
                super::prod_access_recertification::OktaProdAccessRecertificationCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self
            .selected
            .iter()
            .any(|s| s == "okta-shared-account-broker")
        {
            v.push(Box::new(
                super::shared_account_broker_config::OktaSharedAccountBrokerConfigCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.selected.iter().any(|s| s == "okta-password-policy") {
            v.push(Box::new(
                super::password_policy_first_use::OktaPasswordPolicyFirstUseCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.selected.iter().any(|s| s == "okta-group-changes") {
            v.push(Box::new(
                super::group_membership_change_log::OktaGroupMembershipChangeLogCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.selected.iter().any(|s| s == "okta-offboarding-sla") {
            v.push(Box::new(
                super::offboarding_sla::OktaOffboardingSlaCollector::new(self.client.clone()),
            ));
        }
        if self.selected.iter().any(|s| s == "okta-transfer-diff") {
            v.push(Box::new(
                super::transfer_access_diff::OktaTransferAccessDiffCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.selected.iter().any(|s| s == "okta-contractor-deprov") {
            v.push(Box::new(
                super::contractor_deprovisioning::OktaContractorDeprovisioningCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.selected.iter().any(|s| s == "okta-stig-compliance") {
            v.push(Box::new(
                super::stig_compliance::OktaStigComplianceCollector::new(self.client.clone()),
            ));
        }
        v
    }
    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        Vec::new()
    }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        Vec::new()
    }
}
