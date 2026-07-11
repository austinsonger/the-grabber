<<<<<<< HEAD
//! GCP provider factory — builds the right set of collectors given a project/org
//! and an optional filter list of collector keys.

use anyhow::Result;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::gcp::{
    asset_inventory::AssetInventoryCollector,
    audit_logs_config::AuditLogsConfigCollector,
    client::GcpClient,
    cloud_armor::CloudArmorCollector,
    cloud_audit_logs::CloudAuditLogsCollector,
    cloud_dns::CloudDnsCollector,
    cloud_dlp::CloudDlpCollector,
    cloud_functions::CloudFunctionsCollector,
    cloud_monitoring::CloudMonitoringCollector,
    cloud_run::CloudRunCollector,
    cloud_sql::CloudSqlCollector,
    cloud_sql_backups::CloudSqlBackupsCollector,
    cloud_storage_config::CloudStorageConfigCollector,
    cloud_storage_inventory::CloudStorageInventoryCollector,
    cloud_storage_policies::CloudStoragePoliciesCollector,
    compute_config::ComputeConfigCollector,
    compute_inventory::ComputeInventoryCollector,
    filestore::FilestoreCollector,
    gke::GkeCollector,
    iam_policies::IamPoliciesCollector,
    iam_service_account_keys::IamServiceAccountKeysCollector,
    iam_service_accounts::IamServiceAccountsCollector,
    kms::KmsCollector,
    kms_policies::KmsPoliciesCollector,
    memorystore::MemorystoreCollector,
    org_policy::OrgPolicyCollector,
    organizations::OrganizationsCollector,
    persistent_disk::PersistentDiskCollector,
    pubsub_topics::PubsubTopicsCollector,
    scc_config::SccConfigCollector,
    scc_findings::SccFindingsCollector,
    scc_standards::SccStandardsCollector,
    scc_vulnerabilities::SccVulnerabilitiesCollector,
    secret_manager::SecretManagerCollector,
    secret_manager_extended::SecretManagerExtendedCollector,
    vpc::VpcCollector,
    vpc_flow_logs::VpcFlowLogsCollector,
};

/// Builds all GCP collectors and groups them by output type.
pub struct GcpProviderFactory {
    client:     GcpClient,
    project_id: String,
    location:   String,
    org_id:     String,
    /// If empty, all collectors are enabled.
    selected:   Vec<String>,
}

impl GcpProviderFactory {
    /// Construct the factory, authenticating via ADC.
    pub async fn new(
        project_id: impl Into<String>,
        location: impl Into<String>,
        org_id: Option<String>,
        selected: Vec<String>,
    ) -> Result<Self> {
        let client = GcpClient::from_adc().await?;
        Ok(Self {
            client,
            project_id: project_id.into(),
            location: location.into(),
            org_id: org_id.unwrap_or_default(),
            selected,
        })
    }

    /// The GCP project ID is used wherever an AWS account ID would be.
    pub fn account_id(&self) -> &str {
        &self.project_id
    }

    /// The primary location (region) for this factory.
    pub fn region(&self) -> &str {
        &self.location
    }

    // -----------------------------------------------------------------------
    // Helper: test whether a collector key is in the selected set
    // -----------------------------------------------------------------------
    fn wants(&self, key: &str) -> bool {
        self.selected.is_empty() || self.selected.iter().any(|s| s == key)
    }

    // -----------------------------------------------------------------------
    // Collector builders
    // -----------------------------------------------------------------------

    /// All CSV snapshot collectors.
    pub fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let mut out: Vec<Box<dyn CsvCollector>> = Vec::new();

        macro_rules! push_csv {
            ($key:expr, $col:expr) => {
                if self.wants($key) {
                    out.push(Box::new($col));
                }
            };
        }

        push_csv!("gcp-iam-policies",       IamPoliciesCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-iam-service-accounts", IamServiceAccountsCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-iam-sa-keys",         IamServiceAccountKeysCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-compute-inventory",   ComputeInventoryCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-storage-inventory",   CloudStorageInventoryCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-storage-policies",    CloudStoragePoliciesCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-kms",                 KmsCollector::new(self.client.clone(), &self.project_id, &self.location));
        push_csv!("gcp-kms-policies",        KmsPoliciesCollector::new(self.client.clone(), &self.project_id, &self.location));
        push_csv!("gcp-scc-config",          SccConfigCollector::new(self.client.clone(), &self.org_id));
        push_csv!("gcp-cloud-sql",           CloudSqlCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-cloud-sql-backups",   CloudSqlBackupsCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-gke",                 GkeCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-secrets",             SecretManagerCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-cloud-functions",     CloudFunctionsCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-cloud-run",           CloudRunCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-vpc",                 VpcCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-vpc-flow-logs",       VpcFlowLogsCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-cloud-dns",           CloudDnsCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-pubsub",              PubsubTopicsCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-cloud-armor",         CloudArmorCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-persistent-disks",    PersistentDiskCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-memorystore",         MemorystoreCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-filestore",           FilestoreCollector::new(self.client.clone(), &self.project_id));

        out
    }

    /// All JSON snapshot collectors.
    pub fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        let mut out: Vec<Box<dyn JsonCollector>> = Vec::new();

        macro_rules! push_json {
            ($key:expr, $col:expr) => {
                if self.wants($key) {
                    out.push(Box::new($col));
                }
            };
        }

        push_json!("gcp-compute-config",     ComputeConfigCollector::new(self.client.clone(), &self.project_id));
        push_json!("gcp-storage-config",     CloudStorageConfigCollector::new(self.client.clone(), &self.project_id));
        push_json!("gcp-scc-findings",       SccFindingsCollector::new(self.client.clone(), &self.org_id));
        push_json!("gcp-scc-vulnerabilities", SccVulnerabilitiesCollector::new(self.client.clone(), &self.org_id));
        push_json!("gcp-scc-standards",      SccStandardsCollector::new(self.client.clone(), &self.org_id));
        push_json!("gcp-org-policy",         OrgPolicyCollector::new(self.client.clone(), &self.project_id));
        push_json!("gcp-organizations",      OrganizationsCollector::new(self.client.clone(), &self.org_id));
        push_json!("gcp-asset-inventory",    AssetInventoryCollector::new(self.client.clone(), &self.project_id));
        push_json!("gcp-monitoring",         CloudMonitoringCollector::new(self.client.clone(), &self.project_id));
        push_json!("gcp-cloud-dlp",          CloudDlpCollector::new(self.client.clone(), &self.project_id));
        push_json!("gcp-audit-logs-config",  AuditLogsConfigCollector::new(self.client.clone(), &self.project_id));
        push_json!("gcp-secrets-extended",   SecretManagerExtendedCollector::new(self.client.clone(), &self.project_id));

        out
    }

    /// Time-windowed evidence collectors (audit logs).
    pub fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        let mut out: Vec<Box<dyn EvidenceCollector>> = Vec::new();
        if self.wants("gcp-audit-logs") {
            out.push(Box::new(CloudAuditLogsCollector::new(
                self.client.clone(),
                &self.project_id,
            )));
        }
        out
=======
use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct GcpProviderFactory {
    project_id: String,
    region: String,
    selected: Vec<String>,
    // credential: google_cloud_auth::Token  — added when first collector ships
}

impl GcpProviderFactory {
    pub fn new(project_id: String, region: String, selected: Vec<String>) -> Self {
        Self {
            project_id,
            region,
            selected,
        }
    }
}

impl ProviderFactory for GcpProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }
    fn account_id(&self) -> &str {
        &self.project_id
    }
    fn region(&self) -> &str {
        &self.region
    }

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        vec![]
    }
    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        vec![]
    }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        vec![]
>>>>>>> origin/main
    }
}
