// ---------------------------------------------------------------------------
// Inventory Orchestrator — Unified AWS asset inventory CSV collector
// ---------------------------------------------------------------------------
//
// Implements CsvCollector.  Given a list of selected asset-type keys, it
// queries each service in parallel via tokio::spawn and merges all rows into
// a single CSV that uses the canonical 14-column schema from inventory_core.

mod compute;
mod data_services;
mod storage;

use anyhow::Result;
use async_trait::async_trait;

use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_ecr::Client as EcrClient;
use aws_sdk_ecs::Client as EcsClient;
use aws_sdk_eks::Client as EksClient;
use aws_sdk_elasticache::Client as ElastiCacheClient;
use aws_sdk_elasticloadbalancingv2::Client as ElbClient;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_lambda::Client as LambdaClient;
use aws_sdk_rds::Client as RdsClient;
use aws_sdk_s3::Client as S3Client;

use crate::evidence::CsvCollector;
use crate::inventory_core::{
    ASSET_KEY_ALB, ASSET_KEY_CONTAINER, ASSET_KEY_EC2_INSTANCE, ASSET_KEY_ELASTICACHE_CLUSTER,
    ASSET_KEY_KMS_KEY, ASSET_KEY_LAMBDA_FUNCTION, ASSET_KEY_RDS_DB_INSTANCE, ASSET_KEY_S3_BUCKET,
    INVENTORY_CSV_HEADERS,
};

// ---------------------------------------------------------------------------
// Struct
// ---------------------------------------------------------------------------

pub struct InventoryCollector {
    pub selected_types: Vec<String>,
    kms: KmsClient,
    s3: S3Client,
    lambda: LambdaClient,
    ec2: Ec2Client,
    elb: ElbClient,
    rds: RdsClient,
    elasticache: ElastiCacheClient,
    ecr: EcrClient,
    ecs: EcsClient,
    eks: EksClient,
}

impl InventoryCollector {
    pub fn new(config: &aws_config::SdkConfig, selected_types: Vec<String>) -> Self {
        Self {
            selected_types,
            kms: KmsClient::new(config),
            s3: S3Client::new(config),
            lambda: LambdaClient::new(config),
            ec2: Ec2Client::new(config),
            elb: ElbClient::new(config),
            rds: RdsClient::new(config),
            elasticache: ElastiCacheClient::new(config),
            ecr: EcrClient::new(config),
            ecs: EcsClient::new(config),
            eks: EksClient::new(config),
        }
    }
}

// ---------------------------------------------------------------------------
// CsvCollector impl
// ---------------------------------------------------------------------------

#[async_trait]
impl CsvCollector for InventoryCollector {
    fn name(&self) -> &str {
        "AWS Inventory"
    }
    fn filename_prefix(&self) -> &str {
        "AWS_Inventory"
    }
    fn headers(&self) -> &'static [&'static str] {
        INVENTORY_CSV_HEADERS
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let region = region.to_string();
        let mut all_rows: Vec<Vec<String>> = Vec::new();

        for type_key in &self.selected_types {
            let result = match type_key.as_str() {
                ASSET_KEY_KMS_KEY => storage::collect_kms_keys(&self.kms, &region).await,
                ASSET_KEY_S3_BUCKET => storage::collect_s3_buckets(&self.s3, &region).await,
                ASSET_KEY_LAMBDA_FUNCTION => {
                    compute::collect_lambda_functions(&self.lambda, &region).await
                }
                ASSET_KEY_EC2_INSTANCE => compute::collect_ec2_instances(&self.ec2, &region).await,
                ASSET_KEY_ALB => data_services::collect_albs(&self.elb, &region).await,
                ASSET_KEY_RDS_DB_INSTANCE => {
                    data_services::collect_rds_instances(&self.rds, &region).await
                }
                ASSET_KEY_ELASTICACHE_CLUSTER => {
                    data_services::collect_elasticache_clusters(&self.elasticache, &region).await
                }
                ASSET_KEY_CONTAINER => {
                    compute::collect_containers(&self.ecr, &self.ecs, &self.eks, &region).await
                }
                other => {
                    eprintln!("WARN: inventory: unknown asset type key '{other}' — skipped");
                    continue;
                }
            };
            match result {
                Ok(rows) => {
                    let row_count = rows.len();
                    if row_count == 0 {
                        eprintln!("    [inventory] {type_key} returned 0 rows");
                    }
                    all_rows.extend(rows);
                }
                Err(e) => eprintln!("WARN: inventory collection error ({type_key}): {e:#}"),
            }
        }
        eprintln!(
            "    [inventory] total for all types: {} rows",
            all_rows.len()
        );

        Ok(all_rows)
    }
}
