// ---------------------------------------------------------------------------
// Inventory Orchestrator — Unified AWS asset inventory CSV collector
// ---------------------------------------------------------------------------
//
// Implements CsvCollector.  Given a list of selected asset-type keys, it
// queries each service in parallel via tokio::spawn and merges all rows into
// a single CSV that uses the canonical 14-column schema from inventory_core.

mod apigateway;
mod compute;
mod data_services;
mod messaging;
mod network_fabric;
mod secrets;
mod security_services;
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
use aws_sdk_apigateway::Client as ApiGatewayV1Client;
use aws_sdk_apigatewayv2::Client as ApiGatewayV2Client;
use aws_sdk_cloudtrail::Client as CloudTrailClient;
use aws_sdk_config::Client as ConfigClient;
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_efs::Client as EfsClient;
use aws_sdk_eventbridge::Client as EventBridgeClient;
use aws_sdk_firehose::Client as FirehoseClient;
use aws_sdk_fsx::Client as FsxClient;
use aws_sdk_guardduty::Client as GuardDutyClient;
use aws_sdk_kinesis::Client as KinesisClient;
use aws_sdk_redshift::Client as RedshiftClient;
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use aws_sdk_securityhub::Client as SecurityHubClient;
use aws_sdk_sns::Client as SnsClient;
use aws_sdk_sqs::Client as SqsClient;
use aws_sdk_wafv2::Client as Wafv2Client;

use crate::evidence::CsvCollector;
use crate::inventory_core::{
    ASSET_KEY_ALB, ASSET_KEY_APIGW, ASSET_KEY_CLOUDTRAIL_TRAIL, ASSET_KEY_CONFIG_RECORDER,
    ASSET_KEY_CONTAINER, ASSET_KEY_DYNAMODB_TABLE, ASSET_KEY_EBS_VOLUME, ASSET_KEY_EC2_INSTANCE,
    ASSET_KEY_EFS_FILE_SYSTEM, ASSET_KEY_ELASTICACHE_CLUSTER, ASSET_KEY_EVENTBRIDGE,
    ASSET_KEY_FIREHOSE_STREAM, ASSET_KEY_FSX_FILE_SYSTEM, ASSET_KEY_GUARDDUTY_DETECTOR,
    ASSET_KEY_KINESIS_STREAM, ASSET_KEY_KMS_KEY, ASSET_KEY_LAMBDA_FUNCTION, ASSET_KEY_NLB,
    ASSET_KEY_RDS_DB_INSTANCE, ASSET_KEY_REDSHIFT_CLUSTER, ASSET_KEY_S3_BUCKET,
    ASSET_KEY_SECRETSMANAGER_SECRET, ASSET_KEY_SECURITYHUB_HUB, ASSET_KEY_SNS_TOPIC,
    ASSET_KEY_SQS_QUEUE, ASSET_KEY_VPC_NETWORK, ASSET_KEY_WAF_WEBACL, INVENTORY_CSV_HEADERS,
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
    apigw_v1: ApiGatewayV1Client,
    apigw_v2: ApiGatewayV2Client,
    cloudtrail: CloudTrailClient,
    config_svc: ConfigClient,
    dynamodb: DynamoDbClient,
    efs: EfsClient,
    eventbridge: EventBridgeClient,
    firehose: FirehoseClient,
    fsx: FsxClient,
    guardduty: GuardDutyClient,
    kinesis: KinesisClient,
    redshift: RedshiftClient,
    secretsmanager: SecretsManagerClient,
    securityhub: SecurityHubClient,
    sns: SnsClient,
    sqs: SqsClient,
    wafv2: Wafv2Client,
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
            apigw_v1: ApiGatewayV1Client::new(config),
            apigw_v2: ApiGatewayV2Client::new(config),
            cloudtrail: CloudTrailClient::new(config),
            config_svc: ConfigClient::new(config),
            dynamodb: DynamoDbClient::new(config),
            efs: EfsClient::new(config),
            eventbridge: EventBridgeClient::new(config),
            firehose: FirehoseClient::new(config),
            fsx: FsxClient::new(config),
            guardduty: GuardDutyClient::new(config),
            kinesis: KinesisClient::new(config),
            redshift: RedshiftClient::new(config),
            secretsmanager: SecretsManagerClient::new(config),
            securityhub: SecurityHubClient::new(config),
            sns: SnsClient::new(config),
            sqs: SqsClient::new(config),
            wafv2: Wafv2Client::new(config),
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
        account_id: &str,
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
                ASSET_KEY_NLB => data_services::collect_nlbs(&self.elb, &region).await,
                ASSET_KEY_EBS_VOLUME => storage::collect_ebs_volumes(&self.ec2, &region).await,
                ASSET_KEY_EFS_FILE_SYSTEM => storage::collect_efs_file_systems(&self.efs, &region).await,
                ASSET_KEY_FSX_FILE_SYSTEM => storage::collect_fsx_file_systems(&self.fsx, &region).await,
                ASSET_KEY_REDSHIFT_CLUSTER => data_services::collect_redshift_clusters(&self.redshift, &region).await,
                ASSET_KEY_DYNAMODB_TABLE => data_services::collect_dynamodb_tables(&self.dynamodb, &region).await,
                ASSET_KEY_APIGW => apigateway::collect_apigw(&self.apigw_v1, &self.apigw_v2, &region).await,
                ASSET_KEY_SNS_TOPIC => messaging::collect_sns_topics(&self.sns, &region).await,
                ASSET_KEY_SQS_QUEUE => messaging::collect_sqs_queues(&self.sqs, &region).await,
                ASSET_KEY_KINESIS_STREAM => messaging::collect_kinesis_streams(&self.kinesis, &region).await,
                ASSET_KEY_FIREHOSE_STREAM => messaging::collect_firehose_streams(&self.firehose, &region).await,
                ASSET_KEY_EVENTBRIDGE => messaging::collect_eventbridge(&self.eventbridge, &region).await,
                ASSET_KEY_SECRETSMANAGER_SECRET => secrets::collect_secretsmanager_secrets(&self.secretsmanager, &region).await,
                ASSET_KEY_VPC_NETWORK => network_fabric::collect_vpc_network(&self.ec2, account_id, &region).await,
                ASSET_KEY_CLOUDTRAIL_TRAIL => security_services::collect_cloudtrail_trails(&self.cloudtrail, &region).await,
                ASSET_KEY_CONFIG_RECORDER => security_services::collect_config_recorders(&self.config_svc, account_id, &region).await,
                ASSET_KEY_GUARDDUTY_DETECTOR => security_services::collect_guardduty_detectors(&self.guardduty, account_id, &region).await,
                ASSET_KEY_SECURITYHUB_HUB => security_services::collect_securityhub_hubs(&self.securityhub, &region).await,
                ASSET_KEY_WAF_WEBACL => security_services::collect_waf_webacls(&self.wafv2, &region).await,
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
