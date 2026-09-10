use crate::dto::CollectorMetaDto;
use crate::error::GuiError;

#[tauri::command]
pub async fn list_collectors(_provider: String) -> Result<Vec<CollectorMetaDto>, GuiError> {
    // Hard-coded AWS collector catalog for the initial desktop UI.
    // A future iteration can introspect the provider factories at runtime.
    Ok(vec![
        CollectorMetaDto {
            key: "cloudtrail".into(),
            name: "CloudTrail".into(),
            category: "Logging & Monitoring".into(),
        },
        CollectorMetaDto {
            key: "config_rules".into(),
            name: "Config Rules".into(),
            category: "Compliance".into(),
        },
        CollectorMetaDto {
            key: "iam_inventory".into(),
            name: "IAM Inventory".into(),
            category: "Identity".into(),
        },
        CollectorMetaDto {
            key: "s3_config".into(),
            name: "S3 Configuration".into(),
            category: "Storage".into(),
        },
        CollectorMetaDto {
            key: "ec2_inventory".into(),
            name: "EC2 Inventory".into(),
            category: "Compute".into(),
        },
        CollectorMetaDto {
            key: "rds".into(),
            name: "RDS".into(),
            category: "Databases".into(),
        },
        CollectorMetaDto {
            key: "securityhub".into(),
            name: "Security Hub".into(),
            category: "Security Services".into(),
        },
        CollectorMetaDto {
            key: "guardduty".into(),
            name: "GuardDuty".into(),
            category: "Security Services".into(),
        },
    ])
}
