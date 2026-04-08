// ---------------------------------------------------------------------------
// Inventory Core — Shared types and canonical CSV schema
// ---------------------------------------------------------------------------

/// Canonical 14-column CSV header row — exact capitalization and wording required.
pub const INVENTORY_CSV_HEADERS: &[&str] = &[
    "UNIQUE ASSET IDENTIFIER",
    "IPv4 or IPv6 Address",
    "Virtual",
    "Public",
    "DNS Name or URL",
    "MAC Address",
    "Location",
    "Asset Type",
    "Hardware Make/Model",
    "Software/ Database Vendor",
    "Software/ Database Name & Version",
    "Function",
    "VLAN/ Network ID",
    "Comments",
];

// Asset type keys — match the TUI inventory_items keys exactly.
pub const ASSET_KEY_KMS_KEY:             &str = "kms-key";
pub const ASSET_KEY_S3_BUCKET:           &str = "s3-bucket";
pub const ASSET_KEY_LAMBDA_FUNCTION:     &str = "lambda-function";
pub const ASSET_KEY_EC2_INSTANCE:        &str = "ec2-instance";
pub const ASSET_KEY_ALB:                 &str = "alb";
pub const ASSET_KEY_RDS_DB_INSTANCE:     &str = "rds-db-instance";
pub const ASSET_KEY_ELASTICACHE_CLUSTER: &str = "elasticache-cluster";
pub const ASSET_KEY_CONTAINER:           &str = "container";

/// Build a 14-element all-empty row.
pub fn empty_row() -> Vec<String> {
    vec![String::new(); INVENTORY_CSV_HEADERS.len()]
}

/// Convenience: build a full row by index position.
pub struct RowBuilder {
    inner: Vec<String>,
}

impl RowBuilder {
    pub fn new() -> Self {
        Self { inner: empty_row() }
    }

    pub fn unique_id(mut self, v: impl Into<String>) -> Self      { self.inner[0] = v.into(); self }
    pub fn ipv4_ipv6(mut self, v: impl Into<String>) -> Self      { self.inner[1] = v.into(); self }
    pub fn virtual_flag(mut self, v: impl Into<String>) -> Self   { self.inner[2] = v.into(); self }
    pub fn public(mut self, v: impl Into<String>) -> Self         { self.inner[3] = v.into(); self }
    pub fn dns_url(mut self, v: impl Into<String>) -> Self        { self.inner[4] = v.into(); self }
    pub fn mac_address(mut self, v: impl Into<String>) -> Self    { self.inner[5] = v.into(); self }
    pub fn location(mut self, v: impl Into<String>) -> Self       { self.inner[6] = v.into(); self }
    pub fn asset_type(mut self, v: impl Into<String>) -> Self     { self.inner[7] = v.into(); self }
    pub fn hw_make_model(mut self, v: impl Into<String>) -> Self  { self.inner[8] = v.into(); self }
    pub fn sw_vendor(mut self, v: impl Into<String>) -> Self      { self.inner[9] = v.into(); self }
    pub fn sw_name_ver(mut self, v: impl Into<String>) -> Self    { self.inner[10] = v.into(); self }
    pub fn function(mut self, v: impl Into<String>) -> Self       { self.inner[11] = v.into(); self }
    pub fn vlan_network_id(mut self, v: impl Into<String>) -> Self { self.inner[12] = v.into(); self }
    pub fn comments(mut self, v: impl Into<String>) -> Self       { self.inner[13] = v.into(); self }

    pub fn build(self) -> Vec<String> {
        self.inner
    }
}

impl Default for RowBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract a tag value by key (case-insensitive key match).
pub fn tag_value<'a>(tags: &'a [(&str, &str)], key: &str) -> Option<&'a str> {
    tags.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| *v)
}

/// Normalize an S3 bucket region — empty constraint means us-east-1.
pub fn normalize_s3_region(constraint: Option<&str>) -> &str {
    match constraint {
        None | Some("") => "us-east-1",
        Some(r) => r,
    }
}
