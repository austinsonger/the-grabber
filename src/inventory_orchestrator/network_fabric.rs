use anyhow::Result;
use aws_sdk_ec2::Client as Ec2Client;

pub(super) async fn collect_vpc_network(
    _c: &Ec2Client,
    _account_id: &str,
    _region: &str,
) -> Result<Vec<Vec<String>>> {
    Ok(Vec::new())
}
