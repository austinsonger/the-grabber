use anyhow::Result;
use aws_sdk_apigateway::Client as ApiGatewayV1Client;
use aws_sdk_apigatewayv2::Client as ApiGatewayV2Client;

pub(super) async fn collect_apigw(
    _v1: &ApiGatewayV1Client,
    _v2: &ApiGatewayV2Client,
    _region: &str,
) -> Result<Vec<Vec<String>>> {
    Ok(Vec::new())
}
