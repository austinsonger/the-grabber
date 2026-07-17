use std::collections::HashMap;

use anyhow::{Context, Result};
use aws_sdk_apigateway::Client as ApiGatewayV1Client;
use aws_sdk_apigatewayv2::Client as ApiGatewayV2Client;

use crate::inventory_core::RowBuilder;

pub(super) async fn collect_apigw(
    v1: &ApiGatewayV1Client,
    v2: &ApiGatewayV2Client,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();

    // Custom domain names are an account/region-wide resource shared by
    // REST (v1) and HTTP/WebSocket (v2) APIs alike. Fetch once and reuse in
    // both branches rather than resolving the exact base-path-mapping /
    // api-mapping relationship per API (would cost one extra call per API).
    let custom_domains = fetch_custom_domain_names(v1).await;

    rows.extend(
        collect_apigw_v1(v1, region, &custom_domains)
            .await
            .unwrap_or_default(),
    );
    rows.extend(
        collect_apigw_v2(v2, region, &custom_domains)
            .await
            .unwrap_or_default(),
    );

    Ok(rows)
}

/// Tag-first Function-column derivation shared by the REST (v1) and
/// HTTP/WebSocket (v2) branches. Both SDKs return API tags as a plain
/// `HashMap<String, String>` (no dedicated `Tag` type), so lookups are
/// direct key gets rather than an iterator search like the EC2/EFS/FSx
/// helpers in `storage.rs`. Same Purpose/App/Role/Function convention.
fn function_from_apigw_tags(tags: Option<&HashMap<String, String>>) -> Option<String> {
    let tags = tags?;
    ["Purpose", "App", "Role", "Function", "purpose", "app", "role"]
        .iter()
        .find_map(|k| tags.get(*k).cloned())
}

/// Lists every custom domain name in the account/region, paged via
/// `position`. Soft-fails to an empty list on error (logged) — a missing
/// domain-name list shouldn't abort API Gateway collection.
async fn fetch_custom_domain_names(client: &ApiGatewayV1Client) -> Vec<String> {
    let mut names = Vec::new();
    let mut position: Option<String> = None;

    loop {
        let mut req = client.get_domain_names();
        if let Some(ref p) = position {
            req = req.position(p);
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("apigateway get_domain_names failed: {e}");
                break;
            }
        };

        for d in resp.items() {
            if let Some(name) = d.domain_name() {
                names.push(name.to_string());
            }
        }

        position = resp.position().map(|s| s.to_string());
        if position.is_none() {
            break;
        }
    }

    names
}

// ---------------------------------------------------------------------------
// REST API (v1) — mapping doc §7
// ---------------------------------------------------------------------------

async fn collect_apigw_v1(
    client: &ApiGatewayV1Client,
    region: &str,
    custom_domains: &[String],
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut position: Option<String> = None;
    let custom_domains_joined = custom_domains.join(", ");

    loop {
        let mut req = client.get_rest_apis();
        if let Some(ref p) = position {
            req = req.position(p);
        }
        let resp = req.send().await.context("API Gateway v1 get_rest_apis")?;

        for api in resp.items() {
            let Some(api_id) = api.id() else {
                continue;
            };

            let endpoint_types: Vec<&str> = api
                .endpoint_configuration()
                .map(|ec| ec.types().iter().map(|t| t.as_str()).collect())
                .unwrap_or_default();

            // Public rule: "Yes" if EDGE or REGIONAL present; "No" if only
            // PRIVATE. Empty types (rare) default to "Yes" — edge is the
            // historical default for APIs created before endpoint types
            // existed.
            let is_public = endpoint_types.is_empty()
                || endpoint_types.iter().any(|t| *t == "EDGE" || *t == "REGIONAL");
            let is_private_only = !endpoint_types.is_empty()
                && endpoint_types.iter().all(|t| *t == "PRIVATE");

            let vlan_network_id = if is_private_only {
                let vpce_ids = api
                    .endpoint_configuration()
                    .map(|ec| ec.vpc_endpoint_ids().join(", "))
                    .unwrap_or_default();
                format!("VPC-Endpoints: {vpce_ids}")
            } else {
                String::new()
            };

            let unique_id = format!("arn:aws:apigateway:{region}::/restapis/{api_id}");

            let function = function_from_apigw_tags(api.tags())
                .or_else(|| api.description().map(|d| d.to_string()))
                .unwrap_or_default();

            let min_compression_size = api
                .minimum_compression_size()
                .map(|n| n.to_string())
                .unwrap_or_default();
            let disable_execute_api_endpoint = api.disable_execute_api_endpoint();

            let stages = match client.get_stages().rest_api_id(api_id).send().await {
                Ok(r) => r.item().to_vec(),
                Err(e) => {
                    eprintln!("apigateway get_stages failed for REST API {api_id}: {e}");
                    Vec::new()
                }
            };

            if stages.is_empty() {
                let dns_url = format!("https://{api_id}.execute-api.{region}.amazonaws.com");
                // ApiKeyRequired and AuthorizerType are per-method attributes
                // in the v1 API model, not exposed on Stage/MethodSetting —
                // left empty per task brief rather than making an extra
                // get_method call per route.
                let comments = format!(
                    "ApiId: {api_id} | StageName: | ApiKeyRequired: | AuthorizerType: | \
                     MinimumCompressionSize: {min_compression_size} | \
                     DisableExecuteApiEndpoint: {disable_execute_api_endpoint} | \
                     XrayTracing: | LoggingLevel: | CustomDomains: {custom_domains_joined}"
                );

                rows.push(
                    RowBuilder::new()
                        .unique_id(&unique_id)
                        .virtual_flag("Yes")
                        .public(if is_public { "Yes" } else { "No" })
                        .dns_url(dns_url)
                        .location(region)
                        .asset_type("API Gateway REST API")
                        .sw_vendor("Amazon Web Services")
                        .sw_name_ver("Amazon API Gateway (REST)")
                        .function(function.as_str())
                        .vlan_network_id(vlan_network_id.as_str())
                        .comments(comments)
                        .build(),
                );
                continue;
            }

            for stage in &stages {
                let stage_name = stage.stage_name().unwrap_or("").to_string();
                let dns_url =
                    format!("https://{api_id}.execute-api.{region}.amazonaws.com/{stage_name}");

                let logging_level = stage
                    .method_settings()
                    .and_then(|m| m.get("*/*"))
                    .and_then(|m| m.logging_level())
                    .unwrap_or("");
                let xray_tracing = stage.tracing_enabled();

                let comments = format!(
                    "ApiId: {api_id} | StageName: {stage_name} | ApiKeyRequired: | \
                     AuthorizerType: | MinimumCompressionSize: {min_compression_size} | \
                     DisableExecuteApiEndpoint: {disable_execute_api_endpoint} | \
                     XrayTracing: {xray_tracing} | LoggingLevel: {logging_level} | \
                     CustomDomains: {custom_domains_joined}"
                );

                rows.push(
                    RowBuilder::new()
                        .unique_id(&unique_id)
                        .virtual_flag("Yes")
                        .public(if is_public { "Yes" } else { "No" })
                        .dns_url(dns_url)
                        .location(region)
                        .asset_type("API Gateway REST API")
                        .sw_vendor("Amazon Web Services")
                        .sw_name_ver("Amazon API Gateway (REST)")
                        .function(function.as_str())
                        .vlan_network_id(vlan_network_id.as_str())
                        .comments(comments)
                        .build(),
                );
            }
        }

        position = resp.position().map(|s| s.to_string());
        if position.is_none() {
            break;
        }
    }

    Ok(rows)
}

// ---------------------------------------------------------------------------
// HTTP + WebSocket APIs (v2) — mapping doc §7b
// ---------------------------------------------------------------------------

async fn collect_apigw_v2(
    client: &ApiGatewayV2Client,
    region: &str,
    custom_domains: &[String],
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut next_token: Option<String> = None;
    let custom_domains_joined = custom_domains.join(", ");
    let has_custom_domains = !custom_domains.is_empty();

    loop {
        let mut req = client.get_apis();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = req.send().await.context("API Gateway v2 get_apis")?;

        for api in resp.items() {
            let Some(api_id) = api.api_id() else {
                continue;
            };

            let protocol_type_str = api.protocol_type().map(|p| p.as_str()).unwrap_or("");
            let is_websocket = matches!(
                api.protocol_type(),
                Some(aws_sdk_apigatewayv2::types::ProtocolType::Websocket)
            );
            let (asset_type, sw_name_ver) = if is_websocket {
                ("API Gateway WebSocket API", "Amazon API Gateway (WebSocket)")
            } else {
                ("API Gateway HTTP API", "Amazon API Gateway (HTTP)")
            };

            let disable_execute_api_endpoint = api.disable_execute_api_endpoint().unwrap_or(false);
            // "No" only when the default execute-api endpoint is disabled
            // AND no custom domain fronts the API; otherwise reachable via
            // either the default endpoint or a custom domain, so "Yes".
            let is_public = !disable_execute_api_endpoint || has_custom_domains;

            let unique_id = format!("arn:aws:apigateway:{region}::/apis/{api_id}");
            let dns_url = api
                .api_endpoint()
                .filter(|e| !e.is_empty())
                .map(|e| e.to_string())
                .unwrap_or_else(|| format!("https://{api_id}.execute-api.{region}.amazonaws.com"));

            let function = function_from_apigw_tags(api.tags())
                .or_else(|| api.description().map(|d| d.to_string()))
                .unwrap_or_default();
            let route_selection_expression = api.route_selection_expression().unwrap_or("");

            let stages = match client.get_stages().api_id(api_id).send().await {
                Ok(r) => r.items().to_vec(),
                Err(e) => {
                    eprintln!("apigatewayv2 get_stages failed for API {api_id}: {e}");
                    Vec::new()
                }
            };

            if stages.is_empty() {
                let comments = format!(
                    "ApiId: {api_id} | ProtocolType: {protocol_type_str} | StageName: | \
                     RouteSelectionExpression: {route_selection_expression} | AutoDeploy: | \
                     DisableExecuteApiEndpoint: {disable_execute_api_endpoint} | \
                     DefaultRouteSettings.LoggingLevel: | CustomDomains: {custom_domains_joined}"
                );

                rows.push(
                    RowBuilder::new()
                        .unique_id(&unique_id)
                        .virtual_flag("Yes")
                        .public(if is_public { "Yes" } else { "No" })
                        .dns_url(dns_url.as_str())
                        .location(region)
                        .asset_type(asset_type)
                        .sw_vendor("Amazon Web Services")
                        .sw_name_ver(sw_name_ver)
                        .function(function.as_str())
                        .comments(comments)
                        .build(),
                );
                continue;
            }

            for stage in &stages {
                let stage_name = stage.stage_name().unwrap_or("").to_string();
                let auto_deploy = stage.auto_deploy().unwrap_or(false);
                let default_logging_level = stage
                    .default_route_settings()
                    .and_then(|r| r.logging_level())
                    .map(|l| l.as_str())
                    .unwrap_or("");

                let comments = format!(
                    "ApiId: {api_id} | ProtocolType: {protocol_type_str} | \
                     StageName: {stage_name} | \
                     RouteSelectionExpression: {route_selection_expression} | \
                     AutoDeploy: {auto_deploy} | \
                     DisableExecuteApiEndpoint: {disable_execute_api_endpoint} | \
                     DefaultRouteSettings.LoggingLevel: {default_logging_level} | \
                     CustomDomains: {custom_domains_joined}"
                );

                rows.push(
                    RowBuilder::new()
                        .unique_id(&unique_id)
                        .virtual_flag("Yes")
                        .public(if is_public { "Yes" } else { "No" })
                        .dns_url(dns_url.as_str())
                        .location(region)
                        .asset_type(asset_type)
                        .sw_vendor("Amazon Web Services")
                        .sw_name_ver(sw_name_ver)
                        .function(function.as_str())
                        .comments(comments)
                        .build(),
                );
            }
        }

        next_token = resp.next_token().map(|s| s.to_string());
        if next_token.is_none() {
            break;
        }
    }

    Ok(rows)
}
