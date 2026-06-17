use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_appmesh::Client as AppMeshClient;

use crate::evidence::CsvCollector;

pub struct AppMeshTlsCollector {
    client: AppMeshClient,
}

impl AppMeshTlsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: AppMeshClient::new(config),
        }
    }
}

fn unsupported(msg: &str) -> bool {
    msg.contains("ResourceNotFoundException")
        || msg.contains("UnrecognizedClientException")
        || msg.contains("InvalidAction")
        || msg.contains("not supported")
        || msg.contains("AccessDenied")
        || msg.contains("OperationNotPermitted")
}

#[async_trait]
impl CsvCollector for AppMeshTlsCollector {
    fn name(&self) -> &str {
        "AppMesh TLS Configuration"
    }
    fn filename_prefix(&self) -> &str {
        "AppMesh_TLS_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Mesh Name",
            "Resource Type",
            "Resource Name",
            "Listener Port",
            "TLS Mode",
            "Certificate Type",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // List meshes.
        let mut meshes: Vec<String> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_meshes();
            if let Some(t) = next_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e}");
                    if unsupported(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: AppMesh list_meshes: {e:#}");
                    return Ok(rows);
                }
            };
            for m in resp.meshes() {
                meshes.push(m.mesh_name().to_string());
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        for mesh_name in &meshes {
            // Virtual nodes.
            let mut vn_token: Option<String> = None;
            loop {
                let mut req = self.client.list_virtual_nodes().mesh_name(mesh_name);
                if let Some(t) = vn_token.as_ref() {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("{e}");
                        if unsupported(&msg) {
                            break;
                        }
                        eprintln!("  WARN: AppMesh list_virtual_nodes({mesh_name}): {e:#}");
                        break;
                    }
                };
                for vn in resp.virtual_nodes() {
                    let vn_name = vn.virtual_node_name().to_string();
                    let desc = match self
                        .client
                        .describe_virtual_node()
                        .mesh_name(mesh_name)
                        .virtual_node_name(&vn_name)
                        .send()
                        .await
                    {
                        Ok(d) => d,
                        Err(e) => {
                            let msg = format!("{e}");
                            if !unsupported(&msg) {
                                eprintln!(
                                    "  WARN: AppMesh describe_virtual_node({vn_name}): {e:#}"
                                );
                            }
                            continue;
                        }
                    };
                    let Some(node) = desc.virtual_node() else {
                        continue;
                    };
                    let Some(spec) = node.spec() else { continue };
                    for listener in spec.listeners() {
                        let port = listener
                            .port_mapping()
                            .map(|p| p.port().to_string())
                            .unwrap_or_default();
                        let (mode, cert_type) = match listener.tls() {
                            Some(tls) => {
                                let mode = tls.mode().as_str().to_string();
                                let ct = match tls.certificate() {
                                    Some(c) if c.is_acm() => "acm",
                                    Some(c) if c.is_file() => "file",
                                    Some(c) if c.is_sds() => "sds",
                                    Some(_) => "unknown",
                                    None => "",
                                }
                                .to_string();
                                (mode, ct)
                            }
                            None => ("DISABLED".to_string(), String::new()),
                        };
                        rows.push(vec![
                            mesh_name.clone(),
                            "VirtualNode".to_string(),
                            vn_name.clone(),
                            port,
                            mode,
                            cert_type,
                        ]);
                    }
                }
                vn_token = resp.next_token().map(|s| s.to_string());
                if vn_token.is_none() {
                    break;
                }
            }

            // Virtual gateways.
            let mut vg_token: Option<String> = None;
            loop {
                let mut req = self.client.list_virtual_gateways().mesh_name(mesh_name);
                if let Some(t) = vg_token.as_ref() {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("{e}");
                        if unsupported(&msg) {
                            break;
                        }
                        eprintln!("  WARN: AppMesh list_virtual_gateways({mesh_name}): {e:#}");
                        break;
                    }
                };
                for vg in resp.virtual_gateways() {
                    let vg_name = vg.virtual_gateway_name().to_string();
                    let desc = match self
                        .client
                        .describe_virtual_gateway()
                        .mesh_name(mesh_name)
                        .virtual_gateway_name(&vg_name)
                        .send()
                        .await
                    {
                        Ok(d) => d,
                        Err(e) => {
                            let msg = format!("{e}");
                            if !unsupported(&msg) {
                                eprintln!(
                                    "  WARN: AppMesh describe_virtual_gateway({vg_name}): {e:#}"
                                );
                            }
                            continue;
                        }
                    };
                    let Some(gw) = desc.virtual_gateway() else {
                        continue;
                    };
                    let Some(spec) = gw.spec() else { continue };
                    for listener in spec.listeners() {
                        let port = listener
                            .port_mapping()
                            .map(|p| p.port().to_string())
                            .unwrap_or_default();
                        let (mode, cert_type) = match listener.tls() {
                            Some(tls) => {
                                let mode = tls.mode().as_str().to_string();
                                let ct = match tls.certificate() {
                                    Some(c) if c.is_acm() => "acm",
                                    Some(c) if c.is_file() => "file",
                                    Some(c) if c.is_sds() => "sds",
                                    Some(_) => "unknown",
                                    None => "",
                                }
                                .to_string();
                                (mode, ct)
                            }
                            None => ("DISABLED".to_string(), String::new()),
                        };
                        rows.push(vec![
                            mesh_name.clone(),
                            "VirtualGateway".to_string(),
                            vg_name.clone(),
                            port,
                            mode,
                            cert_type,
                        ]);
                    }
                }
                vg_token = resp.next_token().map(|s| s.to_string());
                if vg_token.is_none() {
                    break;
                }
            }
        }

        Ok(rows)
    }
}
