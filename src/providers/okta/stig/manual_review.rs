//! The 3 STIG checks that are not reliably automatable via API and are
//! always reported `NotReviewed`, with best-effort evidence attached so a
//! human reviewer has a head start rather than nothing:
//!
//! V-273187 (Admin Console app-level session idle timeout — distinct field
//! from V-273186's global session policy, exact API location unconfirmed),
//! V-273192 (DOD warning banner — inherently a browser-rendering check per
//! the STIG's own check text), V-273207 (DOD-approved CA for the Smart
//! Card IdP — matching a certificate issuer against "DOD-approved" is a
//! policy judgment call, not a value comparison).

use okta_rs::OktaClient;

use crate::stig_status::StigCheckResult;

pub async fn evaluate(client: &OktaClient) -> Vec<StigCheckResult> {
    vec![
        admin_console_session_idle(),
        dod_warning_banner(client).await,
        dod_approved_ca(client).await,
    ]
}

fn admin_console_session_idle() -> StigCheckResult {
    StigCheckResult::not_reviewed(
        "V-273187",
        "The Okta Admin Console app's own \"Maximum app session idle time\" setting (Applications >> Okta Admin Console >> Sign On tab) is not currently reachable through a confirmed API field — verify manually in the Admin Console. Note this is distinct from the global session policy evaluated for V-273186.",
    )
}

async fn dod_warning_banner(client: &OktaClient) -> StigCheckResult {
    let brands = match client.sign_in_widget().brands().await {
        Ok(v) => v,
        Err(e) if super::is_feature_unavailable(&e) => {
            return StigCheckResult::not_reviewed(
                "V-273192",
                format!("Could not fetch brands to inspect the sign-in page: {e}"),
            );
        }
        Err(e) => {
            return StigCheckResult::not_reviewed("V-273192", format!("Error fetching brands: {e}"))
        }
    };

    let Some(brand_id) = brands
        .as_array()
        .and_then(|a| a.first())
        .and_then(|b| b.get("id"))
        .and_then(|v| v.as_str())
    else {
        return StigCheckResult::not_reviewed("V-273192", "No brand found — cannot inspect sign-in page for a DOD warning banner. Verify by logging in to the tenant.");
    };

    let page = client
        .sign_in_widget()
        .customized_page(brand_id)
        .await
        .unwrap_or(serde_json::Value::Null);
    let has_custom_content = page
        .get("signInHtml")
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false)
        || page
            .get("content")
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);

    StigCheckResult::not_reviewed(
        "V-273192",
        if has_custom_content {
            format!("Brand {brand_id} has custom sign-in page content — inspect it for the DOD-mandated consent banner text and verify by logging in to the tenant.")
        } else {
            format!("Brand {brand_id} has no custom sign-in page content configured — a DOD warning banner is unlikely to be present. Verify by logging in to the tenant.")
        },
    )
}

async fn dod_approved_ca(client: &OktaClient) -> StigCheckResult {
    let idps = match client.lifecycle().idps().await {
        Ok(v) => v,
        Err(e) if super::is_feature_unavailable(&e) => {
            return StigCheckResult::not_reviewed(
                "V-273207",
                format!("Identity Providers endpoint unavailable on this tenant: {e}"),
            );
        }
        Err(e) => {
            return StigCheckResult::not_reviewed(
                "V-273207",
                format!("Error fetching Identity Providers: {e}"),
            )
        }
    };

    let smart_card_idps: Vec<String> = idps
        .as_array()
        .into_iter()
        .flatten()
        .filter(|idp| {
            idp.get("type")
                .and_then(|v| v.as_str())
                .map(|t| t.eq_ignore_ascii_case("X509"))
                .unwrap_or(false)
        })
        .map(|idp| {
            let name = idp
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("(unnamed)");
            let status = idp
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("(unknown)");
            format!("{name} [{status}]")
        })
        .collect();

    StigCheckResult::not_reviewed(
        "V-273207",
        if smart_card_idps.is_empty() {
            "No X509 (Smart Card) Identity Provider found. Verify manually — this may be Not_Applicable if PIV/CAC auth is not in use.".to_string()
        } else {
            format!("Smart Card IdP(s) found: {}. Certificate issuer/chain must be manually verified against the DOD-approved CA list — this cannot be determined from the IdP configuration alone.", smart_card_idps.join(", "))
        },
    )
}
