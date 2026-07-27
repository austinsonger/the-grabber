import { invoke } from "@tauri-apps/api/core";

export interface StigFinding {
  v_id: string;
  title: string;
  severity: string;
  fedramp_req_ids: string[];
  status: string;
  actionable: boolean;
  expected_value: string;
  actual_value: string;
  details: string;
  needs_text_input: boolean;
  remediation: string[];
}

export interface StigApplyRequestDto {
  credential_id: string;
  tenant_name: string;
  v_ids: string[];
  text_input?: string;
  output_dir: string;
}

export interface StigRemediationOutcome {
  v_id: string;
  target: string;
  label: string;
  detail: string;
  log_path?: string;
}

export const stigScan = (credentialId: string) =>
  invoke<StigFinding[]>("stig_scan", { credentialId });

export const startStigRemediation = (request: StigApplyRequestDto) =>
  invoke<StigRemediationOutcome[]>("start_stig_remediation", { request });
