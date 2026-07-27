import { invoke } from "@tauri-apps/api/core";

export interface CollectionRequestDto {
  account_name: string;
  credential_id: string;
  regions: string[];
  start_date: string;
  end_date: string;
  collectors: string[];
  output_dir: string;
  zip: boolean;
  sign: boolean;
  include_raw: boolean;
  write_run_manifest: boolean;
  write_chain_of_custody: boolean;
  signing_key?: string;
}

/** Payload of the `collection:progress` event emitted by the Rust backend. */
export interface ProgressEvent {
  run_id: string;
  account: string;
  region?: string;
  collector: string;
  status: string;
  records: number;
  message?: string;
}

export const TERMINAL_STATUSES = ["finished", "failed", "cancelled"];

export const startCollection = (request: CollectionRequestDto) =>
  invoke<string>("start_collection", { request });

export const cancelCollection = (runId: string) =>
  invoke<boolean>("cancel_collection", { runId });
