import { invoke } from "@tauri-apps/api/core";

export interface PoamRequestDto {
  evidence_base: string;
  year?: string;
  month?: string;
  /** "xlsx" for the legacy workbook, "oscal" for the OSCAL JSON document. */
  format: string;
  output_dir: string;
}

export const startPoam = (request: PoamRequestDto) =>
  invoke<string>("start_poam", { request });
