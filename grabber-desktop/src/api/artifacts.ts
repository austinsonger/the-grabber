import { invoke } from "@tauri-apps/api/core";

export interface ArtifactDto {
  name: string;
  path: string;
  extension: string;
  size_bytes: number;
  modified_epoch_secs: number;
}

export const listRunArtifacts = (outputDir: string) =>
  invoke<ArtifactDto[]>("list_run_artifacts", { outputDir });

export const readArtifactPreview = (path: string) =>
  invoke<string>("read_artifact_preview", { path });

export const openOutputDir = (path: string) =>
  invoke<void>("open_output_dir", { path });
