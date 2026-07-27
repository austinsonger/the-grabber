import { invoke } from "@tauri-apps/api/core";

export interface CollectorMetaDto {
  key: string;
  name: string;
  category: string;
}

export const listCollectors = (provider: string) =>
  invoke<CollectorMetaDto[]>("list_collectors", { provider });
