import { invoke } from "@tauri-apps/api/core";

export interface InventoryTypeDto {
  key: string;
  name: string;
}

export interface InventoryRequestDto {
  account_name: string;
  credential_id: string;
  regions: string[];
  /** Empty means every asset type. */
  inventory_types: string[];
  output_dir: string;
  all_accounts: boolean;
  zip: boolean;
}

export const listInventoryTypes = () =>
  invoke<InventoryTypeDto[]>("list_inventory_types");

export const startInventory = (request: InventoryRequestDto) =>
  invoke<string>("start_inventory", { request });
