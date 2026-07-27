import { invoke } from "@tauri-apps/api/core";

export interface AppConfigDto {
  accounts: AccountDto[];
  defaults: DefaultsDto;
}

export interface AccountDto {
  name: string;
  provider: string;
  account_id?: string;
  credential_id?: string;
  profile?: string;
  region: string;
  output_dir?: string;
}

export interface DefaultsDto {
  region: string;
  output_dir: string;
  start_date_offset_days: number;
}

export const loadAppConfig = () => invoke<AppConfigDto>("load_app_config");

export const saveAppConfig = (config: AppConfigDto) =>
  invoke<void>("save_app_config", { config });
