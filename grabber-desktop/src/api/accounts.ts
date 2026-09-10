import { invoke } from "@tauri-apps/api/core";

export interface AccountDto {
  name: string;
  provider: string;
  account_id?: string;
  credential_id?: string;
  profile?: string;
  region: string;
  output_dir?: string;
}

export interface IdentityInfoDto {
  account?: string;
  user_id?: string;
  arn?: string;
}

export const listAccounts = () => invoke<AccountDto[]>("list_accounts");

export const testAccount = (name: string) =>
  invoke<IdentityInfoDto>("test_account", { name });

export const discoverRegions = (credentialId: string) =>
  invoke<string[]>("discover_regions", { credentialId });
