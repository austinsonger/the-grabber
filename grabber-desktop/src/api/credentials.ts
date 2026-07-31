import { invoke } from "@tauri-apps/api/core";

export interface CredentialMetaDto {
  id: string;
  name: string;
  provider: string;
  kind: string;
  domain?: string;
  host?: string;
  access_key_id?: string;
  account_id?: string;
  profile_name?: string;
}

export interface CredentialWriteDto {
  name: string;
  provider: string;
  kind: string;
  domain?: string;
  host?: string;
  start_url?: string;
  account_id?: string;
  role_name?: string;
  region?: string;
  session_name?: string;
  access_key_id?: string;
  secret_access_key?: string;
  session_token?: string;
  username?: string;
  password?: string;
  token?: string;
  client_id?: string;
  client_secret?: string;
  profile_name?: string;
}

export const listCredentials = () => invoke<CredentialMetaDto[]>("list_credentials");

export const createCredential = (dto: CredentialWriteDto) =>
  invoke<CredentialMetaDto>("create_credential", { dto });

export const deleteCredential = (id: string) =>
  invoke<void>("delete_credential", { id });

export interface DetectedAwsProfileDto {
  name: string;
  region?: string;
  kind: string;
  sources: string[];
  imported: boolean;
}

export const detectAwsProfiles = () =>
  invoke<DetectedAwsProfileDto[]>("detect_aws_profiles");

export const importAwsProfiles = (names: string[]) =>
  invoke<CredentialMetaDto[]>("import_aws_profiles", { names });
