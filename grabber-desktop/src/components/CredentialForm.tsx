import { CredentialWriteDto } from "../api/credentials";

interface CredentialFormProps {
  value: CredentialWriteDto;
  onChange: (value: CredentialWriteDto) => void;
}

const KINDS = [
  "aws_sso",
  "aws_access_key",
  "aws_profile_reference",
  "api_token",
  "basic_auth",
  "oauth",
];

const PROVIDERS = ["aws", "azure", "gcp", "tenable", "okta", "jira", "elastic", "jamf", "github"];

export default function CredentialForm({ value, onChange }: CredentialFormProps) {
  const update = (patch: Partial<CredentialWriteDto>) => {
    onChange({ ...value, ...patch });
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <input
        value={value.name}
        onChange={(e) => update({ name: e.target.value })}
        placeholder="Name"
      />
      <select value={value.provider} onChange={(e) => update({ provider: e.target.value })}>
        {PROVIDERS.map((p) => (
          <option key={p} value={p}>
            {p}
          </option>
        ))}
      </select>
      <select value={value.kind} onChange={(e) => update({ kind: e.target.value })}>
        {KINDS.map((k) => (
          <option key={k} value={k}>
            {k}
          </option>
        ))}
      </select>

      {value.kind === "aws_sso" && (
        <>
          <input
            value={value.start_url || ""}
            onChange={(e) => update({ start_url: e.target.value })}
            placeholder="SSO Start URL"
          />
          <input
            value={value.account_id || ""}
            onChange={(e) => update({ account_id: e.target.value })}
            placeholder="Account ID"
          />
          <input
            value={value.role_name || ""}
            onChange={(e) => update({ role_name: e.target.value })}
            placeholder="Role Name"
          />
          <input
            value={value.region || ""}
            onChange={(e) => update({ region: e.target.value })}
            placeholder="SSO Region"
          />
          <input
            value={value.session_name || ""}
            onChange={(e) => update({ session_name: e.target.value })}
            placeholder="Session Name"
          />
        </>
      )}

      {value.kind === "aws_access_key" && (
        <>
          <input
            value={value.access_key_id || ""}
            onChange={(e) => update({ access_key_id: e.target.value })}
            placeholder="Access Key ID"
          />
          <input
            type="password"
            value={value.secret_access_key || ""}
            onChange={(e) => update({ secret_access_key: e.target.value })}
            placeholder="Secret Access Key"
          />
          <input
            type="password"
            value={value.session_token || ""}
            onChange={(e) => update({ session_token: e.target.value })}
            placeholder="Session Token (optional)"
          />
        </>
      )}

      {value.kind === "aws_profile_reference" && (
        <input
          value={value.profile_name || ""}
          onChange={(e) => update({ profile_name: e.target.value })}
          placeholder="AWS Profile Name"
        />
      )}

      {(value.kind === "api_token" || value.kind === "oauth") && (
        <>
          <input
            value={value.domain || ""}
            onChange={(e) => update({ domain: e.target.value })}
            placeholder="Domain"
          />
          {value.kind === "oauth" && (
            <input
              value={value.client_id || ""}
              onChange={(e) => update({ client_id: e.target.value })}
              placeholder="Client ID"
            />
          )}
          <input
            type="password"
            value={value.token || value.client_secret || ""}
            onChange={(e) =>
              update(value.kind === "oauth" ? { client_secret: e.target.value } : { token: e.target.value })
            }
            placeholder={value.kind === "oauth" ? "Client Secret" : "Token"}
          />
        </>
      )}

      {value.kind === "basic_auth" && (
        <>
          <input
            value={value.host || ""}
            onChange={(e) => update({ host: e.target.value })}
            placeholder="Host"
          />
          <input
            value={value.username || ""}
            onChange={(e) => update({ username: e.target.value })}
            placeholder="Username"
          />
          <input
            type="password"
            value={value.password || ""}
            onChange={(e) => update({ password: e.target.value })}
            placeholder="Password"
          />
        </>
      )}
    </div>
  );
}
