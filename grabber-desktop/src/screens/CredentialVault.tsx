import { useEffect, useState } from "react";
import CredentialForm from "../components/CredentialForm";
import {
  createCredential,
  CredentialMetaDto,
  CredentialWriteDto,
  deleteCredential,
  detectAwsProfiles,
  DetectedAwsProfileDto,
  importAwsProfiles,
  listCredentials,
} from "../api/credentials";

const EMPTY_FORM: CredentialWriteDto = {
  name: "",
  provider: "aws",
  kind: "aws_sso",
};

export default function CredentialVault() {
  const [creds, setCreds] = useState<CredentialMetaDto[]>([]);
  const [detected, setDetected] = useState<DetectedAwsProfileDto[]>([]);
  const [form, setForm] = useState<CredentialWriteDto>(EMPTY_FORM);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    try {
      setError(null);
      const result = await listCredentials();
      setCreds(result);
      setDetected(await detectAwsProfiles());
    } catch (e) {
      setError(String(e));
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setError(null);
      await createCredential(form);
      setForm(EMPTY_FORM);
      await refresh();
    } catch (err) {
      setError(String(err));
    }
  };

  const onImport = async (names: string[]) => {
    try {
      setError(null);
      await importAwsProfiles(names);
      await refresh();
    } catch (err) {
      setError(String(err));
    }
  };

  const onDelete = async (id: string) => {
    try {
      setError(null);
      await deleteCredential(id);
      await refresh();
    } catch (err) {
      setError(String(err));
    }
  };

  return (
    <div style={{ padding: 24 }}>
      <h1>Credential Vault</h1>
      {error && <div style={{ color: "var(--red)" }}>{error}</div>}
      <table style={{ width: "100%", marginTop: 16, marginBottom: 16 }}>
        <thead>
          <tr>
            <th>Name</th>
            <th>Provider</th>
            <th>Kind</th>
            <th>Identifier</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {creds.map((c) => (
            <tr key={c.id}>
              <td>{c.name}</td>
              <td>{c.provider}</td>
              <td>{c.kind}</td>
              <td>
                {c.access_key_id || c.account_id || c.profile_name || c.domain || c.host || "—"}
              </td>
              <td>
                <button onClick={() => onDelete(c.id)}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {detected.some((p) => !p.imported) && (
        <>
          <h2>Detected AWS Profiles (~/.aws)</h2>
          <p style={{ opacity: 0.7 }}>
            Profiles found in your AWS config/credentials files. Importing adds a
            reference — secrets stay in ~/.aws and are never copied.
          </p>
          <table style={{ width: "100%", marginBottom: 16 }}>
            <thead>
              <tr>
                <th>Profile</th>
                <th>Type</th>
                <th>Region</th>
                <th>Found in</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {detected
                .filter((p) => !p.imported)
                .map((p) => (
                  <tr key={p.name}>
                    <td>{p.name}</td>
                    <td>{p.kind}</td>
                    <td>{p.region || "—"}</td>
                    <td>{p.sources.join(", ")}</td>
                    <td>
                      <button onClick={() => onImport([p.name])}>Import</button>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
          <button
            onClick={() =>
              onImport(detected.filter((p) => !p.imported).map((p) => p.name))
            }
          >
            Import all
          </button>
        </>
      )}

      <h2>Add Credential</h2>
      <form onSubmit={onSubmit} style={{ maxWidth: 400 }}>
        <CredentialForm value={form} onChange={setForm} />
        <button type="submit" style={{ marginTop: 12 }}>
          Save
        </button>
      </form>
    </div>
  );
}
