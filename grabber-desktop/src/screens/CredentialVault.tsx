import { useEffect, useState } from "react";
import CredentialForm from "../components/CredentialForm";
import {
  createCredential,
  CredentialMetaDto,
  CredentialWriteDto,
  deleteCredential,
  listCredentials,
} from "../api/credentials";

const EMPTY_FORM: CredentialWriteDto = {
  name: "",
  provider: "aws",
  kind: "aws_sso",
};

export default function CredentialVault() {
  const [creds, setCreds] = useState<CredentialMetaDto[]>([]);
  const [form, setForm] = useState<CredentialWriteDto>(EMPTY_FORM);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    try {
      setError(null);
      const result = await listCredentials();
      setCreds(result);
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
      {error && <div style={{ color: "red" }}>{error}</div>}
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
