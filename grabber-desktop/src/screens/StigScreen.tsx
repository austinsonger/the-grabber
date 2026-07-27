import { useEffect, useMemo, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { CredentialMetaDto, listCredentials } from "../api/credentials";
import {
  StigFinding,
  StigRemediationOutcome,
  startStigRemediation,
  stigScan,
} from "../api/stig";

interface StigScreenProps {
  onDone: () => void;
  onBack: () => void;
}

export default function StigScreen({ onDone, onBack }: StigScreenProps) {
  const [credentials, setCredentials] = useState<CredentialMetaDto[]>([]);
  const [credentialId, setCredentialId] = useState("");
  const [findings, setFindings] = useState<StigFinding[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [textInput, setTextInput] = useState("");
  const [outputDir, setOutputDir] = useState("");
  const [outcomes, setOutcomes] = useState<StigRemediationOutcome[]>([]);
  const [busy, setBusy] = useState<null | "scanning" | "applying">(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listCredentials()
      .then((all) => setCredentials(all.filter((c) => c.provider === "okta")))
      .catch((e) => setError(String(e)));
  }, []);

  const tenantName = useMemo(
    () => credentials.find((c) => c.id === credentialId)?.name ?? "",
    [credentials, credentialId],
  );

  const actionable = findings.filter((f) => f.actionable && f.remediation.length > 0);
  const needsText = actionable.some(
    (f) => selected.has(f.v_id) && f.needs_text_input,
  );

  const scan = async () => {
    setBusy("scanning");
    setError(null);
    setOutcomes([]);
    try {
      const results = await stigScan(credentialId);
      setFindings(results);
      setSelected(new Set());
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  };

  const apply = async () => {
    setBusy("applying");
    setError(null);
    try {
      const results = await startStigRemediation({
        credential_id: credentialId,
        tenant_name: tenantName,
        v_ids: Array.from(selected),
        text_input: textInput || undefined,
        output_dir: outputDir,
      });
      setOutcomes(results);
      // Re-scan so the list reflects what the remediation actually changed.
      setFindings(await stigScan(credentialId));
      setSelected(new Set());
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  };

  const toggle = (vId: string) => {
    const next = new Set(selected);
    if (next.has(vId)) next.delete(vId);
    else next.add(vId);
    setSelected(next);
  };

  const pickOutputDir = async () => {
    const path = await open({ directory: true, multiple: false });
    if (typeof path === "string") setOutputDir(path);
  };

  return (
    <div style={{ padding: 24 }}>
      <h1>Okta STIG Remediation</h1>
      {error && <div style={{ color: "var(--red)" }}>{error}</div>}

      <div style={{ marginTop: 16, display: "flex", gap: 8, alignItems: "center" }}>
        <select value={credentialId} onChange={(e) => setCredentialId(e.target.value)}>
          <option value="">Select an Okta credential…</option>
          {credentials.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name} {c.domain ? `(${c.domain})` : ""}
            </option>
          ))}
        </select>
        <button onClick={scan} disabled={!credentialId || busy !== null}>
          {busy === "scanning" ? "Scanning…" : "Scan"}
        </button>
      </div>
      {credentials.length === 0 && (
        <p style={{ opacity: 0.7 }}>
          No Okta credentials in the vault yet. Add one in the Credential Vault first.
        </p>
      )}

      {findings.length > 0 && (
        <>
          <h3 style={{ marginTop: 24 }}>
            Findings — {actionable.length} actionable of {findings.length} checks
          </h3>
          <table style={{ width: "100%", textAlign: "left" }}>
            <thead>
              <tr>
                <th />
                <th>V-ID</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Title</th>
                <th>Remediation</th>
              </tr>
            </thead>
            <tbody>
              {actionable.map((f) => (
                <tr key={f.v_id}>
                  <td>
                    <input
                      type="checkbox"
                      checked={selected.has(f.v_id)}
                      onChange={() => toggle(f.v_id)}
                    />
                  </td>
                  <td>{f.v_id}</td>
                  <td>{f.severity}</td>
                  <td>{f.status}</td>
                  <td>{f.title}</td>
                  <td>{f.remediation.join("; ")}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {needsText && (
            <input
              value={textInput}
              onChange={(e) => setTextInput(e.target.value)}
              placeholder="Required text (e.g. sign-in banner content)"
              style={{ marginTop: 12, width: "100%", padding: 8 }}
            />
          )}

          <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
            <input
              value={outputDir}
              onChange={(e) => setOutputDir(e.target.value)}
              placeholder="Remediation log directory"
              style={{ flex: 1 }}
            />
            <button onClick={pickOutputDir}>Browse</button>
          </div>

          <div style={{ marginTop: 16, display: "flex", gap: 12, alignItems: "center" }}>
            <button
              onClick={apply}
              disabled={
                selected.size === 0 ||
                !outputDir.trim() ||
                busy !== null ||
                (needsText && !textInput.trim())
              }
            >
              {busy === "applying" ? "Applying…" : `Apply ${selected.size} selected`}
            </button>
            <span style={{ opacity: 0.7 }}>
              Remediation writes directly to the live Okta tenant.
            </span>
          </div>
        </>
      )}

      {outcomes.length > 0 && (
        <>
          <h3 style={{ marginTop: 24 }}>Outcomes</h3>
          <ul>
            {outcomes.map((o, i) => (
              <li key={`${o.v_id}-${i}`}>
                <strong>{o.v_id}</strong> — {o.label}
                {o.detail ? `: ${o.detail}` : ""} ({o.target})
              </li>
            ))}
          </ul>
          {outcomes[0]?.log_path && <p>Log: {outcomes[0].log_path}</p>}
        </>
      )}

      <div style={{ marginTop: 24, display: "flex", gap: 12 }}>
        <button onClick={onBack}>Back</button>
        <button onClick={onDone}>Done</button>
      </div>
    </div>
  );
}
