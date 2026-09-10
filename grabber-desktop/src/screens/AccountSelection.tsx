import { errorMessage } from "../api/errors";
import { useEffect, useState } from "react";
import { AccountDto, listAccounts } from "../api/accounts";

interface AccountSelectionProps {
  onNext: (accounts: AccountDto[]) => void;
  onBack: () => void;
}

export default function AccountSelection({ onNext, onBack }: AccountSelectionProps) {
  const [accounts, setAccounts] = useState<AccountDto[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listAccounts()
      .then((data) => {
        setAccounts(data);
        if (data.length === 1) {
          setSelected(new Set([data[0].name]));
        }
      })
      .catch((e) => setError(errorMessage(e)));
  }, []);

  const toggle = (name: string) => {
    const next = new Set(selected);
    if (next.has(name)) {
      next.delete(name);
    } else {
      next.add(name);
    }
    setSelected(next);
  };

  const handleNext = () => {
    const chosen = accounts.filter((a) => selected.has(a.name));
    if (chosen.length === 0) {
      setError("Select at least one account");
      return;
    }
    onNext(chosen);
  };

  return (
    <div style={{ padding: 24 }}>
      <h1>Account Selection</h1>
      {error && <div style={{ color: "var(--red)" }}>{error}</div>}
      <table style={{ width: "100%", marginTop: 16 }}>
        <thead>
          <tr>
            <th></th>
            <th>Name</th>
            <th>Provider</th>
            <th>Region</th>
            <th>Credential</th>
          </tr>
        </thead>
        <tbody>
          {accounts.map((a) => (
            <tr key={a.name}>
              <td>
                <input
                  type="checkbox"
                  checked={selected.has(a.name)}
                  onChange={() => toggle(a.name)}
                />
              </td>
              <td>{a.name}</td>
              <td>{a.provider}</td>
              <td>{a.region || "—"}</td>
              <td>{a.credential_id ? "Vault" : a.profile || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ marginTop: 24, display: "flex", gap: 12 }}>
        <button onClick={onBack}>Back</button>
        <button onClick={handleNext}>Next</button>
      </div>
    </div>
  );
}
