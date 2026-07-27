import { useEffect, useState } from "react";
import { AccountDto, discoverRegions } from "../api/accounts";

interface RegionSelectionProps {
  accounts: AccountDto[];
  onNext: (regions: string[]) => void;
  onBack: () => void;
}

export default function RegionSelection({ accounts, onNext, onBack }: RegionSelectionProps) {
  const [regions, setRegions] = useState<string[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const primary = accounts[0];

  useEffect(() => {
    if (!primary?.credential_id) {
      setError("Selected account has no vault credential; region discovery requires one.");
      return;
    }
    setLoading(true);
    discoverRegions(primary.credential_id)
      .then((data) => {
        setRegions(data);
        setSelected(new Set(data));
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [primary?.credential_id]);

  const toggle = (region: string) => {
    const next = new Set(selected);
    if (next.has(region)) {
      next.delete(region);
    } else {
      next.add(region);
    }
    setSelected(next);
  };

  return (
    <div style={{ padding: 24 }}>
      <h1>Region Selection</h1>
      <p>
        Account: <strong>{primary?.name}</strong>
      </p>
      {error && <div style={{ color: "red" }}>{error}</div>}
      {loading && <div>Discovering regions…</div>}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, marginTop: 16 }}>
        {regions.map((r) => (
          <label key={r} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <input type="checkbox" checked={selected.has(r)} onChange={() => toggle(r)} />
            {r}
          </label>
        ))}
      </div>
      <div style={{ marginTop: 24, display: "flex", gap: 12 }}>
        <button onClick={onBack}>Back</button>
        <button onClick={() => onNext(Array.from(selected))}>Next</button>
      </div>
    </div>
  );
}
