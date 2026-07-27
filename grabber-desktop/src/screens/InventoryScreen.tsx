import { useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { InventoryTypeDto, listInventoryTypes } from "../api/inventory";

export interface InventorySettings {
  types: string[];
  allAccounts: boolean;
  zip: boolean;
  outputDir: string;
}

interface InventoryScreenProps {
  onNext: (settings: InventorySettings) => void;
  onBack: () => void;
}

export default function InventoryScreen({ onNext, onBack }: InventoryScreenProps) {
  const [types, setTypes] = useState<InventoryTypeDto[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [allAccounts, setAllAccounts] = useState(false);
  const [zip, setZip] = useState(false);
  const [outputDir, setOutputDir] = useState("");
  const [error, setError] = useState<string | null>(null);

  const pickOutputDir = async () => {
    const path = await open({ directory: true, multiple: false });
    if (typeof path === "string") setOutputDir(path);
  };

  useEffect(() => {
    listInventoryTypes()
      .then((data) => {
        setTypes(data);
        setSelected(new Set(data.map((t) => t.key)));
      })
      .catch((e) => setError(String(e)));
  }, []);

  const toggle = (key: string) => {
    const next = new Set(selected);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    setSelected(next);
  };

  const allSelected = types.length > 0 && selected.size === types.length;

  return (
    <div style={{ padding: 24 }}>
      <h1>Asset Inventory</h1>
      <p>Choose which asset types to inventory. Inventory is a current-state
        snapshot and ignores the evidence date range.</p>
      {error && <div style={{ color: "red" }}>{error}</div>}

      <div style={{ display: "flex", gap: 12, margin: "12px 0" }}>
        <button onClick={() => setSelected(new Set(types.map((t) => t.key)))}>
          Select all
        </button>
        <button onClick={() => setSelected(new Set())}>Select none</button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 8 }}>
        {types.map((t) => (
          <label key={t.key} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <input
              type="checkbox"
              checked={selected.has(t.key)}
              onChange={() => toggle(t.key)}
            />
            {t.name}
          </label>
        ))}
      </div>

      <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 8 }}>
        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input
            type="checkbox"
            checked={allAccounts}
            onChange={() => setAllAccounts(!allAccounts)}
          />
          Merge every configured account into one unified inventory
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input type="checkbox" checked={zip} onChange={() => setZip(!zip)} />
          Bundle output into a dated ZIP
        </label>
        <div style={{ display: "flex", gap: 8 }}>
          <input
            value={outputDir}
            onChange={(e) => setOutputDir(e.target.value)}
            placeholder="Output directory"
            style={{ flex: 1 }}
          />
          <button onClick={pickOutputDir}>Browse</button>
        </div>
      </div>

      <div style={{ marginTop: 24, display: "flex", gap: 12, alignItems: "center" }}>
        <button onClick={onBack}>Back</button>
        <button
          onClick={() =>
            onNext({
              // An all-selected list means "everything"; send it empty so the
              // engine takes its own default rather than pinning the list.
              types: allSelected ? [] : Array.from(selected),
              allAccounts,
              zip,
              outputDir,
            })
          }
          disabled={selected.size === 0 || !outputDir.trim()}
        >
          Next
        </button>
        {selected.size === 0 && (
          <span style={{ opacity: 0.7 }}>Select at least one asset type.</span>
        )}
        {selected.size > 0 && !outputDir.trim() && (
          <span style={{ opacity: 0.7 }}>Choose an output directory to continue.</span>
        )}
      </div>
    </div>
  );
}
