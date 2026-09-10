import { errorMessage } from "../api/errors";
import { useEffect, useMemo, useState } from "react";
import { CollectorMetaDto, listCollectors } from "../api/collectors";

interface CollectorSelectionProps {
  provider?: string;
  onNext: (collectors: string[]) => void;
  onBack: () => void;
}

export default function CollectorSelection({
  provider = "aws",
  onNext,
  onBack,
}: CollectorSelectionProps) {
  const [collectors, setCollectors] = useState<CollectorMetaDto[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listCollectors(provider)
      .then((data) => {
        setCollectors(data);
        setSelected(new Set(data.map((c) => c.key)));
      })
      .catch((e) => setError(errorMessage(e)));
  }, [provider]);

  const categories = useMemo(() => {
    const map = new Map<string, CollectorMetaDto[]>();
    for (const c of collectors) {
      if (!c.name.toLowerCase().includes(search.toLowerCase())) continue;
      const list = map.get(c.category) || [];
      list.push(c);
      map.set(c.category, list);
    }
    return map;
  }, [collectors, search]);

  const toggle = (key: string) => {
    const next = new Set(selected);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    setSelected(next);
  };

  const toggleAll = (keys: string[], on: boolean) => {
    const next = new Set(selected);
    for (const k of keys) {
      if (on) next.add(k);
      else next.delete(k);
    }
    setSelected(next);
  };

  return (
    <div style={{ padding: 24 }}>
      <h1>Collector Selection</h1>
      {error && <div style={{ color: "var(--red)" }}>{error}</div>}
      <input
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Search collectors"
        style={{ marginTop: 12, marginBottom: 12, width: "100%", padding: 8 }}
      />
      <div style={{ display: "flex", gap: 12, marginBottom: 12 }}>
        <button onClick={() => toggleAll(collectors.map((c) => c.key), true)}>
          Select all
        </button>
        <button onClick={() => toggleAll(collectors.map((c) => c.key), false)}>
          Select none
        </button>
      </div>

      {Array.from(categories.entries()).map(([category, items]) => (
        <div key={category} style={{ marginBottom: 16 }}>
          <h3>{category}</h3>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 8 }}>
            {items.map((c) => (
              <label key={c.key} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <input
                  type="checkbox"
                  checked={selected.has(c.key)}
                  onChange={() => toggle(c.key)}
                />
                {c.name}
              </label>
            ))}
          </div>
        </div>
      ))}

      <div style={{ display: "flex", gap: 12 }}>
        <button onClick={onBack}>Back</button>
        <button onClick={() => onNext(Array.from(selected))}>Next</button>
      </div>
    </div>
  );
}
