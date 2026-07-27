export type Feature = "evidence" | "inventory" | "poam" | "stig";

interface FeatureSelectionProps {
  onNext: (feature: Feature) => void;
  onBack: () => void;
}

const FEATURES: { id: Feature; label: string; description: string }[] = [
  {
    id: "evidence",
    label: "Evidence Collection",
    description: "Collect time-windowed compliance evidence across selected regions.",
  },
  {
    id: "inventory",
    label: "Inventory",
    description: "Generate a point-in-time snapshot of cloud resources.",
  },
  {
    id: "poam",
    label: "POA&M",
    description: "Export a Plan of Action and Milestones from findings.",
  },
  {
    id: "stig",
    label: "STIG",
    description: "Run STIG scans and remediation tracking.",
  },
];

export default function FeatureSelection({ onNext, onBack }: FeatureSelectionProps) {
  return (
    <div style={{ padding: 24 }}>
      <h1>Select Feature</h1>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(2, 1fr)",
          gap: 16,
          marginTop: 24,
        }}
      >
        {FEATURES.map((f) => (
          <button
            key={f.id}
            onClick={() => onNext(f.id)}
            style={{
              padding: 24,
              textAlign: "left",
              cursor: "pointer",
            }}
          >
            <h2 style={{ margin: 0 }}>{f.label}</h2>
            <p style={{ marginBottom: 0 }}>{f.description}</p>
          </button>
        ))}
      </div>
      <div style={{ marginTop: 24 }}>
        <button onClick={onBack}>Back</button>
      </div>
    </div>
  );
}
