import { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";

export interface PoamSettings {
  evidenceBase: string;
  year?: string;
  month?: string;
  format: "xlsx" | "oscal";
  outputDir: string;
}

interface PoamScreenProps {
  onNext: (settings: PoamSettings) => void;
  onBack: () => void;
}

const MONTHS = [
  "01", "02", "03", "04", "05", "06",
  "07", "08", "09", "10", "11", "12",
];

export default function PoamScreen({ onNext, onBack }: PoamScreenProps) {
  const thisYear = new Date().getFullYear();
  const years = Array.from({ length: 6 }, (_, i) => String(thisYear - i));

  const [evidenceBase, setEvidenceBase] = useState("");
  const [year, setYear] = useState<string>("");
  const [month, setMonth] = useState<string>("");
  const [format, setFormat] = useState<"xlsx" | "oscal">("oscal");
  const [outputDir, setOutputDir] = useState("");

  const pickDir = async (set: (path: string) => void) => {
    const path = await open({ directory: true, multiple: false });
    if (typeof path === "string") set(path);
  };

  return (
    <div style={{ padding: 24 }}>
      <h1>POA&amp;M</h1>
      <p>
        Reconcile previously collected findings into a POA&amp;M document. Point
        this at the directory holding your evidence output.
      </p>

      <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 12 }}>
        <div style={{ display: "flex", gap: 8 }}>
          <input
            value={evidenceBase}
            onChange={(e) => setEvidenceBase(e.target.value)}
            placeholder="Evidence directory"
            style={{ flex: 1 }}
          />
          <button onClick={() => pickDir(setEvidenceBase)}>Browse</button>
        </div>

        <div style={{ display: "flex", gap: 8 }}>
          <input
            value={outputDir}
            onChange={(e) => setOutputDir(e.target.value)}
            placeholder="Output directory"
            style={{ flex: 1 }}
          />
          <button onClick={() => pickDir(setOutputDir)}>Browse</button>
        </div>

        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          Year
          <select value={year} onChange={(e) => setYear(e.target.value)}>
            <option value="">All</option>
            {years.map((y) => (
              <option key={y} value={y}>
                {y}
              </option>
            ))}
          </select>
        </label>

        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          Month
          <select value={month} onChange={(e) => setMonth(e.target.value)}>
            <option value="">All</option>
            {MONTHS.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </label>

        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          Format
          <select
            value={format}
            onChange={(e) => setFormat(e.target.value as "xlsx" | "oscal")}
          >
            <option value="oscal">OSCAL JSON</option>
            <option value="xlsx">FedRAMP XLSX workbook</option>
          </select>
        </label>
      </div>

      <div style={{ marginTop: 24, display: "flex", gap: 12, alignItems: "center" }}>
        <button onClick={onBack}>Back</button>
        <button
          onClick={() =>
            onNext({
              evidenceBase,
              year: year || undefined,
              month: month || undefined,
              format,
              outputDir,
            })
          }
          disabled={!evidenceBase.trim() || !outputDir.trim()}
        >
          Next
        </button>
        {(!evidenceBase.trim() || !outputDir.trim()) && (
          <span style={{ opacity: 0.7 }}>
            Choose an evidence directory and an output directory to continue.
          </span>
        )}
      </div>
    </div>
  );
}
