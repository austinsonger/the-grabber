import { errorMessage } from "../api/errors";
import { useEffect, useState } from "react";
import {
  ArtifactDto,
  listRunArtifacts,
  openOutputDir,
  readArtifactPreview,
} from "../api/artifacts";

interface ResultsScreenProps {
  outputDir: string;
  onDone: () => void;
}

const formatSize = (bytes: number) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

export default function ResultsScreen({ outputDir, onDone }: ResultsScreenProps) {
  const [artifacts, setArtifacts] = useState<ArtifactDto[]>([]);
  const [selected, setSelected] = useState<ArtifactDto | null>(null);
  const [preview, setPreview] = useState<string>("");
  const [error, setError] = useState<string | null>(null);

  const refresh = () => {
    listRunArtifacts(outputDir)
      .then((data) => {
        setArtifacts(data);
        setError(null);
      })
      .catch((e) => setError(errorMessage(e)));
  };

  useEffect(refresh, [outputDir]);

  const select = (artifact: ArtifactDto) => {
    setSelected(artifact);
    setPreview("Loading…");
    readArtifactPreview(artifact.path)
      .then(setPreview)
      .catch((e) => setPreview(errorMessage(e)));
  };

  return (
    <div style={{ padding: 24 }}>
      <h1>Results</h1>
      <p>{outputDir}</p>
      {error && <div style={{ color: "var(--red)" }}>{error}</div>}

      <div style={{ display: "flex", gap: 12, marginTop: 12 }}>
        <button onClick={refresh}>Refresh</button>
        <button
          onClick={() => openOutputDir(outputDir).catch((e) => setError(errorMessage(e)))}
        >
          Open Folder
        </button>
      </div>

      <div style={{ display: "flex", gap: 24, marginTop: 16 }}>
        <div style={{ flex: 1 }}>
          <h3>Artifacts ({artifacts.length})</h3>
          {artifacts.length === 0 && <p>No artifacts found in this directory.</p>}
          <ul style={{ listStyle: "none", padding: 0 }}>
            {artifacts.map((a) => (
              <li key={a.path}>
                <button
                  onClick={() => select(a)}
                  style={{
                    width: "100%",
                    textAlign: "left",
                    fontWeight: selected?.path === a.path ? "bold" : "normal",
                  }}
                >
                  {a.name} — {formatSize(a.size_bytes)}
                </button>
              </li>
            ))}
          </ul>
        </div>

        <div style={{ flex: 2 }}>
          <h3>{selected ? selected.name : "Preview"}</h3>
          <pre
            style={{
              maxHeight: 420,
              overflow: "auto",
              padding: 12,
              fontSize: 12,
            }}
          >
            {selected ? preview : "Select an artifact to preview it."}
          </pre>
        </div>
      </div>

      <div style={{ marginTop: 24 }}>
        <button onClick={onDone}>Done</button>
      </div>
    </div>
  );
}
