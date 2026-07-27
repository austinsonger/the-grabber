import { RunOptions } from "./OptionsScreen";

interface ConfirmScreenProps {
  options: RunOptions;
  onStart: () => void;
  onBack: () => void;
}

export default function ConfirmScreen({ options, onStart, onBack }: ConfirmScreenProps) {
  return (
    <div style={{ padding: 24 }}>
      <h1>Confirm Run</h1>
      <dl style={{ marginTop: 16 }}>
        <dt>Output Directory</dt>
        <dd>{options.outputDir || "(default)"}</dd>
        <dt>ZIP Bundle</dt>
        <dd>{options.zip ? "Yes" : "No"}</dd>
        <dt>Sign Output</dt>
        <dd>{options.sign ? "Yes" : "No"}</dd>
        <dt>Include Raw JSON</dt>
        <dd>{options.includeRaw ? "Yes" : "No"}</dd>
        <dt>Run Manifest</dt>
        <dd>{options.runManifest ? "Yes" : "No"}</dd>
        <dt>Chain of Custody</dt>
        <dd>{options.chainOfCustody ? "Yes" : "No"}</dd>
      </dl>
      <div style={{ marginTop: 24, display: "flex", gap: 12 }}>
        <button onClick={onBack}>Back</button>
        <button onClick={onStart}>Start Collection</button>
      </div>
    </div>
  );
}
