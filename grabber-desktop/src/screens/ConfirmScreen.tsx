import { RunOptions } from "./OptionsScreen";

export interface RunSummary {
  feature: string;
  account: string;
  regions: string[];
  startDate: string;
  endDate: string;
  collectors: string[];
}

interface ConfirmScreenProps {
  summary: RunSummary;
  options: RunOptions;
  onStart: () => void;
  onBack: () => void;
}

export default function ConfirmScreen({
  summary,
  options,
  onStart,
  onBack,
}: ConfirmScreenProps) {
  return (
    <div style={{ padding: 24 }}>
      <h1>Confirm Run</h1>
      <dl style={{ marginTop: 16 }}>
        <dt>Feature</dt>
        <dd>{summary.feature}</dd>
        <dt>Account</dt>
        <dd>{summary.account}</dd>
        <dt>Regions</dt>
        <dd>{summary.regions.join(", ") || "(account default)"}</dd>
        <dt>Date Range</dt>
        <dd>
          {summary.startDate} → {summary.endDate}
        </dd>
        <dt>Collectors</dt>
        <dd>{summary.collectors.length} selected</dd>
        <dt>Output Directory</dt>
        <dd>{options.outputDir}</dd>
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
