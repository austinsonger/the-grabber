import { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";

export interface RunOptions {
  outputDir: string;
  zip: boolean;
  sign: boolean;
  includeRaw: boolean;
  runManifest: boolean;
  chainOfCustody: boolean;
  signingKey?: string;
}

interface OptionsScreenProps {
  onNext: (options: RunOptions) => void;
  onBack: () => void;
}

export default function OptionsScreen({ onNext, onBack }: OptionsScreenProps) {
  const [options, setOptions] = useState<RunOptions>({
    outputDir: "",
    zip: false,
    sign: false,
    includeRaw: false,
    runManifest: true,
    chainOfCustody: false,
  });

  const pickDirectory = async () => {
    const path = await open({ directory: true, multiple: false });
    if (typeof path === "string") {
      setOptions((o) => ({ ...o, outputDir: path }));
    }
  };

  const toggle = (key: keyof RunOptions) => {
    setOptions((o) => ({ ...o, [key]: !o[key] } as RunOptions));
  };

  return (
    <div style={{ padding: 24 }}>
      <h1>Run Options</h1>
      <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 12 }}>
        <div style={{ display: "flex", gap: 8 }}>
          <input
            value={options.outputDir}
            onChange={(e) => setOptions((o) => ({ ...o, outputDir: e.target.value }))}
            placeholder="Output directory"
            style={{ flex: 1 }}
          />
          <button onClick={pickDirectory}>Browse</button>
        </div>

        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input type="checkbox" checked={options.zip} onChange={() => toggle("zip")} />
          Bundle output into a dated ZIP
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input type="checkbox" checked={options.sign} onChange={() => toggle("sign")} />
          HMAC-SHA256-sign output files
        </label>
        {options.sign && (
          <input
            value={options.signingKey || ""}
            onChange={(e) => setOptions((o) => ({ ...o, signingKey: e.target.value }))}
            placeholder="Signing key (hex) - generated if empty"
          />
        )}
        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input type="checkbox" checked={options.includeRaw} onChange={() => toggle("includeRaw")} />
          Include raw JSON responses
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input type="checkbox" checked={options.runManifest} onChange={() => toggle("runManifest")} />
          Write run manifest
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input
            type="checkbox"
            checked={options.chainOfCustody}
            onChange={() => toggle("chainOfCustody")}
          />
          Generate chain-of-custody log
        </label>
      </div>
      <div style={{ marginTop: 24, display: "flex", gap: 12 }}>
        <button onClick={onBack}>Back</button>
        <button onClick={() => onNext(options)}>Next</button>
      </div>
    </div>
  );
}
