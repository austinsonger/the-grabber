import { useMemo, useState } from "react";
import { AccountDto } from "./api/accounts";
import { CollectionRequestDto } from "./api/collection";
import AccountSelection from "./screens/AccountSelection";
import CollectorSelection from "./screens/CollectorSelection";
import ConfirmScreen from "./screens/ConfirmScreen";
import CredentialVault from "./screens/CredentialVault";
import Dashboard from "./screens/Dashboard";
import DateRangeSelection from "./screens/DateRangeSelection";
import FeatureSelection, { Feature } from "./screens/FeatureSelection";
import OptionsScreen, { RunOptions } from "./screens/OptionsScreen";
import RegionSelection from "./screens/RegionSelection";
import ResultsScreen from "./screens/ResultsScreen";
import RunningScreen from "./screens/RunningScreen";

type Screen =
  | "dashboard"
  | "vault"
  | "accountSelection"
  | "regionSelection"
  | "featureSelection"
  | "dateRangeSelection"
  | "collectorSelection"
  | "options"
  | "confirm"
  | "running"
  | "results";

function App() {
  const [screen, setScreen] = useState<Screen>("dashboard");
  const [selectedAccounts, setSelectedAccounts] = useState<AccountDto[]>([]);
  const [regions, setRegions] = useState<string[]>([]);
  const [feature, setFeature] = useState<Feature>("evidence");
  const [dateRange, setDateRange] = useState({ start: "", end: "" });
  const [collectors, setCollectors] = useState<string[]>([]);
  const [runOptions, setRunOptions] = useState<RunOptions | null>(null);

  const account = selectedAccounts[0];
  const effectiveRegions = regions.length > 0 ? regions : account ? [account.region] : [];

  // The wizard collects one account's worth of settings; multi-account runs
  // stay on the CLI/TUI path driven by config.toml for now.
  const request = useMemo<CollectionRequestDto | null>(() => {
    if (!account?.credential_id || !runOptions) return null;
    return {
      account_name: account.name,
      credential_id: account.credential_id,
      regions: effectiveRegions,
      start_date: dateRange.start,
      end_date: dateRange.end,
      collectors,
      output_dir: runOptions.outputDir,
      zip: runOptions.zip,
      sign: runOptions.sign,
      include_raw: runOptions.includeRaw,
      write_run_manifest: runOptions.runManifest,
      write_chain_of_custody: runOptions.chainOfCustody,
      signing_key: runOptions.signingKey,
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [account, runOptions, effectiveRegions.join(","), dateRange, collectors]);

  const goDashboard = () => setScreen("dashboard");
  const navigate = (target: string) =>
    setScreen(target === "accounts" ? "accountSelection" : "vault");

  switch (screen) {
    case "vault":
      return (
        <>
          <button onClick={goDashboard} style={{ margin: 12 }}>
            ← Back
          </button>
          <CredentialVault />
        </>
      );
    case "accountSelection":
      return (
        <AccountSelection
          onNext={(accounts) => {
            setSelectedAccounts(accounts);
            setScreen("regionSelection");
          }}
          onBack={goDashboard}
        />
      );
    case "regionSelection":
      return (
        <RegionSelection
          accounts={selectedAccounts}
          onNext={(selected) => {
            setRegions(selected);
            setScreen("featureSelection");
          }}
          onBack={() => setScreen("accountSelection")}
        />
      );
    case "featureSelection":
      return (
        <FeatureSelection
          onNext={(selected) => {
            setFeature(selected);
            setScreen("dateRangeSelection");
          }}
          onBack={() => setScreen("regionSelection")}
        />
      );
    case "dateRangeSelection":
      return (
        <DateRangeSelection
          onNext={(start, end) => {
            setDateRange({ start, end });
            setScreen("collectorSelection");
          }}
          onBack={() => setScreen("featureSelection")}
        />
      );
    case "collectorSelection":
      return (
        <CollectorSelection
          provider={account?.provider ?? "aws"}
          onNext={(selected) => {
            setCollectors(selected);
            setScreen("options");
          }}
          onBack={() => setScreen("dateRangeSelection")}
        />
      );
    case "options":
      return (
        <OptionsScreen
          onNext={(options) => {
            setRunOptions(options);
            setScreen("confirm");
          }}
          onBack={() => setScreen("collectorSelection")}
        />
      );
    case "confirm":
      if (!account || !runOptions) return <Dashboard onNavigate={navigate} />;
      return (
        <ConfirmScreen
          summary={{
            feature,
            account: account.name,
            regions: effectiveRegions,
            startDate: dateRange.start,
            endDate: dateRange.end,
            collectors,
          }}
          options={runOptions}
          onStart={() => setScreen("running")}
          onBack={() => setScreen("options")}
        />
      );
    case "running":
      if (!request) {
        return (
          <div style={{ padding: 24 }}>
            <h1>Cannot start run</h1>
            <p>
              The selected account has no credential assigned. Add one in the
              Credential Vault, then attach it to the account in config.toml.
            </p>
            <button onClick={() => setScreen("accountSelection")}>Back</button>
          </div>
        );
      }
      return (
        <RunningScreen
          request={request}
          onFinished={() => setScreen("results")}
          onBack={() => setScreen("confirm")}
        />
      );
    case "results":
      return (
        <ResultsScreen
          outputDir={runOptions?.outputDir ?? ""}
          onDone={goDashboard}
        />
      );
    default:
      return <Dashboard onNavigate={navigate} />;
  }
}

export default App;
