import { useMemo, useState } from "react";
import { AccountDto } from "./api/accounts";
import { CollectionRequestDto, startCollection } from "./api/collection";
import { startInventory } from "./api/inventory";
import { startPoam } from "./api/poam";
import AccountSelection from "./screens/AccountSelection";
import CollectorSelection from "./screens/CollectorSelection";
import ConfirmScreen from "./screens/ConfirmScreen";
import CredentialVault from "./screens/CredentialVault";
import Dashboard from "./screens/Dashboard";
import DateRangeSelection from "./screens/DateRangeSelection";
import FeatureSelection, { Feature } from "./screens/FeatureSelection";
import InventoryScreen, { InventorySettings } from "./screens/InventoryScreen";
import OptionsScreen, { RunOptions } from "./screens/OptionsScreen";
import PoamScreen, { PoamSettings } from "./screens/PoamScreen";
import RegionSelection from "./screens/RegionSelection";
import ResultsScreen from "./screens/ResultsScreen";
import RunningScreen from "./screens/RunningScreen";
import StigScreen from "./screens/StigScreen";

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
  | "inventory"
  | "poam"
  | "stig"
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
  const [inventorySettings, setInventorySettings] =
    useState<InventorySettings | null>(null);
  const [poamSettings, setPoamSettings] = useState<PoamSettings | null>(null);

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

  /** Where the results screen should look, per feature. */
  const resultsDir =
    feature === "inventory"
      ? (inventorySettings?.outputDir ?? "")
      : feature === "poam"
        ? (poamSettings?.outputDir ?? "")
        : (runOptions?.outputDir ?? "");

  const missingCredential = (
    <div style={{ padding: 24 }}>
      <h1>Cannot start run</h1>
      <p>
        The selected account has no credential assigned. Add one in the
        Credential Vault, then attach it to the account in config.toml.
      </p>
      <button onClick={() => setScreen("accountSelection")}>Back</button>
    </div>
  );

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
            setScreen(
              selected === "evidence"
                ? "dateRangeSelection"
                : selected === "inventory"
                  ? "inventory"
                  : selected === "poam"
                    ? "poam"
                    : "stig",
            );
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
    case "inventory":
      return (
        <InventoryScreen
          onNext={(settings) => {
            setInventorySettings(settings);
            setScreen("running");
          }}
          onBack={() => setScreen("featureSelection")}
        />
      );
    case "poam":
      return (
        <PoamScreen
          onNext={(settings) => {
            setPoamSettings(settings);
            setScreen("running");
          }}
          onBack={() => setScreen("featureSelection")}
        />
      );
    case "stig":
      return (
        <StigScreen
          onDone={goDashboard}
          onBack={() => setScreen("featureSelection")}
        />
      );
    case "running":
      if (feature === "inventory") {
        if (!account?.credential_id || !inventorySettings) return missingCredential;
        const settings = inventorySettings;
        const credentialId = account.credential_id;
        return (
          <RunningScreen
            title="Collecting Inventory"
            subtitle={`Inventorying assets for ${account.name}…`}
            start={() =>
              startInventory({
                account_name: account.name,
                credential_id: credentialId,
                regions: effectiveRegions,
                inventory_types: settings.types,
                output_dir: settings.outputDir,
                all_accounts: settings.allAccounts,
                zip: settings.zip,
              })
            }
            onFinished={() => setScreen("results")}
            onBack={() => setScreen("inventory")}
          />
        );
      }
      if (feature === "poam") {
        if (!poamSettings) return <Dashboard onNavigate={navigate} />;
        const settings = poamSettings;
        return (
          <RunningScreen
            title="Generating POA&M"
            subtitle={`Reconciling findings under ${settings.evidenceBase}…`}
            start={() =>
              startPoam({
                evidence_base: settings.evidenceBase,
                year: settings.year,
                month: settings.month,
                format: settings.format,
                output_dir: settings.outputDir,
              })
            }
            onFinished={() => setScreen("results")}
            onBack={() => setScreen("poam")}
          />
        );
      }
      if (!request) return missingCredential;
      return (
        <RunningScreen
          title="Collecting Evidence"
          subtitle={`Running ${request.collectors.length} collectors for ${request.account_name}…`}
          start={() => startCollection(request)}
          onFinished={() => setScreen("results")}
          onBack={() => setScreen("confirm")}
        />
      );
    case "results":
      return <ResultsScreen outputDir={resultsDir} onDone={goDashboard} />;
    default:
      return <Dashboard onNavigate={navigate} />;
  }
}

export default App;
