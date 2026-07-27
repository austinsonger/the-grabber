import { useState } from "react";
import { AccountDto } from "./api/accounts";
import AccountSelection from "./screens/AccountSelection";
import CollectorSelection from "./screens/CollectorSelection";
import ConfirmScreen from "./screens/ConfirmScreen";
import CredentialVault from "./screens/CredentialVault";
import Dashboard from "./screens/Dashboard";
import DateRangeSelection from "./screens/DateRangeSelection";
import FeatureSelection from "./screens/FeatureSelection";
import OptionsScreen, { RunOptions } from "./screens/OptionsScreen";
import RegionSelection from "./screens/RegionSelection";

type Screen =
  | "dashboard"
  | "vault"
  | "accountSelection"
  | "regionSelection"
  | "featureSelection"
  | "dateRangeSelection"
  | "collectorSelection"
  | "options"
  | "confirm";

function App() {
  const [screen, setScreen] = useState<Screen>("dashboard");
  const [selectedAccounts, setSelectedAccounts] = useState<AccountDto[]>([]);
  const [runOptions, setRunOptions] = useState<RunOptions | null>(null);

  switch (screen) {
    case "vault":
      return (
        <>
          <button onClick={() => setScreen("dashboard")} style={{ margin: 12 }}>
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
          onBack={() => setScreen("dashboard")}
        />
      );
    case "regionSelection":
      return (
        <RegionSelection
          accounts={selectedAccounts}
          onNext={() => setScreen("featureSelection")}
          onBack={() => setScreen("accountSelection")}
        />
      );
    case "featureSelection":
      return (
        <FeatureSelection
          onNext={() => setScreen("dateRangeSelection")}
          onBack={() => setScreen("regionSelection")}
        />
      );
    case "dateRangeSelection":
      return (
        <DateRangeSelection
          onNext={() => setScreen("collectorSelection")}
          onBack={() => setScreen("featureSelection")}
        />
      );
    case "collectorSelection":
      return (
        <CollectorSelection
          onNext={() => setScreen("options")}
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
      return runOptions ? (
        <ConfirmScreen
          options={runOptions}
          onStart={() => setScreen("dashboard")}
          onBack={() => setScreen("options")}
        />
      ) : (
        <Dashboard onNavigate={(s) => setScreen(s === "accounts" ? "accountSelection" : "vault")} />
      );
    default:
      return (
        <Dashboard
          onNavigate={(s) =>
            setScreen(s === "accounts" ? "accountSelection" : "vault")
          }
        />
      );
  }
}

export default App;
