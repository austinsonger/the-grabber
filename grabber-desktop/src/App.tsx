import { useState } from "react";
import { AccountDto } from "./api/accounts";
import AccountSelection from "./screens/AccountSelection";
import CredentialVault from "./screens/CredentialVault";
import Dashboard from "./screens/Dashboard";
import RegionSelection from "./screens/RegionSelection";

type Screen = "dashboard" | "vault" | "accountSelection" | "regionSelection";

function App() {
  const [screen, setScreen] = useState<Screen>("dashboard");
  const [selectedAccounts, setSelectedAccounts] = useState<AccountDto[]>([]);
  const [, setSelectedRegions] = useState<string[]>([]);

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
          onNext={(regions) => {
            setSelectedRegions(regions);
            setScreen("dashboard");
          }}
          onBack={() => setScreen("accountSelection")}
        />
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
