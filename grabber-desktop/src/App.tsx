import { useState } from "react";
import CredentialVault from "./screens/CredentialVault";
import Dashboard from "./screens/Dashboard";

type Screen = "dashboard" | "vault" | "accounts";

function App() {
  const [screen, setScreen] = useState<Screen>("dashboard");

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
    case "accounts":
      return (
        <>
          <button onClick={() => setScreen("dashboard")} style={{ margin: 12 }}>
            ← Back
          </button>
          <div style={{ padding: 24 }}>
            <h1>Account Selection</h1>
            <p>Placeholder for account selection.</p>
          </div>
        </>
      );
    default:
      return <Dashboard onNavigate={setScreen} />;
  }
}

export default App;
