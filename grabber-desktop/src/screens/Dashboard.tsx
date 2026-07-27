interface DashboardProps {
  onNavigate: (screen: "vault" | "accounts") => void;
}

export default function Dashboard({ onNavigate }: DashboardProps) {
  return (
    <div style={{ padding: 24 }}>
      <h1>The Grabber</h1>
      <p>Welcome to the desktop evidence collector.</p>

      <div style={{ display: "flex", gap: 12, marginTop: 24 }}>
        <button onClick={() => onNavigate("accounts")}>Start Collection</button>
        <button onClick={() => onNavigate("vault")}>Credential Vault</button>
      </div>

      <h2 style={{ marginTop: 32 }}>Recent Runs</h2>
      <p style={{ color: "#666" }}>No recent runs yet.</p>
    </div>
  );
}
