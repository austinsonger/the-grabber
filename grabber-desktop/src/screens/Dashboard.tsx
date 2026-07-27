import Logo from "../components/Logo";

interface DashboardProps {
  onNavigate: (screen: "vault" | "accounts") => void;
}

export default function Dashboard({ onNavigate }: DashboardProps) {
  return (
    <div style={{ padding: 24 }}>
      <Logo />
      <p>
        Compliance evidence, asset inventory, and POA&amp;M generation for AWS,
        Okta, Jira, and Tenable.
      </p>

      <div style={{ display: "flex", gap: 12, marginTop: 24 }}>
        <button onClick={() => onNavigate("accounts")}>Start Collection</button>
        <button onClick={() => onNavigate("vault")}>Credential Vault</button>
      </div>

      <h2 style={{ marginTop: 32 }}>Recent Runs</h2>
      <p style={{ color: "var(--text-dim)" }}>No recent runs yet.</p>
    </div>
  );
}
