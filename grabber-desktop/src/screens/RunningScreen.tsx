import { useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import {
  ProgressEvent,
  TERMINAL_STATUSES,
  cancelCollection,
} from "../api/collection";

export type RunOutcome = "finished" | "failed" | "cancelled";

interface RunningScreenProps {
  title: string;
  subtitle: string;
  /** Kicks off the backend run and resolves to its run id. */
  start: () => Promise<string>;
  onFinished: (outcome: RunOutcome) => void;
  onBack: () => void;
}

/** Key a progress row by the unit of work it describes. */
const rowKey = (e: ProgressEvent) =>
  `${e.account}::${e.region ?? "-"}::${e.collector}`;

export default function RunningScreen({
  title,
  subtitle,
  start,
  onFinished,
  onBack,
}: RunningScreenProps) {
  const [rows, setRows] = useState<Map<string, ProgressEvent>>(new Map());
  const [log, setLog] = useState<string[]>([]);
  const [runId, setRunId] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<RunOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);
  // React StrictMode mounts effects twice in dev; without this guard the
  // wizard would kick off two concurrent runs.
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;

    let unlisten: (() => void) | undefined;
    let disposed = false;

    (async () => {
      unlisten = await listen<ProgressEvent>("collection:progress", (event) => {
        const payload = event.payload;
        setRows((prev) => new Map(prev).set(rowKey(payload), payload));
        setLog((prev) =>
          [
            ...prev,
            `[${payload.status}] ${payload.collector}${
              payload.message ? ` — ${payload.message}` : ""
            }`,
          ].slice(-500),
        );
        if (TERMINAL_STATUSES.includes(payload.status)) {
          setOutcome(payload.status as RunOutcome);
        }
      });
      if (disposed) {
        unlisten?.();
        return;
      }
      try {
        setRunId(await start());
      } catch (e) {
        setError(String(e));
        setOutcome("failed");
      }
    })();

    return () => {
      disposed = true;
      unlisten?.();
    };
    // Runs once per mount; `start` is a fresh closure on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onCancel = async () => {
    if (!runId) return;
    try {
      await cancelCollection(runId);
    } catch (e) {
      setError(String(e));
    }
  };

  const done = outcome !== null;

  return (
    <div style={{ padding: 24 }}>
      <h1>{title}</h1>
      <p className={done ? `status-${outcome}` : undefined}>
        {done ? `Run ${outcome}.` : subtitle}
      </p>
      {error && <div style={{ color: "var(--red)" }}>{error}</div>}

      <table style={{ width: "100%", marginTop: 16, textAlign: "left" }}>
        <thead>
          <tr>
            <th>Account</th>
            <th>Region</th>
            <th>Step</th>
            <th>Status</th>
            <th>Records</th>
          </tr>
        </thead>
        <tbody>
          {Array.from(rows.values()).map((r) => (
            <tr key={rowKey(r)}>
              <td>{r.account}</td>
              <td>{r.region ?? "—"}</td>
              <td>{r.collector}</td>
              <td className={`status-${r.status}`}>{r.status}</td>
              <td>{r.records}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3 style={{ marginTop: 24 }}>Log</h3>
      <pre
        style={{
          maxHeight: 220,
          overflowY: "auto",
          padding: 12,
          fontSize: 12,
        }}
      >
        {log.join("\n") || "Waiting for progress…"}
      </pre>

      <div style={{ marginTop: 24, display: "flex", gap: 12 }}>
        {done ? (
          <>
            <button onClick={onBack}>Back</button>
            <button onClick={() => onFinished(outcome)}>View Results</button>
          </>
        ) : (
          <button onClick={onCancel} disabled={!runId}>
            Cancel
          </button>
        )}
      </div>
    </div>
  );
}
