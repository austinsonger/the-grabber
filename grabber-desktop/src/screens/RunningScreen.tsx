import { useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import {
  CollectionRequestDto,
  ProgressEvent,
  TERMINAL_STATUSES,
  cancelCollection,
  startCollection,
} from "../api/collection";

interface RunningScreenProps {
  request: CollectionRequestDto;
  onFinished: (outcome: "finished" | "failed" | "cancelled") => void;
  onBack: () => void;
}

/** Key a progress row by the unit of work it describes. */
const rowKey = (e: ProgressEvent) =>
  `${e.account}::${e.region ?? "-"}::${e.collector}`;

export default function RunningScreen({
  request,
  onFinished,
  onBack,
}: RunningScreenProps) {
  const [rows, setRows] = useState<Map<string, ProgressEvent>>(new Map());
  const [log, setLog] = useState<string[]>([]);
  const [runId, setRunId] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // React StrictMode mounts effects twice in dev; without this the wizard
  // would kick off two concurrent runs.
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;

    let unlisten: (() => void) | undefined;
    let cancelled = false;

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
          setOutcome(payload.status);
        }
      });
      if (cancelled) {
        unlisten?.();
        return;
      }
      try {
        setRunId(await startCollection(request));
      } catch (e) {
        setError(String(e));
        setOutcome("failed");
      }
    })();

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [request]);

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
      <h1>Collecting Evidence</h1>
      <p>
        {done
          ? `Run ${outcome}.`
          : `Running ${request.collectors.length} collectors for ${request.account_name}…`}
      </p>
      {error && <div style={{ color: "red" }}>{error}</div>}

      <table style={{ width: "100%", marginTop: 16, textAlign: "left" }}>
        <thead>
          <tr>
            <th>Account</th>
            <th>Region</th>
            <th>Collector</th>
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
              <td>{r.status}</td>
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
          background: "rgba(0,0,0,0.25)",
          fontSize: 12,
        }}
      >
        {log.join("\n") || "Waiting for progress…"}
      </pre>

      <div style={{ marginTop: 24, display: "flex", gap: 12 }}>
        {done ? (
          <>
            <button onClick={onBack}>Back</button>
            <button
              onClick={() =>
                onFinished(outcome as "finished" | "failed" | "cancelled")
              }
            >
              View Results
            </button>
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
