import { useState } from "react";

interface DateRangeSelectionProps {
  onNext: (start: string, end: string) => void;
  onBack: () => void;
}

const offset = (days: number) => {
  const d = new Date();
  d.setDate(d.getDate() - days);
  return d.toISOString().split("T")[0];
};

const today = () => new Date().toISOString().split("T")[0];

export default function DateRangeSelection({ onNext, onBack }: DateRangeSelectionProps) {
  const [start, setStart] = useState<string>(offset(30));
  const [end, setEnd] = useState<string>(today());

  const apply = (days: number) => {
    setStart(offset(days));
    setEnd(today());
  };

  return (
    <div style={{ padding: 24 }}>
      <h1>Date Range</h1>
      <div style={{ display: "flex", gap: 8, marginTop: 16 }}>
        <button onClick={() => apply(7)}>Last 7 days</button>
        <button onClick={() => apply(30)}>Last 30 days</button>
        <button onClick={() => apply(90)}>Last 90 days</button>
        <button onClick={() => apply(365)}>Last year</button>
      </div>
      <div style={{ marginTop: 24, display: "flex", gap: 16 }}>
        <label>
          Start
          <input
            type="date"
            value={start}
            onChange={(e) => setStart(e.target.value)}
            style={{ marginLeft: 8 }}
          />
        </label>
        <label>
          End
          <input
            type="date"
            value={end}
            onChange={(e) => setEnd(e.target.value)}
            style={{ marginLeft: 8 }}
          />
        </label>
      </div>
      <div style={{ marginTop: 24, display: "flex", gap: 12 }}>
        <button onClick={onBack}>Back</button>
        <button onClick={() => onNext(start, end)}>Next</button>
      </div>
    </div>
  );
}
