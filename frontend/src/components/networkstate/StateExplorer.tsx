import { useMemo, useState } from "react";
import Button from "../ui/Button";
import StatusBadge from "../ui/StatusBadge";
import type { NetworkStateWindow } from "../../types/networkState";
import "./StateExplorer.css";

type LabelFilter = "all" | "Benign" | "Infilteration";

interface StateExplorerProps {
  windows: NetworkStateWindow[];
  selected: NetworkStateWindow;
  onSelect: (window: NetworkStateWindow) => void;
}

export default function StateExplorer({ windows, selected, onSelect }: StateExplorerProps) {
  const [filter, setFilter] = useState<LabelFilter>("all");

  const filtered = useMemo(
    () => (filter === "all" ? windows : windows.filter((w) => w.label === filter)),
    [windows, filter],
  );

  const currentIndex = filtered.findIndex((w) => w.windowId === selected.windowId);

  function step(delta: number) {
    if (filtered.length === 0) return;
    const base = currentIndex === -1 ? 0 : currentIndex;
    const next = (base + delta + filtered.length) % filtered.length;
    onSelect(filtered[next]);
  }

  return (
    <div className="state-explorer">
      <div className="state-explorer__controls">
        <div className="state-explorer__filters">
          {(["all", "Benign", "Infilteration"] as LabelFilter[]).map((f) => (
            <button
              key={f}
              className={`state-explorer__filter ${filter === f ? "state-explorer__filter--active" : ""}`}
              onClick={() => setFilter(f)}
              type="button"
            >
              {f === "all" ? "All" : f}
            </button>
          ))}
        </div>

        <select
          className="state-explorer__select"
          value={selected.windowId}
          onChange={(e) => {
            const w = filtered.find((f) => f.windowId === Number(e.target.value));
            if (w) onSelect(w);
          }}
        >
          {filtered.map((w) => (
            <option key={w.windowId} value={w.windowId}>
              {w.timestamp.replace("T", " ")} - {w.label} (window #{w.windowId})
            </option>
          ))}
        </select>

        <div className="state-explorer__nav">
          <Button variant="secondary" onClick={() => step(-1)}>
            Prev
          </Button>
          <Button variant="secondary" onClick={() => step(1)}>
            Next
          </Button>
        </div>
      </div>

      <div className="state-explorer__details">
        <div className="state-explorer__field">
          <span className="state-explorer__field-label">Timestamp</span>
          <span className="state-explorer__field-value">{selected.timestamp.replace("T", " ")}</span>
        </div>
        <div className="state-explorer__field">
          <span className="state-explorer__field-label">State Label</span>
          <StatusBadge
            label={selected.label}
            tone={selected.label === "Infilteration" ? "danger" : "success"}
          />
        </div>
        <div className="state-explorer__field">
          <span className="state-explorer__field-label">Window ID</span>
          <span className="state-explorer__field-value">{selected.windowId.toLocaleString()}</span>
        </div>
        <div className="state-explorer__field">
          <span className="state-explorer__field-label">Observation Count</span>
          <span className="state-explorer__field-value">{selected.observationCount.toLocaleString()}</span>
        </div>
      </div>

      <p className="state-explorer__sample-note">
        Browsing a representative sample of {windows.length.toLocaleString()} of the full 32,068 one-second
        windows (evenly spaced across the 2018-03-01 01:00:00 - 12:59:59 capture), loaded from a generated
        JSON snapshot rather than the full 331,027-row research CSV.
      </p>
    </div>
  );
}
