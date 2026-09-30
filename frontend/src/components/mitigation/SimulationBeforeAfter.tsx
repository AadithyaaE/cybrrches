import Button from "../ui/Button";
import StatusBadge from "../ui/StatusBadge";
import type { MitigationSimulationResult, MitigationLevel } from "../../types/mitigation";
import "./SimulationBeforeAfter.css";

interface SimulationBeforeAfterProps {
  result: MitigationSimulationResult;
  status: "idle" | "applied" | "rolled_back";
  level: MitigationLevel;
  onApply: () => void;
  onRollback: () => void;
  onReset: () => void;
}

export default function SimulationBeforeAfter({ result, status, level, onApply, onRollback, onReset }: SimulationBeforeAfterProps) {
  const canApply = status === "idle" && level !== "MONITOR" && level !== "ALERT" && level !== "ESCALATE";

  return (
    <div className="simulation-before-after">
      <div className="simulation-before-after__grid">
        <div className="simulation-before-after__col">
          <span className="simulation-before-after__col-title">Before</span>
          <div className="simulation-before-after__stat">
            <span>Suspicious traffic</span>
            <strong>{result.before.suspiciousFlows.toLocaleString()}</strong>
          </div>
          <div className="simulation-before-after__stat">
            <span>Legitimate traffic</span>
            <strong>{result.before.legitimateFlows.toLocaleString()}</strong>
          </div>
          <div className="simulation-before-after__stat">
            <span>Total</span>
            <strong>{result.before.totalFlows.toLocaleString()}</strong>
          </div>
        </div>

        <div className="simulation-before-after__col simulation-before-after__col--after">
          <span className="simulation-before-after__col-title">
            After <StatusBadge label={status === "applied" ? "Simulated Outcome" : "Not Yet Applied"} tone={status === "applied" ? "success" : "neutral"} dot={false} />
          </span>
          <div className="simulation-before-after__stat">
            <span>Suspicious traffic</span>
            <strong>{status === "applied" ? result.after.suspiciousFlows.toLocaleString() : "—"}</strong>
          </div>
          <div className="simulation-before-after__stat">
            <span>Legitimate traffic</span>
            <strong>{status === "applied" ? result.after.legitimateFlows.toLocaleString() : "—"}</strong>
          </div>
          <div className="simulation-before-after__stat">
            <span>Total</span>
            <strong>{status === "applied" ? result.after.totalFlows.toLocaleString() : "—"}</strong>
          </div>
        </div>
      </div>

      {status === "applied" && (
        <div className="simulation-before-after__summary">
          <span>Suspicious traffic reduced by {result.suspiciousReductionPct.toFixed(1)}%</span>
          <span>Legitimate traffic preserved at {result.legitimatePreservedPct.toFixed(1)}%</span>
          {result.durationSeconds !== null && <span>Simulated duration: {result.durationSeconds.toLocaleString()}s</span>}
        </div>
      )}

      <div className="simulation-before-after__controls">
        <Button variant="primary" onClick={onApply} disabled={!canApply}>
          Apply Simulation
        </Button>
        <Button variant="secondary" onClick={onRollback} disabled={status !== "applied"}>
          Roll Back
        </Button>
        <Button variant="ghost" onClick={onReset}>
          Reset Simulation
        </Button>
      </div>

      <p className="simulation-before-after__note">
        {result.baselineNote} All figures above are a <strong>{result.label}</strong> - deterministic
        arithmetic over an illustrative baseline, never a real network measurement, and never a fabricated
        accuracy/F1/ROC-AUC value.
      </p>
    </div>
  );
}
