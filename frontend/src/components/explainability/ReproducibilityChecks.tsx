import StatusBadge from "../ui/StatusBadge";
import "./ReproducibilityChecks.css";

interface ReproducibilityChecksProps {
  evaluationChecks: Record<string, boolean>;
  leakageChecks: Record<string, boolean>;
  reproducibility: { pass1EqualsPass2: boolean; tolerance: string };
}

function CheckGroup({ title, checks }: { title: string; checks: Record<string, boolean> }) {
  const entries = Object.entries(checks);
  return (
    <div className="reproducibility-checks__group">
      <h4 className="reproducibility-checks__group-title">
        {title} ({entries.length} checks)
      </h4>
      <div className="reproducibility-checks__grid">
        {entries.map(([name, passed]) => (
          <div className="reproducibility-checks__item" key={name}>
            <span className="reproducibility-checks__item-name">{name}</span>
            <StatusBadge label={passed ? "PASS" : "FAIL"} tone={passed ? "success" : "danger"} />
          </div>
        ))}
      </div>
    </div>
  );
}

export default function ReproducibilityChecks({ evaluationChecks, leakageChecks, reproducibility }: ReproducibilityChecksProps) {
  return (
    <div className="reproducibility-checks">
      <div className="reproducibility-checks__repro">
        <StatusBadge label={reproducibility.pass1EqualsPass2 ? "Reproducible" : "Not Reproducible"} tone={reproducibility.pass1EqualsPass2 ? "success" : "danger"} />
        <span>Two independent runs match to {reproducibility.tolerance}.</span>
      </div>
      <CheckGroup title="Attribution Integrity Checks" checks={evaluationChecks} />
      <CheckGroup title="Leakage / Model-Integrity Checks" checks={leakageChecks} />
    </div>
  );
}
