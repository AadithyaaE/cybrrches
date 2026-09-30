import StatusBadge from "../ui/StatusBadge";
import type { MitigationInput, MitigationScenario } from "../../types/mitigation";
import "./MitigationInputSelector.css";

interface MitigationInputSelectorProps {
  researchInputs: MitigationInput[];
  scenarios: MitigationScenario[];
  selectedId: string;
  onSelect: (id: string) => void;
}

export default function MitigationInputSelector({ researchInputs, scenarios, selectedId, onSelect }: MitigationInputSelectorProps) {
  return (
    <div className="mitigation-input-selector">
      <label className="mitigation-input-selector__label">
        Input record:
        <select className="mitigation-input-selector__select" value={selectedId} onChange={(e) => onSelect(e.target.value)}>
          <optgroup label="Research-Derived (Feature 13/14/15 validation sequences)">
            {researchInputs.map((r) => (
              <option key={r.id} value={r.id}>
                {r.label}
              </option>
            ))}
          </optgroup>
          <optgroup label="Demonstration Scenarios (not research results)">
            {scenarios.map((s) => (
              <option key={s.id} value={s.id}>
                {s.title}
              </option>
            ))}
          </optgroup>
        </select>
      </label>
      <StatusBadge
        label={selectedId.startsWith("seq-") ? "Research-Derived" : "Demonstration Scenario"}
        tone={selectedId.startsWith("seq-") ? "success" : "warning"}
      />
    </div>
  );
}
