import StatusBadge from "../ui/StatusBadge";
import type { ExplanationExample } from "../../types/explainability";
import "./ExampleSelector.css";

interface ExampleSelectorProps {
  examples: ExplanationExample[];
  selectedSequenceId: number;
  onSelect: (sequenceId: number) => void;
}

export default function ExampleSelector({ examples, selectedSequenceId, onSelect }: ExampleSelectorProps) {
  return (
    <div className="example-selector">
      <label className="example-selector__label">
        Validation sequence:
        <select
          className="example-selector__select"
          value={selectedSequenceId}
          onChange={(e) => onSelect(Number(e.target.value))}
        >
          {examples.map((ex) => (
            <option key={ex.sequence_id} value={ex.sequence_id}>
              seq #{ex.sequence_id} - predicted {ex.prediction} (P={ex.attack_probability.toFixed(3)})
            </option>
          ))}
        </select>
      </label>
      <StatusBadge label="20 deterministic evaluation-sample sequences" tone="neutral" dot={false} />
    </div>
  );
}
