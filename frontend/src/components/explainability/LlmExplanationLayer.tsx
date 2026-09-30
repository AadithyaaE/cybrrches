import StatusBadge from "../ui/StatusBadge";
import "./LlmExplanationLayer.css";

interface LlmStatus {
  provider: string;
  anyLiveTextGenerated: boolean;
  statusNote: string;
  scopeStatement: string;
}

interface LlmExplanationLayerProps {
  status: LlmStatus;
  promptRules: string[];
}

const CANNOT_DO = [
  "It cannot calculate attack probability.",
  "It cannot calculate MITRE stage.",
  "It cannot determine mitigation.",
  "It cannot override model outputs.",
  "It must not invent evidence.",
];

export default function LlmExplanationLayer({ status, promptRules }: LlmExplanationLayerProps) {
  return (
    <div className="llm-explanation-layer">
      <div className="llm-explanation-layer__status">
        <StatusBadge label={`Provider: ${status.provider}`} tone="neutral" />
        <StatusBadge label="Disabled by default" tone="warning" />
        <p>{status.statusNote}</p>
      </div>

      <p className="llm-explanation-layer__scope">{status.scopeStatement}</p>

      <ul className="llm-explanation-layer__cannot-list">
        {CANNOT_DO.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>

      <p className="llm-explanation-layer__note">
        No API call is required for the current research evaluation - the LLM layer's prompt-construction
        and evidence-grounding logic was exercised, but no live network call or generated text is part of
        any result shown on this page.
      </p>

      <details className="llm-explanation-layer__rules">
        <summary>Real constraints baked into the LLM prompt template (8 rules, verbatim)</summary>
        <ol>
          {promptRules.map((rule) => (
            <li key={rule}>{rule}</li>
          ))}
        </ol>
      </details>
    </div>
  );
}
