import DataTable, { type DataTableColumn } from "../ui/DataTable";
import StatusBadge from "../ui/StatusBadge";
import type { ExplanationExample, TopContributor } from "../../types/explainability";
import "./ClassifierAttribution.css";

interface ClassifierAttributionProps {
  example: ExplanationExample;
  groundingCheckMaxDiff: number;
}

export default function ClassifierAttribution({ example, groundingCheckMaxDiff }: ClassifierAttributionProps) {
  const columns: DataTableColumn<TopContributor>[] = [
    { key: "feature", header: "Feature", render: (r) => r.feature },
    { key: "time_step", header: "Time Step", render: (r) => r.time_step },
    { key: "contribution", header: "Contribution", align: "right", render: (r) => r.contribution.toFixed(4) },
    {
      key: "direction",
      header: "Direction",
      render: (r) => <StatusBadge label={r.direction} tone={r.direction === "attack" ? "danger" : "success"} dot={false} />,
    },
  ];

  return (
    <div className="classifier-attribution">
      <div className="classifier-attribution__intro">
        <StatusBadge label="Exact Attribution (Layer C)" tone="success" dot={false} />
        <p>
          {example.classifier_attribution_note} Because the classifier is a linear model, coefficient x
          feature-value is an exact per-dimension contribution to its logit - not an approximation.
        </p>
      </div>

      <div className="classifier-attribution__meaning">
        <div className="classifier-attribution__meaning-item">
          <StatusBadge label="attack" tone="danger" dot={false} />
          <span>Positive contribution: this feature's value pushed the prediction toward Infiltration.</span>
        </div>
        <div className="classifier-attribution__meaning-item">
          <StatusBadge label="benign" tone="success" dot={false} />
          <span>Negative contribution: this feature's value pushed the prediction toward Benign.</span>
        </div>
      </div>

      <DataTable columns={columns} rows={example.top_contributors} getRowKey={(r) => `${r.feature}-${r.time_step}`} />

      <p className="classifier-attribution__grounding">
        Reconstruction check: summing every feature's exact contribution and comparing it against the
        classifier's own reported logit for this prediction path matches to within{" "}
        {groundingCheckMaxDiff.toExponential(2)} across all validation sequences - confirming this
        attribution is a faithful decomposition, not an approximation.
      </p>
    </div>
  );
}
