import StatusBadge from "../ui/StatusBadge";
import DataTable, { type DataTableColumn } from "../ui/DataTable";
import type { ExplanationExample, FeatureGroupSummaryEntry } from "../../types/explainability";
import "./LstmOcclusionAttribution.css";

interface LstmOcclusionAttributionProps {
  example: ExplanationExample;
  occlusionBaseline: string;
}

export default function LstmOcclusionAttribution({ example, occlusionBaseline }: LstmOcclusionAttributionProps) {
  const featureColumns: DataTableColumn<FeatureGroupSummaryEntry>[] = [
    { key: "feature", header: "Feature", render: (r) => r.feature },
    { key: "mean", header: "Mean Contribution", align: "right", render: (r) => r.mean_contribution.toFixed(5) },
    { key: "sum", header: "Sum Contribution", align: "right", render: (r) => r.sum_contribution.toFixed(5) },
    { key: "sumAbs", header: "Sum |Contribution|", align: "right", render: (r) => r.sum_abs_contribution.toFixed(5) },
  ];

  return (
    <div className="lstm-occlusion-attribution">
      <div className="lstm-occlusion-attribution__banner">
        <StatusBadge label="Approximate Occlusion Attribution" tone="warning" />
        <p>{example.temporal_summary.method}</p>
      </div>

      <p className="lstm-occlusion-attribution__baseline">
        <strong>Baseline used:</strong> {occlusionBaseline}
      </p>

      <h4 className="lstm-occlusion-attribution__subheading">Per-Timestep Occlusion (t-9 ... t)</h4>
      <div className="lstm-occlusion-attribution__timestep-row">
        {example.temporal_summary.per_timestep.map((ts) => (
          <div className="lstm-occlusion-attribution__timestep-point" key={ts.time_step}>
            <span className="lstm-occlusion-attribution__timestep-label">{ts.time_step}</span>
            <span
              className={`lstm-occlusion-attribution__timestep-value lstm-occlusion-attribution__timestep-value--${ts.direction}`}
            >
              {ts.contribution >= 0 ? "+" : ""}
              {ts.contribution.toFixed(4)}
            </span>
            <span className="lstm-occlusion-attribution__timestep-sub">
              full {ts.full_probability.toFixed(3)} → occluded {ts.occluded_probability.toFixed(3)}
            </span>
          </div>
        ))}
      </div>

      <h4 className="lstm-occlusion-attribution__subheading">Per-Feature Occlusion Summary (top features by |contribution|)</h4>
      <DataTable columns={featureColumns} rows={example.feature_group_summary} getRowKey={(r) => r.feature} />

      <p className="lstm-occlusion-attribution__caveat">
        This is a <strong>perturbation diagnostic</strong>, not a causal proof: it measures how much the
        model's own output changed when a piece of its input was replaced with the training-set mean, not
        whether that feature actually caused any real-world event.
      </p>
    </div>
  );
}
