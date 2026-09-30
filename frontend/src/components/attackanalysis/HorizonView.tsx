import MiniBarChart from "../ui/MiniBarChart";
import type { AttackProgressionMetric } from "../../data/attackProgressionData";
import "./HorizonView.css";

interface HorizonViewProps {
  metrics: AttackProgressionMetric[];
}

const HORIZONS = [1, 2, 3, 5];

export default function HorizonView({ metrics }: HorizonViewProps) {
  const fullPipelineValidation = metrics.filter((m) => m.mode === "full_pipeline" && m.partition === "validation");
  const seriesFor = (key: "rocAuc" | "prAuc" | "recall") =>
    HORIZONS.map((h) => fullPipelineValidation.find((m) => m.horizon === h)?.[key] ?? null);
  const nFor = (h: number) => fullPipelineValidation.find((m) => m.horizon === h)?.n ?? null;

  return (
    <div className="horizon-view">
      <div className="horizon-view__chart">
        <MiniBarChart
          categories={HORIZONS.map((h) => `K=${h}`)}
          series={[
            { label: "ROC-AUC", color: "var(--status-neutral)", values: seriesFor("rocAuc") },
            { label: "PR-AUC", color: "var(--accent-cyan)", values: seriesFor("prAuc") },
            { label: "Recall", color: "var(--accent-violet)", values: seriesFor("recall") },
          ]}
          valueFormatter={(v) => v.toFixed(3)}
        />
      </div>

      <p className="horizon-view__caveat">
        <strong>These metrics all increase from K=1 to K=5 on the validation partition - this does not mean
        higher K is a "better" forecast.</strong> Longer-horizon recursive forecasts (Feature 12) accumulate
        state-prediction error, and the attack classifier's decision boundary can respond to that
        accumulated error in ways that raise threshold-based metrics like recall without the underlying
        state forecast actually being more accurate.
      </p>

      <p className="horizon-view__caveat">
        <strong>Research note (sample-size shrinkage across horizons):</strong> the number of valid
        sequences shrinks as K increases - only sequences whose forecast horizon does not cross a temporal
        gap or partition boundary survive. On validation this is n=
        {nFor(1)?.toLocaleString()} at K=1 down to n={nFor(5)?.toLocaleString()} at K=5. Metrics at
        different K are therefore computed on slightly different, non-random subsets of sequences, which
        can affect the comparability of threshold-based metrics (precision/recall/F1) across horizons.
      </p>
    </div>
  );
}
