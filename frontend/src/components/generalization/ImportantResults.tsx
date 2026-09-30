import StatusBadge from "../ui/StatusBadge";
import "./ImportantResults.css";

interface Wed21Outlier {
  mse: number;
  rmse: number;
  mae: number;
  n: number;
  worstSampleSequenceId: number;
  worstSampleMse: number;
  worstSampleDominantFeature: string;
}

interface ImportantResultsProps {
  wed21Outlier: Wed21Outlier;
}

const OBSERVED_RESULTS = [
  { label: "Wed-28 Infiltration - full-pipeline recall", value: "≈ 82.3%" },
  { label: "Wed-14 FTP-BruteForce recall", value: "≈ 63.3%" },
  { label: "Wed-14 SSH-Bruteforce recall", value: "≈ 69.2%" },
  { label: "Wed-21 DDOS-HOIC recall", value: "100%" },
  { label: "Wed-21 DDOS-LOIC-UDP recall", value: "≈ 0.22%" },
];

export default function ImportantResults({ wed21Outlier }: ImportantResultsProps) {
  return (
    <div className="important-results">
      <div className="important-results__grid">
        {OBSERVED_RESULTS.map((r) => (
          <div className="important-results__item" key={r.label}>
            <span className="important-results__label">{r.label}</span>
            <span className="important-results__value">{r.value}</span>
          </div>
        ))}
      </div>

      <div className="important-results__callout important-results__callout--danger">
        <StatusBadge label="Documented Finding" tone="danger" />
        <p>DDOS-LOIC-UDP showed near-total detection failure.</p>
      </div>

      <div className="important-results__callout important-results__callout--warning">
        <StatusBadge label="Documented Finding" tone="warning" />
        <p>
          For Wednesday-21-02-2018, the LSTM one-step forecasting error was extremely large and
          outlier-dominated: MSE = {wed21Outlier.mse.toLocaleString(undefined, { maximumFractionDigits: 2 })}{" "}
          (n = {wed21Outlier.n.toLocaleString()}), with the single worst sequence alone reaching MSE ={" "}
          {wed21Outlier.worstSampleMse.toLocaleString(undefined, { maximumFractionDigits: 2 })} - roughly
          19x the day's mean, dominated by the feature "{wed21Outlier.worstSampleDominantFeature}".
        </p>
      </div>
    </div>
  );
}
