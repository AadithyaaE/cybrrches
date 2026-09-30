import StatusBadge from "../ui/StatusBadge";
import "./FrozenEvaluationBanner.css";

export default function FrozenEvaluationBanner() {
  return (
    <div className="frozen-evaluation-banner">
      <StatusBadge label="Frozen Generalization Evaluation" tone="info" />
      <p>
        The trained CyberChess models were kept unchanged and evaluated on additional CSE-CIC-IDS2018
        capture days. No model retraining. No hyperparameter tuning on the external datasets. No fitting of
        a new classifier.
      </p>
    </div>
  );
}
