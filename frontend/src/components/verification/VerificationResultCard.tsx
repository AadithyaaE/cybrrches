import StatusBadge from "../ui/StatusBadge";
import type { VerificationStatus } from "../../types/verification";
import "./VerificationResultCard.css";

interface VerificationResultCardProps {
  status: VerificationStatus;
  reason: string;
  verifiedAt: number;
}

const STATUS_TONE: Record<VerificationStatus, "success" | "warning" | "danger" | "neutral"> = {
  VERIFIED: "success",
  PARTIALLY_VERIFIED: "warning",
  NOT_VERIFIED: "danger",
  UNAVAILABLE: "neutral",
};

const STATUS_MEANING: Record<VerificationStatus, string> = {
  VERIFIED: "Mitigation was applied and both objectives (threat suppression, legitimate-traffic preservation) were satisfied.",
  PARTIALLY_VERIFIED: "Mitigation was applied and at least one objective was satisfied, but at least one was not.",
  NOT_VERIFIED: "Mitigation was applied, but the objectives were not satisfied.",
  UNAVAILABLE: "Insufficient evidence exists to perform verification (e.g. the action has not been applied yet). This is not a failure.",
};

export default function VerificationResultCard({ status, reason, verifiedAt }: VerificationResultCardProps) {
  return (
    <div className={`verification-result-card verification-result-card--${STATUS_TONE[status]}`}>
      <StatusBadge label={status.replace(/_/g, " ")} tone={STATUS_TONE[status]} />
      <p className="verification-result-card__meaning">{STATUS_MEANING[status]}</p>
      <p className="verification-result-card__reason">{reason}</p>
      <p className="verification-result-card__timestamp">Verification run at {new Date(verifiedAt).toLocaleTimeString()}</p>
    </div>
  );
}
