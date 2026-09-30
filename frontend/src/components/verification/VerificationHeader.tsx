import StatusBadge from "../ui/StatusBadge";
import type { VerificationStatus, VerificationSource } from "../../types/verification";
import "./VerificationHeader.css";

interface VerificationHeaderProps {
  status: VerificationStatus | null;
  source: VerificationSource;
}

const STATUS_TONE: Record<VerificationStatus, "success" | "warning" | "danger" | "neutral"> = {
  VERIFIED: "success",
  PARTIALLY_VERIFIED: "warning",
  NOT_VERIFIED: "danger",
  UNAVAILABLE: "neutral",
};

export default function VerificationHeader({ status, source }: VerificationHeaderProps) {
  return (
    <div className="verification-header">
      <div className="verification-header__mode">
        <StatusBadge label="Mode: Simulated Verification" tone="warning" />
        <StatusBadge label={source === "RESEARCH_DERIVED" ? "Source: Research-Derived Input" : "Source: Demonstration Scenario"} tone={source === "RESEARCH_DERIVED" ? "success" : "warning"} dot={false} />
        {status && <StatusBadge label={status.replace(/_/g, " ")} tone={STATUS_TONE[status]} />}
      </div>
      <p className="verification-header__notice">
        <strong>SIMULATED VERIFICATION.</strong> CyberChess verifies whether the simulated mitigation
        objective was satisfied using the simulated before/after traffic state from Feature 10. This is not
        a claim that a real network attack was suppressed, that a real firewall enforced anything, or that
        production verification occurred.
      </p>
    </div>
  );
}
