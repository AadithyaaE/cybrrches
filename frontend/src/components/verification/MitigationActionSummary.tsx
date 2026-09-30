import MetricCard from "../ui/MetricCard";
import { IconAttack, IconClock, IconLayers } from "../ui/icons";
import type { VerificationInput } from "../../types/verification";
import "./MitigationActionSummary.css";

interface MitigationActionSummaryProps {
  input: VerificationInput;
}

export default function MitigationActionSummary({ input }: MitigationActionSummaryProps) {
  return (
    <div className="mitigation-action-summary">
      <div className="mitigation-action-summary__grid">
        <MetricCard
          eyebrow="Action"
          value={input.decision.level.replace(/_/g, " ")}
          detail={input.decision.action}
          statusLabel={input.applied ? "Applied" : "Not Applied"}
          statusTone={input.applied ? "success" : "neutral"}
          accent="violet"
          icon={<IconAttack />}
        />
        <MetricCard
          eyebrow="Duration"
          value={input.simulationResult.durationSeconds !== null ? `${input.simulationResult.durationSeconds.toLocaleString()}s` : "N/A"}
          detail="Simulated duration, if applicable"
          statusLabel="Simulation-Only"
          statusTone="warning"
          accent="cyan"
          icon={<IconClock />}
        />
        <MetricCard
          eyebrow="Status"
          value={input.rolledBack ? "Rolled Back" : input.applied ? "Active" : "Idle"}
          detail={input.rolledBack ? "Simulation rolled back to baseline" : input.applied ? "Simulation currently applied" : "Awaiting simulation"}
          statusLabel={input.rolledBack ? "Rolled Back" : input.applied ? "Applied" : "Idle"}
          statusTone={input.rolledBack ? "warning" : input.applied ? "success" : "neutral"}
          accent="cyan"
          icon={<IconLayers />}
        />
      </div>
      <p className="mitigation-action-summary__note">
        This action is <strong>simulation-only</strong> - no real firewall, network, or routing configuration
        was affected.
      </p>
    </div>
  );
}
