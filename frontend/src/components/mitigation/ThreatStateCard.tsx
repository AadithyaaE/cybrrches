import MetricCard from "../ui/MetricCard";
import { IconAttack, IconForecast, IconMitre, IconExplain } from "../ui/icons";
import type { MitigationInput, EvidenceQuality } from "../../types/mitigation";
import "./ThreatStateCard.css";

interface ThreatStateCardProps {
  input: MitigationInput;
  evidenceQuality: EvidenceQuality;
}

const QUALITY_TONE: Record<EvidenceQuality, "success" | "info" | "warning" | "danger"> = {
  HIGH: "success",
  MEDIUM: "info",
  LOW: "warning",
  INSUFFICIENT: "danger",
};

export default function ThreatStateCard({ input, evidenceQuality }: ThreatStateCardProps) {
  const horizons = (["1", "2", "3", "5"] as const).map((k) => ({ k, v: input.horizonProbabilities[k] }));

  return (
    <div className="threat-state-card">
      <div className="threat-state-card__grid">
        <MetricCard
          eyebrow="Attack Probability"
          value={input.attackProbability === null ? "— Not available" : `${(input.attackProbability * 100).toFixed(1)}%`}
          detail="P(Infiltration), K=1 (Feature 13)"
          statusLabel={input.attackProbability === null ? "Unavailable" : "Forecast"}
          statusTone={input.attackProbability === null ? "neutral" : "info"}
          accent="violet"
          icon={<IconAttack />}
        />
        <MetricCard
          eyebrow="Progression Horizon"
          value={horizons.filter((h) => h.v !== null).length > 0 ? `${horizons.filter((h) => h.v !== null).length} of 4 horizons` : "— Not available"}
          detail="K=1 / K=2 / K=3 / K=5"
          statusLabel="Forecast"
          statusTone="info"
          accent="violet"
          icon={<IconForecast />}
        />
        <MetricCard
          eyebrow="MITRE Stage"
          value={input.evidence.mitreStage?.stage ?? "— Not available"}
          detail={input.evidence.mitreStage ? `${input.evidence.mitreStage.evidenceScore.toFixed(0)}/100 (${input.evidence.mitreStage.evidenceLabel})` : "No primary stage"}
          statusLabel={input.evidence.mitreStage?.status ?? "unknown"}
          statusTone={input.evidence.mitreStage?.status === "mapped" ? "success" : input.evidence.mitreStage?.status === "candidate" ? "warning" : "neutral"}
          accent="cyan"
          icon={<IconMitre />}
        />
        <MetricCard
          eyebrow="Evidence Quality"
          value={evidenceQuality}
          detail="Composite of probability/stage/attribution availability"
          statusLabel={evidenceQuality}
          statusTone={QUALITY_TONE[evidenceQuality]}
          accent="cyan"
          icon={<IconExplain />}
        />
      </div>

      <div className="threat-state-card__horizons">
        {horizons.map((h) => (
          <div className="threat-state-card__horizon-point" key={h.k}>
            <span className="threat-state-card__horizon-k">K={h.k}</span>
            <span className="threat-state-card__horizon-value">{h.v === null ? "—" : `${(h.v * 100).toFixed(1)}%`}</span>
          </div>
        ))}
      </div>
      <p className="threat-state-card__note">{input.note}</p>
    </div>
  );
}
