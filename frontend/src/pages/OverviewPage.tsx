import SectionHeader from "../components/ui/SectionHeader";
import MetricCard from "../components/ui/MetricCard";
import StatusBadge from "../components/ui/StatusBadge";
import CyberChessCycle from "../components/overview/CyberChessCycle";
import ResearchSummary from "../components/overview/ResearchSummary";
import ForecastingSummary from "../components/overview/ForecastingSummary";
import AttackProgressionSummary from "../components/overview/AttackProgressionSummary";
import ExplainabilitySummary from "../components/overview/ExplainabilitySummary";
import MitreSummary from "../components/overview/MitreSummary";
import GeneralizationSummary from "../components/overview/GeneralizationSummary";
import ResearchNotes from "../components/overview/ResearchNotes";
import { IconNetwork, IconLayers, IconForecast, IconResearch } from "../components/ui/icons";
import "./OverviewPage.css";

export default function OverviewPage() {
  return (
    <div>
      <SectionHeader
        title="Network Intelligence Overview"
        description="Observe the current network state, forecast future behaviour, and inspect model evidence."
        actions={
          <div className="overview-header-badges">
            <StatusBadge label="Offline Research" tone="warning" />
            <StatusBadge label="Dataset: CSE-CIC-IDS2018" tone="info" dot={false} />
          </div>
        }
      />

      <div className="overview-grid">
        <MetricCard
          eyebrow="Network State"
          value="S(t)"
          detail="68 features, 1-second aggregation"
          statusLabel="Ready"
          statusTone="success"
          accent="cyan"
          icon={<IconNetwork />}
        />
        <MetricCard
          eyebrow="World Model"
          value="LSTM"
          detail="10-second history, 68-dimensional state"
          statusLabel="Ready"
          statusTone="success"
          accent="violet"
          icon={<IconLayers />}
        />
        <MetricCard
          eyebrow="Forecast Horizon"
          value="5 seconds"
          detail="K = 1, 2, 3, 5"
          statusLabel="Ready"
          statusTone="success"
          accent="violet"
          icon={<IconForecast />}
        />
        <MetricCard
          eyebrow="Research Pipeline"
          value="Features 1-16"
          detail="Offline research pipeline"
          statusLabel="Complete"
          statusTone="success"
          accent="cyan"
          icon={<IconResearch />}
        />
      </div>

      <div className="overview-cycle">
        <CyberChessCycle />
      </div>

      <div className="overview-sections">
        <ResearchSummary />
        <ForecastingSummary />
        <AttackProgressionSummary />
        <ExplainabilitySummary />
        <MitreSummary />
        <GeneralizationSummary />
        <ResearchNotes />
      </div>
    </div>
  );
}
