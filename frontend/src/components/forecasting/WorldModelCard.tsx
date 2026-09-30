import MetricCard from "../ui/MetricCard";
import { IconLayers, IconNetwork, IconClock, IconForecast } from "../ui/icons";
import type { LstmModelConfig } from "../../services/forecastingService";
import "./WorldModelCard.css";

interface WorldModelCardProps {
  config: LstmModelConfig;
}

export default function WorldModelCard({ config }: WorldModelCardProps) {
  return (
    <div className="world-model-card__grid">
      <MetricCard
        eyebrow="Model"
        value="LSTM World Model"
        detail={`${config.hiddenSize}-unit hidden state, ${config.numLayers} layers`}
        statusLabel="Frozen"
        statusTone="neutral"
        accent="violet"
        icon={<IconLayers />}
      />
      <MetricCard
        eyebrow="Input"
        value={`${config.inputDimensionality}-dimensional state`}
        detail="Network state S(t)"
        statusLabel="Ready"
        statusTone="success"
        accent="cyan"
        icon={<IconNetwork />}
      />
      <MetricCard
        eyebrow="History"
        value={`${config.historySeconds} seconds`}
        detail="10-step input sequence"
        statusLabel="Ready"
        statusTone="success"
        accent="cyan"
        icon={<IconClock />}
      />
      <MetricCard
        eyebrow="Output"
        value={`${config.outputDimensionality}-dimensional state`}
        detail="Next network state forecast"
        statusLabel="Ready"
        statusTone="success"
        accent="violet"
        icon={<IconLayers />}
      />
      <MetricCard
        eyebrow="Forecast Horizons"
        value={config.forecastHorizons.map((h) => `K=${h}`).join(", ")}
        detail="Recursive / free-running rollout"
        statusLabel="Evaluated"
        statusTone="info"
        accent="violet"
        icon={<IconForecast />}
      />
    </div>
  );
}
