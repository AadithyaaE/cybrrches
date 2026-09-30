import { useEffect, useState } from "react";
import SectionHeader from "../components/ui/SectionHeader";
import MetricCard from "../components/ui/MetricCard";
import StatusBadge from "../components/ui/StatusBadge";
import SummarySection from "../components/overview/SummarySection";
import StateExplorer from "../components/networkstate/StateExplorer";
import FeatureGroupView from "../components/networkstate/FeatureGroupView";
import FeatureHeatBars from "../components/networkstate/FeatureHeatBars";
import TemporalContextStrip from "../components/networkstate/TemporalContextStrip";
import WhatIsState from "../components/networkstate/WhatIsState";
import NetworkStateLimitations from "../components/networkstate/NetworkStateLimitations";
import { IconNetwork, IconLayers, IconClock, IconDatasets } from "../components/ui/icons";
import { getNetworkStateSummary, getNetworkStateWindows, getFeatureRanges } from "../services/networkStateService";
import type { NetworkStateSummary, NetworkStateWindow, FeatureRanges } from "../types/networkState";
import "./NetworkStatePage.css";

export default function NetworkStatePage() {
  const [summary, setSummary] = useState<NetworkStateSummary | null>(null);
  const [windows, setWindows] = useState<NetworkStateWindow[] | null>(null);
  const [ranges, setRanges] = useState<FeatureRanges | null>(null);
  const [selected, setSelected] = useState<NetworkStateWindow | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([getNetworkStateSummary(), getNetworkStateWindows(), getFeatureRanges()])
      .then(([summaryRes, windowsRes, rangesRes]) => {
        setSummary(summaryRes);
        setWindows(windowsRes);
        setRanges(rangesRes);
        setSelected(windowsRes[0] ?? null);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load network state data."));
  }, []);

  return (
    <div>
      <SectionHeader
        title="Network State"
        description="Inspect the 68-dimensional network state S(t) produced from 1-second network-flow aggregation."
        actions={<StatusBadge label="Offline Research" tone="warning" />}
      />

      {error && (
        <SummarySection title="Unable to load network state data">
          <p className="network-state-page__error">{error}</p>
        </SummarySection>
      )}

      {summary && (
        <div className="network-state-page__grid">
          <MetricCard
            eyebrow="State Dimensionality"
            value="68 features"
            detail={`${summary.aggregationSeconds}-second aggregation`}
            statusLabel="Ready"
            statusTone="success"
            accent="cyan"
            icon={<IconNetwork />}
          />
          <MetricCard
            eyebrow="Aggregation"
            value={`${summary.aggregationSeconds} second`}
            detail="Per network-flow window"
            statusLabel="Ready"
            statusTone="success"
            accent="cyan"
            icon={<IconClock />}
          />
          <MetricCard
            eyebrow="Total States"
            value={summary.totalStates.toLocaleString()}
            detail="Per-observation state rows"
            statusLabel="Ready"
            statusTone="success"
            accent="violet"
            icon={<IconLayers />}
          />
          <MetricCard
            eyebrow="Unique Timestamps"
            value={summary.uniqueTimestamps.toLocaleString()}
            detail="1-second aggregated windows"
            statusLabel="Ready"
            statusTone="success"
            accent="violet"
            icon={<IconDatasets />}
          />
        </div>
      )}

      {!summary && !error && <p className="network-state-page__loading">Loading network state artifacts...</p>}

      {summary && windows && selected && ranges && (
        <div className="network-state-page__sections">
          <SummarySection
            title="State Explorer"
            description="Browse real, saved states from the research dataset by timestamp and label."
          >
            <StateExplorer windows={windows} selected={selected} onSelect={setSelected} />
          </SummarySection>

          <SummarySection
            title="Temporal Context"
            description="The selected window's position inside the 10-second input sequence used by the temporal pipeline (Features 6-13), where one exists."
          >
            <TemporalContextStrip window={selected} />
          </SummarySection>

          <SummarySection
            title="State Visualization"
            description="Compact relative-magnitude view of all 68 feature values for the selected state."
          >
            <FeatureHeatBars features={selected.features} ranges={ranges} />
          </SummarySection>

          <SummarySection
            title="Feature View"
            description={`All 68 S(t) feature values for window #${selected.windowId} (${selected.timestamp.replace("T", " ")}), grouped by feature category.`}
          >
            <FeatureGroupView features={selected.features} />
          </SummarySection>

          <WhatIsState />
          <NetworkStateLimitations />
        </div>
      )}
    </div>
  );
}
