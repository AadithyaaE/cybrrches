import { useEffect, useMemo, useState } from "react";
import SectionHeader from "../components/ui/SectionHeader";
import SummarySection from "../components/overview/SummarySection";
import MitigationHeader from "../components/mitigation/MitigationHeader";
import MitigationInputSelector from "../components/mitigation/MitigationInputSelector";
import ThreatStateCard from "../components/mitigation/ThreatStateCard";
import PolicyDecisionCard from "../components/mitigation/PolicyDecisionCard";
import RecommendedAction from "../components/mitigation/RecommendedAction";
import SimulationBeforeAfter from "../components/mitigation/SimulationBeforeAfter";
import MitigationTimeline from "../components/mitigation/MitigationTimeline";
import MitigationEvidence from "../components/mitigation/MitigationEvidence";
import MitigationSafetyNotice from "../components/mitigation/MitigationSafetyNotice";
import MitigationCycle from "../components/mitigation/MitigationCycle";
import MitigationDeploymentArchitecture from "../components/mitigation/MitigationDeploymentArchitecture";
import {
  getResearchDerivedInputs,
  getDemonstrationScenarios,
  getPolicyConfig,
} from "../services/mitigation/mitigationService";
import { decideMitigation } from "../services/mitigation/mitigationPolicy";
import { buildBeforeTrafficState, simulateMitigation } from "../services/mitigation/mitigationSimulation";
import type { MitigationInput, MitigationActionRecord } from "../types/mitigation";
import "./MitigationPage.css";

type SimulationStatus = "idle" | "applied" | "rolled_back";

export default function MitigationPage() {
  const [researchInputs, setResearchInputs] = useState<MitigationInput[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string>("scenario-monitor");
  const [simulationStatus, setSimulationStatus] = useState<SimulationStatus>("idle");
  const [actionRecords, setActionRecords] = useState<MitigationActionRecord[]>([]);

  const scenarios = useMemo(() => getDemonstrationScenarios(), []);
  const policyConfig = useMemo(() => getPolicyConfig(), []);

  useEffect(() => {
    getResearchDerivedInputs()
      .then((inputs) => {
        setResearchInputs(inputs);
        if (inputs.length > 0) setSelectedId(inputs[0].id);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load research-derived inputs."));
  }, []);

  const currentInput: MitigationInput | null = useMemo(() => {
    const fromResearch = researchInputs?.find((r) => r.id === selectedId);
    if (fromResearch) return fromResearch;
    const fromScenario = scenarios.find((s) => s.id === selectedId);
    return fromScenario ? fromScenario.input : null;
  }, [researchInputs, scenarios, selectedId]);

  const decision = useMemo(() => (currentInput ? decideMitigation(currentInput) : null), [currentInput]);
  const beforeTraffic = useMemo(() => (currentInput ? buildBeforeTrafficState(currentInput) : null), [currentInput]);
  const simResult = useMemo(
    () => (beforeTraffic && decision ? simulateMitigation(beforeTraffic, decision.level) : null),
    [beforeTraffic, decision],
  );

  useEffect(() => {
    if (!decision) return;
    setSimulationStatus("idle");
    setActionRecords([
      {
        actionId: `${selectedId}-proposed-${Date.now()}`,
        timestamp: Date.now(),
        level: decision.level,
        action: decision.action,
        durationSeconds: null,
        status: "proposed",
        reversible: true,
        simulationOnly: true,
      },
    ]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId]);

  function handleApply() {
    if (!decision || !simResult) return;
    setSimulationStatus("applied");
    setActionRecords((prev) => [
      ...prev,
      {
        actionId: `${selectedId}-applied-${Date.now()}`,
        timestamp: Date.now(),
        level: decision.level,
        action: decision.action,
        durationSeconds: simResult.durationSeconds,
        status: "applied",
        reversible: true,
        simulationOnly: true,
      },
    ]);
  }

  function handleRollback() {
    if (!decision) return;
    setSimulationStatus("rolled_back");
    setActionRecords((prev) => [
      ...prev,
      {
        actionId: `${selectedId}-rollback-${Date.now()}`,
        timestamp: Date.now(),
        level: decision.level,
        action: "Rolled back to pre-action baseline traffic state.",
        durationSeconds: null,
        status: "rolled_back",
        reversible: true,
        simulationOnly: true,
      },
    ]);
  }

  function handleReset() {
    if (!decision) return;
    setSimulationStatus("idle");
    setActionRecords((prev) => [
      ...prev,
      {
        actionId: `${selectedId}-reset-${Date.now()}`,
        timestamp: Date.now(),
        level: decision.level,
        action: "Simulation reset to initial state.",
        durationSeconds: null,
        status: "reset",
        reversible: true,
        simulationOnly: true,
      },
    ]);
  }

  return (
    <div>
      <SectionHeader
        title="Mitigation"
        description="A deterministic mitigation policy engine and controlled simulation, sitting between Attack Analysis / MITRE evidence and the simulated Verification stage."
      />

      <MitigationHeader />

      {error && (
        <SummarySection title="Unable to load research-derived inputs">
          <p className="mitigation-page__error">{error}</p>
        </SummarySection>
      )}

      {!researchInputs && !error && <p className="mitigation-page__loading">Loading research-derived inputs...</p>}

      {researchInputs && currentInput && decision && beforeTraffic && simResult && (
        <div className="mitigation-page__sections">
          <SummarySection title="Input Selection">
            <MitigationInputSelector
              researchInputs={researchInputs}
              scenarios={scenarios}
              selectedId={selectedId}
              onSelect={setSelectedId}
            />
          </SummarySection>

          <SummarySection title="Current Threat State">
            <ThreatStateCard input={currentInput} evidenceQuality={decision.evidenceQuality} />
          </SummarySection>

          <SummarySection title="Policy Decision">
            <PolicyDecisionCard decision={decision} policyConfig={policyConfig} />
          </SummarySection>

          <SummarySection title="Recommended Action">
            <RecommendedAction decision={decision} />
          </SummarySection>

          <SummarySection title="Before / After Simulation">
            <SimulationBeforeAfter
              result={simResult}
              status={simulationStatus}
              level={decision.level}
              onApply={handleApply}
              onRollback={handleRollback}
              onReset={handleReset}
            />
          </SummarySection>

          <SummarySection title="Action Timeline">
            <MitigationTimeline records={actionRecords} />
          </SummarySection>

          <SummarySection title="Evidence / Explainability">
            <MitigationEvidence input={currentInput} />
          </SummarySection>

          <SummarySection title="Safety / Limitations">
            <MitigationSafetyNotice />
          </SummarySection>

          <SummarySection title="Real-World Deployment Architecture">
            <MitigationDeploymentArchitecture />
          </SummarySection>

          <SummarySection title="CyberChess Cycle">
            <MitigationCycle />
          </SummarySection>
        </div>
      )}
    </div>
  );
}
