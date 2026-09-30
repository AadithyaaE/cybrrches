import { useEffect, useMemo, useState } from "react";
import SectionHeader from "../components/ui/SectionHeader";
import Button from "../components/ui/Button";
import EmptyState from "../components/ui/EmptyState";
import SummarySection from "../components/overview/SummarySection";
import MitigationInputSelector from "../components/mitigation/MitigationInputSelector";
import VerificationHeader from "../components/verification/VerificationHeader";
import MitigationActionSummary from "../components/verification/MitigationActionSummary";
import BeforeAfterTraffic from "../components/verification/BeforeAfterTraffic";
import VerificationObjectives from "../components/verification/VerificationObjectives";
import VerificationResultCard from "../components/verification/VerificationResultCard";
import VerificationEvidence from "../components/verification/VerificationEvidence";
import VerificationTimeline from "../components/verification/VerificationTimeline";
import RollbackVerification from "../components/verification/RollbackVerification";
import SimulationNotice from "../components/verification/SimulationNotice";
import RealVerificationArchitecture from "../components/verification/RealVerificationArchitecture";
import VerificationCycle from "../components/verification/VerificationCycle";
import { IconAttack } from "../components/ui/icons";
import {
  getVerificationCandidateInputs,
  getVerificationScenarios,
  buildVerificationInput,
} from "../services/verification/verificationService";
import { runVerification } from "../services/verification/verificationEngine";
import { decideMitigation } from "../services/mitigation/mitigationPolicy";
import { simulateMitigation } from "../services/mitigation/mitigationSimulation";
import type { MitigationInput, MitigationActionRecord } from "../types/mitigation";
import type { VerificationSummary } from "../types/verification";
import "./VerificationPage.css";

type SimulationStatus = "idle" | "applied" | "rolled_back";

export default function VerificationPage() {
  const [researchInputs, setResearchInputs] = useState<MitigationInput[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string>("scenario-monitor");
  const [simulationStatus, setSimulationStatus] = useState<SimulationStatus>("idle");
  const [actionRecords, setActionRecords] = useState<MitigationActionRecord[]>([]);
  const [verificationSummary, setVerificationSummary] = useState<VerificationSummary | null>(null);

  const scenarios = useMemo(() => getVerificationScenarios(), []);

  useEffect(() => {
    getVerificationCandidateInputs()
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

  const proposedRecord = actionRecords.find((r) => r.status === "proposed") ?? null;
  const appliedRecord = [...actionRecords].reverse().find((r) => r.status === "applied") ?? null;
  const rolledBackRecord = [...actionRecords].reverse().find((r) => r.status === "rolled_back") ?? null;

  const verificationInput = useMemo(() => {
    if (!currentInput) return null;
    return buildVerificationInput(currentInput, proposedRecord, simulationStatus === "applied" || simulationStatus === "rolled_back" ? appliedRecord : null, simulationStatus === "rolled_back" ? rolledBackRecord : null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentInput, actionRecords, simulationStatus]);

  useEffect(() => {
    if (!currentInput) return;
    const decision = decideMitigation(currentInput);
    setSimulationStatus("idle");
    setVerificationSummary(null);
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
  }, [selectedId, currentInput]);

  function handleApply() {
    if (!verificationInput) return;
    const simResult = simulateMitigation(verificationInput.before, verificationInput.decision.level);
    setSimulationStatus("applied");
    setVerificationSummary(null);
    setActionRecords((prev) => [
      ...prev,
      {
        actionId: `${selectedId}-applied-${Date.now()}`,
        timestamp: Date.now(),
        level: verificationInput.decision.level,
        action: verificationInput.decision.action,
        durationSeconds: simResult.durationSeconds,
        status: "applied",
        reversible: true,
        simulationOnly: true,
      },
    ]);
  }

  function handleRollback() {
    if (!verificationInput) return;
    setSimulationStatus("rolled_back");
    setVerificationSummary(null);
    setActionRecords((prev) => [
      ...prev,
      {
        actionId: `${selectedId}-rollback-${Date.now()}`,
        timestamp: Date.now(),
        level: verificationInput.decision.level,
        action: "Rolled back to pre-action baseline traffic state.",
        durationSeconds: null,
        status: "rolled_back",
        reversible: true,
        simulationOnly: true,
      },
    ]);
  }

  function handleReset() {
    if (!verificationInput) return;
    setSimulationStatus("idle");
    setVerificationSummary(null);
    setActionRecords((prev) => [
      ...prev.filter((r) => r.status === "proposed"),
      {
        actionId: `${selectedId}-reset-${Date.now()}`,
        timestamp: Date.now(),
        level: verificationInput.decision.level,
        action: "Simulation reset to initial state.",
        durationSeconds: null,
        status: "reset",
        reversible: true,
        simulationOnly: true,
      },
    ]);
  }

  function handleRunVerification() {
    if (!verificationInput) return;
    setVerificationSummary(runVerification(verificationInput, Date.now()));
  }

  const displayComparisons = useMemo(() => {
    if (verificationSummary) return verificationSummary.trafficComparisons;
    if (!verificationInput) return [];
    const before = verificationInput.before;
    const after = simulationStatus === "idle" ? before : verificationInput.simulationResult.after;
    return [
      { metric: "suspicious" as const, label: "Suspicious Traffic", before: before.suspiciousFlows, after: after.suspiciousFlows, absoluteChange: after.suspiciousFlows - before.suspiciousFlows, percentChange: before.suspiciousFlows === 0 ? 0 : ((after.suspiciousFlows - before.suspiciousFlows) / before.suspiciousFlows) * 100, objectiveResult: "UNAVAILABLE" as const },
      { metric: "legitimate" as const, label: "Legitimate Traffic", before: before.legitimateFlows, after: after.legitimateFlows, absoluteChange: after.legitimateFlows - before.legitimateFlows, percentChange: before.legitimateFlows === 0 ? 0 : ((after.legitimateFlows - before.legitimateFlows) / before.legitimateFlows) * 100, objectiveResult: "UNAVAILABLE" as const },
      { metric: "total" as const, label: "Total Traffic", before: before.totalFlows, after: after.totalFlows, absoluteChange: after.totalFlows - before.totalFlows, percentChange: before.totalFlows === 0 ? 0 : ((after.totalFlows - before.totalFlows) / before.totalFlows) * 100, objectiveResult: "INFO" as const },
    ];
  }, [verificationSummary, verificationInput, simulationStatus]);

  return (
    <div>
      <SectionHeader
        title="Verification"
        description="After the mitigation action, did the mitigation objective actually get satisfied? CyberChess verifies whether the simulated mitigation objective was satisfied using the simulated before/after traffic state."
      />

      <VerificationHeader status={verificationSummary?.status ?? null} source={currentInput?.source ?? "DEMONSTRATION_SCENARIO"} />

      {error && (
        <SummarySection title="Unable to load research-derived inputs">
          <p className="verification-page__error">{error}</p>
        </SummarySection>
      )}

      {!researchInputs && !error && <p className="verification-page__loading">Loading research-derived inputs...</p>}

      {researchInputs && currentInput && verificationInput && (
        <div className="verification-page__sections">
          <SummarySection title="Input Selection">
            <MitigationInputSelector researchInputs={researchInputs} scenarios={scenarios} selectedId={selectedId} onSelect={setSelectedId} />
            <div className="verification-page__controls">
              <Button variant="primary" onClick={handleApply} disabled={simulationStatus !== "idle"}>
                Apply Simulation
              </Button>
              <Button variant="secondary" onClick={handleRollback} disabled={simulationStatus !== "applied"}>
                Roll Back
              </Button>
              <Button variant="ghost" onClick={handleReset}>
                Reset Simulation
              </Button>
              <Button variant="primary" onClick={handleRunVerification}>
                Run Verification
              </Button>
            </div>
          </SummarySection>

          <SummarySection title="Mitigation Action Summary">
            <MitigationActionSummary input={verificationInput} />
          </SummarySection>

          <SummarySection title="Before / After Traffic">
            <BeforeAfterTraffic comparisons={displayComparisons} />
          </SummarySection>

          {verificationSummary ? (
            <>
              <SummarySection title="Verification Objectives">
                <VerificationObjectives objectives={verificationSummary.objectives} />
              </SummarySection>

              <SummarySection title="Verification Result">
                <VerificationResultCard status={verificationSummary.status} reason={verificationSummary.reason} verifiedAt={verificationSummary.verifiedAt} />
              </SummarySection>

              <SummarySection title="Evidence / Reasoning">
                <VerificationEvidence objectives={verificationSummary.objectives} />
              </SummarySection>

              <SummarySection title="Verification Timeline">
                <VerificationTimeline events={verificationSummary.timeline} />
              </SummarySection>

              <SummarySection title="Rollback Verification">
                <RollbackVerification rollback={verificationSummary.rollback} />
              </SummarySection>
            </>
          ) : (
            <SummarySection title="Verification Result">
              <EmptyState
                icon={<IconAttack />}
                title="Verification not yet run"
                description="Select an input, optionally apply the simulation, then click 'Run Verification' to evaluate the mitigation objective for the current state."
              />
            </SummarySection>
          )}

          <SummarySection title="Simulated vs Real Verification Notice">
            <SimulationNotice />
          </SummarySection>

          <SummarySection title="Future Real-Telemetry Architecture">
            <RealVerificationArchitecture />
          </SummarySection>

          <SummarySection title="CyberChess Cycle">
            <VerificationCycle />
          </SummarySection>
        </div>
      )}
    </div>
  );
}
