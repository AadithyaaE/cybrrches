import { getResearchDerivedInputs, getDemonstrationScenarios } from "../mitigation/mitigationService";
import { decideMitigation } from "../mitigation/mitigationPolicy";
import { buildBeforeTrafficState, simulateMitigation } from "../mitigation/mitigationSimulation";
import { VERIFICATION_CONFIG } from "../../data/verificationConfig";
import type { MitigationInput, MitigationActionRecord } from "../../types/mitigation";
import type { VerificationInput } from "../../types/verification";

/**
 * Verification service layer (Frontend Feature 11). Does NOT recompute
 * Feature 10's decision or simulation math independently - it calls the
 * exact same Feature 10 services (mitigationPolicy.decideMitigation,
 * mitigationSimulation.buildBeforeTrafficState/simulateMitigation) and only
 * assembles their outputs into the shape verificationEngine.ts consumes.
 */

export function getVerificationCandidateInputs(): Promise<MitigationInput[]> {
  return getResearchDerivedInputs();
}

export function getVerificationScenarios() {
  return getDemonstrationScenarios();
}

export function getVerificationConfig() {
  return VERIFICATION_CONFIG;
}

export function buildVerificationInput(
  mitigationInput: MitigationInput,
  proposedRecord: MitigationActionRecord | null,
  appliedRecord: MitigationActionRecord | null,
  rolledBackRecord: MitigationActionRecord | null,
): VerificationInput {
  const decision = decideMitigation(mitigationInput);
  const before = buildBeforeTrafficState(mitigationInput);
  const simulationResult = simulateMitigation(before, decision.level);

  return {
    mitigationInput,
    decision,
    before,
    simulationResult,
    proposedRecord,
    applied: appliedRecord !== null,
    appliedRecord,
    rolledBack: rolledBackRecord !== null,
    rolledBackRecord,
  };
}
