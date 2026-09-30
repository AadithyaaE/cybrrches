import { getExplanationExamples } from "./explainabilityService";
import { buildMitigationInputFromExample, getPolicyConfig } from "./mitigation/mitigationService";
import { decideMitigation } from "./mitigation/mitigationPolicy";
import { buildBeforeTrafficState, simulateMitigation, rollbackSimulation } from "./mitigation/mitigationSimulation";
import { buildVerificationInput, getVerificationConfig } from "./verification/verificationService";
import { runVerification } from "./verification/verificationEngine";
import type { ExplanationExample } from "../types/explainability";
import type { MitigationInput, MitigationActionRecord, MitigationDecision, MitigationTrafficState, MitigationSimulationResult } from "../types/mitigation";
import type { VerificationInput, VerificationSummary } from "../types/verification";

/**
 * Feature 18 - End-to-End Research Demo orchestration.
 *
 * Wires together EXISTING, unmodified Feature 10/11 engines
 * (mitigationPolicy/mitigationSimulation/verificationEngine) and EXISTING
 * Feature 13/14/15 data (via explainabilityService.ts) around ONE fixed,
 * deterministically-selected sequence. Introduces NO new business logic
 * beyond selecting the sequence and sequencing the existing pure function
 * calls - every probability, MITRE score, attribution value, mitigation
 * decision, and verification objective is computed by code that already
 * existed before this feature.
 *
 * DETERMINISM: a fixed timestamp constant (not the JS wall-clock "now" function) is used for the
 * simulated action records and verification run, so that running the demo
 * twice produces byte-for-byte identical output, including record IDs.
 */

export const DEMO_FIXED_TIMESTAMP_MS = 1719800000000; // fixed, arbitrary epoch constant, never the live wall clock - for full reproducibility

export interface DemoManifest {
  feature: string;
  label: string;
  selected_sequence: {
    sequence_id: number;
    partition: string;
    selection_rule: string;
    input_start_window: number;
    input_end_window: number;
    target_window: number;
    input_start_timestamp: string;
    input_end_timestamp: string;
    target_timestamp: string;
    target_window_label: string;
    target_window_target: number;
  };
  source_artifacts: Record<string, string>;
  observe: {
    ten_window_history: Array<{
      window_id: number;
      window_start: string;
      window_end: string;
      observation_count: number;
      "Tot Fwd Pkts": number;
      "Tot Bwd Pkts": number;
      "Flow Duration": number;
      "Flow Byts/s": number;
      "Flow Pkts/s": number;
    }>;
  };
  cross_day_generalization_summary: unknown;
}

let manifestCache: Promise<DemoManifest> | null = null;
export function getDemoManifest(): Promise<DemoManifest> {
  if (!manifestCache) {
    manifestCache = fetch("/data/demo_manifest.json").then((res) => {
      if (!res.ok) throw new Error(`Failed to load demo manifest: ${res.status}`);
      return res.json();
    });
  }
  return manifestCache;
}

export async function getDemoExample(): Promise<{ manifest: DemoManifest; example: ExplanationExample }> {
  const [manifest, examples] = await Promise.all([getDemoManifest(), getExplanationExamples()]);
  const example = examples.find((e) => e.sequence_id === manifest.selected_sequence.sequence_id);
  if (!example) {
    throw new Error(
      `Demo sequence_id ${manifest.selected_sequence.sequence_id} (from demo_manifest.json) was not found in ` +
      `explanation_examples.json - the two artifacts are out of sync.`,
    );
  }
  return { manifest, example };
}

export interface DemoMitigateVerifyResult {
  mitigationInput: MitigationInput;
  decision: MitigationDecision;
  before: MitigationTrafficState;
  appliedResult: MitigationSimulationResult;
  rolledBackResult: MitigationSimulationResult;
  proposedRecord: MitigationActionRecord;
  appliedRecord: MitigationActionRecord;
  rolledBackRecord: MitigationActionRecord;
  verificationInput: VerificationInput;
  verificationSummary: VerificationSummary;
  policyConfig: ReturnType<typeof getPolicyConfig>;
  verificationConfig: ReturnType<typeof getVerificationConfig>;
}

/**
 * Runs the full, deterministic Mitigate -> Verify pipeline for the demo's
 * selected example. Pure with respect to its `example` input plus the
 * fixed DEMO_FIXED_TIMESTAMP_MS constant - calling this twice with the
 * same example always returns deep-equal results (verified in
 * tests/test_demo.py's frontend-adjacent determinism check and by manual
 * inspection: no live wall-clock read, no random-number generation, no network mutation
 * anywhere in this function or the engines it calls).
 */
export function runDemoMitigateVerify(example: ExplanationExample): DemoMitigateVerifyResult {
  const mitigationInput = buildMitigationInputFromExample(example);
  const decision = decideMitigation(mitigationInput);
  const before = buildBeforeTrafficState(mitigationInput);
  const appliedResult = simulateMitigation(before, decision.level);
  const rolledBackResult = rollbackSimulation(before);

  const proposedRecord: MitigationActionRecord = {
    actionId: `${mitigationInput.id}-proposed-demo`,
    timestamp: DEMO_FIXED_TIMESTAMP_MS,
    level: decision.level,
    action: decision.action,
    durationSeconds: null,
    status: "proposed",
    reversible: true,
    simulationOnly: true,
  };
  const appliedRecord: MitigationActionRecord = {
    actionId: `${mitigationInput.id}-applied-demo`,
    timestamp: DEMO_FIXED_TIMESTAMP_MS + 1000,
    level: decision.level,
    action: decision.action,
    durationSeconds: appliedResult.durationSeconds,
    status: "applied",
    reversible: true,
    simulationOnly: true,
  };
  const rolledBackRecord: MitigationActionRecord = {
    actionId: `${mitigationInput.id}-rollback-demo`,
    timestamp: DEMO_FIXED_TIMESTAMP_MS + 2000,
    level: decision.level,
    action: "Rolled back to pre-action baseline traffic state.",
    durationSeconds: null,
    status: "rolled_back",
    reversible: true,
    simulationOnly: true,
  };

  const verificationInput = buildVerificationInput(mitigationInput, proposedRecord, appliedRecord, rolledBackRecord);
  const verificationSummary = runVerification(verificationInput, DEMO_FIXED_TIMESTAMP_MS + 3000);

  return {
    mitigationInput, decision, before, appliedResult, rolledBackResult,
    proposedRecord, appliedRecord, rolledBackRecord,
    verificationInput, verificationSummary,
    policyConfig: getPolicyConfig(),
    verificationConfig: getVerificationConfig(),
  };
}
