import { useEffect, useMemo, useState } from "react";
import SectionHeader from "../components/ui/SectionHeader";
import Card from "../components/ui/Card";
import Button from "../components/ui/Button";
import MetricCard from "../components/ui/MetricCard";
import DataTable from "../components/ui/DataTable";
import StatusBadge from "../components/ui/StatusBadge";
import EmptyState from "../components/ui/EmptyState";
import ClassifierAttribution from "../components/explainability/ClassifierAttribution";
import MitigationHeader from "../components/mitigation/MitigationHeader";
import ThreatStateCard from "../components/mitigation/ThreatStateCard";
import PolicyDecisionCard from "../components/mitigation/PolicyDecisionCard";
import RecommendedAction from "../components/mitigation/RecommendedAction";
import MitigationEvidence from "../components/mitigation/MitigationEvidence";
import MitigationSafetyNotice from "../components/mitigation/MitigationSafetyNotice";
import VerificationHeader from "../components/verification/VerificationHeader";
import VerificationResultCard from "../components/verification/VerificationResultCard";
import VerificationObjectives from "../components/verification/VerificationObjectives";
import BeforeAfterTraffic from "../components/verification/BeforeAfterTraffic";
import RollbackVerification from "../components/verification/RollbackVerification";
import SimulationNotice from "../components/verification/SimulationNotice";
import { CLASSIFIER_ATTRIBUTION_GROUNDING_CHECK_MAX_DIFF } from "../data/explainabilityFeature15Data";
import {
  CROSS_DAY_FOLDS,
  CROSS_DAY_FAILURE_MODES,
  CROSS_DAY_METHODOLOGY_NOTE,
  CROSS_DAY_MULTI_DAY_VERDICT,
  CROSS_DAY_EXCLUDED_DAY,
} from "../data/crossDayGeneralizationData";
import { getDemoExample, runDemoMitigateVerify, type DemoManifest, type DemoMitigateVerifyResult } from "../services/demoService";
import type { ExplanationExample } from "../types/explainability";
import "./DemoPage.css";

const HORIZONS = ["1", "2", "3", "5"] as const;

export default function DemoPage() {
  const [manifest, setManifest] = useState<DemoManifest | null>(null);
  const [example, setExample] = useState<ExplanationExample | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [hasRun, setHasRun] = useState(false);
  const [runCount, setRunCount] = useState(0);
  const [result, setResult] = useState<DemoMitigateVerifyResult | null>(null);

  useEffect(() => {
    getDemoExample()
      .then(({ manifest, example }) => {
        setManifest(manifest);
        setExample(example);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load the demo sequence."));
  }, []);

  const mitreStageRows = useMemo(() => {
    if (!example) return [];
    return Object.entries(example.mitre_evidence.stage_scores).map(([stage, score]) => ({
      stage,
      score,
      label: example.mitre_evidence.stage_labels[stage] ?? "—",
      isPrimary: stage === example.mitre_evidence.primary_stage,
    }));
  }, [example]);

  function handleRunDemo() {
    if (!example) return;
    setResult(runDemoMitigateVerify(example));
    setHasRun(true);
    setRunCount((c) => c + 1);
  }

  if (error) {
    return (
      <div className="demo-page">
        <SectionHeader title="CyberChess End-to-End Demo" description="OFFLINE RESEARCH DEMONSTRATION" />
        <EmptyState title="Could not load the demo sequence" description={error} />
      </div>
    );
  }

  if (!manifest || !example) {
    return (
      <div className="demo-page">
        <SectionHeader title="CyberChess End-to-End Demo" description="Loading real research artifacts…" />
      </div>
    );
  }

  const seq = manifest.selected_sequence;

  return (
    <div className="demo-page">
      <SectionHeader
        title="CyberChess End-to-End Demo"
        description="OFFLINE RESEARCH DEMONSTRATION — every value below is either a real, already-computed research artifact or a clearly labeled controlled simulation. Nothing here is live network capture, live detection, or a real firewall action."
        actions={
          <Button variant="primary" onClick={handleRunDemo}>
            {hasRun ? `Run Demo Again (run #${runCount + 1})` : "Run Demo"}
          </Button>
        }
      />

      <Card className="demo-page__badge-row">
        <StatusBadge label="OFFLINE RESEARCH DEMONSTRATION" tone="info" />
        <StatusBadge label={`Fixed sequence #${seq.sequence_id} — never changes between runs`} tone="neutral" dot={false} />
        <StatusBadge label="Not live enforcement" tone="warning" dot={false} />
      </Card>

      <Card className="demo-page__selection-note">
        <h3>Why this sequence?</h3>
        <p>{seq.selection_rule}</p>
        <p>
          Selected sequence <strong>#{seq.sequence_id}</strong> (partition: {seq.partition}) — input window{" "}
          {seq.input_start_timestamp} → {seq.input_end_timestamp}, target window at {seq.target_timestamp}, real
          ground-truth label: <strong>{seq.target_window_label}</strong>.
        </p>
      </Card>

      {/* ============================== 1. OBSERVE ============================== */}
      <section className="demo-page__step" id="observe">
        <SectionHeader title="1 · Observe" description="Research-derived — real 10-second temporal history from Feature 6's window table." />
        <div className="demo-page__metric-row">
          <MetricCard eyebrow="Observation timestamp" value={seq.input_end_timestamp} detail="Last window of the 10-second input history" statusLabel="Research-derived" statusTone="info" />
          <MetricCard eyebrow="Network-state dimensions" value="68" detail="65 features + Protocol_0/6/17 one-hot" statusLabel="Fixed contract" statusTone="neutral" />
          <MetricCard eyebrow="History length" value="10 windows" detail="1-second windows, gap-safe sequence" statusLabel="Research-derived" statusTone="info" />
        </div>
        <DataTable
          columns={[
            { key: "window_id", header: "Window", render: (r) => r.window_id },
            { key: "window_start", header: "Start", render: (r) => r.window_start },
            { key: "observation_count", header: "Flows/s", render: (r) => r.observation_count },
            { key: "Tot Fwd Pkts", header: "Fwd Pkts", render: (r) => r["Tot Fwd Pkts"] },
            { key: "Tot Bwd Pkts", header: "Bwd Pkts", render: (r) => r["Tot Bwd Pkts"] },
            { key: "Flow Duration", header: "Flow Duration (µs)", render: (r) => Math.round(r["Flow Duration"]).toLocaleString() },
          ]}
          rows={manifest.observe.ten_window_history}
          getRowKey={(r) => String(r.window_id)}
        />
      </section>

      {/* ============================== 2. IDENTIFY ============================== */}
      <section className="demo-page__step" id="identify">
        <SectionHeader title="2 · Identify" description="Research-derived — real Feature 13 attack-progression probability at the existing 0.50 threshold." />
        <div className="demo-page__metric-row">
          <MetricCard
            eyebrow="Attack probability (K=1)"
            value={`${(example.attack_probability * 100).toFixed(1)}%`}
            detail={`Predicted class: ${example.prediction}`}
            statusLabel="Research-derived"
            statusTone="info"
          />
          <MetricCard
            eyebrow="Ground truth (K=1 target)"
            value={seq.target_window_label}
            detail="Real label for this sequence's target window"
            statusLabel="Observed"
            statusTone="success"
          />
        </div>
      </section>

      {/* ============================== 3. PREDICT ============================== */}
      <section className="demo-page__step" id="predict">
        <SectionHeader title="3 · Predict" description="Research-derived — real Feature 12/13 K-step forecast and attack-progression probability." />
        <DataTable
          columns={[
            { key: "h", header: "Horizon (K)", render: (r) => `K=${r.h}` },
            { key: "prob", header: "Attack probability", render: (r) => (r.prob !== null && r.prob !== undefined ? `${(r.prob * 100).toFixed(1)}%` : "— Not available") },
            { key: "cls", header: "Predicted class", render: (r) => (r.cls !== undefined ? r.cls : "— Not available") },
            { key: "actual", header: "Actual future label", render: (r) => r.actual ?? "— Not available" },
          ]}
          rows={HORIZONS.map((h) => {
            const entry = manifest.selected_sequence && (example.feature_13_probability as Record<string, { probability: number; predicted_class: number; actual_future_label: string } | undefined>)[h];
            return { h, prob: entry?.probability ?? null, cls: entry?.predicted_class, actual: entry?.actual_future_label };
          })}
          getRowKey={(r) => r.h}
        />
      </section>

      {/* ============================== 4. EXPLAIN ============================== */}
      <section className="demo-page__step" id="explain">
        <SectionHeader title="4 · Explain" description="Research-derived — real Feature 15 attribution/occlusion evidence for this exact sequence. LLM layer (if configured) is interpretation-only and cannot change any value shown here." />
        <ClassifierAttribution example={example} groundingCheckMaxDiff={CLASSIFIER_ATTRIBUTION_GROUNDING_CHECK_MAX_DIFF} />
      </section>

      {/* ============================== 5. MITRE ============================== */}
      <section className="demo-page__step" id="mitre">
        <SectionHeader title="5 · MITRE ATT&CK" description="Research-derived — real Feature 14 rule-based evidence mapping. Candidate mappings are not treated as ground truth." />
        <div className="demo-page__metric-row">
          <MetricCard eyebrow="Primary mapped stage" value={example.mitre_evidence.primary_stage} detail="Highest-evidence stage for this sequence" statusLabel="Research-derived" statusTone="info" />
        </div>
        <DataTable
          columns={[
            { key: "stage", header: "Stage", render: (r) => (r.isPrimary ? `★ ${r.stage}` : r.stage) },
            { key: "score", header: "Evidence score", render: (r) => r.score },
            { key: "label", header: "Evidence quality", render: (r) => r.label },
          ]}
          rows={mitreStageRows}
          getRowKey={(r) => r.stage}
        />
        <p className="demo-page__limitations-note">Known limitations: {example.limitations.join(" ")}</p>
      </section>

      {/* ============================== 6 & 7. MITIGATE / VERIFY ============================== */}
      <section className="demo-page__step" id="mitigate-verify">
        <SectionHeader
          title="6 · Mitigate  &nbsp;→&nbsp;  7 · Verify"
          description="CONTROLLED MITIGATION SIMULATION — click Run Demo to compute the deterministic policy decision, simulated traffic effect, and simulated verification for this sequence. A second click produces identical output."
        />
        {!hasRun && (
          <EmptyState title="Not yet run" description="Click “Run Demo” above to compute the Mitigate and Verify steps for this fixed sequence." />
        )}
        {hasRun && result && (
          <>
            <MitigationHeader />
            <StatusBadge label="CONTROLLED MITIGATION SIMULATION" tone="warning" />
            <div className="demo-page__two-col">
              <ThreatStateCard input={result.mitigationInput} evidenceQuality={result.decision.evidenceQuality} />
              <PolicyDecisionCard decision={result.decision} policyConfig={result.policyConfig} />
            </div>
            <RecommendedAction decision={result.decision} />
            <MitigationEvidence input={result.mitigationInput} />
            <h4 className="demo-page__subheading">Safety guarantees (this simulation never does the following)</h4>
            <MitigationSafetyNotice />

            <div className="demo-page__divider" />

            <VerificationHeader status={result.verificationSummary.status} source={result.mitigationInput.source} />
            <SimulationNotice />
            <VerificationResultCard status={result.verificationSummary.status} reason={result.verificationSummary.reason} verifiedAt={result.verificationSummary.verifiedAt} />
            <BeforeAfterTraffic comparisons={result.verificationSummary.trafficComparisons} />
            <VerificationObjectives objectives={result.verificationSummary.objectives} />
            <RollbackVerification rollback={result.verificationSummary.rollback} />
            <p className="demo-page__distinction-note">
              This is a <strong>simulation verification</strong> (arithmetic over a simulated traffic model), not a{" "}
              <strong>real network verification</strong> — no real packets were inspected or blocked.
            </p>
          </>
        )}
      </section>

      {/* ============================== FEATURE 17 SUMMARY ============================== */}
      <section className="demo-page__step" id="cross-day">
        <SectionHeader title="Cross-Day Generalization (Feature 17)" description="Research-derived — real Feature 17 results, unmodified. No winner is declared." />
        <p>{CROSS_DAY_METHODOLOGY_NOTE}</p>
        <p className="demo-page__excluded-day">
          Excluded: {CROSS_DAY_EXCLUDED_DAY.day} — {CROSS_DAY_EXCLUDED_DAY.reason}
        </p>
        <DataTable
          columns={[
            { key: "foldName", header: "Fold", render: (r) => r.foldName },
            { key: "holdoutDay", header: "Held-out day", render: (r) => r.holdoutDay },
            { key: "frozenF1", header: "Frozen F1 / FPR", render: (r) => `${r.fullPipelineFrozen.f1.toFixed(3)} / ${r.fullPipelineFrozen.fpr.toFixed(3)}` },
            { key: "multiF1", header: "Multi-day F1 / FPR", render: (r) => `${r.fullPipelineMultiDay.f1.toFixed(3)} / ${r.fullPipelineMultiDay.fpr.toFixed(3)}` },
          ]}
          rows={CROSS_DAY_FOLDS}
          getRowKey={(r) => r.foldName}
        />
        <h4 className="demo-page__subheading">Observed failure modes (not hidden)</h4>
        <ul className="demo-page__failure-list">
          {CROSS_DAY_FAILURE_MODES.map((f) => (
            <li key={f}>{f}</li>
          ))}
        </ul>
        <p className="demo-page__verdict-note">{CROSS_DAY_MULTI_DAY_VERDICT}</p>
      </section>
    </div>
  );
}
