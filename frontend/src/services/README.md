# services/

Data-access modules that abstract where research-pipeline data comes from,
so pages depend only on function calls, not on how the data is fetched.

- `networkStateService.ts` (Frontend Feature 3): fetches static JSON
  snapshots generated from the Feature 5/6 research artifacts
  (`data/processed/temporal/temporal_windows.csv` and
  `sequence_metadata.csv`) under `frontend/public/data/`. Swapping the
  `fetch()` calls inside it for real API requests later requires no changes
  to consuming components.
- `forecastingService.ts` (Frontend Feature 4): wraps the small Feature 12
  (`results/forecasting/`) and LSTM (`results/lstm/`) metrics as typed async
  functions. Data is bundled as constants (see `src/data/lstmWorldModelData.ts`)
  rather than fetched, since it is small, but the async function signatures
  match `networkStateService.ts` so a future API can replace the
  implementation without changing consuming components.
- `forecastFutureStateService.ts` (Frontend Feature 4B): fetches static JSON
  snapshots generated from the EXISTING Feature 12 saved rollout predictions
  (`data/processed/forecasting/test_rollout_predictions.npy`) and the frozen,
  train-fitted preprocessing pipeline, under `frontend/public/data/`. Powers
  the "Future Network State" section of the Forecasting page with real saved
  model outputs (never fabricated), in both standardized and raw-unit form.
- `attackAnalysisService.ts` (Frontend Feature 5): wraps the small Feature 13
  aggregate metrics (`src/data/attackProgressionData.ts`, Frontend Feature 2)
  as an async function, and fetches static JSON snapshots generated from the
  EXISTING Feature 13 per-sequence predictions artifact
  (`results/attack_progression/attack_progression_predictions.csv`) under
  `frontend/public/data/` for the Attack Analysis page's sequence explorer.
- `mitreService.ts` (Frontend Feature 6): wraps the small Feature 14
  rule/evidence data (`src/data/mitreRulesData.ts`, read directly from
  `results/mitre/mitre_stage_rule_definitions.json` and
  `mitre_stage_mapping_metrics.json`) as an async function. Data is bundled
  as constants since it is small, matching the `forecastingService.ts`
  pattern.
- `explainabilityService.ts` (Frontend Feature 7): wraps the small Feature 15
  aggregate metrics/checks/config (`src/data/explainabilityFeature15Data.ts`,
  read directly from `results/explainability/`) as an async function, and
  fetches `frontend/public/data/explainability_examples.json` - a
  byte-for-byte copy of the real
  `results/explainability/explanation_examples.json` artifact (20 real local
  explanations), unmodified.
- `frozenGeneralizationService.ts` (Frontend Feature 8): wraps the small
  Feature 16 frozen cross-capture evaluation data
  (`src/data/frozenGeneralizationData.ts`, read directly from
  `results/frozen_generalization/` and
  `results/external_dataset_preparation/`) as an async function. Data is
  bundled as constants since it is small, matching the
  `forecastingService.ts` pattern.
- `dataset/` (Frontend Feature 9): NOT a research-artifact reader - this
  subfolder holds the browser-side CSV ingestion/compatibility engine for
  the Dataset Ingestion page (`csvParser.ts`, `datasetCompatibility.ts`,
  `schemaDetection.ts`, `pcapPipeline.ts`). It compares uploaded data against
  the real CyberChess feature requirements in
  `src/data/cyberChessFeatureRequirements.ts` (read from
  `results/model_feature_list.json`), but processes user-supplied files
  entirely client-side; it never reads from or writes to `results/` or
  `data/`.
- `mitigation/` (Frontend Feature 10): `mitigationService.ts` builds typed
  `MitigationInput` records from REAL Feature 13/14/15 data already fetched
  by `explainabilityService.ts` (never duplicates that artifact) and exposes
  the demonstration scenarios (`src/data/mitigationScenarios.ts`).
  `mitigationPolicy.ts` is the deterministic, pure decision function (no
  network calls, no side effects) using documented thresholds from
  `src/data/mitigationPolicyConfig.ts`. `mitigationSimulation.ts` is a pure,
  arithmetic-only traffic simulation - it never issues a firewall, shell, or
  network command of any kind.
- `verification/` (Frontend Feature 11): `verificationService.ts` reuses
  Feature 10's `mitigationService`/`mitigationPolicy`/`mitigationSimulation`
  (calls the same functions, never reimplements their math) to assemble a
  `VerificationInput`. `verificationEngine.ts` is the pure, deterministic
  verification-objective evaluator using documented criteria from
  `src/data/verificationConfig.ts` - every result is a "SIMULATED
  VERIFICATION", never a claim about a real network.
