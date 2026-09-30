# CyberChess

**AI-Based Network Attack Detection, Forecasting & Real-Time DDoS Mitigation** — a research prototype built for Smart India Hackathon (SIH).

> **Status: offline/research predictive cyber-defense prototype with a controlled mitigation *simulation*.**
> CyberChess is **not** a production firewall. It does **not** perform live network enforcement, and it does **not** modify any real firewall, router, or network device. Every "mitigation" and "verification" result in this project is an explicitly labeled, deterministic, arithmetic-only **simulation** over research data — never a claim about real traffic being blocked.

## Live Demo

**[Open CyberChess Live Demo](https://cybrrches.vercel.app/overview)**

The public CyberChess research/demo interface for exploring this prototype, including its **simulated** mitigation and verification workflow. Like the rest of the project, the demo does not perform real firewall enforcement or real network verification.

---

## The research cycle: Observe → Identify → Predict → Mitigate → Verify

CyberChess is organized around one repeating cycle, applied to network traffic represented as a 68-dimensional state vector:

1. **Observe** — raw CICFlowMeter-style flow features are cleaned, assembled into a 65-feature + one-hot-Protocol (68-dimensional) per-flow state, and aggregated into 1-second temporal windows.
2. **Identify** — baseline classifiers (Logistic Regression, Random Forest) and a next-state classifier estimate whether a window's traffic is anomalous.
3. **Predict** — an LSTM **World Model** forecasts the network's *future* state (K=1, 2, 3, 5 steps ahead), and an attack-progression probability is derived from that forecast.
4. **Explain** — feature-attribution and LSTM-occlusion evidence explain *why* a prediction was made, optionally rephrased (never altered) by a strictly evidence-bound LLM layer.
5. **MITRE ATT&CK mapping** — a deterministic, rule-based evidence engine maps observed traffic characteristics to candidate ATT&CK stages, with explicit confidence/evidence-quality labeling.
6. **Mitigate** — a documented policy engine proposes one of `MONITOR / ALERT / RATE_LIMIT / TEMPORARY_BLOCK / ESCALATE`, and a **controlled, arithmetic-only simulation** models the traffic effect. No firewall, shell, or network command is ever issued.
7. **Verify** — a deterministic verification engine checks the simulated mitigation against documented objectives (threat suppression, legitimate-traffic preservation, action status, reversibility) and reports a **simulated verification** result.

---

## What's actually implemented

| Area | What it is | Key evidence |
|---|---|---|
| Temporal network-state modelling | 65 CICFlowMeter-style features + Protocol one-hot → 68-D state, 1-second windows, 10-step sequences | `src/data/build_temporal_windows.py`, `results/state_schema.json` |
| Baseline classifiers | Logistic Regression + Random Forest on flattened 10-step sequences | `src/models/train_logistic_baseline.py`, `train_random_forest_baseline.py` |
| LSTM World Model | `LSTM(68, hidden=128, layers=2, dropout=0.2) → Linear(128, 68)`, trained with a fixed seed and early stopping | `src/models/lstm_world_model.py`, `results/lstm/` |
| K-step forecasting | Recursive rollout to K=1/2/3/5, with MSE/RMSE/MAE and (as of Feature 17) median/P95/outlier-flagged per-feature error | `src/models/k_step_forecaster.py`, `results/forecasting/` |
| Attack progression probability | A state-to-attack classifier applied to forecasted future states | `src/models/attack_progression_probability.py`, `results/attack_progression/` |
| MITRE ATT&CK evidence mapping | Deterministic rule engine, never claims ground truth | `src/models/mitre_stage_mapper.py`, `results/mitre/` |
| Explainability | Feature attribution + LSTM occlusion, real per-sequence examples | `src/models/model_explainer.py`, `results/explainability/` |
| LLM explanation layer | **Interpretation-only** — cannot change a probability, classification, MITRE stage, or mitigation decision; defaults to a no-op `DisabledLLMExplainer` requiring no API key | `src/models/llm_explainer.py` |
| Controlled mitigation simulation | Pure, deterministic policy + arithmetic traffic simulation — no firewall/shell/network commands anywhere in the code path | `frontend/src/services/mitigation/` |
| Verification simulation | Pure, deterministic objective evaluation over the simulated mitigation | `frontend/src/services/verification/` |
| CSV interface | Browser-side CSV ingestion/schema-compatibility checker against the real 65-feature contract | `frontend/src/services/dataset/` |
| PCAP adapter (offline, with known validation limitations) | Offline `.pcap`→flow→feature adapter; **most feature formulas remain unvalidated against the original CICFlowMeter-V3 generation process** — see [Known limitations](#known-limitations) | `src/data/pcap/`, `results/pcap_validation/` |
| Frozen external / cross-day generalization evaluation | The frozen, Thursday-trained models evaluated (never retrained) on 3 unseen external days, plus a genuine multi-day-training experiment (2 of 4 possible leave-one-day-out folds) | `results/frozen_generalization/`, `results/cross_day_generalization/` |
| End-to-end research demo | A single `/demo` page walking one real, fixed, deterministically-selected sequence through the full 7-step cycle | `frontend/src/pages/DemoPage.tsx`, `results/demo/` |

---

## Known limitations (stated honestly, not hidden)

- **PCAP feature validation is incomplete.** Of the 65 features the PCAP adapter computes, an internal audit against the real 331,027-row training CSV found only 6 fully `VALIDATED`, 21 `PARTIALLY_VALIDATED`, and (after one round of correction) 37 remain `UNVALIDATED`. **PCAP-derived input is not currently approved for frozen-model inference.**
- **No confirmed flow-level correspondence between any raw PCAP sample and the training CSV.** The official CSE-CIC-IDS2018 archive source was located and is plausible, but a direct flow-by-flow correlation attempt found the one candidate segment tested had zero timestamp overlap with the training window.
- **The original test partition contains zero attack sequences** (a known chronological-split artifact), so a *separate* attack-containing external-day evaluation is used instead for attack-recall metrics.
- **Cross-day generalization is inconsistent.** The frozen model's recall/precision/FPR vary substantially across external days; multi-day training changed results in different directions on the two folds tested (one improved FPR, the other degraded it) — **no universal improvement is claimed**, and Random Forest showed degenerate (all-negative) behavior on both multi-day folds.
- **Mitigation/verification are simulations only.** No real network interface, firewall, or traffic-shaping mechanism is touched anywhere in this codebase.
- **The LLM explanation layer is optional and interpretation-only**, and defaults to disabled.

---

## Datasets

CyberChess is trained and evaluated on **CSE-CIC-IDS2018** (Communications Security Establishment & Canadian Institute for Cybersecurity). Several of the largest raw/processed dataset files (up to ~360 MB each) are **intentionally not stored in this Git repository**, to stay within normal GitHub repository-size norms (GitHub hard-blocks any single file over 100 MB). See **[`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md)** for the exact list of excluded files and how to obtain them.

**Official dataset source** (verified reachable and used by this project — see `results/pcap_ground_truth_discovery/` for the full provenance investigation):
- Dataset page: `https://www.unb.ca/cic/datasets/ids-2018.html`
- Public AWS S3 bucket (anonymous read): `s3://cse-cic-ids2018/` — e.g. `aws s3 cp --no-sign-request s3://cse-cic-ids2018/"Processed Traffic Data for ML Algorithms/"<day>.csv .`
- Citation: Sharafaldin, I., Lashkari, A.H., Ghorbani, A.A. — *"Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization."* ICISSP, 2018.

---

## Repository layout

```
src/data/            Feature 1-6 data pipeline (cleaning, states, windows, sequences) + PCAP adapter + Sandbox contract
src/models/           Feature 7-16 model training/evaluation scripts
src/experiments/       Feature 17 (cross-day generalization) and Feature 18 (demo) code
frontend/               React + TypeScript SPA (Vite)
results/                 Every feature's output artifacts (reports, metrics, confusion matrices, trained models)
data/                    Raw and processed datasets (large files partially excluded - see docs/REPRODUCIBILITY.md)
tests/                   Standalone Python validation scripts (no pytest dependency)
docs/                    Additional documentation (Sandbox input contract, reproducibility)
```

## Getting started

See **[`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md)** for full setup instructions (Python dependencies, dataset acquisition, frontend build, and exactly what is/isn't reproducible without the excluded large files).

Quick frontend-only start (uses the bundled, real research-artifact snapshots already checked into `frontend/public/data/` — no dataset download required for this):
```bash
cd frontend
npm install
npm run build   # or: npm run dev
```
