"""
Feature 15 - model-grounded explainability engine.

"Why did the model make this prediction?"

Explains the actual deployed forecasting path:

    Feature 10 LSTM (frozen) -> predicted next state Shat(t+1)
        -> Feature 11 classifier (frozen) -> P(Infiltration)

Because the LSTM itself has no exact closed-form per-input attribution,
the explanation is explicitly decomposed into two DIFFERENT, clearly
labeled layers (never conflated):

    LAYER C - CLASSIFIER ATTRIBUTION (exact, cheap):
        LogisticRegression is linear, so its logit decomposes exactly as
        logit = intercept + sum_f(coef_f * state_value_f). Each term is
        an EXACT per-dimension contribution to THIS prediction's logit -
        not an approximation. Computed over the 68 dimensions of the
        LSTM-predicted next state (temporal position = "t+1", a single
        future point, not itself decomposed by history timestep).

    LAYER D - LSTM TEMPORAL OCCLUSION DIAGNOSTIC (approximate, defensible):
        The LSTM's OWN sensitivity to its 10-timestep input history is
        measured by controlled occlusion: replace one (timestep, feature)
        cell (or one whole timestep) with a TRAIN-mean baseline value,
        rerun the frozen LSTM -> frozen classifier, and record the change
        in P(Infiltration). This is a standard perturbation/ablation
        attribution method - NOT an exact attribution, NOT SHAP, and NOT
        the same quantity as Layer C. It preserves temporal structure
        (t-9 .. t) as required.

No model is fit, trained, or modified anywhere in this module.
"""

from pathlib import Path

import numpy as np
import torch

SEQUENCE_LENGTH = 10
EXPECTED_FEATURE_COUNT = 68
TEMPORAL_LABELS = ["t-9", "t-8", "t-7", "t-6", "t-5", "t-4", "t-3", "t-2", "t-1", "t"]


def compute_train_baseline_vector(train_X_scaled: np.ndarray) -> np.ndarray:
    """Deterministic occlusion baseline: mean state vector over every (sequence, timestep)
    position in TRAIN. No leakage - TRAIN statistics only, computed once, never refit."""
    return train_X_scaled.reshape(-1, EXPECTED_FEATURE_COUNT).mean(axis=0).astype("float32")


# ----------------------------------------------------------------------
# LAYER C: exact classifier attribution over the predicted next-state vector
# ----------------------------------------------------------------------
def classifier_attribution(classifier, predicted_state_scaled: np.ndarray, feature_order: list) -> dict:
    """
    Exact per-dimension logit decomposition of the frozen LogisticRegression
    classifier's prediction for ONE 68-dim (already-scaled) state vector.

    Returns a dict with intercept, per-feature contributions (signed, exact),
    the resulting logit/probability (for a grounding cross-check), sorted by
    |contribution| descending.
    """
    inner = classifier.model
    coef = inner.coef_.ravel()
    intercept = float(inner.intercept_.ravel()[0])
    if len(coef) != EXPECTED_FEATURE_COUNT or len(feature_order) != EXPECTED_FEATURE_COUNT:
        raise ValueError(f"Coefficient/feature-order length mismatch: coef={len(coef)}, feature_order={len(feature_order)}.")

    contributions = coef * predicted_state_scaled  # exact, elementwise
    logit = intercept + float(contributions.sum())
    proba = 1.0 / (1.0 + np.exp(-logit))

    ranked = sorted(
        (
            {"feature": feature_order[i], "time_step": "t+1", "contribution": float(contributions[i]),
             "direction": "attack" if contributions[i] > 0 else ("benign" if contributions[i] < 0 else "neutral"),
             "coefficient": float(coef[i]), "state_value": float(predicted_state_scaled[i])}
            for i in range(EXPECTED_FEATURE_COUNT)
        ),
        key=lambda r: abs(r["contribution"]), reverse=True,
    )
    return {"intercept": intercept, "logit": float(logit), "reconstructed_probability": float(proba), "contributions": ranked}


# ----------------------------------------------------------------------
# LAYER D: LSTM temporal occlusion diagnostics (perturbation-based)
# ----------------------------------------------------------------------
@torch.no_grad()
def _predict_proba_from_history(lstm_model, classifier, history: np.ndarray, device) -> float:
    """history: (10, 68) -> LSTM one-step forward -> classifier -> P(Infiltration)."""
    x = torch.from_numpy(history[None, :, :].astype("float32")).to(device)
    pred_state = lstm_model(x).cpu().numpy()[0]  # (68,)
    proba = classifier.predict_proba(pred_state[None, :])
    pos_idx = list(classifier.classes_).index(1)
    return float(proba[0, pos_idx]), pred_state


def per_timestep_occlusion(lstm_model, classifier, history: np.ndarray, baseline_vector: np.ndarray, device) -> list:
    """Coarse diagnostic: occlude one WHOLE timestep at a time (10 forward passes)."""
    full_proba, _ = _predict_proba_from_history(lstm_model, classifier, history, device)
    results = []
    for t in range(SEQUENCE_LENGTH):
        occluded = history.copy()
        occluded[t, :] = baseline_vector
        occ_proba, _ = _predict_proba_from_history(lstm_model, classifier, occluded, device)
        contribution = full_proba - occ_proba
        results.append({
            "time_step": TEMPORAL_LABELS[t], "contribution": float(contribution),
            "direction": "attack" if contribution > 0 else ("benign" if contribution < 0 else "neutral"),
            "full_probability": full_proba, "occluded_probability": occ_proba,
        })
    return results


def per_cell_occlusion(lstm_model, classifier, history: np.ndarray, baseline_vector: np.ndarray, feature_order: list, device) -> list:
    """Fine-grained diagnostic: occlude one (timestep, feature) cell at a time (10*68=680 forward passes).
    Expensive - intended only for a small deterministic sample (see evaluate_explainability.py)."""
    full_proba, _ = _predict_proba_from_history(lstm_model, classifier, history, device)
    results = []
    for t in range(SEQUENCE_LENGTH):
        for f in range(EXPECTED_FEATURE_COUNT):
            occluded = history.copy()
            occluded[t, f] = baseline_vector[f]
            occ_proba, _ = _predict_proba_from_history(lstm_model, classifier, occluded, device)
            contribution = full_proba - occ_proba
            results.append({
                "feature": feature_order[f], "time_step": TEMPORAL_LABELS[t], "contribution": float(contribution),
                "direction": "attack" if contribution > 0 else ("benign" if contribution < 0 else "neutral"),
            })
    return results, full_proba


def summarize_temporal(per_cell_results: list) -> dict:
    """Aggregate per-cell occlusion into (a) per-timestep summary and (b) per-feature-group summary."""
    import pandas as pd
    df = pd.DataFrame(per_cell_results)
    by_timestep = df.groupby("time_step")["contribution"].agg(["mean", "sum", lambda s: s.abs().sum()])
    by_timestep.columns = ["mean_contribution", "sum_contribution", "sum_abs_contribution"]
    by_feature = df.groupby("feature")["contribution"].agg(["mean", "sum", lambda s: s.abs().sum()])
    by_feature.columns = ["mean_contribution", "sum_contribution", "sum_abs_contribution"]
    return {
        "by_timestep": by_timestep.reset_index().to_dict(orient="records"),
        "by_feature": by_feature.sort_values("sum_abs_contribution", ascending=False).reset_index().to_dict(orient="records"),
    }
