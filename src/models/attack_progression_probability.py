"""
Feature 13 - reusable attack-progression probability utilities.

Converts a 68-dimensional future network-state vector (ground-truth OR
LSTM-predicted) into P(Infiltration) using the FROZEN Feature 11
classifier. This module never fits/retrains/calibrates anything - it
only loads an already-fitted classifier and calls predict_proba().

"Feature 12 answers: what might the future network state look like?
Feature 13 answers: given the predicted future network state, how
strongly does the frozen attack classifier associate that future state
with Infiltration?"
"""

from pathlib import Path

import joblib
import numpy as np
from sklearn.utils.validation import check_is_fitted, NotFittedError

EXPECTED_STATE_DIM = 68
DEFAULT_THRESHOLD = 0.50
POSITIVE_CLASS = 1
NEGATIVE_CLASS = 0


def load_frozen_classifier(path: Path):
    """Load the Feature 11 classifier and verify it is fitted and binary. Never fits/refits."""
    classifier = joblib.load(path)
    inner_model = getattr(classifier, "model", classifier)
    try:
        check_is_fitted(inner_model)
    except NotFittedError as e:
        raise RuntimeError(f"Classifier at {path} is not fitted.") from e
    classes = sorted(int(c) for c in classifier.classes_)
    if classes != [NEGATIVE_CLASS, POSITIVE_CLASS]:
        raise ValueError(f"Classifier at {path} has unexpected classes_ {classes}; expected [0, 1].")
    return classifier


def infiltration_probability(classifier, states: np.ndarray) -> np.ndarray:
    """
    P(Infiltration) for each row of `states` (N, 68).

    Never trains/fits/calibrates anything - a pure inference call on an
    already-frozen classifier.
    """
    if states.ndim != 2 or states.shape[1] != EXPECTED_STATE_DIM:
        raise ValueError(f"Expected states of shape (N, {EXPECTED_STATE_DIM}), got {states.shape}.")
    proba = classifier.predict_proba(states)
    pos_idx = list(classifier.classes_).index(POSITIVE_CLASS)
    return proba[:, pos_idx]


def threshold_predict(proba_infiltration: np.ndarray, threshold: float = DEFAULT_THRESHOLD) -> np.ndarray:
    """
    Explicit, documented thresholding of the probability output.

    Deliberately NOT classifier.predict() - Feature 13's primary output is
    the probability; this function only exists to derive classification
    metrics (precision/recall/F1/confusion matrix) at a clearly stated
    threshold (default 0.50, mathematically equivalent to sklearn's
    default LogisticRegression.predict() decision rule).
    """
    return (proba_infiltration >= threshold).astype(int)
