"""
Feature 11 - downstream state-to-attack classifier abstraction.

Wraps a simple, interpretable classifier that maps a 68-dimensional
network-state vector S(t+1) (either the ground-truth state or the LSTM
World Model's predicted state) to a discrete attack-state prediction
(Benign=0 / Infilteration=1).

This is NOT the LSTM World Model and is never used to retrain it. The
LSTM (Feature 10) predicts network-state dynamics; this classifier
separately learns the state-to-attack-label mapping from ground-truth
states only (see train_next_state_attack_classifier.py for the
methodology and why).
"""

import numpy as np
from sklearn.linear_model import LogisticRegression

EXPECTED_STATE_DIM = 68
LABEL_ENCODING = {"Benign": 0, "Infilteration": 1}


class NextStateAttackClassifier:
    """Thin, explicit wrapper around LogisticRegression for S(t+1) -> attack-state."""

    def __init__(self, max_iter=2000, class_weight="balanced", random_state=42, solver="lbfgs"):
        self.config = {
            "max_iter": max_iter,
            "class_weight": class_weight,
            "random_state": random_state,
            "solver": solver,
        }
        self.model = LogisticRegression(**self.config)
        self._fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray) -> "NextStateAttackClassifier":
        if X.shape[1] != EXPECTED_STATE_DIM:
            raise ValueError(f"Expected {EXPECTED_STATE_DIM}-dimensional state input, got {X.shape[1]}.")
        self.model.fit(X, y)
        self._fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        self._check_fitted()
        if X.shape[1] != EXPECTED_STATE_DIM:
            raise ValueError(f"Expected {EXPECTED_STATE_DIM}-dimensional state input, got {X.shape[1]}.")
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        self._check_fitted()
        if X.shape[1] != EXPECTED_STATE_DIM:
            raise ValueError(f"Expected {EXPECTED_STATE_DIM}-dimensional state input, got {X.shape[1]}.")
        return self.model.predict_proba(X)

    def _check_fitted(self):
        if not self._fitted:
            raise RuntimeError("NextStateAttackClassifier must be fit() before predict()/predict_proba().")

    @property
    def classes_(self):
        self._check_fitted()
        return self.model.classes_
