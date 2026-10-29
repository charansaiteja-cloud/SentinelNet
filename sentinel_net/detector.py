"""Isolation Forest wrapper with an explicit, inspectable threshold."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from sentinel_net.features import FEATURE_NAMES


class DetectorNotFittedError(RuntimeError):
    """Raised when scoring is attempted before fitting."""


class InsufficientBaselineError(ValueError):
    """Raised when the baseline is too small to fit a stable model."""


class AnomalyDetector:
    """Unsupervised anomaly detector for packet feature vectors.

    The model learns what normal traffic looks like from a baseline capture.
    A packet is anomalous when its anomaly score exceeds the baseline score at
    the ``1 - contamination`` quantile. The threshold is stored explicitly so
    operators can inspect and tune it instead of relying on an opaque
    ``predict()`` call.
    """

    def __init__(
        self,
        contamination: float = 0.02,
        seed: int = 42,
        n_estimators: int = 200,
        min_baseline: int = 20,
    ) -> None:
        if not 0.0 < contamination < 0.5:
            raise ValueError("contamination must be between 0 and 0.5")
        if min_baseline < 10:
            raise ValueError("min_baseline must be at least 10")
        self.contamination = contamination
        self.seed = seed
        self.n_estimators = n_estimators
        self.min_baseline = min_baseline
        self._model: IsolationForest | None = None
        self._threshold: float | None = None
        self._baseline_size = 0

    @property
    def is_fitted(self) -> bool:
        return self._model is not None

    @property
    def threshold(self) -> float:
        if self._threshold is None:
            raise DetectorNotFittedError("detector has not been fitted")
        return self._threshold

    @property
    def baseline_size(self) -> int:
        return self._baseline_size

    def fit(self, vectors: Sequence[Sequence[float]]) -> None:
        matrix = np.asarray(vectors, dtype=float)
        if matrix.ndim != 2 or matrix.shape[1] != len(FEATURE_NAMES):
            raise ValueError(f"expected a 2-D matrix with {len(FEATURE_NAMES)} columns")
        if matrix.shape[0] < self.min_baseline:
            raise InsufficientBaselineError(
                f"need at least {self.min_baseline} baseline packets, got {matrix.shape[0]}"
            )

        model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.seed,
            n_jobs=1,
        )
        model.fit(matrix)

        # decision_function is higher for normal points; negate it so that a
        # larger score always means "more anomalous".
        scores = -model.decision_function(matrix)
        self._model = model
        self._threshold = float(np.quantile(scores, 1.0 - self.contamination))
        self._baseline_size = int(matrix.shape[0])

    def score(self, vector: Sequence[float]) -> float:
        if self._model is None:
            raise DetectorNotFittedError("detector has not been fitted")
        row = np.asarray(vector, dtype=float).reshape(1, -1)
        if row.shape[1] != len(FEATURE_NAMES):
            raise ValueError(f"expected {len(FEATURE_NAMES)} features")
        return float(-self._model.decision_function(row)[0])

    def is_anomaly(self, vector: Sequence[float]) -> bool:
        return self.score(vector) > self.threshold

    def save(self, path: str | Path) -> None:
        if self._model is None or self._threshold is None:
            raise DetectorNotFittedError("cannot save an unfitted detector")
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self._model,
                "threshold": self._threshold,
                "baseline_size": self._baseline_size,
                "contamination": self.contamination,
                "seed": self.seed,
                "feature_names": FEATURE_NAMES,
            },
            target,
        )

    @classmethod
    def load(cls, path: str | Path) -> AnomalyDetector:
        payload = joblib.load(Path(path))
        if payload.get("feature_names") != FEATURE_NAMES:
            raise ValueError("saved model uses a different feature schema")
        detector = cls(
            contamination=float(payload["contamination"]),
            seed=int(payload["seed"]),
        )
        detector._model = payload["model"]
        detector._threshold = float(payload["threshold"])
        detector._baseline_size = int(payload["baseline_size"])
        return detector
