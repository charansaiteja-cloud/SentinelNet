from __future__ import annotations

import numpy as np
import pytest

from sentinel_net.detector import (
    AnomalyDetector,
    DetectorNotFittedError,
    InsufficientBaselineError,
)
from sentinel_net.features import FEATURE_NAMES


def _baseline(rows: int = 120, seed: int = 7) -> np.ndarray:
    rng = np.random.default_rng(seed)
    data = np.zeros((rows, len(FEATURE_NAMES)))
    data[:, 0] = rng.normal(300, 40, rows).clip(64, 1500)  # length
    data[:, 1] = rng.integers(40000, 60000, rows)  # src_port
    data[:, 2] = rng.choice([80, 443, 53], rows)  # dst_port
    data[:, 3] = rng.choice([1.0, 2.0], rows)  # protocol
    data[:, 8] = rng.normal(100, 30, rows).clip(0, 1200)  # payload
    data[:, 9] = 64
    data[:, 10] = rng.exponential(0.05, rows)
    return data


def test_fit_sets_threshold_and_size() -> None:
    detector = AnomalyDetector(contamination=0.05)
    detector.fit(_baseline())

    assert detector.is_fitted
    assert np.isfinite(detector.threshold)
    assert detector.baseline_size == 120


def test_extreme_packet_scores_higher_than_normal() -> None:
    detector = AnomalyDetector(contamination=0.05)
    data = _baseline()
    detector.fit(data)

    normal = detector.score(data[0])
    anomaly = detector.score([90_000, 65000, 4444, 1, 2, 4, 1, 2, 60_000, 255, 3600])

    assert anomaly > normal
    assert detector.is_anomaly([90_000, 65000, 4444, 1, 2, 4, 1, 2, 60_000, 255, 3600])


def test_small_baseline_is_rejected() -> None:
    detector = AnomalyDetector()

    with pytest.raises(InsufficientBaselineError, match="at least 20"):
        detector.fit(_baseline(rows=10))


def test_wrong_feature_count_is_rejected() -> None:
    detector = AnomalyDetector()

    with pytest.raises(ValueError, match="columns"):
        detector.fit([[1.0, 2.0]])


def test_scoring_before_fit_is_rejected() -> None:
    detector = AnomalyDetector()

    with pytest.raises(DetectorNotFittedError):
        detector.score([0.0] * len(FEATURE_NAMES))
    with pytest.raises(DetectorNotFittedError):
        detector.is_anomaly([0.0] * len(FEATURE_NAMES))


def test_score_rejects_wrong_width() -> None:
    detector = AnomalyDetector()
    detector.fit(_baseline())

    with pytest.raises(ValueError, match="features"):
        detector.score([0.0])


def test_save_and_load_roundtrip(tmp_path) -> None:
    detector = AnomalyDetector(contamination=0.05)
    detector.fit(_baseline())
    path = tmp_path / "model.joblib"
    detector.save(path)

    restored = AnomalyDetector.load(path)

    assert restored.is_fitted
    assert restored.threshold == pytest.approx(detector.threshold)
    assert restored.baseline_size == detector.baseline_size
    assert restored.is_anomaly([90_000, 65000, 4444, 1, 2, 4, 1, 2, 60_000, 255, 3600])


def test_saving_unfitted_detector_is_rejected(tmp_path) -> None:
    with pytest.raises(DetectorNotFittedError):
        AnomalyDetector().save(tmp_path / "model.joblib")


def test_constructor_validation() -> None:
    with pytest.raises(ValueError, match="contamination"):
        AnomalyDetector(contamination=0.9)
    with pytest.raises(ValueError, match="min_baseline"):
        AnomalyDetector(min_baseline=5)
