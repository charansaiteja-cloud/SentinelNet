"""Detection pipeline: baseline learning, scoring, rules, and alert cooldown."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sentinel_net.detector import AnomalyDetector
from sentinel_net.features import FEATURE_NAMES, PacketFeatures

# Ports that are almost never legitimate on a monitored corporate segment.
# This is a documented heuristic layered on top of the model, not a substitute
# for it. Override with ``risky_ports`` if your environment differs.
DEFAULT_RISKY_PORTS: frozenset[int] = frozenset({23, 2323, 4444, 5555, 1337, 31337, 6667, 9001})


@dataclass(frozen=True)
class Alert:
    """One suspicious packet, serialisable to JSON."""

    timestamp: str
    src: str
    dst: str
    protocol: str
    dst_port: int
    score: float
    reason: str
    length: int
    baseline_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "src": self.src,
            "dst": self.dst,
            "protocol": self.protocol,
            "dst_port": self.dst_port,
            "score": round(self.score, 6),
            "reason": self.reason,
            "length": self.length,
            "baseline_size": self.baseline_size,
        }


@dataclass
class PipelineStats:
    packets_seen: int = 0
    baseline_packets: int = 0
    alerts: int = 0
    suppressed: int = 0
    model_alerts: int = 0
    rule_alerts: int = 0
    started_at: float = field(default_factory=time.monotonic)

    def summary(self) -> dict[str, Any]:
        elapsed = max(time.monotonic() - self.started_at, 1e-9)
        return {
            "packets_seen": self.packets_seen,
            "baseline_packets": self.baseline_packets,
            "alerts": self.alerts,
            "suppressed": self.suppressed,
            "model_alerts": self.model_alerts,
            "rule_alerts": self.rule_alerts,
            "elapsed_seconds": round(elapsed, 3),
            "packets_per_second": round(self.packets_seen / elapsed, 2),
        }


class DetectionPipeline:
    """Two-phase pipeline: learn a baseline, then score every packet."""

    def __init__(
        self,
        detector: AnomalyDetector | None = None,
        baseline_packets: int = 200,
        cooldown_seconds: float = 10.0,
        risky_ports: frozenset[int] = DEFAULT_RISKY_PORTS,
        on_alert: Callable[[Alert], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if baseline_packets < 10:
            raise ValueError("baseline_packets must be at least 10")
        if cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must not be negative")
        self.detector = detector or AnomalyDetector()
        self.baseline_packets = baseline_packets
        self.cooldown_seconds = cooldown_seconds
        self.risky_ports = risky_ports
        self.on_alert = on_alert
        self._clock = clock
        self._baseline: list[list[float]] = []
        self._last_alert: dict[tuple[str, int, str], float] = {}
        self.stats = PipelineStats()
        if detector is not None and detector.is_fitted:
            self._baseline = []

    @property
    def is_ready(self) -> bool:
        return self.detector.is_fitted

    def _fit_if_ready(self) -> None:
        if self.is_ready:
            return
        if len(self._baseline) < self.baseline_packets:
            return
        self.detector.fit(self._baseline)
        self.stats.baseline_packets = len(self._baseline)

    def _in_cooldown(self, key: tuple[str, int, str], now: float) -> bool:
        previous = self._last_alert.get(key)
        if previous is not None and now - previous < self.cooldown_seconds:
            self.stats.suppressed += 1
            return True
        self._last_alert[key] = now
        return False

    def process(
        self,
        features: PacketFeatures,
        src: str,
        dst: str,
        protocol: str,
        dst_port: int,
        timestamp: float | None = None,
    ) -> Alert | None:
        """Observe one packet and return an alert when it is suspicious."""
        self.stats.packets_seen += 1

        if not self.is_ready:
            self._baseline.append(features.as_vector())
            self._fit_if_ready()
            return None

        score = self.detector.score(features.as_vector())
        model_anomaly = score > self.detector.threshold
        rule_anomaly = dst_port in self.risky_ports

        if not (model_anomaly or rule_anomaly):
            return None

        reason = "risky_dst_port" if rule_anomaly else "model_anomaly"
        now = self._clock()
        if self._in_cooldown((src, dst_port, reason), now):
            return None

        captured_at = (
            datetime.fromtimestamp(float(timestamp), tz=timezone.utc).isoformat(
                timespec="milliseconds"
            )
            if timestamp is not None
            else datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        )
        alert = Alert(
            timestamp=captured_at,
            src=src,
            dst=dst,
            protocol=protocol,
            dst_port=dst_port,
            score=score,
            reason=reason,
            length=int(features.length),
            baseline_size=self.detector.baseline_size,
        )
        self.stats.alerts += 1
        if rule_anomaly:
            self.stats.rule_alerts += 1
        else:
            self.stats.model_alerts += 1
        if self.on_alert is not None:
            self.on_alert(alert)
        return alert


def feature_names() -> tuple[str, ...]:
    """Expose the schema for documentation and tests."""
    return FEATURE_NAMES
