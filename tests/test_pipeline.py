from __future__ import annotations

from sentinel_net.features import PacketFeatures
from sentinel_net.pipeline import Alert, DetectionPipeline


def _features(
    length: float = 300,
    dst_port: float = 443,
    payload: float = 100,
) -> PacketFeatures:
    return PacketFeatures(
        length=length,
        src_port=50000,
        dst_port=dst_port,
        protocol=1,
        tcp_flags=2,
        ip_version=4,
        private_src=1,
        dst_port_bucket=0 if dst_port < 1024 else 1,
        payload_length=payload,
        ttl=64,
        inter_arrival=0.05,
    )


def _baseline_pipeline(**kwargs) -> DetectionPipeline:
    kwargs.setdefault("cooldown_seconds", 0)
    pipeline = DetectionPipeline(baseline_packets=20, **kwargs)
    for _ in range(20):
        assert pipeline.process(_features(), "10.0.0.1", "10.0.0.2", "tcp", 443) is None
    assert pipeline.is_ready
    return pipeline


def test_baseline_must_complete_before_scoring() -> None:
    pipeline = DetectionPipeline(baseline_packets=20)

    for _ in range(19):
        assert pipeline.process(_features(), "a", "b", "tcp", 443) is None

    assert not pipeline.is_ready
    assert pipeline.stats.baseline_packets == 0
    assert pipeline.stats.packets_seen == 19


def test_risky_port_produces_rule_alert() -> None:
    pipeline = _baseline_pipeline()
    alerts: list[Alert] = []
    pipeline.on_alert = alerts.append

    alert = pipeline.process(_features(dst_port=4444), "10.0.0.5", "10.0.0.6", "tcp", 4444)

    assert alert is not None
    assert alert.reason == "risky_dst_port"
    assert alert.dst_port == 4444
    assert alert.src == "10.0.0.5"
    assert alerts == [alert]
    assert pipeline.stats.rule_alerts == 1
    assert pipeline.stats.alerts == 1


def test_cooldown_suppresses_repeated_alerts() -> None:
    now = 1000.0
    pipeline = _baseline_pipeline(cooldown_seconds=10, clock=lambda: now)

    first = pipeline.process(_features(dst_port=4444), "10.0.0.5", "10.0.0.6", "tcp", 4444)
    second = pipeline.process(_features(dst_port=4444), "10.0.0.5", "10.0.0.6", "tcp", 4444)

    assert first is not None
    assert second is None
    assert pipeline.stats.suppressed == 1

    now += 11
    third = pipeline.process(_features(dst_port=4444), "10.0.0.5", "10.0.0.6", "tcp", 4444)
    assert third is not None


def test_alert_accepts_decimal_timestamps() -> None:
    from decimal import Decimal

    pipeline = _baseline_pipeline()
    alert = pipeline.process(
        _features(dst_port=4444),
        "a",
        "b",
        "tcp",
        4444,
        timestamp=Decimal("1700000000.125"),
    )

    assert alert is not None
    assert alert.timestamp.startswith("2023-11-14")


def test_alert_serialisation_contains_expected_fields() -> None:
    pipeline = _baseline_pipeline()
    alert = pipeline.process(_features(dst_port=1337), "a", "b", "tcp", 1337)

    assert alert is not None
    payload = alert.to_dict()
    assert payload["reason"] == "risky_dst_port"
    assert payload["score"] == round(alert.score, 6)
    assert payload["baseline_size"] == 20
    assert payload["timestamp"].endswith("+00:00")


def test_stats_summary_reports_activity() -> None:
    pipeline = _baseline_pipeline()
    pipeline.process(_features(dst_port=23), "a", "b", "tcp", 23)

    summary = pipeline.stats.summary()

    assert summary["packets_seen"] == 21
    assert summary["alerts"] == 1
    assert summary["baseline_packets"] == 20
    assert summary["packets_per_second"] >= 0


def test_constructor_validation() -> None:
    import pytest

    with pytest.raises(ValueError, match="baseline_packets"):
        DetectionPipeline(baseline_packets=5)
    with pytest.raises(ValueError, match="cooldown"):
        DetectionPipeline(cooldown_seconds=-1)
