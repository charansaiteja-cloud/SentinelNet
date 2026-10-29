from __future__ import annotations

from pathlib import Path

import pytest

from sentinel_net.config import Settings


def test_defaults() -> None:
    settings = Settings(_env_file=None)

    assert settings.baseline_packets == 200
    assert settings.contamination == 0.02
    assert settings.cooldown_seconds == 10.0
    assert settings.log_level == "INFO"
    assert settings.source == "unconfigured"


def test_environment_prefix(monkeypatch) -> None:
    monkeypatch.setenv("SENTINEL_BASELINE_PACKETS", "50")
    monkeypatch.setenv("SENTINEL_LOG_LEVEL", "debug")
    monkeypatch.setenv("SENTINEL_PCAP", "/tmp/demo.pcap")

    settings = Settings(_env_file=None)

    assert settings.baseline_packets == 50
    assert settings.log_level == "DEBUG"
    assert settings.pcap == Path("/tmp/demo.pcap")
    assert settings.source == "pcap:/tmp/demo.pcap"


def test_interface_source() -> None:
    assert Settings(_env_file=None, interface="eth0").source == "iface:eth0"


def test_both_sources_are_rejected() -> None:
    with pytest.raises(ValueError, match="either an interface or a pcap"):
        Settings(_env_file=None, interface="eth0", pcap=Path("demo.pcap"))


def test_blank_bpf_is_rejected() -> None:
    with pytest.raises(ValueError, match="BPF filter"):
        Settings(_env_file=None, bpf="   ")


def test_bpf_is_trimmed() -> None:
    assert Settings(_env_file=None, bpf="  tcp port 443  ").bpf == "tcp port 443"


def test_invalid_log_level_is_rejected() -> None:
    with pytest.raises(ValueError, match="log level"):
        Settings(_env_file=None, log_level="LOUD")


def test_baseline_bounds() -> None:
    with pytest.raises(ValueError):
        Settings(_env_file=None, baseline_packets=1)
    with pytest.raises(ValueError):
        Settings(_env_file=None, contamination=0.0)
