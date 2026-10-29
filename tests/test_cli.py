from __future__ import annotations

import json
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Ether, wrpcap

from sentinel_net.cli import build_parser, main
from sentinel_net.config import Settings


def _normal_pcap(path: Path, count: int = 80) -> None:
    packets = []
    for index in range(count):
        port = (80, 443, 53)[index % 3]
        packet = (
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=40000 + (index % 1000), dport=port)
        )
        packet.time = 1000.0 + index * 0.1
        packets.append(packet)
    wrpcap(str(path), packets)


def test_parser_defaults() -> None:
    args = build_parser().parse_args(["--pcap", "demo.pcap"])

    assert args.baseline == 200
    assert args.count == 0
    assert args.json_logs is False


def test_list_interfaces(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sentinel_net.cli.list_interfaces", lambda: ["eth0", "lo"])

    assert main(["--list-interfaces"]) == 0
    assert capsys.readouterr().out.splitlines() == ["eth0", "lo"]


def test_no_interfaces_is_an_error(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sentinel_net.cli.list_interfaces", lambda: [])

    assert main(["--list-interfaces"]) == 1
    assert "No interfaces" in capsys.readouterr().err


def test_requires_exactly_one_source(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 2

    with pytest.raises(SystemExit):
        main(["--interface", "lo", "--pcap", "demo.pcap"])


def test_bad_settings_are_reported(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "sentinel_net.cli.Settings",
        lambda **kwargs: (_ for _ in ()).throw(ValueError("bad config")),
    )

    assert main(["--pcap", "demo.pcap"]) == 1
    assert "Invalid configuration" in capsys.readouterr().err


def test_missing_pcap_returns_error(capsys) -> None:
    assert main(["--pcap", "/tmp/does-not-exist-12345.pcap"]) == 1
    assert "Capture error" in capsys.readouterr().err


def test_end_to_end_pcap_run(tmp_path: Path, capsys) -> None:
    pcap = tmp_path / "normal.pcap"
    alerts = tmp_path / "alerts.jsonl"
    _normal_pcap(pcap, count=60)

    exit_code = main(
        [
            "--pcap",
            str(pcap),
            "--baseline",
            "20",
            "--count",
            "60",
            "--alerts",
            str(alerts),
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    summary = json.loads(output.strip().splitlines()[-1])
    assert summary["event"] == "summary"
    assert summary["packets_seen"] == 60
    assert summary["baseline_packets"] == 20


def test_save_model_after_baseline(tmp_path: Path) -> None:
    pcap = tmp_path / "normal.pcap"
    model = tmp_path / "model.joblib"
    _normal_pcap(pcap, count=40)

    exit_code = main(
        [
            "--pcap",
            str(pcap),
            "--baseline",
            "20",
            "--count",
            "40",
            "--save-model",
            str(model),
        ]
    )

    assert exit_code == 0
    assert model.is_file()


def test_run_uses_settings(monkeypatch, tmp_path: Path) -> None:
    from sentinel_net import cli

    pcap = tmp_path / "normal.pcap"
    _normal_pcap(pcap, count=25)
    settings = Settings(_env_file=None, pcap=pcap, baseline_packets=20)

    summary = cli.run(settings, count=25)

    assert summary["packets_seen"] == 25
    assert summary["baseline_packets"] == 20
