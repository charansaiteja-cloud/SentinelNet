from __future__ import annotations

from pathlib import Path

import pytest
from scapy.all import IP, TCP, Ether, wrpcap

from sentinel_net.capture import capture_live, list_interfaces, replay_pcap


def _packets(count: int = 3):
    packets = []
    for index in range(count):
        packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000 + index, dport=443)
        packet.time = 1000.0 + index
        packets.append(packet)
    return packets


def test_list_interfaces_returns_strings() -> None:
    interfaces = list_interfaces()
    assert isinstance(interfaces, list)
    assert all(isinstance(item, str) for item in interfaces)


def test_invalid_interface_is_rejected() -> None:
    with pytest.raises(ValueError, match="not found"):
        capture_live("definitely-not-an-interface", lambda packet: None)


def test_negative_count_is_rejected() -> None:
    with pytest.raises(ValueError, match="count"):
        capture_live("lo", lambda packet: None, count=-1)


def test_missing_pcap_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="pcap file not found"):
        replay_pcap(tmp_path / "missing.pcap", lambda packet: None)


def test_replay_reads_packets_in_order(tmp_path: Path) -> None:
    pcap = tmp_path / "demo.pcap"
    wrpcap(str(pcap), _packets(5))
    seen = []

    replay_pcap(pcap, seen.append, count=3)

    assert len(seen) == 3
    assert [packet[TCP].sport for packet in seen] == [50000, 50001, 50002]


def test_replay_rejects_negative_count(tmp_path: Path) -> None:
    pcap = tmp_path / "demo.pcap"
    wrpcap(str(pcap), _packets(1))

    with pytest.raises(ValueError, match="count"):
        replay_pcap(pcap, lambda packet: None, count=-1)
