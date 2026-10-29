from __future__ import annotations

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from sentinel_net.features import FEATURE_NAMES, PROTOCOL_CODES, extract_features


def test_tcp_ipv4_features() -> None:
    packet = (
        Ether()
        / IP(src="192.168.1.10", dst="93.184.216.34", ttl=64)
        / TCP(sport=51515, dport=443, flags="S")
        / Raw(load=b"hello")
    )
    packet.time = 1000.0

    features = extract_features(packet)

    assert features.length == float(len(packet))
    assert features.src_port == 51515
    assert features.dst_port == 443
    assert features.protocol == PROTOCOL_CODES["tcp"]
    assert features.tcp_flags == 2.0  # SYN
    assert features.ip_version == 4.0
    assert features.private_src == 1.0
    assert features.dst_port_bucket == 0.0
    assert features.payload_length == 5.0
    assert features.ttl == 64.0
    assert features.inter_arrival == 0.0


def test_udp_ipv6_features() -> None:
    packet = (
        Ether()
        / IPv6(src="2606:4700:4700::1111", dst="2001:db8::2", hlim=55)
        / UDP(sport=53000, dport=53)
    )

    features = extract_features(packet)

    assert features.ip_version == 6.0
    assert features.protocol == PROTOCOL_CODES["udp"]
    assert features.dst_port == 53
    assert features.private_src == 0.0
    assert features.ttl == 55.0


def test_icmp_features() -> None:
    packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP() / Raw(load=b"ping")

    features = extract_features(packet)

    assert features.protocol == PROTOCOL_CODES["icmp"]
    assert features.payload_length == 4.0
    assert features.dst_port == 0.0
    assert features.dst_port_bucket == 3.0


def test_arp_features() -> None:
    packet = Ether() / ARP(psrc="192.168.1.20", pdst="192.168.1.1")

    features = extract_features(packet)

    assert features.protocol == PROTOCOL_CODES["arp"]
    assert features.ip_version == 0.0
    assert features.private_src == 1.0
    assert features.ttl == 0.0


def test_inter_arrival_is_clamped() -> None:
    packet = Ether() / IP() / TCP()
    packet.time = 5000.0

    assert extract_features(packet, previous_timestamp=4999.5).inter_arrival == 0.5
    assert extract_features(packet, previous_timestamp=9000.0).inter_arrival == 0.0
    assert extract_features(packet, previous_timestamp=1.0).inter_arrival == 3600.0


def test_every_feature_has_a_name() -> None:
    packet = Ether() / IP() / TCP()
    features = extract_features(packet)

    assert len(FEATURE_NAMES) == len(features.as_vector())
    assert set(features.as_dict()) == set(FEATURE_NAMES)


def test_dst_port_buckets() -> None:
    def bucket(port: int) -> float:
        return extract_features(Ether() / IP() / TCP(dport=port)).dst_port_bucket

    assert bucket(22) == 0.0
    assert bucket(8080) == 1.0
    assert bucket(50000) == 2.0
