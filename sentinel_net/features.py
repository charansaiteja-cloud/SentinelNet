"""Turn Scapy packets into a fixed numeric feature vector.

The feature set is deliberately small, explainable, and independent of payload
content: packet length, ports, protocol, TCP flags, address family, whether the
source is private, a destination-port bucket, payload length, TTL/hop limit,
and inter-arrival time. No application data is retained.
"""

from __future__ import annotations

from dataclasses import astuple, dataclass
from ipaddress import ip_address

from scapy.packet import Packet

try:  # Scapy exposes concrete ICMPv6 classes across versions.
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP
except ImportError as exc:  # pragma: no cover - dependency is mandatory
    raise RuntimeError("Scapy is required to extract packet features") from exc


FEATURE_NAMES: tuple[str, ...] = (
    "length",
    "src_port",
    "dst_port",
    "protocol",
    "tcp_flags",
    "ip_version",
    "private_src",
    "dst_port_bucket",
    "payload_length",
    "ttl",
    "inter_arrival",
)

# Numeric protocol codes keep the vector stable for the model.
PROTOCOL_CODES = {
    "other": 0.0,
    "tcp": 1.0,
    "udp": 2.0,
    "icmp": 3.0,
    "arp": 4.0,
}


@dataclass(frozen=True)
class PacketFeatures:
    """Numeric summary of one packet."""

    length: float
    src_port: float
    dst_port: float
    protocol: float
    tcp_flags: float
    ip_version: float
    private_src: float
    dst_port_bucket: float
    payload_length: float
    ttl: float
    inter_arrival: float

    def as_vector(self) -> list[float]:
        return list(astuple(self))

    def as_dict(self) -> dict[str, float]:
        return dict(zip(FEATURE_NAMES, astuple(self), strict=True))


def _port_bucket(port: int | None) -> float:
    if port is None:
        return 3.0
    if port < 1024:
        return 0.0
    if port < 49152:
        return 1.0
    return 2.0


def _payload_length(packet: Packet) -> int:
    # Measure the application payload, not the IP header that follows Ethernet.
    if TCP in packet:
        payload = packet[TCP].payload
    elif UDP in packet:
        payload = packet[UDP].payload
    elif ICMP in packet:
        payload = packet[ICMP].payload
    else:
        payload = packet.payload
    if payload is None or payload.__class__.__name__ == "NoPayload":
        return 0
    try:
        return len(bytes(payload))
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return 0


def _is_private(value: str) -> float:
    try:
        return 1.0 if ip_address(value).is_private else 0.0
    except ValueError:
        return 0.0


def extract_features(
    packet: Packet,
    previous_timestamp: float | None = None,
) -> PacketFeatures:
    """Convert a Scapy packet into :class:`PacketFeatures`.

    ``previous_timestamp`` is the capture timestamp of the preceding packet;
    it is used to compute inter-arrival time without keeping global state.
    """

    length = float(len(packet))
    src = ""
    src_port: int | None = None
    dst_port: int | None = None
    protocol = "other"
    ip_version = 0.0
    ttl = 0.0

    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        ip_version = 4.0
        ttl = float(ip_layer.ttl)
    elif IPv6 in packet:
        ip_layer6 = packet[IPv6]
        src = ip_layer6.src
        ip_version = 6.0
        ttl = float(ip_layer6.hlim)
    elif ARP in packet:
        arp_layer = packet[ARP]
        src = arp_layer.psrc
        protocol = "arp"

    if TCP in packet:
        tcp_layer = packet[TCP]
        protocol = "tcp"
        src_port, dst_port = int(tcp_layer.sport), int(tcp_layer.dport)
        tcp_flags = float(int(tcp_layer.flags))
    elif UDP in packet:
        udp_layer = packet[UDP]
        protocol = "udp"
        src_port, dst_port = int(udp_layer.sport), int(udp_layer.dport)
        tcp_flags = 0.0
    elif ICMP in packet:
        protocol = "icmp"
        tcp_flags = 0.0
    else:
        tcp_flags = 0.0

    packet_time = getattr(packet, "time", None)
    if packet_time is None or previous_timestamp is None:
        inter_arrival = 0.0
    else:
        inter_arrival = max(0.0, min(float(packet_time) - previous_timestamp, 3600.0))

    return PacketFeatures(
        length=length,
        src_port=float(src_port if src_port is not None else 0),
        dst_port=float(dst_port if dst_port is not None else 0),
        protocol=PROTOCOL_CODES[protocol],
        tcp_flags=tcp_flags,
        ip_version=ip_version,
        private_src=_is_private(src),
        dst_port_bucket=_port_bucket(dst_port),
        payload_length=float(_payload_length(packet)),
        ttl=ttl,
        inter_arrival=inter_arrival,
    )
