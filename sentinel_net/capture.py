"""Live interface capture and PCAP replay built on Scapy."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from scapy.all import get_if_list, sniff
from scapy.packet import Packet

PacketCallback = Callable[[Packet], None]


def list_interfaces() -> list[str]:
    """Return the interfaces Scapy can see, sorted and de-duplicated."""
    return sorted(set(get_if_list()))


def capture_live(
    interface: str,
    on_packet: PacketCallback,
    bpf: str | None = None,
    count: int = 0,
    timeout: float | None = None,
) -> None:
    """Capture from ``interface`` until ``count``/``timeout``/Ctrl+C.

    ``count=0`` means unlimited. Packets are streamed to ``on_packet`` and never
    stored in memory.
    """
    if count < 0:
        raise ValueError("count must be zero or greater")
    if timeout is not None and timeout <= 0:
        raise ValueError("timeout must be positive when provided")
    if interface not in list_interfaces():
        choices = ", ".join(list_interfaces()) or "(none detected)"
        raise ValueError(f"interface {interface!r} not found; available: {choices}")

    sniff(
        iface=interface,
        filter=bpf,
        prn=on_packet,
        store=False,
        count=count,
        timeout=timeout,
        chainCC=True,
    )


def replay_pcap(
    path: str | Path,
    on_packet: PacketCallback,
    bpf: str | None = None,
    count: int = 0,
) -> None:
    """Replay a PCAP file through the same callback used for live capture."""
    pcap = Path(path)
    if not pcap.is_file():
        raise FileNotFoundError(f"pcap file not found: {pcap}")
    if count < 0:
        raise ValueError("count must be zero or greater")

    sniff(
        offline=str(pcap),
        filter=bpf,
        prn=on_packet,
        store=False,
        count=count,
    )
