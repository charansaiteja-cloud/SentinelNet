"""Command-line entry point for SentinelNet."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP

from sentinel_net import __version__
from sentinel_net.capture import capture_live, list_interfaces, replay_pcap
from sentinel_net.config import Settings
from sentinel_net.detector import AnomalyDetector
from sentinel_net.features import PROTOCOL_CODES, extract_features
from sentinel_net.logging_utils import configure_logging
from sentinel_net.pipeline import Alert, DetectionPipeline

logger = logging.getLogger("sentinel_net")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INTERRUPTED = 130

PROTOCOL_NAMES = {value: name for name, value in PROTOCOL_CODES.items()}


class AlertWriter:
    """Write alerts to an optional JSON-lines file, and always to the log."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._handle: TextIO | None = None
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = path.open("a", encoding="utf-8")

    def __call__(self, alert: Alert) -> None:
        payload = alert.to_dict()
        logger.warning(
            "alert src=%s dst=%s port=%s reason=%s score=%.4f",
            alert.src,
            alert.dst,
            alert.dst_port,
            alert.reason,
            alert.score,
            extra={"ctx_alert": payload},
        )
        if self._handle is not None:
            self._handle.write(json.dumps(payload, separators=(",", ":")) + "\n")
            self._handle.flush()

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelnet",
        description=(
            "Learn a baseline of normal traffic, then flag anomalous packets. "
            "Use only on networks you are authorized to monitor."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-i", "--interface", help="interface for live capture")
    parser.add_argument("-p", "--pcap", type=Path, help="PCAP file to replay")
    parser.add_argument(
        "-f",
        "--bpf",
        help="optional BPF filter, for example 'tcp port 443'",
    )
    parser.add_argument(
        "-b",
        "--baseline",
        type=int,
        default=200,
        help="packets used to learn normal traffic (default: 200)",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.02,
        help="expected anomaly fraction used to set the threshold (default: 0.02)",
    )
    parser.add_argument(
        "--cooldown",
        type=float,
        default=10.0,
        help="seconds before repeating the same alert (default: 10)",
    )
    parser.add_argument(
        "--alerts",
        type=Path,
        help="append alerts as JSON lines to this file",
    )
    parser.add_argument(
        "--load-model",
        type=Path,
        help="load a fitted model instead of learning a baseline",
    )
    parser.add_argument(
        "--save-model",
        type=Path,
        help="save the fitted model after a run that completed its baseline",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="stop after N packets; 0 means unlimited (default: 0)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=None,
        help="stop live capture after N seconds",
    )
    parser.add_argument(
        "--json-logs",
        action="store_true",
        help="emit structured JSON logs to stderr",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="logging verbosity (default: INFO)",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="print capture interfaces and exit",
    )
    return parser


def _settings_from_args(args: argparse.Namespace) -> Settings:
    return Settings(
        interface=args.interface,
        pcap=args.pcap,
        bpf=args.bpf,
        baseline_packets=args.baseline,
        contamination=args.contamination,
        cooldown_seconds=args.cooldown,
        alert_log=args.alerts,
        model_path=args.load_model,
        log_level=args.log_level,
        json_logs=args.json_logs,
    )


def _endpoints(packet: Any) -> tuple[str, str]:
    if IP in packet:
        return str(packet[IP].src), str(packet[IP].dst)
    if IPv6 in packet:
        return str(packet[IPv6].src), str(packet[IPv6].dst)
    if ARP in packet:
        return str(packet[ARP].psrc), str(packet[ARP].pdst)
    return "unknown", "unknown"


def run(
    settings: Settings,
    count: int = 0,
    duration: float | None = None,
    save_model: Path | None = None,
) -> dict[str, Any]:
    """Run capture and detection, returning the final statistics summary."""
    writer = AlertWriter(settings.alert_log)
    detector = (
        AnomalyDetector.load(settings.model_path) if settings.model_path is not None else None
    )
    if detector is not None:
        logger.info("loaded model threshold=%.6f", detector.threshold)

    pipeline = DetectionPipeline(
        detector=detector,
        baseline_packets=settings.baseline_packets,
        cooldown_seconds=settings.cooldown_seconds,
        on_alert=writer,
    )

    previous_timestamp: float | None = None
    baseline_announced = detector is not None

    def handle_packet(packet: Any) -> None:
        nonlocal previous_timestamp, baseline_announced
        features = extract_features(packet, previous_timestamp)
        packet_time = getattr(packet, "time", None)
        if packet_time is not None:
            previous_timestamp = float(packet_time)

        src, dst = _endpoints(packet)
        protocol = PROTOCOL_NAMES[features.protocol]
        pipeline.process(
            features,
            src=src,
            dst=dst,
            protocol=protocol,
            dst_port=int(features.dst_port),
            timestamp=packet_time,
        )

        if not baseline_announced and pipeline.is_ready:
            baseline_announced = True
            logger.info(
                "baseline complete packets=%d threshold=%.6f",
                pipeline.stats.baseline_packets,
                pipeline.detector.threshold,
            )
            if save_model is not None:
                pipeline.detector.save(save_model)
                logger.info("saved model to %s", save_model)

    try:
        if settings.pcap is not None:
            logger.info("replaying %s bpf=%s", settings.pcap, settings.bpf or "(none)")
            replay_pcap(settings.pcap, handle_packet, bpf=settings.bpf, count=count)
        else:
            if settings.interface is None:  # guarded by the CLI, defensive here
                raise ValueError("live capture requires an interface")
            logger.info(
                "capturing on %s bpf=%s baseline=%d",
                settings.interface,
                settings.bpf or "(none)",
                settings.baseline_packets,
            )
            capture_live(
                settings.interface,
                handle_packet,
                bpf=settings.bpf,
                count=count,
                timeout=duration,
            )
    except KeyboardInterrupt:
        print("\nCapture interrupted.", file=sys.stderr)
    finally:
        summary = pipeline.stats.summary()
        writer.close()

    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.log_level, args.json_logs)

    if args.list_interfaces:
        interfaces = list_interfaces()
        if not interfaces:
            print("No interfaces detected.", file=sys.stderr)
            return EXIT_ERROR
        print("\n".join(interfaces))
        return EXIT_OK

    if bool(args.interface) == bool(args.pcap):
        parser.error("provide exactly one of --interface or --pcap")

    try:
        settings = _settings_from_args(args)
    except Exception as exc:
        print(f"Invalid configuration: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        summary = run(
            settings,
            count=args.count,
            duration=args.duration,
            save_model=args.save_model,
        )
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"Capture error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED

    print(json.dumps({"event": "summary", **summary}, sort_keys=True))
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
