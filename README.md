# SentinelNet

**ML-assisted network anomaly detection with live capture and PCAP replay.**

SentinelNet learns what normal traffic looks like on a segment, then flags
packets that deviate from that baseline. It combines an Isolation Forest model
with a small, documented set of high-risk destination ports, writes alerts as
JSON lines, and never stores packet payloads.

Use it only on networks you own or have **written permission** to monitor.

---

## What it actually does

```text
live interface ─┐
                ├─▶ Scapy capture ─▶ feature extraction ─▶ baseline (N packets)
PCAP replay ────┘                                              │
                                                               ▼
                                      Isolation Forest fit ─▶ threshold
                                                               │
                        every later packet ─▶ score ─▶ alert (model or rule)
                                                               │
                                                    console + alerts.jsonl
```

1. **Baseline.** The first `--baseline` packets are summarised into an
   11-dimension numeric vector and used to fit an Isolation Forest.
2. **Threshold.** The anomaly threshold is the `1 - contamination` quantile of
   the baseline scores. It is stored with the model and printed on startup, so
   it can be inspected instead of hidden inside `predict()`.
3. **Detection.** Each later packet is scored. A packet alerts when its score
   exceeds the threshold **or** its destination port is in the documented
   high-risk set (`23`, `2323`, `4444`, `5555`, `1337`, `31337`, `6667`, `9001`).
4. **Cooldown.** Repeated alerts for the same `(source, port, reason)` are
   suppressed for `--cooldown` seconds so a scan does not produce thousands of
   duplicate lines.
5. **Output.** One JSON object per alert, on stderr and optionally appended to
   `--alerts alerts.jsonl`. The final line of stdout is a JSON run summary.

No payload bytes are written to disk or printed. The feature vector contains
packet length, ports, protocol, TCP flags, address family, whether the source is
private, a destination-port bucket, payload length, TTL/hop limit, and
inter-arrival time.

---

## Quick start: replay a PCAP (no root required)

```bash
git clone https://github.com/charansaiteja-cloud/SentinelNet.git
cd SentinelNet
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# Replay a capture, learn from the first 200 packets, write alerts
sentinelnet --pcap capture.pcap --baseline 200 --alerts alerts.jsonl
```

If you do not have a PCAP handy, create a synthetic one:

```bash
python - <<'PY'
from scapy.all import Ether, IP, TCP, wrpcap
packets = []
for i in range(300):
    p = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000 + i, dport=443)
    p.time = 1000 + i * 0.1
    packets.append(p)
wrpcap("capture.pcap", packets)
PY
```

## Live capture

Live capture needs raw-socket access. On Linux, grant the interpreter the
capability once instead of running as root:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f .venv/bin/python)"
sentinelnet --interface eth0 --baseline 500 --alerts alerts.jsonl
```

List interfaces with `sentinelnet --list-interfaces`. Stop with `Ctrl+C`; the
summary still prints. Use `--bpf "tcp port 443"` to limit what is captured.

> On macOS, `setcap` does not exist; run with `sudo` or use the Docker image.
> On Windows, use Npcap in "WinPcap API-compatible" mode.

---

## CLI reference

| Flag | Default | Meaning |
| --- | --- | --- |
| `-i, --interface` | — | live capture interface |
| `-p, --pcap` | — | replay a PCAP file instead of live capture |
| `-f, --bpf` | none | BPF filter applied by libpcap/Scapy |
| `-b, --baseline` | `200` | packets used to learn normal traffic |
| `--contamination` | `0.02` | expected anomaly fraction; sets the threshold |
| `--cooldown` | `10` | seconds before repeating the same alert |
| `--alerts` | none | append alerts as JSON lines to this file |
| `--load-model` | none | load a fitted model and skip the baseline |
| `--save-model` | none | save the fitted model after the baseline completes |
| `--count` | `0` | stop after N packets (`0` = unlimited) |
| `--duration` | none | stop live capture after N seconds |
| `--json-logs` | off | structured JSON logs on stderr |
| `--log-level` | `INFO` | `DEBUG`…`CRITICAL` |
| `--list-interfaces` | — | print interfaces and exit |

Exactly one of `--interface` or `--pcap` is required. Configuration can also
come from `SENTINEL_*` environment variables (see `sentinel_net/config.py` and
`.env.example`).

### Reusing a model

```bash
# Learn once and save
sentinelnet --pcap baseline.pcap --baseline 500 --save-model model.joblib

# Later, score without re-learning
sentinelnet --pcap suspect.pcap --load-model model.joblib --alerts alerts.jsonl
```

---

## Docker

```bash
docker compose build
docker compose run --rm sentinelnet --pcap /data/capture.pcap --baseline 200
```

Live capture from a container needs `network_mode: host` (Linux) and
`NET_RAW`/`NET_ADMIN`, both already set in `docker-compose.yml`. Mount PCAPs
under `/data` and alerts under `/alerts`.

---

## Testing and quality

```bash
pytest                    # 48 tests, ~91% line/branch coverage
ruff check .
ruff format --check .
mypy sentinel_net
bandit -q -r sentinel_net
pip-audit
```

The test suite uses synthetic Scapy packets and temporary PCAPs; it does not
require root, a live interface, or network access. CI runs the same checks on
Python 3.10, 3.11, and 3.12.

---

## Project layout

```text
sentinel_net/
├── capture.py        # live interface capture and PCAP replay
├── cli.py            # argparse entry point, alerts, run summary
├── config.py         # pydantic-settings configuration
├── detector.py       # Isolation Forest + explicit threshold + save/load
├── features.py       # packet → 11-dimension numeric vector
├── logging_utils.py  # text or JSON-lines logging
├── pipeline.py       # baseline, scoring, risky-port rule, cooldown
└── __main__.py       # python -m sentinel_net
```

## Limitations

- This is an anomaly **detector**, not a full IDS/IPS. It does not reassemble
  flows, inspect payloads, or block traffic.
- Unsupervised baselines inherit their environment: a baseline captured during
  an attack teaches the model that the attack is normal. Capture a known-good
  period.
- The risky-port list is a heuristic and will not fit every network; edit
  `DEFAULT_RISKY_PORTS` or pass a custom set when embedding the pipeline.
- The model is per-segment and per-baseline. Re-train when the network changes
  materially.
- UDP and ICMP floods, encrypted payloads, and low-and-slow application abuse
  are outside the feature set.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately rather than
opening a public issue.

## License

MIT — see [LICENSE](LICENSE).
