# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | yes |

## Reporting a vulnerability

Please do **not** open a public issue for a security problem. Report it
privately to the maintainer through the contact details on the GitHub profile,
or use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).

Include the affected version, a reproduction, and the impact you observed. You
can expect an initial response within seven days.

## Scope

SentinelNet reads packets from an interface you nominate and from PCAP files.
It does not transmit packets, modify traffic, or open network listeners.

Operational hardening that is intentionally left to the operator:

- Run live capture with the narrowest capability that works (`CAP_NET_RAW`),
  not full root, where the platform allows it.
- Treat `alerts.jsonl` as sensitive: source and destination addresses and ports
  can reveal network topology and user behaviour.
- Do not point `--pcap` at files you are not authorised to inspect.
- Baseline and alert files should be stored with restrictive permissions.

The detector is statistical. A clean run is not evidence that a network is
free of compromise, and an alert is not proof of an attack.
