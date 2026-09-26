# Security policy

## Scope and safety (non-negotiable)
- THROUGHLINE **reasons about** attacks. It does not perform them. This repository contains no exploit, emulation or malware code.
- `throughline.synth` produces **data records only**. Nothing is executed and nothing is contacted. All IPs come from RFC 5737 documentation ranges.
- Future emulation engines (the GAUNTLET slot) must only run inside an isolated no-egress lab range, gated behind an explicit lab-mode configuration flag. Malware samples stay in an offline sandbox, and development uses EICAR or benign samples.
- Do not point connectors at systems you do not own or are not authorized to monitor.

## Deployment guidance
- The API has **no authentication** in this MVP. Keep it on `127.0.0.1` (the default). Never expose it to a network.
- Treat exported graphs (`export`) as sensitive: they map an organization's attack surface.
- The Neo4j adapter expects a local instance. Change the default credentials.

## Reporting a vulnerability
Please report privately through GitHub Security Advisories on this repository, or email the maintainer. Do not open a public issue. Expect an acknowledgement within 7 days.
