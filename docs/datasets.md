# Datasets


`python scripts/download_data.py all` fetches about 290 MB into `../../datasets/throughline/` (or `$THROUGHLINE_DATA`), outside the repo. Pinned sources are checked against `scripts/checksums.sha256`; the rolling OSV feed records its date and digest instead. Nothing downloaded is committed; `tests/fixtures/data/` holds a 113 KB slice (two real captures, five SigmaHQ rules, an ATT&CK subset) with its licences in [tests/fixtures/README.md](https://github.com/rakshit-737/throughline/blob/main/tests/fixtures/README.md).

| dataset | pinned at | size | use | licence |
| --- | --- | ---: | --- | --- |
| [MITRE ATT&CK Enterprise STIX 2.1](https://github.com/mitre-attack/attack-stix-data) v19.2 and v10.1 | `6cda5ad` | 82 MB | techniques, groups, software, campaigns, mitigations; v10.1 for the temporal hold-out | [ATT&CK terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) |
| [SigmaHQ rules](https://github.com/SigmaHQ/sigma) | `07ec293` | 17 MB | ANVIL detection library, VANTAGE catalog | Detection Rule License 1.1 |
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) atomic Windows host captures + APT29 evaluation days 1-2 | `d9d40ef` | 118 MB | real attack telemetry with technique labels | MIT |
| [CIS Controls v8 -> ATT&CK mapping](https://www.cisecurity.org/controls/cis-controls-navigator) (xlsx) | sha256 pinned | 1.2 MB | VANTAGE control coverage | CIS, free with attribution |
| [MISP galaxy threat-actor cluster](https://github.com/MISP/misp-galaxy) | `e9e867f` | 1.4 MB | sponsor countries for DRAGNET's false-flag checks | CC0 / BSD-2-Clause |
| [OSV.dev PyPI advisories](https://osv.dev) | rolling (manifest) | 34 MB | vulnerable pins | CC-BY 4.0 |
| [healthchecks/healthchecks](https://github.com/healthchecks/healthchecks) git history | `3731fc4` | 23 MB | real dependency lineage | BSD-3-Clause |

Two OTRF archives are routinely quarantined by endpoint antivirus (they contain attack command lines); the loaders skip unreadable captures and report them, which is why 95 of 97 labelled captures were scored. The optional `baseline` source (NextronSystems evtx-baseline) is not part of `all`.
