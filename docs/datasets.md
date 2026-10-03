# Datasets

`python scripts/download_data.py all` fetches about 330 MB into `../../datasets/throughline/` (or `$THROUGHLINE_DATA`), outside the repo. Every file is checked against `scripts/checksums.sha256` (OTRF files also against the pinned commit's git blob ids) and an unpinned file is refused; the rolling OSV feed records its date and digest instead. Nothing downloaded is committed; `tests/fixtures/data/` holds an 83 KB slice (two real captures, five SigmaHQ rules, an ATT&CK subset) with its licences in [tests/fixtures/README.md](https://github.com/rakshit-737/throughline/blob/main/tests/fixtures/README.md).

| dataset | pinned at | size | use | licence |
| --- | --- | ---: | --- | --- |
| [MITRE ATT&CK Enterprise STIX 2.1](https://github.com/mitre-attack/attack-stix-data) v19.2 and v10.1 | `6cda5ad` | 82 MB | techniques, groups, software, campaigns; v10.1 for the temporal hold-out; per-report cases | [ATT&CK terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) |
| [SigmaHQ rules](https://github.com/SigmaHQ/sigma) | `07ec293` | 17 MB | ANVIL detection library, VANTAGE catalog | Detection Rule License 1.1 |
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets): 97 labelled atomic Windows captures; compound: APT29 evaluation days 1-2, APT3 (Empire, CALDERA round 1), LSASS campaigns 01-07 | `d9d40ef` | 178 MB | real attack telemetry with technique labels | MIT |
| [CTID adversary emulation plan, APT29](https://github.com/center-for-threat-informed-defense/adversary_emulation_library) (`APT29.yaml`) | `4467a6e` | 0.1 MB | per-step ground truth for the APT29 captures | Apache-2.0 |
| [CIS Controls v8 -> ATT&CK mapping](https://www.cisecurity.org/controls/cis-controls-navigator) (xlsx) | sha256 pinned | 1.2 MB | VANTAGE control coverage | CC BY-NC-ND 4.0 |
| [MISP galaxy threat-actor cluster](https://github.com/MISP/misp-galaxy) | `e9e867f` | 1.4 MB | sponsor countries for DRAGNET's false-flag checks | CC0 / BSD-2-Clause |
| [OSV.dev PyPI advisories](https://osv.dev) | rolling (manifest) | 34 MB | vulnerable pins | CC-BY 4.0 |
| [healthchecks/healthchecks](https://github.com/healthchecks/healthchecks) git history | `3731fc4` | 23 MB | real dependency lineage | BSD-3-Clause |

The benchmarks run in CI on Linux, where all 97 labelled captures are readable; endpoint antivirus on Windows quarantines two OTRF archives (they contain attack command lines), and the loaders skip and report unreadable captures. The optional `baseline` source (NextronSystems evtx-baseline) is not part of `all`.

## Ground truth used by the benchmarks

| benchmark | ground truth | source |
| --- | --- | --- |
| B1/B2, B5 | one ATT&CK technique per atomic capture | each capture's OTRF metadata YAML (`attack_mappings`) |
| B3 | the culprit group of each ATT&CK campaign, report or malware family | ATT&CK `attributed-to` / `uses` relationships and their citations |
| B4 | per-step techniques of the APT29 evaluation; lateral-movement host pairs | CTID `APT29.yaml`; [`benchmarks/truth/apt29_lateral.yaml`](https://github.com/rakshit-737/throughline/blob/main/benchmarks/truth/apt29_lateral.yaml) (resolved from the logged command lines, cited) |
| compound | techniques emulated in each LSASS campaign | OTRF compound metadata (`LSASS_campaign_0N.yaml`) |
| supply chain | the commit that introduced each pin at HEAD | `git blame` (agreement check, not an independent oracle) |

The OTRF APT29 day-1 export stores the RTLO payload name double-encoded (the bytes of U+202E read as Windows-1252, `â€®cod.3aka3.scr`); THROUGHLINE keeps evidence as the log recorded it, and the documentation writes the name as `<U+202E>cod.3aka3.scr`.

