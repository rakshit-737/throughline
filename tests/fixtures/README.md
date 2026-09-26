# Test fixtures (tiny slices of the real datasets)

`data/` has the same layout as a full `$THROUGHLINE_DATA` root, so the whole stack runs on it in CI.

| path | what | source / licence |
| --- | --- | --- |
| `data/otrf/atomic/windows/credential_access/host/psh_lsass_memory_dump_comsvcs.zip` | 184 real Windows event records: LSASS dumped via `comsvcs.dll` (T1003.001) | [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) SDWIN-201018195009, MIT |
| `data/otrf/atomic/windows/discovery/host/cmd_discover_iexplorer_version_registry.zip` | 68 records: Internet Explorer version discovery (T1518) | OTRF SDWIN-201021232814, MIT |
| `data/otrf/atomic/_metadata/*.yaml` | the two captures' metadata (ATT&CK labels) | OTRF, MIT |
| `data/sigma/rules/windows/**.yml` | five unmodified SigmaHQ rules that fire on the captures | [SigmaHQ](https://github.com/SigmaHQ/sigma) @ 07ec293, Detection Rule License 1.1 (`data/sigma/LICENSE`); authors are kept in each rule |
| `data/attack/enterprise-attack-19.2.json` | 90-object subset of the ATT&CK Enterprise v19.2 STIX bundle (20 techniques, 3 groups, 2 software, 1 campaign, 1 mitigation, 1 revoked technique) with descriptions stripped | [MITRE ATT&CK](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/), royalty-free licence |

The files are data only (event logs, rule YAML, JSON). Nothing here is executable.
