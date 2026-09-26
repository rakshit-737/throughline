# ADR-0005: Windows process identity is host/pid/image, with the Sysmon GUID as a fallback

**Status:** Accepted

## Context
Several sensors describe the same process: Sysmon (ProcessGuid, ProcessId, Image), the Security log (4688 NewProcessId in hex, 5156 ProcessID with a device path) and the sibling engines' own parsers (REVENANT's `process:<pid>:<image>`, ROOTLINE's host, pid and comm). For corroboration to work, all of them must name the same graph node.

## Decision
The node id is `<short lower-case host>/<decimal pid>/<lower-case image basename>`. Hex pids are converted. When an export dropped the pid (some OTRF/NXLog captures keep only ProcessGuid), the GUID without its per-machine first block stands in, for example `ws5/g-4a98-5ee0-1704-000000000300/powershell.exe`. The REVENANT and ROOTLINE adapters map their references onto the same key.

## Consequences
- Sysmon 1 and Security 4688 for one process land on one node, so two sensors corroborate each other (noisy-OR) instead of producing two half-known processes.
- Two processes that reuse a pid *with the same image* inside one capture are merged. Over the 96 OTRF captures this is rare. It is a known limitation for long captures such as APT29 (hours of activity) and is recorded in the README.
- ROOTLINE cannot reconstruct captures whose Sysmon records have no pid. Its adapter reports that instead of guessing.
