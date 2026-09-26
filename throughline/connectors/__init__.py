"""Built-in connectors beyond the MVP vocabulary (registered with the normalizer).

* ``windows`` - Sysmon + Security event log JSON (OTRF/Mordor, Winlogbeat, NXLog)
* ``ocsf``    - OCSF 1.x process / file / network / DNS / authentication events
* :mod:`.otrf` - loader for OTRF Security-Datasets captures and their ATT&CK labels
"""
from .ocsf import map_ocsf
from .windows import Skip, acting_process, map_windows

__all__ = ["Skip", "acting_process", "map_ocsf", "map_windows"]
