"""Connectors (Windows, OCSF, OTRF) and the ATT&CK STIX catalog, on real fixture data."""
from __future__ import annotations

import json
import zipfile

import pytest
from conftest import FIX

from throughline import attack
from throughline.connectors.otrf import iter_records, load_catalog
from throughline.connectors.windows import Skip, acting_process, map_windows, proc_id
from throughline.contracts import ContractError
from throughline.normalizer import normalize

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def _sysmon(eid, **kw):
    return {"Channel": SYSMON, "EventID": eid, "Hostname": "WS5.lab.local", "UtcTime": "2020-10-18 19:50:01.100",
            **kw}


def test_process_create_maps_to_spawned_with_attributes():
    ev = normalize(_sysmon(1, ProcessId="4200", Image=r"C:\Windows\System32\rundll32.exe",
                           CommandLine="rundll32 comsvcs.dll MiniDump 640 out.dmp full",
                           ParentProcessId="6100", ParentImage=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                           Hashes="SHA1=AA,SHA256=ABCDEF"), "windows")
    assert (ev.actor_id, ev.action, ev.object_id) == ("ws5/6100/powershell.exe", "SPAWNED", "ws5/4200/rundll32.exe")
    assert ev.ts == "2020-10-18T19:50:01.100Z"
    assert ev.attributes["object.cmdline"].startswith("rundll32 comsvcs.dll")
    assert ev.attributes["object.sha256"] == "abcdef"


def test_guid_stands_in_for_missing_pid():
    rec = _sysmon(11, Image=r"C:\x\powershell.exe", ProcessGuid="{b669e388-4a98-5ee0-1704-000000000300}",
                  TargetFilename=r"C:\Temp\a.txt")
    ev = normalize(rec, "windows")
    assert ev.actor_id == "ws5/g-4a98-5ee0-1704-000000000300/powershell.exe"
    assert acting_process(rec) == "Process:" + ev.actor_id


def test_security_and_sysmon_share_process_identity():
    sec = {"Channel": "Security", "EventID": 4688, "Hostname": "ws5", "NewProcessId": "0x1068",
           "NewProcessName": r"C:\Windows\System32\rundll32.exe", "ProcessId": "0x17d4", "@timestamp": "2020-01-01T00:00:00Z"}
    assert normalize(sec, "windows").object_id == proc_id("ws5", 4200, "rundll32.exe")


@pytest.mark.parametrize("rec", [
    {"Channel": "Security", "EventID": 4663},
    {"Channel": "Windows PowerShell", "EventID": 400},
    _sysmon(5, Image="x.exe", ProcessId="1"),
    {"Channel": "Security", "EventID": 4624, "TargetUserName": "WS5$", "Hostname": "ws5"},
])
def test_unmodelled_records_are_skipped_not_rejected(rec):
    with pytest.raises(Skip):
        map_windows(rec)


def test_skip_is_a_contract_error():
    assert issubclass(Skip, ContractError)


def test_ocsf_process_activity():
    rec = {"class_uid": 1007, "time": 1600000000000, "device": {"hostname": "WS5.corp"},
           "process": {"pid": 42, "file": {"path": r"C:\x\cmd.exe"}, "cmd_line": "cmd /c whoami",
                       "parent_process": {"pid": 7, "file": {"path": r"C:\x\explorer.exe"}}}}
    ev = normalize(rec, "ocsf")
    assert (ev.actor_id, ev.action, ev.object_id) == ("ws5/7/explorer.exe", "SPAWNED", "ws5/42/cmd.exe")


def test_otrf_catalog_and_records_from_fixture():
    caps = {c.id: c for c in load_catalog(FIX / "otrf")}
    assert set(caps) == {"SDWIN-201018195009", "SDWIN-201021232814"}
    c = caps["SDWIN-201018195009"]
    assert c.techniques == ["T1003.001"] and c.available
    recs = list(c.records())
    assert len(recs) == 184 and all(isinstance(r, dict) for r in recs)


def test_iter_records_reads_json_lines_and_zip(tmp_path):
    lines = [json.dumps({"EventID": i}) for i in range(3)] + ["not json", ""]
    p = tmp_path / "cap.json"
    p.write_text("\n".join(lines))
    assert [r["EventID"] for r in iter_records(p)] == [0, 1, 2]
    z = tmp_path / "cap.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("x/cap.json", "\n".join(lines))
        zf.writestr("__MACOSX/._cap.json", "junk")
    assert len(list(iter_records(z))) == 3


def test_attack_catalog_from_real_subset():
    cat = attack.AttackCatalog.load(FIX / "attack" / "enterprise-attack-19.2.json")
    s = cat.summary()
    assert s["techniques"] == 20 and s["groups"] == 3 and s["attributed_campaigns"] == 1
    assert cat.resolve("T1086") == "T1059.001"               # revoked id forwarded
    assert cat.name("T1003.001") == "OS Credential Dumping: LSASS Memory"
    assert "T1059.001" in cat.group_profile("G0016")         # APT29 uses PowerShell
    camp = next(iter(cat.attributed))
    assert cat.attributed[camp] == "G0016"
    attack.set_active(cat)
    assert attack.canonical_technique("t1086") == "T1059.001"
    assert attack.technique_name("T1518") == "Software Discovery"
