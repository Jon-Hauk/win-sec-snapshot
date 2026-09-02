import json
import subprocess

import pytest

from win_sec_snapshot.collectors import collect
from win_sec_snapshot.powershell import PowerShellError, run_json


def test_run_json_parses(monkeypatch):
    def runner(argv):
        return subprocess.CompletedProcess(argv, 0, stdout='{"ok":true}', stderr="")

    assert run_json("ignored", runner=runner) == {"ok": True}


def test_run_json_nonzero(monkeypatch):
    def runner(argv):
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="boom")

    with pytest.raises(PowerShellError, match="boom"):
        run_json("ignored", runner=runner)


def test_collect_continues_on_section_failure():
    def runner(argv):
        script = argv[-1]
        if "Get-NetFirewallProfile" in script:
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="access denied")
        if "Get-NetTCPConnection" in script:
            payload = json.dumps([{"LocalAddress": "0.0.0.0", "LocalPort": 22, "OwningProcess": 4}])
            return subprocess.CompletedProcess(argv, 0, stdout=payload, stderr="")
        if "Get-Process" in script:
            payload = json.dumps([{"Id": 4, "ProcessName": "System"}])
            return subprocess.CompletedProcess(argv, 0, stdout=payload, stderr="")
        payload = json.dumps([])
        return subprocess.CompletedProcess(argv, 0, stdout=payload, stderr="")

    snap = collect(runner=runner)
    assert snap["version"] == "0.0.0"
    assert snap["sections"]["firewall"] is None
    assert any(e["section"] == "firewall" for e in snap["errors"])
    assert snap["sections"]["ports"][0]["process"] == "System"
    assert snap["sections"]["ports"][0]["port"] == 22
