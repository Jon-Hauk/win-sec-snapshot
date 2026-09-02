import json

import pytest

from win_sec_snapshot import __version__
from win_sec_snapshot.formatters import assert_no_secrets, to_json, to_markdown


def _snap():
    return {
        "version": "0.0.0",
        "readonly": True,
        "sections": {
            "system": {
                "hostname": "<workstation>",
                "user": "alice",
                "os": "Windows",
                "timestamp": "2026-08-26T00:00:00Z",
            },
            "firewall": [
                {
                    "Name": "Private",
                    "Enabled": True,
                    "DefaultInboundAction": "NotConfigured",
                }
            ],
            "ports": [{"address": "127.0.0.1", "port": 22, "pid": 1, "process": "sshd"}],
            "services": {"total": 2, "running": 1, "autostart": 1},
            "admins": [{"Name": "HOST\\alice", "ObjectClass": "User"}],
            "autoruns": [{"Hive": "HKCU:\\...\\Run", "Name": "OneDrive"}],
            "rdp": {"fDenyTSConnections": 1},
            "defender": {"Name": "WinDefend", "Status": "Running"},
            "hotfixes": {"Count": 3, "Latest": "KB123"},
        },
        "errors": [],
    }


def test_version_constant():
    assert __version__ == "0.0.0"


def test_json_roundtrip():
    text = to_json(_snap())
    data = json.loads(text)
    assert data["version"] == "0.0.0"
    assert data["readonly"] is True
    assert data["sections"]["rdp"]["fDenyTSConnections"] == 1


def test_markdown_headings():
    md = to_markdown(_snap())
    assert md.startswith("# win-sec-snapshot 0.0.0")
    assert "## Firewall" in md
    assert "sshd" in md


def test_rejects_commandline_key():
    bad = _snap()
    bad["sections"]["ports"][0]["CommandLine"] = "sshd.exe -f /etc/ssh"
    with pytest.raises(AssertionError):
        assert_no_secrets(bad)
