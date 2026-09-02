"""Best-effort collectors. A failed section is recorded; the rest still run."""

from __future__ import annotations

import os
import platform
import socket
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from win_sec_snapshot import __version__
from win_sec_snapshot.powershell import PowerShellError, Runner, run_json

# Metadata only. Never request CommandLine, env, or registry value data.
_PS_FIREWALL = r"""
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction |
  ConvertTo-Json -Compress
"""

_PS_PORTS = r"""
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Select-Object LocalAddress, LocalPort, OwningProcess |
  ConvertTo-Json -Compress
"""

_PS_PROC_NAMES = r"""
Get-Process | Select-Object Id, ProcessName | ConvertTo-Json -Compress
"""

_PS_SERVICES = r"""
Get-CimInstance Win32_Service |
  Select-Object Name, State, StartMode |
  ConvertTo-Json -Compress
"""

_PS_ADMINS = r"""
Get-LocalGroupMember -Group Administrators -ErrorAction Stop |
  Select-Object Name, ObjectClass, PrincipalSource |
  ConvertTo-Json -Compress
"""

_PS_AUTORUNS = r"""
$paths = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
)
$rows = foreach ($p in $paths) {
  if (Test-Path $p) {
    Get-Item $p | ForEach-Object {
      $_.Property | ForEach-Object {
        [pscustomobject]@{ Hive = $p; Name = $_ }
      }
    }
  }
}
@($rows) | ConvertTo-Json -Compress
"""

_PS_RDP = r"""
$p = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$v = Get-ItemProperty -Path $p -Name fDenyTSConnections -ErrorAction SilentlyContinue
[pscustomobject]@{ fDenyTSConnections = $v.fDenyTSConnections } | ConvertTo-Json -Compress
"""

_PS_DEFENDER = r"""
Get-Service WinDefend -ErrorAction Stop |
  Select-Object Name, Status, StartType |
  ConvertTo-Json -Compress
"""

_PS_HOTFIX = r"""
$h = @(Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn)
[pscustomobject]@{
  Count = $h.Count
  Latest = if ($h) { $h[-1].HotFixID } else { $null }
} | ConvertTo-Json -Compress
"""


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def collect(runner: Runner | None = None) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    sections: dict[str, Any] = {}

    def grab(name: str, script: str, transform: Callable[[Any], Any] | None = None) -> None:
        try:
            data = run_json(script, runner=runner)
            sections[name] = transform(data) if transform else data
        except Exception as exc:  # a failed section must not abort the snapshot
            sections[name] = None
            errors.append({"section": name, "error": str(exc)[:300]})

    sections["system"] = {
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "python": platform.python_version(),
        "user": os.environ.get("USERNAME") or os.environ.get("USER"),
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    grab("firewall", _PS_FIREWALL, lambda d: _as_list(d))

    def ports(data: Any) -> list[dict[str, Any]]:
        names = {}
        try:
            for row in _as_list(run_json(_PS_PROC_NAMES, runner=runner)):
                names[int(row["Id"])] = row.get("ProcessName")
        except (PowerShellError, KeyError, TypeError, ValueError):
            # Process names are an enrichment, not the point. If the lookup
            # fails, report ports with pid only rather than losing the
            # section. Drop a partial map so no row is half-labelled.
            names = {}
        out = []
        for row in _as_list(data):
            pid = row.get("OwningProcess")
            out.append(
                {
                    "address": row.get("LocalAddress"),
                    "port": row.get("LocalPort"),
                    "pid": pid,
                    "process": names.get(int(pid)) if pid is not None else None,
                }
            )
        out.sort(key=lambda r: (r.get("port") or 0, r.get("address") or ""))
        return out

    grab("ports", _PS_PORTS, ports)

    def services(data: Any) -> dict[str, Any]:
        rows = _as_list(data)
        auto = [r["Name"] for r in rows if str(r.get("StartMode")).lower() == "auto"]
        running = [r["Name"] for r in rows if str(r.get("State")).lower() == "running"]
        return {
            "total": len(rows),
            "running": len(running),
            "autostart": len(auto),
            "autostart_names": sorted(auto)[:40],
        }

    grab("services", _PS_SERVICES, services)

    grab("admins", _PS_ADMINS, lambda d: _as_list(d))
    grab("autoruns", _PS_AUTORUNS, lambda d: _as_list(d))
    grab("rdp", _PS_RDP)
    grab("defender", _PS_DEFENDER)
    grab("hotfixes", _PS_HOTFIX)

    return {
        "version": __version__,
        "readonly": True,
        "sections": sections,
        "errors": errors,
    }
