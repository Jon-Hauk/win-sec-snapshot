from __future__ import annotations

import json
from typing import Any


def to_json(snapshot: dict[str, Any], pretty: bool = True) -> str:
    if pretty:
        return json.dumps(snapshot, indent=2, sort_keys=True) + "\n"
    return json.dumps(snapshot, separators=(",", ":"), sort_keys=True)


def to_markdown(snapshot: dict[str, Any]) -> str:
    s = snapshot.get("sections") or {}
    sysinfo = s.get("system") or {}
    lines = [
        f"# win-sec-snapshot {snapshot.get('version', '0.0.0')}",
        "",
        f"- host: {sysinfo.get('hostname')}",
        f"- user: {sysinfo.get('user')}",
        f"- os: {sysinfo.get('os')}",
        f"- when: {sysinfo.get('timestamp')}",
        f"- readonly: {snapshot.get('readonly')}",
        "",
        "## Firewall",
    ]
    for p in s.get("firewall") or []:
        lines.append(
            f"- {p.get('Name')}: enabled={p.get('Enabled')} inbound={p.get('DefaultInboundAction')}"
        )
    ports = s.get("ports") or []
    lines += ["", f"## Listening TCP ({len(ports)})"]
    for p in ports[:30]:
        lines.append(f"- {p.get('address')}:{p.get('port')} {p.get('process')} pid={p.get('pid')}")
    svc = s.get("services") or {}
    lines += [
        "",
        "## Services",
        f"- total={svc.get('total')} running={svc.get('running')} autostart={svc.get('autostart')}",
        "",
        "## Local Administrators",
    ]
    for a in s.get("admins") or []:
        lines.append(f"- {a.get('Name')} ({a.get('ObjectClass')})")
    lines += ["", "## Autorun value names (no values)"]
    for a in s.get("autoruns") or []:
        lines.append(f"- {a.get('Hive')} {a.get('Name')}")
    rdp = s.get("rdp") or {}
    lines += ["", f"## RDP fDenyTSConnections={rdp.get('fDenyTSConnections')}"]
    den = s.get("defender") or {}
    lines += ["", f"## Defender {den.get('Name')} status={den.get('Status')}"]
    hf = s.get("hotfixes") or {}
    lines += ["", f"## Hotfixes count={hf.get('Count')} latest={hf.get('Latest')}"]
    errs = snapshot.get("errors") or []
    if errs:
        lines += ["", "## Collection errors"]
        for e in errs:
            lines.append(f"- {e.get('section')}: {e.get('error')}")
    lines.append("")
    return "\n".join(lines)


FORBIDDEN_KEYS = ("password", "secret", "token", "commandline", "env")


def assert_no_secrets(snapshot: dict[str, Any]) -> None:
    blob = json.dumps(snapshot).lower()
    for key in FORBIDDEN_KEYS:
        if f'"{key}"' in blob:
            raise AssertionError(f"forbidden key present: {key}")
