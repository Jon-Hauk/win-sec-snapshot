# win-sec-snapshot 0.0.0

Read-only Windows host security posture snapshot. JSON + Markdown, no secrets,
no network, no ACL changes.

Requires Windows, Python 3.12, and uv (install them first if they are not
already present). Then run one command, below.

Built for a reviewer checking a Windows machine's security settings:
clone, run, attach the receipt.

## Why it is safe

- Local only. Does not call the internet or Tailscale APIs.
- Read-only. Does not change firewall, services, or policy.
- Metadata only. Autoruns record **value names**, not values. Processes record
  **names**, not command lines. Env vars are not collected.
- A failed section is an error object; the rest of the snapshot still writes.

## Requirements

Windows, Python 3.12 via `uv`.

## One command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1
```

That runs tests, then writes `snapshot.json` and `snapshot.md`.

Runtime only:

```powershell
uv run python -m win_sec_snapshot --format md
```

Tests:

```powershell
uv run pytest -q
```

`--version` prints `0.0.0`.

## What you get

- firewall profiles (enabled / default inbound)
- listening TCP ports + process names
- service counts (running / autostart)
- local Administrators members
- Run-key **names**
- RDP `fDenyTSConnections`
- Defender service status
- hotfix count

Non-goals for 0.0.0: CVE feeds, remote scan, remediation, wrapping fieldkit.

## Sample

```
# win-sec-snapshot 0.0.0
- host: <workstation>
- readonly: True
## Firewall
- Private: enabled=True inbound=NotConfigured
```
