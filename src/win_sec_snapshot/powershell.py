"""Run a PowerShell snippet and parse JSON. No secrets, no live shell history."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from typing import Any

Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


class PowerShellError(RuntimeError):
    pass


def default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    # S603: argv is built in run_json from module-level literals only - never
    # from caller input - and shell=False. Running PowerShell is this tool's
    # entire purpose, so the finding is acknowledged, not worked around.
    return subprocess.run(  # noqa: S603
        argv,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def run_json(script: str, runner: Runner | None = None) -> Any:
    """Execute -NoProfile PowerShell and parse stdout as JSON."""
    run = runner or default_runner
    argv = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]
    proc = run(argv)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise PowerShellError(err or f"powershell exit {proc.returncode}")
    raw = (proc.stdout or "").strip()
    if not raw:
        return None
    return json.loads(raw)
