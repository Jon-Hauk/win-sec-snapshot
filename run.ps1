# One command: tests, then snapshot.json + snapshot.md next to this script.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here
uv run pytest -q
uv run python -m win_sec_snapshot --format json --output "$here\snapshot.json"
uv run python -m win_sec_snapshot --format md --output "$here\snapshot.md"
Write-Host "wrote snapshot.json snapshot.md"
