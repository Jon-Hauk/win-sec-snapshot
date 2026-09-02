from __future__ import annotations

import argparse
import sys
from pathlib import Path

from win_sec_snapshot import __version__
from win_sec_snapshot.collectors import collect
from win_sec_snapshot.formatters import assert_no_secrets, to_json, to_markdown


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="win-sec-snapshot",
        description="Read-only Windows host security posture snapshot.",
    )
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--format", choices=("json", "md"), default="json")
    p.add_argument("--output", "-o", help="Write to PATH instead of stdout")
    p.add_argument("--pretty", action="store_true", default=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    snap = collect()
    assert_no_secrets(snap)
    text = to_markdown(snap) if args.format == "md" else to_json(snap, pretty=args.pretty)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0 if not snap.get("errors") else 1


if __name__ == "__main__":
    raise SystemExit(main())
