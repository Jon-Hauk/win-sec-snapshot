from win_sec_snapshot import __version__
from win_sec_snapshot.cli import build_parser


def test_parser_defaults():
    ns = build_parser().parse_args([])
    assert ns.format == "json"


def test_packaged_version():
    assert __version__ == "0.0.0"
    help_text = build_parser().format_help()
    assert "win-sec-snapshot" in help_text
