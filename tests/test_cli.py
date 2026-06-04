import json
from pathlib import Path

from typer.testing import CliRunner

from sol_audit_challenges import __version__
from sol_audit_challenges.cli import app


runner = CliRunner()


def test_cli_shows_help() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Package, run, and score" in result.stdout


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_validate_public_manifest_accepts_valid_file() -> None:
    result = runner.invoke(
        app, ["validate-public", "examples/challenge-manifest/case-0000.public.json"]
    )

    assert result.exit_code == 0
    assert "Valid public manifest" in result.stdout


def test_validate_public_manifest_reports_schema_path(tmp_path: Path) -> None:
    manifest = tmp_path / "invalid.public.json"
    write_json(
        manifest,
        {
            "id": "case-zero",
            "language": [],
            "package": {
                "type": "archive",
                "path": "bundles/case-0000.tar.gz",
                "sha256": "not-a-sha",
            },
            "prompt": "Find issues.",
        },
    )

    result = runner.invoke(app, ["validate-public", str(manifest)])

    assert result.exit_code == 1
    assert str(manifest) in result.stderr
    assert "schema: #/" in result.stderr


def test_validate_private_oracle_accepts_valid_file(tmp_path: Path) -> None:
    oracle = tmp_path / "case-0000.private.json"
    write_json(
        oracle,
        {
            "id": "case-0000",
            "origin": {"repository": "https://example.invalid/fake/repo"},
            "vulnerable_commit": "abcdef1",
            "accepted_finding": {
                "summary": "Fake summary",
                "root_cause": "Fake root cause",
                "impact": "Fake impact",
                "locations": [{"path": "src/Fake.sol", "line": 12}],
            },
            "sources": ["https://example.invalid/fake/source"],
        },
    )

    result = runner.invoke(app, ["validate-private", str(oracle)])

    assert result.exit_code == 0
    assert "Valid private oracle" in result.stdout


def test_validate_private_oracle_reports_schema_path(tmp_path: Path) -> None:
    oracle = tmp_path / "invalid.private.json"
    write_json(
        oracle,
        {
            "id": "case-0000",
            "origin": {"repository": "https://example.invalid/fake/repo"},
            "vulnerable_commit": "not a commit",
            "accepted_finding": {
                "summary": "Fake summary",
                "root_cause": "Fake root cause",
                "impact": "Fake impact",
            },
            "sources": ["https://example.invalid/fake/source"],
        },
    )

    result = runner.invoke(app, ["validate-private", str(oracle)])

    assert result.exit_code == 1
    assert str(oracle) in result.stderr
    assert "schema: #/" in result.stderr


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")
