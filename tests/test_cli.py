import json
import shutil
import subprocess
from pathlib import Path

import pytest
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


def test_prepare_case_exports_requested_commit_without_git_metadata(
    tmp_path: Path,
) -> None:
    if shutil.which("git") is None:
        pytest.skip("git is required for prepare-case")

    repo = tmp_path / "repo"
    repo.mkdir()
    run_git(repo, "init")
    run_git(repo, "config", "user.email", "test@example.invalid")
    run_git(repo, "config", "user.name", "Test User")

    source_file = repo / "src" / "Example.sol"
    source_file.parent.mkdir()
    source_file.write_text("contract Example { function value() public {} }\n")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "vulnerable")
    vulnerable_commit = run_git(repo, "rev-parse", "HEAD").strip()

    source_file.write_text("contract Example { function fixedValue() public {} }\n")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "fixed")

    output_dir = tmp_path / "prepared"
    result = runner.invoke(
        app,
        [
            "prepare-case",
            "--repo",
            str(repo),
            "--commit",
            vulnerable_commit,
            "--case-id",
            "case-0001",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    snapshot_file = output_dir / "public" / "case-0001" / "source" / "src" / "Example.sol"
    assert "function value()" in snapshot_file.read_text(encoding="utf-8")
    assert "fixedValue" not in snapshot_file.read_text(encoding="utf-8")
    assert not (output_dir / "public" / "case-0001" / "source" / ".git").exists()
    assert not list((output_dir / "public" / "case-0001" / "source").rglob(".git"))

    private_oracle = output_dir / "private" / "case-0001.private.json"
    assert private_oracle.exists()
    assert output_dir / "public" not in private_oracle.parents

    validation = runner.invoke(app, ["validate-private", str(private_oracle)])
    assert validation.exit_code == 0, validation.output


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout
