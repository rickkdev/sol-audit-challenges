import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
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


def test_validate_report_accepts_valid_file() -> None:
    result = runner.invoke(
        app, ["validate-report", "examples/submitted-reports/case-0000.report.json"]
    )

    assert result.exit_code == 0
    assert "Valid submitted report" in result.stdout


def test_validate_report_reports_schema_path(tmp_path: Path) -> None:
    report = tmp_path / "invalid.report.json"
    write_json(
        report,
        {
            "case_id": "case-0000",
            "findings": [
                {
                    "title": "Fake issue",
                    "affected_files": [{"path": "source/src/FakeVault.sol"}],
                    "root_cause": "Fake root cause",
                    "impact": "Fake impact",
                }
            ],
        },
    )

    result = runner.invoke(app, ["validate-report", str(report)])

    assert result.exit_code == 1
    assert str(report) in result.stderr
    assert "proof_sketch" in result.stderr
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


def test_sanitize_case_removes_default_clue_paths(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "src").mkdir(parents=True)
    (source / "docs").mkdir()
    (source / "broadcast").mkdir()
    (source / "src" / "Example.sol").write_text("contract Example {}\n", encoding="utf-8")
    (source / "README.md").write_text("incident writeup\n", encoding="utf-8")
    (source / "docs" / "audit.md").write_text("audit clue\n", encoding="utf-8")
    (source / "broadcast" / "run.json").write_text("deployment clue\n", encoding="utf-8")
    (source / "src" / "exploit.t.sol").write_text("exploit clue\n", encoding="utf-8")

    output = tmp_path / "sanitized"
    report = tmp_path / "sanitizer-report.json"
    result = runner.invoke(
        app,
        [
            "sanitize-case",
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            "--report",
            str(report),
        ],
    )

    assert result.exit_code == 0, result.output
    assert (output / "src" / "Example.sol").exists()
    assert not (output / "README.md").exists()
    assert not (output / "docs").exists()
    assert not (output / "broadcast").exists()
    assert not (output / "src" / "exploit.t.sol").exists()

    report_data = json.loads(report.read_text(encoding="utf-8"))
    assert sorted(report_data["removed_files"]) == [
        "README.md",
        "broadcast/",
        "docs/",
        "src/exploit.t.sol",
    ]


def test_sanitize_case_applies_replacements_without_reporting_secrets(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "Vault.sol").write_text(
        "contract RealProtocolVault { address constant TARGET = 0x1234567890abcdef1234567890abcdef12345678; }\n",
        encoding="utf-8",
    )
    config = tmp_path / "sanitize.json"
    write_json(
        config,
        {
            "replace": [
                {
                    "label": "protocol_name",
                    "find": "RealProtocol",
                    "replace": "ExampleProtocol",
                },
                {
                    "label": "address",
                    "find": "0x1234567890abcdef1234567890abcdef12345678",
                    "replace": "0x0000000000000000000000000000000000000000",
                },
            ]
        },
    )

    output = tmp_path / "sanitized"
    report = tmp_path / "public-report.json"
    result = runner.invoke(
        app,
        [
            "sanitize-case",
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            "--config",
            str(config),
            "--report",
            str(report),
        ],
    )

    assert result.exit_code == 0, result.output
    sanitized_source = (output / "Vault.sol").read_text(encoding="utf-8")
    assert "ExampleProtocolVault" in sanitized_source
    assert "0x0000000000000000000000000000000000000000" in sanitized_source
    assert "RealProtocol" not in sanitized_source
    assert "0x1234567890abcdef1234567890abcdef12345678" not in sanitized_source

    report_text = report.read_text(encoding="utf-8")
    assert "RealProtocol" not in report_text
    assert "0x1234567890abcdef1234567890abcdef12345678" not in report_text
    report_data = json.loads(report_text)
    assert report_data["replacements"] == [
        {
            "label": "protocol_name",
            "replacement": "ExampleProtocol",
            "count": 1,
            "files": [{"path": "Vault.sol", "count": 1}],
        },
        {
            "label": "address",
            "replacement": "0x0000000000000000000000000000000000000000",
            "count": 1,
            "files": [{"path": "Vault.sol", "count": 1}],
        },
    ]


def test_bundle_case_creates_deterministic_archive_and_manifest(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "Example.sol").write_text("contract Example {}\n", encoding="utf-8")
    (source / "notes").mkdir()
    (source / "notes" / "research-notes.txt").write_text("private clue\n", encoding="utf-8")
    (source / "reports").mkdir()
    (source / "reports" / "sanitizer-report.json").write_text("{}", encoding="utf-8")
    (source / ".git").mkdir()
    (source / ".git" / "config").write_text("[remote]\n", encoding="utf-8")
    (source / "case-0005.private.json").write_text("{}", encoding="utf-8")

    output = tmp_path / "public"
    result = runner.invoke(
        app,
        [
            "bundle-case",
            "--source-dir",
            str(source),
            "--case-id",
            "case-0005",
            "--output-dir",
            str(output),
            "--language",
            "solidity",
        ],
    )

    assert result.exit_code == 0, result.output
    archive = output / "bundles" / "case-0005.tar.gz"
    first_archive_bytes = archive.read_bytes()
    manifest = output / "case-0005.public.json"
    manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
    assert manifest_data["package"]["path"] == "bundles/case-0005.tar.gz"
    assert manifest_data["package"]["sha256"] == sha256_bytes(first_archive_bytes)

    with tarfile.open(archive, "r:gz") as package:
        names = package.getnames()
        members = package.getmembers()

    assert names == ["source/src/Example.sol"]
    assert [member.mtime for member in members] == [0]
    assert [member.uid for member in members] == [0]
    assert [member.gid for member in members] == [0]

    second = runner.invoke(
        app,
        [
            "bundle-case",
            "--source-dir",
            str(source),
            "--case-id",
            "case-0005",
            "--output-dir",
            str(output),
            "--language",
            "solidity",
        ],
    )

    assert second.exit_code == 0, second.output
    assert archive.read_bytes() == first_archive_bytes

    validation = runner.invoke(app, ["validate-public", str(manifest)])
    assert validation.exit_code == 0, validation.output


def test_bundle_case_updates_existing_manifest_package_only(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
    manifest = tmp_path / "case-0006.public.json"
    write_json(
        manifest,
        {
            "id": "case-0006",
            "language": ["solidity"],
            "package": {
                "type": "archive",
                "path": "old.tar.gz",
                "sha256": "0" * 64,
            },
            "prompt": "Existing public prompt.",
            "build": {"commands": ["forge test"], "network": "disabled"},
        },
    )

    result = runner.invoke(
        app,
        [
            "bundle-case",
            "--source-dir",
            str(source),
            "--case-id",
            "case-0006",
            "--output-dir",
            str(tmp_path / "public"),
            "--manifest",
            str(manifest),
        ],
    )

    assert result.exit_code == 0, result.output
    manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
    assert manifest_data["prompt"] == "Existing public prompt."
    assert manifest_data["build"] == {"commands": ["forge test"], "network": "disabled"}
    assert manifest_data["package"]["path"] == "public/bundles/case-0006.tar.gz"
    assert manifest_data["package"]["sha256"] != "0" * 64


def test_run_case_extracts_public_bundle_and_captures_outputs(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "Example.sol").write_text("contract Example {}\n", encoding="utf-8")

    public = tmp_path / "public"
    bundle_result = runner.invoke(
        app,
        [
            "bundle-case",
            "--source-dir",
            str(source),
            "--case-id",
            "case-0007",
            "--output-dir",
            str(public),
        ],
    )
    assert bundle_result.exit_code == 0, bundle_result.output

    command = (
        f"{sys.executable} -c "
        "\"import pathlib; "
        "print(sorted(path.name for path in pathlib.Path('.').iterdir())); "
        "print(pathlib.Path('source/src/Example.sol').read_text().strip()); "
        "print(pathlib.Path('public-manifest.json').exists())\""
    )
    output_dir = tmp_path / "reports"
    result = runner.invoke(
        app,
        [
            "run-case",
            "--bundle",
            str(public / "bundles" / "case-0007.tar.gz"),
            "--manifest",
            str(public / "case-0007.public.json"),
            "--command",
            command,
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    run_dirs = list((output_dir / "runs" / "case-0007").iterdir())
    assert len(run_dirs) == 1
    run_dir = run_dirs[0]
    stdout = (run_dir / "stdout.txt").read_text(encoding="utf-8")
    metadata = json.loads((run_dir / "metadata.json").read_text(encoding="utf-8"))

    assert "['public-manifest.json', 'source']" in stdout
    assert "contract Example {}" in stdout
    assert "True" in stdout
    assert (run_dir / "stderr.txt").read_text(encoding="utf-8") == ""
    assert metadata["case_id"] == "case-0007"
    assert metadata["return_code"] == 0
    assert metadata["workspace"]["private_oracle_available"] is False
    assert metadata["network"]["mechanism"] == "local fallback; no network namespace is enforced"
    assert not (source / "public-manifest.json").exists()


def test_run_case_rejects_bundle_checksum_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "Example.sol").write_text("contract Example {}\n", encoding="utf-8")

    public = tmp_path / "public"
    bundle_result = runner.invoke(
        app,
        [
            "bundle-case",
            "--source-dir",
            str(source),
            "--case-id",
            "case-0008",
            "--output-dir",
            str(public),
        ],
    )
    assert bundle_result.exit_code == 0, bundle_result.output

    manifest = public / "case-0008.public.json"
    manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
    manifest_data["package"]["sha256"] = "0" * 64
    write_json(manifest, manifest_data)

    result = runner.invoke(
        app,
        [
            "run-case",
            "--bundle",
            str(public / "bundles" / "case-0008.tar.gz"),
            "--manifest",
            str(manifest),
            "--command",
            f"{sys.executable} -c \"print('should not run')\"",
            "--output-dir",
            str(tmp_path / "reports"),
        ],
    )

    assert result.exit_code == 1
    assert "checksum mismatch" in result.stderr
    assert not (tmp_path / "reports" / "runs").exists()


def test_score_report_scores_findings_without_printing_oracle_fields(
    tmp_path: Path,
) -> None:
    oracle = tmp_path / "case-0009.private.json"
    write_json(oracle, fake_oracle("case-0009"))
    report = tmp_path / "case-0009.report.json"
    write_json(
        report,
        {
            "case_id": "case-0009",
            "findings": [
                fake_finding(
                    "Accepted fake withdrawal issue",
                    "source/src/FakeVault.sol",
                    root_cause="Balance is updated after an external call in withdraw.",
                    impact="Repeated withdrawals can drain the fake vault balance.",
                    proof_sketch="The attacker reenters withdraw before balance accounting changes.",
                    line=42,
                    symbol="withdraw",
                ),
                fake_finding(
                    "Partial fake vault issue",
                    "source/src/FakeVault.sol",
                    root_cause="The implementation has confusing accounting.",
                    impact="Funds may be affected.",
                    proof_sketch="Maintainer review is needed.",
                ),
                fake_finding(
                    "Unrelated fake owner issue",
                    "source/src/Admin.sol",
                    root_cause="Owner can change settings.",
                    impact="Configuration may change.",
                    proof_sketch="The owner path is privileged.",
                ),
            ],
        },
    )
    output = tmp_path / "score.json"

    result = runner.invoke(
        app,
        [
            "score-report",
            "--report",
            str(report),
            "--oracle",
            str(oracle),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Finding 0: accepted" in result.stdout
    assert "Finding 1: partial" in result.stdout
    assert "Finding 2: false_positive" in result.stdout
    assert "Private fake summary" not in result.stdout
    assert "https://example.invalid/private/source" not in result.stdout

    score = json.loads(output.read_text(encoding="utf-8"))
    assert [finding["status"] for finding in score["results"]] == [
        "accepted",
        "partial",
        "false_positive",
    ]
    assert score["summary"] == {
        "accepted": 1,
        "partial": 1,
        "duplicate": 0,
        "false_positive": 1,
        "out_of_scope": 0,
    }
    score_text = output.read_text(encoding="utf-8")
    assert "Private fake summary" not in score_text
    assert "https://example.invalid/private/source" not in score_text


def test_score_report_marks_duplicate_matches(tmp_path: Path) -> None:
    oracle = tmp_path / "case-0010.private.json"
    write_json(oracle, fake_oracle("case-0010"))
    report = tmp_path / "case-0010.report.json"
    matching = fake_finding(
        "Fake reentrancy match",
        "src/FakeVault.sol",
        root_cause="External call before balance accounting enables reentrancy.",
        impact="Repeated withdraw calls can drain funds from the fake vault.",
        proof_sketch="A callback reenters withdraw before state is updated.",
        line=43,
        symbol="withdraw",
    )
    write_json(
        report,
        {
            "case_id": "case-0010",
            "findings": [matching, {**matching, "title": "Same fake bug again"}],
        },
    )

    result = runner.invoke(
        app,
        [
            "score-report",
            "--report",
            str(report),
            "--oracle",
            str(oracle),
        ],
    )

    assert result.exit_code == 0, result.output
    output = report.with_suffix(".score.json")
    score = json.loads(output.read_text(encoding="utf-8"))
    assert [finding["status"] for finding in score["results"]] == [
        "accepted",
        "duplicate",
    ]


def test_score_report_marks_case_mismatch_out_of_scope(tmp_path: Path) -> None:
    oracle = tmp_path / "case-0011.private.json"
    write_json(oracle, fake_oracle("case-0011"))
    report = tmp_path / "case-0012.report.json"
    write_json(
        report,
        {
            "case_id": "case-0012",
            "findings": [
                fake_finding(
                    "Mismatched fake finding",
                    "src/FakeVault.sol",
                    root_cause="External call before accounting.",
                    impact="Funds can drain.",
                    proof_sketch="Reenter withdraw.",
                )
            ],
        },
    )

    result = runner.invoke(
        app,
        [
            "score-report",
            "--report",
            str(report),
            "--oracle",
            str(oracle),
        ],
    )

    assert result.exit_code == 0, result.output
    score = json.loads(report.with_suffix(".score.json").read_text(encoding="utf-8"))
    assert score["results"][0]["status"] == "out_of_scope"


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def fake_oracle(case_id: str) -> dict[str, object]:
    return {
        "id": case_id,
        "origin": {"repository": "https://example.invalid/private/repo"},
        "vulnerable_commit": "abcdef1",
        "accepted_finding": {
            "summary": "Private fake summary about a reentrant withdrawal drain",
            "root_cause": "The withdraw function performs an external call before updating balance accounting.",
            "impact": "An attacker can reenter withdraw and drain vault funds repeatedly.",
            "locations": [
                {"path": "src/FakeVault.sol", "line": 42, "symbol": "withdraw"}
            ],
        },
        "sources": ["https://example.invalid/private/source"],
    }


def fake_finding(
    title: str,
    path: str,
    *,
    root_cause: str,
    impact: str,
    proof_sketch: str,
    line: int | None = None,
    symbol: str | None = None,
) -> dict[str, object]:
    location: dict[str, object] = {"path": path}
    if line is not None:
        location["line"] = line
    if symbol is not None:
        location["symbol"] = symbol
    return {
        "title": title,
        "affected_files": [location],
        "root_cause": root_cause,
        "impact": impact,
        "proof_sketch": proof_sketch,
    }
