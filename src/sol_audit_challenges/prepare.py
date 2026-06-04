from __future__ import annotations

import json
import re
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path


class PrepareCaseError(Exception):
    """Preparing a challenge case failed."""


CASE_ID_PATTERN = re.compile(r"^case-[0-9]{4}$")


@dataclass(frozen=True)
class PreparedCase:
    case_id: str
    source_dir: Path
    private_oracle: Path
    commit: str


def prepare_case(
    repo: str,
    commit: str,
    case_id: str,
    output_dir: Path,
) -> PreparedCase:
    """Export a repository commit as a source snapshot and draft oracle."""
    if not CASE_ID_PATTERN.fullmatch(case_id):
        raise PrepareCaseError("case id must use the case-0000 format")

    output_dir = output_dir.resolve()
    public_case_dir = output_dir / "public" / case_id
    source_dir = public_case_dir / "source"
    private_dir = output_dir / "private"
    private_oracle = private_dir / f"{case_id}.private.json"

    if source_dir.exists() and any(source_dir.iterdir()):
        raise PrepareCaseError(f"source snapshot already exists: {source_dir}")

    private_dir.mkdir(parents=True, exist_ok=True)
    source_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="sol-audit-challenges-prepare-") as temp:
        repo_path = _materialize_repo(repo, Path(temp))
        resolved_commit = _git(repo_path, "rev-parse", f"{commit}^{{commit}}").strip()
        _export_archive(repo_path, resolved_commit, source_dir)

    _write_draft_oracle(private_oracle, case_id, repo, resolved_commit)

    return PreparedCase(
        case_id=case_id,
        source_dir=source_dir,
        private_oracle=private_oracle,
        commit=resolved_commit,
    )


def _materialize_repo(repo: str, temp_dir: Path) -> Path:
    candidate = Path(repo).expanduser()
    if candidate.exists():
        repo_path = candidate.resolve()
        _git(repo_path, "rev-parse", "--git-dir")
        return repo_path

    clone_dir = temp_dir / "repo"
    _run_git("clone", "--no-checkout", "--quiet", repo, str(clone_dir))
    return clone_dir


def _export_archive(repo_path: Path, commit: str, source_dir: Path) -> None:
    archive_path = source_dir.parent / "source.tar"
    try:
        _git(repo_path, "archive", "--format=tar", f"--output={archive_path}", commit)
        with tarfile.open(archive_path) as archive:
            archive.extractall(source_dir, filter="data")
    finally:
        archive_path.unlink(missing_ok=True)

    git_paths = list(source_dir.rglob(".git"))
    if git_paths:
        for path in git_paths:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()


def _write_draft_oracle(
    oracle_path: Path,
    case_id: str,
    repo: str,
    commit: str,
) -> None:
    oracle = {
        "id": case_id,
        "origin": {"repository": repo},
        "vulnerable_commit": commit,
        "accepted_finding": {
            "summary": "TODO: summarize the accepted finding.",
            "root_cause": "TODO: describe the root cause.",
            "impact": "TODO: describe the security impact.",
            "locations": [],
        },
        "sources": ["TODO: add private source references."],
    }
    oracle_path.write_text(json.dumps(oracle, indent=2) + "\n", encoding="utf-8")


def _git(repo_path: Path, *args: str) -> str:
    return _run_git("-C", str(repo_path), *args)


def _run_git(*args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise PrepareCaseError("git executable was not found") from exc
    except subprocess.CalledProcessError as exc:
        message = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        raise PrepareCaseError(message) from exc
    return result.stdout
