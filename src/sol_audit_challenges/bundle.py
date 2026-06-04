from __future__ import annotations

import fnmatch
import gzip
import hashlib
import io
import json
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class BundleCaseError(Exception):
    """Bundling a challenge case failed."""


DEFAULT_EXCLUDE_PATTERNS = (
    ".git",
    ".git/**",
    "**/.git",
    "**/.git/**",
    "*.private.json",
    "*.private.yaml",
    "*.oracle.json",
    "*.oracle.yaml",
    "private",
    "private/**",
    "**/private",
    "**/private/**",
    "research",
    "research/**",
    "**/research",
    "**/research/**",
    "notes",
    "notes/**",
    "**/notes",
    "**/notes/**",
    "*notes*",
    "**/*notes*",
    "reports",
    "reports/**",
    "**/reports",
    "**/reports/**",
    "runs",
    "runs/**",
    "**/runs",
    "**/runs/**",
    "*report.json",
    "**/*report.json",
)


@dataclass(frozen=True)
class BundledCase:
    case_id: str
    archive_path: Path
    manifest_path: Path
    sha256: str


def bundle_case(
    source_dir: Path,
    case_id: str,
    output_dir: Path,
    manifest_path: Path | None = None,
    language: tuple[str, ...] = ("solidity",),
    prompt: str = "Find security issues in this codebase. Submit each finding with affected files, root cause, exploit impact, and a minimal proof sketch.",
) -> BundledCase:
    """Create a deterministic public archive and write or update its manifest."""
    source_dir = source_dir.resolve()
    output_dir = output_dir.resolve()
    manifest_path = (manifest_path or output_dir / f"{case_id}.public.json").resolve()
    archive_path = output_dir / "bundles" / f"{case_id}.tar.gz"

    if not source_dir.is_dir():
        raise BundleCaseError(f"source directory does not exist: {source_dir}")
    if not language:
        raise BundleCaseError("language must include at least one value")
    if not prompt:
        raise BundleCaseError("prompt cannot be empty")

    archive_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    _write_deterministic_archive(source_dir, archive_path)
    sha256 = _sha256_file(archive_path)
    manifest = _load_or_create_manifest(manifest_path, case_id, language, prompt)
    manifest["id"] = case_id
    manifest["package"] = {
        "type": "archive",
        "path": _manifest_package_path(archive_path, manifest_path),
        "sha256": sha256,
    }
    _write_json(manifest_path, manifest)

    return BundledCase(
        case_id=case_id,
        archive_path=archive_path,
        manifest_path=manifest_path,
        sha256=sha256,
    )


def _write_deterministic_archive(source_dir: Path, archive_path: Path) -> None:
    files = [
        path
        for path in sorted(source_dir.rglob("*"), key=lambda item: item.relative_to(source_dir).as_posix())
        if path.is_file() and not _should_exclude(path.relative_to(source_dir).as_posix())
    ]

    with archive_path.open("wb") as raw_file:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_file, mtime=0) as gzip_file:
            with tarfile.open(fileobj=gzip_file, mode="w") as archive:
                for path in files:
                    relative_path = path.relative_to(source_dir).as_posix()
                    archive_name = f"source/{relative_path}"
                    data = path.read_bytes()
                    tar_info = tarfile.TarInfo(archive_name)
                    tar_info.size = len(data)
                    tar_info.mtime = 0
                    tar_info.uid = 0
                    tar_info.gid = 0
                    tar_info.uname = ""
                    tar_info.gname = ""
                    tar_info.mode = stat.S_IMODE(path.stat().st_mode)
                    archive.addfile(tar_info, io.BytesIO(data))


def _load_or_create_manifest(
    manifest_path: Path,
    case_id: str,
    language: tuple[str, ...],
    prompt: str,
) -> dict[str, Any]:
    if not manifest_path.exists():
        return {
            "id": case_id,
            "language": list(language),
            "package": {
                "type": "archive",
                "path": "",
                "sha256": "",
            },
            "prompt": prompt,
        }

    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BundleCaseError(f"invalid public manifest JSON at {manifest_path}: {exc}") from exc
    except OSError as exc:
        raise BundleCaseError(f"could not read public manifest: {manifest_path}") from exc

    if not isinstance(raw, dict):
        raise BundleCaseError("public manifest must be a JSON object")
    return raw


def _manifest_package_path(archive_path: Path, manifest_path: Path) -> str:
    try:
        return archive_path.relative_to(manifest_path.parent).as_posix()
    except ValueError:
        return archive_path.as_posix()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _should_exclude(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/")
    lowered = normalized.lower()
    for pattern in DEFAULT_EXCLUDE_PATTERNS:
        normalized_pattern = pattern.replace("\\", "/").lower()
        if fnmatch.fnmatchcase(lowered, normalized_pattern):
            return True
        if "/" not in normalized_pattern and fnmatch.fnmatchcase(
            Path(lowered).name, normalized_pattern
        ):
            return True
    return False
