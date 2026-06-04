from __future__ import annotations

import fnmatch
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class SanitizeCaseError(Exception):
    """Sanitizing a challenge case failed."""


DEFAULT_REMOVE_PATTERNS = [
    "README",
    "README.*",
    "readme",
    "readme.*",
    "**/README",
    "**/README.*",
    "**/readme",
    "**/readme.*",
    "docs",
    "docs/**",
    "**/docs",
    "**/docs/**",
    "doc",
    "doc/**",
    "**/doc",
    "**/doc/**",
    "audits",
    "audits/**",
    "**/audits",
    "**/audits/**",
    "audit",
    "audit/**",
    "**/audit",
    "**/audit/**",
    "deployments",
    "deployments/**",
    "**/deployments",
    "**/deployments/**",
    "broadcast",
    "broadcast/**",
    "**/broadcast",
    "**/broadcast/**",
    "cache",
    "cache/**",
    "**/cache",
    "**/cache/**",
    "out",
    "out/**",
    "**/out",
    "**/out/**",
    "*exploit*",
    "**/*exploit*",
    "*poc*",
    "**/*poc*",
    "*incident*",
    "**/*incident*",
]


@dataclass(frozen=True)
class ReplacementRule:
    label: str
    find: str
    replace: str


@dataclass(frozen=True)
class SanitizerConfig:
    remove_patterns: tuple[str, ...]
    replacements: tuple[ReplacementRule, ...]


@dataclass(frozen=True)
class SanitizedCase:
    source_dir: Path
    output_dir: Path
    report_path: Path
    removed_files: tuple[str, ...]


def sanitize_case(
    source_dir: Path,
    output_dir: Path,
    config_path: Path | None = None,
    report_path: Path | None = None,
) -> SanitizedCase:
    """Copy a source snapshot, remove clue-bearing files, and redact configured strings."""
    source_dir = source_dir.resolve()
    output_dir = output_dir.resolve()
    report_path = (report_path or output_dir.parent / "sanitizer-report.json").resolve()

    if not source_dir.is_dir():
        raise SanitizeCaseError(f"source directory does not exist: {source_dir}")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise SanitizeCaseError(f"output directory already exists and is not empty: {output_dir}")

    config = load_sanitizer_config(config_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    removed_files = _copy_sanitized_tree(source_dir, output_dir, config.remove_patterns)
    replacement_report = _apply_replacements(output_dir, config.replacements)

    report = {
        "source_dir": str(source_dir),
        "output_dir": str(output_dir),
        "removed_files": removed_files,
        "replacements": replacement_report,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    return SanitizedCase(
        source_dir=source_dir,
        output_dir=output_dir,
        report_path=report_path,
        removed_files=tuple(removed_files),
    )


def load_sanitizer_config(config_path: Path | None) -> SanitizerConfig:
    remove_patterns = list(DEFAULT_REMOVE_PATTERNS)
    replacements: list[ReplacementRule] = []

    if config_path is None:
        return SanitizerConfig(tuple(remove_patterns), tuple(replacements))

    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SanitizeCaseError(f"could not read sanitizer config: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise SanitizeCaseError(f"invalid sanitizer config JSON at {config_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise SanitizeCaseError("sanitizer config must be a JSON object")

    configured_removals = raw.get("remove", [])
    if not isinstance(configured_removals, list) or not all(
        isinstance(item, str) for item in configured_removals
    ):
        raise SanitizeCaseError("sanitizer config remove must be an array of strings")
    remove_patterns.extend(configured_removals)

    configured_replacements = raw.get("replace", [])
    if not isinstance(configured_replacements, list):
        raise SanitizeCaseError("sanitizer config replace must be an array")

    for index, item in enumerate(configured_replacements):
        if not isinstance(item, dict):
            raise SanitizeCaseError(f"replacement rule {index} must be an object")
        label = item.get("label")
        find = item.get("find")
        replace = item.get("replace")
        if not all(isinstance(value, str) for value in (label, find, replace)):
            raise SanitizeCaseError(
                f"replacement rule {index} requires string label, find, and replace"
            )
        if find == "":
            raise SanitizeCaseError(f"replacement rule {index} find value cannot be empty")
        replacements.append(ReplacementRule(label=label, find=find, replace=replace))

    return SanitizerConfig(tuple(remove_patterns), tuple(replacements))


def _copy_sanitized_tree(
    source_dir: Path,
    output_dir: Path,
    remove_patterns: tuple[str, ...],
) -> list[str]:
    removed_files: list[str] = []

    for current_dir, dirnames, filenames in source_dir.walk():
        relative_dir = current_dir.relative_to(source_dir)
        target_dir = output_dir / relative_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        kept_dirs = []
        for dirname in sorted(dirnames):
            source_path = current_dir / dirname
            relative_path = source_path.relative_to(source_dir).as_posix()
            if _should_remove(relative_path, remove_patterns):
                removed_files.append(f"{relative_path}/")
            else:
                kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        for filename in sorted(filenames):
            source_path = current_dir / filename
            relative_path = source_path.relative_to(source_dir).as_posix()
            if _should_remove(relative_path, remove_patterns):
                removed_files.append(relative_path)
                continue
            shutil.copy2(source_path, target_dir / filename)

    return removed_files


def _apply_replacements(
    output_dir: Path,
    replacements: tuple[ReplacementRule, ...],
) -> list[dict[str, Any]]:
    replacement_report = [
        {"label": rule.label, "replacement": rule.replace, "count": 0, "files": []}
        for rule in replacements
    ]

    if not replacements:
        return replacement_report

    for path in sorted(item for item in output_dir.rglob("*") if item.is_file()):
        try:
            original = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        updated = original
        file_counts: list[tuple[int, int]] = []
        for index, rule in enumerate(replacements):
            count = updated.count(rule.find)
            if count:
                updated = updated.replace(rule.find, rule.replace)
                file_counts.append((index, count))

        if updated != original:
            path.write_text(updated, encoding="utf-8")
            relative_path = path.relative_to(output_dir).as_posix()
            for index, count in file_counts:
                replacement_report[index]["count"] += count
                replacement_report[index]["files"].append(
                    {"path": relative_path, "count": count}
                )

    return replacement_report


def _should_remove(relative_path: str, remove_patterns: tuple[str, ...]) -> bool:
    normalized = relative_path.replace("\\", "/")
    lowered = normalized.lower()

    for pattern in remove_patterns:
        normalized_pattern = pattern.replace("\\", "/").lower()
        if fnmatch.fnmatchcase(lowered, normalized_pattern):
            return True
        if "/" not in normalized_pattern and fnmatch.fnmatchcase(
            Path(lowered).name, normalized_pattern
        ):
            return True

    return False
