from __future__ import annotations

import json
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


class LeakageAuditError(Exception):
    """Auditing a challenge artifact for leakage failed."""


TEXT_SUFFIXES = {
    ".c",
    ".cfg",
    ".conf",
    ".cpp",
    ".css",
    ".env",
    ".gitignore",
    ".h",
    ".html",
    ".js",
    ".json",
    ".lock",
    ".md",
    ".py",
    ".rs",
    ".sol",
    ".toml",
    ".txt",
    ".ts",
    ".yaml",
    ".yml",
}
MAX_TEXT_BYTES = 2 * 1024 * 1024

CONTENT_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "transaction_hash",
        "ethereum transaction hash",
        re.compile(r"\b0x[a-fA-F0-9]{64}\b"),
    ),
    (
        "address",
        "ethereum address",
        re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    ),
    (
        "commit_hash",
        "40-character Git commit hash",
        re.compile(r"\b[0-9a-fA-F]{40}\b"),
    ),
    (
        "repository_url",
        "repository URL",
        re.compile(
            r"(?:https?://[^\s\"'<>]+|git@[A-Za-z0-9_.-]+:[^\s\"'<>]+)",
            re.IGNORECASE,
        ),
    ),
    (
        "incident_keyword",
        "incident or exploit keyword",
        re.compile(
            r"\b(?:incident|postmortem|exploit|attacker|hack|vulnerability disclosure)\b",
            re.IGNORECASE,
        ),
    ),
)


@dataclass(frozen=True)
class AuditEntry:
    path: str
    data: bytes


@dataclass(frozen=True)
class LeakageAuditResult:
    target: Path
    target_type: str
    report_path: Path
    findings: tuple[dict[str, Any], ...]


def audit_leakage(
    target: Path,
    report_path: Path | None = None,
    denylist_path: Path | None = None,
) -> LeakageAuditResult:
    """Scan a source snapshot or archive for public benchmark leakage clues."""
    target = target.resolve()
    if not target.exists():
        raise LeakageAuditError(f"target does not exist: {target}")

    denylist = _load_denylist(denylist_path)
    target_type, entries = _read_entries(target)
    findings: list[dict[str, Any]] = []

    for entry in entries:
        findings.extend(_audit_path(entry.path))
        findings.extend(_audit_content(entry, denylist))

    findings = sorted(
        findings,
        key=lambda item: (item["path"], item["rule"], item["match"]),
    )
    report_path = (report_path or _default_report_path(target)).resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "target": str(target),
        "target_type": target_type,
        "finding_count": len(findings),
        "summary": _summarize(findings),
        "findings": findings,
    }
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    return LeakageAuditResult(
        target=target,
        target_type=target_type,
        report_path=report_path,
        findings=tuple(findings),
    )


def _read_entries(target: Path) -> tuple[str, list[AuditEntry]]:
    if target.is_dir():
        entries = [
            AuditEntry(path=item.relative_to(target).as_posix(), data=item.read_bytes())
            for item in sorted(
                target.rglob("*"),
                key=lambda path: path.relative_to(target).as_posix(),
            )
            if item.is_file()
        ]
        return "directory", entries

    if tarfile.is_tarfile(target):
        try:
            with tarfile.open(target, "r:*") as archive:
                entries = [
                    AuditEntry(path=member.name, data=_read_tar_member(archive, member))
                    for member in sorted(archive.getmembers(), key=lambda item: item.name)
                    if member.isfile()
                ]
        except (tarfile.TarError, OSError) as exc:
            raise LeakageAuditError(f"could not read archive: {target}") from exc
        return "archive", entries

    return "file", [AuditEntry(path=target.name, data=target.read_bytes())]


def _read_tar_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    extracted = archive.extractfile(member)
    if extracted is None:
        return b""
    return extracted.read()


def _audit_path(path: str) -> list[dict[str, Any]]:
    lowered_parts = [part.lower() for part in Path(path).parts]
    filename = Path(path).name.lower()
    findings: list[dict[str, Any]] = []

    if ".git" in lowered_parts or filename.startswith(".git"):
        findings.append(
            _finding("git_metadata", "Git metadata path", path, "path", ".git")
        )
    if "audit" in filename or "audits" in lowered_parts:
        findings.append(
            _finding(
                "audit_filename",
                "audit report filename",
                path,
                "path",
                Path(path).name,
            )
        )
    if any(keyword in filename for keyword in ("incident", "exploit", "poc")):
        findings.append(
            _finding(
                "incident_filename",
                "incident or exploit filename",
                path,
                "path",
                Path(path).name,
            )
        )

    return findings


def _audit_content(
    entry: AuditEntry,
    denylist: tuple[tuple[str, str], ...],
) -> list[dict[str, Any]]:
    if not _looks_text(entry.path, entry.data):
        return []

    try:
        text = entry.data.decode("utf-8")
    except UnicodeDecodeError:
        text = entry.data.decode("utf-8", errors="ignore")

    findings: list[dict[str, Any]] = []
    for rule, description, pattern in CONTENT_RULES:
        for match in _unique_matches(pattern.finditer(text)):
            if rule == "repository_url" and not _looks_repository_url(match):
                continue
            findings.append(_finding(rule, description, entry.path, "content", match))

    for label, term in denylist:
        if not term:
            continue
        matches = re.finditer(re.escape(term), text, flags=re.IGNORECASE)
        for match in _unique_matches(matches):
            findings.append(
                _finding(
                    "denylist",
                    f"private denylist term: {label}",
                    entry.path,
                    "content",
                    match,
                )
            )

    return findings


def _unique_matches(matches: Iterable[re.Match[str]]) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for match in matches:
        value = match.group(0)
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        values.append(value)
    return values


def _looks_text(path: str, data: bytes) -> bool:
    if len(data) > MAX_TEXT_BYTES:
        return False
    suffix = Path(path).suffix.lower()
    if suffix in TEXT_SUFFIXES or Path(path).name in TEXT_SUFFIXES:
        return True
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _looks_repository_url(value: str) -> bool:
    lowered = value.lower().rstrip(".,);]")
    return (
        lowered.startswith("git@")
        or lowered.endswith(".git")
        or "github.com/" in lowered
        or "gitlab.com/" in lowered
        or "bitbucket.org/" in lowered
    )


def _load_denylist(path: Path | None) -> tuple[tuple[str, str], ...]:
    if path is None:
        return ()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise LeakageAuditError(f"could not read denylist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise LeakageAuditError(f"invalid denylist JSON at {path}: {exc}") from exc

    if isinstance(raw, list):
        return tuple(
            (f"term_{index}", item)
            for index, item in enumerate(raw)
            if isinstance(item, str)
        )
    if not isinstance(raw, dict):
        raise LeakageAuditError("denylist must be a JSON object or array")

    terms = raw.get("terms", raw.get("denylist", []))
    if not isinstance(terms, list):
        raise LeakageAuditError("denylist terms must be an array")

    parsed: list[tuple[str, str]] = []
    for index, item in enumerate(terms):
        if isinstance(item, str):
            parsed.append((f"term_{index}", item))
        elif isinstance(item, dict):
            label = item.get("label", f"term_{index}")
            value = item.get("value", item.get("term"))
            if not isinstance(label, str) or not isinstance(value, str):
                raise LeakageAuditError(
                    f"denylist term {index} requires string label and value"
                )
            parsed.append((label, value))
        else:
            raise LeakageAuditError(f"denylist term {index} must be a string or object")
    return tuple(parsed)


def _default_report_path(target: Path) -> Path:
    if target.is_dir():
        return target.parent / f"{target.name}.leakage.json"
    return target.with_suffix(target.suffix + ".leakage.json")


def _summarize(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for finding in findings:
        rule = finding["rule"]
        summary[rule] = summary.get(rule, 0) + 1
    return dict(sorted(summary.items()))


def _finding(
    rule: str,
    description: str,
    path: str,
    location: str,
    match: str,
) -> dict[str, str]:
    return {
        "rule": rule,
        "description": description,
        "path": path,
        "location": location,
        "match": match,
    }
