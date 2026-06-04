from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from sol_audit_challenges.validation import (
    ManifestValidationError,
    validate_private_oracle,
    validate_submitted_report,
)


ScoreStatus = Literal[
    "accepted", "partial", "duplicate", "false_positive", "out_of_scope"
]


class ScoreReportError(Exception):
    """A submitted report could not be scored."""


@dataclass(frozen=True)
class ScoreReportResult:
    case_id: str
    output_path: Path
    results: list[dict[str, Any]]


def score_report(
    report_path: Path,
    oracle_path: Path,
    output_path: Path | None = None,
) -> ScoreReportResult:
    try:
        validate_submitted_report(report_path)
        validate_private_oracle(oracle_path)
    except ManifestValidationError as exc:
        raise ScoreReportError(str(exc)) from exc

    report = _load_json(report_path)
    oracle = _load_json(oracle_path)

    case_id = report["case_id"]
    if case_id != oracle["id"]:
        results = [
            _result(
                index=index,
                title=finding["title"],
                status="out_of_scope",
                explanation=(
                    f"Report case_id {case_id} does not match oracle case_id "
                    f"{oracle['id']}."
                ),
            )
            for index, finding in enumerate(report["findings"])
        ]
    else:
        results = _score_findings(report["findings"], oracle["accepted_finding"])

    output = {
        "case_id": case_id,
        "oracle_id": oracle["id"],
        "results": results,
        "summary": _summary(results),
    }

    resolved_output = output_path or report_path.with_suffix(".score.json")
    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    resolved_output.write_text(
        json.dumps(output, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    return ScoreReportResult(
        case_id=case_id,
        output_path=resolved_output,
        results=results,
    )


def _score_findings(
    findings: list[dict[str, Any]],
    accepted_finding: dict[str, Any],
) -> list[dict[str, Any]]:
    accepted_seen = False
    results: list[dict[str, Any]] = []

    for index, finding in enumerate(findings):
        location_score = _location_score(
            finding.get("affected_files", []),
            accepted_finding.get("locations", []),
        )
        keyword_score = _keyword_score(finding, accepted_finding)

        if location_score >= 0.99 and keyword_score >= 0.2:
            status: ScoreStatus = "duplicate" if accepted_seen else "accepted"
            accepted_seen = True
        elif location_score >= 1.0 or (
            location_score >= 0.5 and keyword_score >= 0.15
        ) or keyword_score >= 0.45:
            status = "partial"
        else:
            status = "false_positive"

        results.append(
            _result(
                index=index,
                title=finding["title"],
                status=status,
                explanation=_explanation(status, location_score, keyword_score),
                location_score=location_score,
                keyword_score=keyword_score,
            )
        )

    return results


def _result(
    *,
    index: int,
    title: str,
    status: ScoreStatus,
    explanation: str,
    location_score: float | None = None,
    keyword_score: float | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "finding_index": index,
        "title": title,
        "status": status,
        "explanation": explanation,
    }
    if location_score is not None:
        result["signals"] = {
            "location_score": round(location_score, 3),
            "keyword_score": round(keyword_score or 0.0, 3),
        }
    return result


def _location_score(
    submitted_locations: list[dict[str, Any]],
    oracle_locations: list[dict[str, Any]],
) -> float:
    if not oracle_locations:
        return 0.0

    best_score = 0.0
    for submitted in submitted_locations:
        submitted_path = _normalize_path(submitted["path"])
        submitted_symbol = _normalize_token(submitted.get("symbol", ""))
        submitted_line = submitted.get("line")

        for oracle in oracle_locations:
            oracle_path = _normalize_path(oracle["path"])
            score = 0.0
            if submitted_path == oracle_path:
                score = 0.7
            elif submitted_path.endswith(f"/{oracle_path}") or oracle_path.endswith(
                f"/{submitted_path}"
            ):
                score = 0.6

            oracle_symbol = _normalize_token(oracle.get("symbol", ""))
            if submitted_symbol and oracle_symbol and submitted_symbol == oracle_symbol:
                score += 0.2

            oracle_line = oracle.get("line")
            if (
                isinstance(submitted_line, int)
                and isinstance(oracle_line, int)
                and abs(submitted_line - oracle_line) <= 3
            ):
                score += 0.1

            best_score = max(best_score, min(score, 1.0))

    return best_score


def _keyword_score(finding: dict[str, Any], accepted_finding: dict[str, Any]) -> float:
    submitted_text = " ".join(
        [
            finding["title"],
            finding["root_cause"],
            finding["impact"],
            finding["proof_sketch"],
            " ".join(finding.get("reproduction_steps", [])),
        ]
    )
    oracle_text = " ".join(
        [
            accepted_finding["summary"],
            accepted_finding["root_cause"],
            accepted_finding["impact"],
        ]
    )

    oracle_tokens = _keywords(oracle_text)
    if not oracle_tokens:
        return 0.0
    submitted_tokens = _keywords(submitted_text)
    return len(oracle_tokens & submitted_tokens) / len(oracle_tokens)


def _keywords(text: str) -> set[str]:
    stop_words = {
        "about",
        "after",
        "allows",
        "because",
        "being",
        "cannot",
        "could",
        "from",
        "have",
        "into",
        "that",
        "their",
        "there",
        "this",
        "through",
        "when",
        "with",
        "would",
    }
    return {
        token
        for token in re.findall(r"[a-z0-9_]{4,}", text.lower())
        if token not in stop_words
    }


def _normalize_path(path: str) -> str:
    normalized = path.replace("\\", "/").strip("/")
    if normalized.startswith("source/"):
        normalized = normalized.removeprefix("source/")
    return normalized.lower()


def _normalize_token(value: str) -> str:
    return value.strip().lower()


def _explanation(
    status: ScoreStatus,
    location_score: float,
    keyword_score: float,
) -> str:
    if status == "accepted":
        return "Finding matched the oracle location and root-cause/impact keywords."
    if status == "duplicate":
        return "Finding matched an already accepted oracle issue."
    if status == "partial":
        return "Finding matched some oracle signals but needs maintainer review."
    return "Finding did not match the oracle location or enough root-cause/impact keywords."


def _summary(results: list[dict[str, Any]]) -> dict[str, int]:
    statuses: list[ScoreStatus] = [
        "accepted",
        "partial",
        "duplicate",
        "false_positive",
        "out_of_scope",
    ]
    return {
        status: sum(1 for result in results if result["status"] == status)
        for status in statuses
    }


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
