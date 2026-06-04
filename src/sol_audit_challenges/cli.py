from __future__ import annotations

from pathlib import Path
from typing import Callable

import typer

from sol_audit_challenges import __version__
from sol_audit_challenges.bundle import BundleCaseError, bundle_case
from sol_audit_challenges.leakage import LeakageAuditError, audit_leakage
from sol_audit_challenges.prepare import PrepareCaseError, prepare_case
from sol_audit_challenges.run import RunCaseError, run_case
from sol_audit_challenges.sanitize import SanitizeCaseError, sanitize_case
from sol_audit_challenges.score import ScoreReportError, score_report
from sol_audit_challenges.validation import (
    ManifestValidationError,
    validate_private_oracle,
    validate_public_manifest,
    validate_submitted_report,
)

app = typer.Typer(
    help="Package, run, and score sanitized Web3 audit benchmark challenges.",
    no_args_is_help=True,
)


@app.callback()
def cli() -> None:
    """Package, run, and score sanitized Web3 audit benchmark challenges."""


@app.command()
def version() -> None:
    """Print the CLI version."""
    typer.echo(__version__)


@app.command("validate-public")
def validate_public(
    manifest: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="Path to a public challenge manifest JSON file.",
    ),
) -> None:
    """Validate a public challenge manifest."""
    _run_validation(manifest, validate_public_manifest, "public manifest")


@app.command("validate-private")
def validate_private(
    oracle: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="Path to a private oracle JSON file.",
    ),
) -> None:
    """Validate a private oracle file."""
    _run_validation(oracle, validate_private_oracle, "private oracle")


@app.command("validate-report")
def validate_report(
    report: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="Path to a submitted finding report JSON file.",
    ),
) -> None:
    """Validate a submitted finding report."""
    _run_validation(report, validate_submitted_report, "submitted report")


@app.command("prepare-case")
def prepare_case_command(
    repo: str = typer.Option(
        ...,
        "--repo",
        help="Repository URL or local repository path to export.",
    ),
    commit: str = typer.Option(
        ...,
        "--commit",
        help="Commit, tag, or ref to export.",
    ),
    case_id: str = typer.Option(
        ...,
        "--case-id",
        help="Challenge case id, such as case-0001.",
    ),
    output_dir: Path = typer.Option(
        ...,
        "--output-dir",
        file_okay=False,
        help="Directory where public source and private oracle files are written.",
    ),
) -> None:
    """Export a repository commit into a clean source snapshot."""
    try:
        prepared = prepare_case(repo, commit, case_id, output_dir)
    except PrepareCaseError as exc:
        typer.secho(f"Prepare failed: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Prepared {prepared.case_id} at {prepared.commit}")
    typer.echo(f"Source snapshot: {prepared.source_dir}")
    typer.echo(f"Draft private oracle: {prepared.private_oracle}")


@app.command("sanitize-case")
def sanitize_case_command(
    source_dir: Path = typer.Option(
        ...,
        "--source-dir",
        exists=True,
        file_okay=False,
        readable=True,
        help="Source snapshot directory to sanitize.",
    ),
    output_dir: Path = typer.Option(
        ...,
        "--output-dir",
        file_okay=False,
        help="Directory where the sanitized source snapshot is written.",
    ),
    config: Path | None = typer.Option(
        None,
        "--config",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Optional sanitizer config JSON file.",
    ),
    report: Path | None = typer.Option(
        None,
        "--report",
        dir_okay=False,
        help="Optional sanitizer report path. Defaults next to the output directory.",
    ),
) -> None:
    """Remove obvious leakage clues and apply configured source replacements."""
    try:
        sanitized = sanitize_case(source_dir, output_dir, config, report)
    except SanitizeCaseError as exc:
        typer.secho(f"Sanitize failed: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Sanitized source snapshot: {sanitized.output_dir}")
    typer.echo(f"Sanitizer report: {sanitized.report_path}")
    typer.echo(f"Removed paths: {len(sanitized.removed_files)}")


@app.command("bundle-case")
def bundle_case_command(
    source_dir: Path = typer.Option(
        ...,
        "--source-dir",
        exists=True,
        file_okay=False,
        readable=True,
        help="Sanitized source snapshot directory to archive.",
    ),
    case_id: str = typer.Option(
        ...,
        "--case-id",
        help="Challenge case id, such as case-0001.",
    ),
    output_dir: Path = typer.Option(
        ...,
        "--output-dir",
        file_okay=False,
        help="Directory where the public archive and manifest are written.",
    ),
    manifest: Path | None = typer.Option(
        None,
        "--manifest",
        dir_okay=False,
        help="Optional existing public manifest to update.",
    ),
    language: list[str] | None = typer.Option(
        None,
        "--language",
        help="Challenge language. Can be provided multiple times.",
    ),
    prompt: str = typer.Option(
        "Find security issues in this codebase. Submit each finding with affected files, root cause, exploit impact, and a minimal proof sketch.",
        "--prompt",
        help="Public prompt written when creating a new manifest.",
    ),
) -> None:
    """Package a sanitized source snapshot as a deterministic public archive."""
    try:
        bundled = bundle_case(
            source_dir=source_dir,
            case_id=case_id,
            output_dir=output_dir,
            manifest_path=manifest,
            language=tuple(language or ["solidity"]),
            prompt=prompt,
        )
    except BundleCaseError as exc:
        typer.secho(f"Bundle failed: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Bundled {bundled.case_id}")
    typer.echo(f"Archive: {bundled.archive_path}")
    typer.echo(f"Manifest: {bundled.manifest_path}")
    typer.echo(f"SHA256: {bundled.sha256}")


@app.command("run-case")
def run_case_command(
    bundle: Path = typer.Option(
        ...,
        "--bundle",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Public challenge bundle archive to extract.",
    ),
    manifest: Path = typer.Option(
        ...,
        "--manifest",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Public challenge manifest for the bundle.",
    ),
    command: str = typer.Option(
        ...,
        "--command",
        help="Tool command to run from the extracted public workspace.",
    ),
    output_dir: Path = typer.Option(
        ...,
        "--output-dir",
        file_okay=False,
        help="Directory where run metadata and captured output are written.",
    ),
    mode: str = typer.Option(
        "local",
        "--mode",
        help="Runner mode: local or docker.",
    ),
    docker_image: str | None = typer.Option(
        None,
        "--docker-image",
        help="Container image used when --mode docker is selected.",
    ),
    timeout: int = typer.Option(
        900,
        "--timeout",
        help="Maximum command runtime in seconds.",
    ),
) -> None:
    """Run a tool against a public challenge bundle."""
    try:
        result = run_case(
            bundle_path=bundle,
            manifest_path=manifest,
            command=command,
            output_dir=output_dir,
            mode=mode,  # type: ignore[arg-type]
            docker_image=docker_image,
            timeout_seconds=timeout,
        )
    except RunCaseError as exc:
        typer.secho(f"Run failed: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Ran {result.case_id}")
    typer.echo(f"Run directory: {result.run_dir}")
    typer.echo(f"Metadata: {result.metadata_path}")
    typer.echo(f"Return code: {result.return_code}")


@app.command("score-report")
def score_report_command(
    report: Path = typer.Option(
        ...,
        "--report",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Submitted finding report JSON file to score.",
    ),
    oracle: Path = typer.Option(
        ...,
        "--oracle",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Private oracle JSON file withheld from evaluated tools.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        dir_okay=False,
        help="Score output JSON path. Defaults next to the submitted report.",
    ),
) -> None:
    """Score a submitted finding report against a private oracle."""
    try:
        result = score_report(report, oracle, output)
    except ScoreReportError as exc:
        typer.secho(f"Score failed: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Scored {result.case_id}")
    typer.echo(f"Score output: {result.output_path}")
    for finding in result.results:
        typer.echo(
            f"Finding {finding['finding_index']}: "
            f"{finding['status']} - {finding['title']}"
        )


@app.command("audit-leakage")
def audit_leakage_command(
    target: Path = typer.Option(
        ...,
        "--target",
        exists=True,
        readable=True,
        help="Source snapshot directory, single file, or tar archive to audit.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        dir_okay=False,
        help="Machine-readable leakage report path. Defaults next to the target.",
    ),
    denylist: Path | None = typer.Option(
        None,
        "--denylist",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Optional private JSON denylist of case-specific terms.",
    ),
) -> None:
    """Audit public challenge artifacts for answer leakage clues."""
    try:
        result = audit_leakage(target=target, report_path=output, denylist_path=denylist)
    except LeakageAuditError as exc:
        typer.secho(f"Leakage audit failed: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Audited {result.target_type}: {result.target}")
    typer.echo(f"Leakage report: {result.report_path}")
    typer.echo(f"Findings: {len(result.findings)}")
    summary: dict[str, int] = {}
    for finding in result.findings:
        rule = finding["rule"]
        summary[rule] = summary.get(rule, 0) + 1
    for rule, count in sorted(summary.items()):
        typer.echo(f"- {rule}: {count}")


def _run_validation(path: Path, validator: Callable[[Path], None], label: str) -> None:
    try:
        validator(path)
    except ManifestValidationError as exc:
        typer.secho(f"Validation failed for {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Valid {label}: {path}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
