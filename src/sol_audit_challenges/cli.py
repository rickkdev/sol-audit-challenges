from __future__ import annotations

from pathlib import Path
from typing import Callable

import typer

from sol_audit_challenges import __version__
from sol_audit_challenges.bundle import BundleCaseError, bundle_case
from sol_audit_challenges.prepare import PrepareCaseError, prepare_case
from sol_audit_challenges.sanitize import SanitizeCaseError, sanitize_case
from sol_audit_challenges.validation import (
    ManifestValidationError,
    validate_private_oracle,
    validate_public_manifest,
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
