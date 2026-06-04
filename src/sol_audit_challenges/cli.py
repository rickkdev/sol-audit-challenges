from __future__ import annotations

from pathlib import Path
from typing import Callable

import typer

from sol_audit_challenges import __version__
from sol_audit_challenges.prepare import PrepareCaseError, prepare_case
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
