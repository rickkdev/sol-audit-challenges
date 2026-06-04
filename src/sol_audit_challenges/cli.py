from __future__ import annotations

from pathlib import Path
from typing import Callable

import typer

from sol_audit_challenges import __version__
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
