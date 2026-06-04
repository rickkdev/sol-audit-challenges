from __future__ import annotations

import typer

from sol_audit_challenges import __version__

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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
