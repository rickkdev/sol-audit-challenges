from __future__ import annotations

import json
from dataclasses import dataclass
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError


SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"


@dataclass(frozen=True)
class ManifestValidationError(Exception):
    """A manifest failed JSON parsing or schema validation."""

    path: Path
    message: str
    schema_location: str | None = None

    def __str__(self) -> str:
        schema_suffix = (
            f" (schema: {self.schema_location})" if self.schema_location else ""
        )
        return f"{self.path}: {self.message}{schema_suffix}"


def validate_public_manifest(path: Path) -> None:
    """Validate a public challenge manifest."""
    validate_json_file(path, SCHEMA_DIR / "public-challenge.schema.json")


def validate_private_oracle(path: Path) -> None:
    """Validate a private oracle record."""
    validate_json_file(path, SCHEMA_DIR / "private-oracle.schema.json")


def validate_submitted_report(path: Path) -> None:
    """Validate a submitted finding report."""
    validate_json_file(path, SCHEMA_DIR / "submitted-report.schema.json")


def validate_json_file(path: Path, schema_path: Path) -> None:
    instance = _load_json(path, path)
    schema = _load_json(schema_path, schema_path)

    validator = Draft202012Validator(schema)
    error = next(validator.iter_errors(instance), None)
    if error is not None:
        raise ManifestValidationError(
            path=path,
            message=error.message,
            schema_location=_format_schema_location(error),
        )


def _load_json(path: Path, display_path: Path) -> Any:
    try:
        with path.open(encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError as exc:
        raise ManifestValidationError(display_path, "file does not exist") from exc
    except JSONDecodeError as exc:
        raise ManifestValidationError(
            display_path,
            f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}",
        ) from exc


def _format_schema_location(error: ValidationError) -> str:
    if not error.absolute_schema_path:
        return "#"
    return "#/" + "/".join(str(part) for part in error.absolute_schema_path)
