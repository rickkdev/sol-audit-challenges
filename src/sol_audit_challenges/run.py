from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal


class RunCaseError(Exception):
    """Running a challenge case failed."""


RunMode = Literal["local", "docker"]


@dataclass(frozen=True)
class RunCaseResult:
    case_id: str
    run_id: str
    run_dir: Path
    metadata_path: Path
    stdout_path: Path
    stderr_path: Path
    return_code: int


def run_case(
    bundle_path: Path,
    manifest_path: Path,
    command: str,
    output_dir: Path,
    mode: RunMode = "local",
    docker_image: str | None = None,
    timeout_seconds: int = 900,
) -> RunCaseResult:
    """Extract a public bundle and run a tool against it without oracle files."""
    bundle_path = bundle_path.resolve()
    manifest_path = manifest_path.resolve()
    output_dir = output_dir.resolve()

    if not bundle_path.is_file():
        raise RunCaseError(f"bundle does not exist: {bundle_path}")
    if not manifest_path.is_file():
        raise RunCaseError(f"manifest does not exist: {manifest_path}")
    if not command:
        raise RunCaseError("command cannot be empty")
    if mode not in ("local", "docker"):
        raise RunCaseError("mode must be local or docker")
    if mode == "docker" and not docker_image:
        raise RunCaseError("docker mode requires --docker-image")
    if timeout_seconds < 1:
        raise RunCaseError("timeout must be at least 1 second")

    manifest = _load_manifest(manifest_path)
    case_id = _manifest_case_id(manifest)
    _verify_bundle_checksum(bundle_path, manifest)

    run_id = _new_run_id()
    run_dir = output_dir / "runs" / case_id / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    stdout_path = run_dir / "stdout.txt"
    stderr_path = run_dir / "stderr.txt"
    metadata_path = run_dir / "metadata.json"

    started_at = _utc_now()
    with tempfile.TemporaryDirectory(prefix=f"{case_id}-run-") as workspace_name:
        workspace = Path(workspace_name)
        _extract_public_source(bundle_path, workspace)
        workspace_manifest = workspace / "public-manifest.json"
        workspace_manifest.write_text(
            json.dumps(manifest, indent=2) + "\n",
            encoding="utf-8",
        )

        try:
            completed = _execute(
                command=command,
                workspace=workspace,
                run_dir=run_dir,
                mode=mode,
                docker_image=docker_image,
                timeout_seconds=timeout_seconds,
            )
            timed_out = False
            return_code = completed.returncode
            stdout = completed.stdout
            stderr = completed.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            return_code = 124
            stdout = _coerce_output(exc.stdout)
            stderr = _coerce_output(exc.stderr)
            stderr = f"{stderr}\nCommand timed out after {timeout_seconds} seconds.\n"

    finished_at = _utc_now()
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    _write_metadata(
        metadata_path,
        {
            "case_id": case_id,
            "run_id": run_id,
            "mode": mode,
            "command": command,
            "docker_image": docker_image,
            "bundle": str(bundle_path),
            "manifest": str(manifest_path),
            "started_at": started_at,
            "finished_at": finished_at,
            "timeout_seconds": timeout_seconds,
            "timed_out": timed_out,
            "return_code": return_code,
            "stdout": "stdout.txt",
            "stderr": "stderr.txt",
            "workspace": {
                "source": "source/",
                "manifest": "public-manifest.json",
                "private_oracle_available": False,
            },
            "network": _network_metadata(mode),
        },
    )

    return RunCaseResult(
        case_id=case_id,
        run_id=run_id,
        run_dir=run_dir,
        metadata_path=metadata_path,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        return_code=return_code,
    )


def _execute(
    command: str,
    workspace: Path,
    run_dir: Path,
    mode: RunMode,
    docker_image: str | None,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    if mode == "docker":
        docker_command = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--workdir",
            "/workspace",
            "--mount",
            f"type=bind,source={workspace},target=/workspace,readonly",
            "--mount",
            f"type=bind,source={run_dir},target=/runs",
            docker_image or "",
            "/bin/sh",
            "-lc",
            command,
        ]
        return subprocess.run(
            docker_command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )

    env = os.environ.copy()
    env["SOL_AUDIT_NETWORK"] = "disabled-local-fallback"
    env["SOL_AUDIT_RUN_DIR"] = str(run_dir)
    return subprocess.run(
        shlex.split(command),
        check=False,
        cwd=workspace,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )


def _extract_public_source(bundle_path: Path, workspace: Path) -> None:
    try:
        with tarfile.open(bundle_path, "r:gz") as archive:
            for member in archive.getmembers():
                _validate_member(member)
            archive.extractall(workspace)
    except tarfile.TarError as exc:
        raise RunCaseError(f"invalid challenge bundle: {bundle_path}") from exc

    source_dir = workspace / "source"
    if not source_dir.is_dir():
        raise RunCaseError("bundle must contain a source/ directory")

    forbidden = [
        path
        for path in source_dir.rglob("*")
        if path.name == ".git" or path.name.endswith(".private.json") or path.name.endswith(".oracle.json")
    ]
    if forbidden:
        first = forbidden[0].relative_to(workspace).as_posix()
        raise RunCaseError(f"bundle contains private or Git metadata path: {first}")


def _validate_member(member: tarfile.TarInfo) -> None:
    name = member.name.replace("\\", "/")
    if Path(name).is_absolute() or ".." in Path(name).parts:
        raise RunCaseError(f"bundle contains unsafe path: {member.name}")
    if member.isdir():
        if name != "source" and not name.startswith("source/"):
            raise RunCaseError(f"bundle contains non-public path: {member.name}")
        return
    if not member.isfile():
        raise RunCaseError(f"bundle contains unsupported tar member: {member.name}")
    if not name.startswith("source/"):
        raise RunCaseError(f"bundle contains non-public path: {member.name}")


def _load_manifest(manifest_path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RunCaseError(f"invalid public manifest JSON at {manifest_path}: {exc}") from exc
    except OSError as exc:
        raise RunCaseError(f"could not read public manifest: {manifest_path}") from exc
    if not isinstance(manifest, dict):
        raise RunCaseError("public manifest must be a JSON object")
    return manifest


def _manifest_case_id(manifest: dict[str, Any]) -> str:
    case_id = manifest.get("id")
    if not isinstance(case_id, str) or not case_id:
        raise RunCaseError("public manifest must include a case id")
    return case_id


def _verify_bundle_checksum(bundle_path: Path, manifest: dict[str, Any]) -> None:
    package = manifest.get("package")
    if not isinstance(package, dict):
        raise RunCaseError("public manifest must include package metadata")
    expected = package.get("sha256")
    if not isinstance(expected, str) or not expected:
        raise RunCaseError("public manifest package must include sha256")
    actual = _sha256_file(bundle_path)
    if actual != expected:
        raise RunCaseError(
            f"bundle checksum mismatch for {bundle_path}: expected {expected}, got {actual}"
        )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _network_metadata(mode: RunMode) -> dict[str, str | bool]:
    if mode == "docker":
        return {"disabled": True, "mechanism": "docker --network none"}
    return {
        "disabled": False,
        "mechanism": "local fallback; no network namespace is enforced",
    }


def _coerce_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _write_metadata(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
