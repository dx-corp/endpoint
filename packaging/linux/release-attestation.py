#!/usr/bin/env python3
"""Write or verify a deterministic Deixic Endpoint package attestation."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def digest(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def expected(
    artifact: pathlib.Path, version: str, repository: str, source_sha: str
) -> dict:
    if not version or any(character.isspace() for character in version):
        raise ValueError("version must be a non-empty single token")
    if repository != "evalops/mono":
        raise ValueError("source repository must be evalops/mono")
    if not SHA_RE.fullmatch(source_sha):
        raise ValueError("source sha must be a lowercase 40-character commit id")
    if not artifact.is_file():
        raise ValueError(f"artifact does not exist: {artifact}")
    parts = artifact.name.removesuffix(".tar.gz").split("-")
    if len(parts) < 4 or parts[-2] != "linux" or parts[-1] not in {"x86_64", "aarch64"}:
        raise ValueError(
            "artifact name must end in -linux-x86_64.tar.gz or -linux-aarch64.tar.gz"
        )
    return {
        "schema_version": 1,
        "subject": {
            "name": artifact.name,
            "sha256": digest(artifact),
            "size_bytes": artifact.stat().st_size,
        },
        "package": {
            "name": "merlin",
            "product": "Deixic Endpoint",
            "version": version,
            "platform": "linux",
            "architecture": parts[-1],
        },
        "build": {
            "source_repository": repository,
            "source_sha": source_sha,
            "builder": "github.com/evalops/mono/.github/workflows/merlin-sensor-release.yml",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("write", "verify"))
    parser.add_argument("--artifact", type=pathlib.Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--repository", default="evalops/mono")
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--attestation", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        payload = expected(
            args.artifact, args.version, args.repository, args.source_sha
        )
        if args.mode == "write":
            args.attestation.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        else:
            actual = json.loads(args.attestation.read_text(encoding="utf-8"))
            if actual != payload:
                raise ValueError(
                    "attestation does not match the artifact and source coordinates"
                )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"release attestation: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
