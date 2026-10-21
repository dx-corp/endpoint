#!/usr/bin/env python3
"""Write the downloads.json manifest published beside Deixic Endpoint release assets.

Reads the SHA256SUMS files the Linux and Windows packaging jobs produce and
emits one entry per package archive with its platform, architecture, format,
public download URL and digest. The Deixic enrollment page reads this file to
offer per-platform downloads; checksum and attestation files are listed in the
release but are not downloads themselves.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

LINUX = re.compile(r"merlin-(?P<version>.+)-linux-(?P<arch>[A-Za-z0-9_]+)\.tar\.gz")
WINDOWS = re.compile(r"deixic-endpoint-(?P<version>.+)-windows-(?P<arch>[A-Za-z0-9_]+)\.zip")
MACOS = re.compile(r"Merlin-(?P<version>.+)\.pkg")


def classify(name: str) -> dict[str, str] | None:
    if match := LINUX.fullmatch(name):
        return {"platform": "linux", "architecture": match.group("arch"), "format": "tar.gz"}
    if match := WINDOWS.fullmatch(name):
        return {"platform": "windows", "architecture": match.group("arch"), "format": "zip"}
    if MACOS.fullmatch(name):
        return {"platform": "macos", "architecture": "universal", "format": "pkg"}
    return None


def manifest(tag: str, source_sha: str, repository: str, sums: list[Path]) -> dict:
    base = f"https://github.com/{repository}/releases/download/{tag}/"
    downloads = []
    for path in sums:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            digest, name = line.split(maxsplit=1)
            name = name.strip().lstrip("*")
            kind = classify(name)
            if kind is None:
                continue
            downloads.append({**kind, "file_name": name, "url": base + name, "sha256": digest})
    downloads.sort(key=lambda item: (item["platform"], item["architecture"]))
    return {
        "schema_version": 1,
        "release_tag": tag,
        "source_repository": "dx-corp/mono",
        "source_sha": source_sha,
        "downloads": downloads,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--repository", default="dx-corp/endpoint")
    parser.add_argument("sums", nargs="+", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"merlin-v[0-9A-Za-z._-]+", args.tag):
        print(f"unsupported release tag {args.tag!r}", file=sys.stderr)
        return 2
    result = manifest(args.tag, args.source_sha, args.repository, args.sums)
    if not result["downloads"]:
        print("no package archives found in the checksum files", file=sys.stderr)
        return 1
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
