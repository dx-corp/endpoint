#!/usr/bin/env python3
"""Bind the staged macOS package to its producer and Accepted final receipt."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import uuid


REPOSITORY = "dx-corp/mono"
WORKFLOW = ".github/workflows/merlin-sensor-release.yml"
CANDIDATE_SCHEMA = "deixic.endpoint.macos-candidate.v1"
RECEIPT_SCHEMA = "deixic.endpoint.macos-notarization.v1"
CONTEXT = ("version", "sourceSha", "sourceRef", "sourceRepository", "sourceRunId", "sourceRunAttempt", "inputPackageSha256")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as stream:
        value = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
        return value.hexdigest()


def context(metadata, package):
    require(metadata.get("schema") == CANDIDATE_SCHEMA, "unsupported candidate schema")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(metadata.get("version", ""))), "invalid candidate version")
    require(re.fullmatch(r"[a-f0-9]{40}", str(metadata.get("sourceSha", ""))), "invalid candidate source")
    require(metadata.get("sourceRepository") == REPOSITORY, "wrong candidate repository")
    for field in ("sourceRunId", "sourceRunAttempt"):
        require(type(metadata.get(field)) is int and metadata[field] > 0, "invalid producer identity")
    require(re.fullmatch(r"[a-f0-9]{64}", str(metadata.get("inputPackageSha256", ""))), "invalid candidate digest")
    require(metadata.get("sourceRef") in ("refs/heads/main", "refs/tags/merlin-v" + metadata["version"]), "untrusted candidate ref")
    require(package.name == "Merlin-" + metadata["version"] + ".pkg", "wrong candidate package filename")


def candidate(version, source_sha, source_ref, run_id, attempt, package):
    result = {
        "schema": CANDIDATE_SCHEMA, "version": version, "sourceSha": source_sha,
        "sourceRef": source_ref, "sourceRepository": REPOSITORY,
        "sourceRunId": run_id, "sourceRunAttempt": attempt,
        "inputPackageSha256": digest(package),
    }
    context(result, package)
    return result


def admit(metadata, run, package, tag_sha):
    context(metadata, package)
    require(digest(package) == metadata["inputPackageSha256"], "candidate package changed")
    require(run.get("id") == metadata["sourceRunId"] and run.get("run_attempt") == metadata["sourceRunAttempt"], "producer run/attempt differs")
    require(run.get("head_sha") == metadata["sourceSha"], "producer source differs")
    require(run.get("repository", {}).get("full_name") == REPOSITORY and run.get("head_repository", {}).get("full_name") == REPOSITORY, "untrusted producer repository")
    require(run.get("path") == WORKFLOW, "untrusted producer workflow")
    require(run.get("status") == "completed" and run.get("conclusion") == "success", "producer has not succeeded")
    tagged = metadata["sourceRef"].startswith("refs/tags/")
    if tagged:
        tag = "merlin-v" + metadata["version"]
        require(run.get("event") == "push" and run.get("head_branch") == tag, "producer is not the admitted tag")
        require(tag_sha == metadata["sourceSha"], "release tag differs from candidate source")
    else:
        tag = ""
        require(run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main", "preflight is not trusted main")
        require(tag_sha is None, "preflight cannot supply a publication tag")
    return {**metadata, "publish": tagged, "tag": tag}


def submission_id(value):
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError("invalid notarization submission ID") from error
    require(str(parsed) == value, "invalid notarization submission ID")


def accepted_response(response):
    require(response.get("status") == "Accepted", "notarization is not Accepted")
    submission_id(response.get("id"))


def receipt(metadata, response, package, submitted_sha):
    context(metadata, package)
    require(submitted_sha == metadata["inputPackageSha256"], "submitted package differs from admitted candidate")
    accepted_response(response)
    result = {field: metadata[field] for field in CONTEXT}
    result.update(schema=RECEIPT_SCHEMA, status="Accepted", submissionId=response["id"], packageSha256=digest(package))
    return result


def verify_receipt(value, metadata, package):
    context(metadata, package)
    require(value.get("schema") == RECEIPT_SCHEMA and value.get("status") == "Accepted", "invalid notarization receipt")
    for field in CONTEXT:
        require(value.get(field) == metadata[field], "notarization context differs: " + field)
    submission_id(value.get("submissionId"))
    require(value.get("packageSha256") == digest(package), "final notarized package changed")


def load(path):
    return json.loads(path.read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("candidate")
    for field in ("version", "source-sha", "source-ref"):
        create.add_argument("--" + field, required=True)
    create.add_argument("--run-id", type=int, required=True)
    create.add_argument("--run-attempt", type=int, required=True)
    admission = commands.add_parser("admit")
    admission.add_argument("--source-run", type=Path, required=True)
    admission.add_argument("--repository-root", type=Path, required=True)
    record = commands.add_parser("receipt")
    record.add_argument("--response", type=Path, required=True)
    record.add_argument("--submitted-sha256", required=True)
    check = commands.add_parser("verify-receipt")
    check.add_argument("--receipt", type=Path, required=True)
    verify = commands.add_parser("verify-candidate")
    response = commands.add_parser("check-response")
    response.add_argument("--response", type=Path, required=True)
    for command in (create, admission, record, check, verify):
        command.add_argument("--package", type=Path, required=True)
        if command is not create:
            command.add_argument("--candidate", type=Path, required=True)
        if command not in (check, verify):
            command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "check-response":
        accepted_response(load(args.response))
        return
    if args.command == "candidate":
        result = candidate(args.version, args.source_sha, args.source_ref, args.run_id, args.run_attempt, args.package)
    else:
        metadata = load(args.candidate)
        if args.command == "admit":
            context(metadata, args.package)
            subprocess.run(["git", "merge-base", "--is-ancestor", metadata["sourceSha"], "origin/main"], cwd=args.repository_root, check=True)
            tag_sha = None
            if metadata["sourceRef"].startswith("refs/tags/"):
                tag_sha = subprocess.check_output(["git", "rev-parse", "--verify", metadata["sourceRef"] + "^{commit}"], cwd=args.repository_root, text=True).strip()
            result = admit(metadata, load(args.source_run), args.package, tag_sha)
        elif args.command == "verify-candidate":
            context(metadata, args.package)
            require(digest(args.package) == metadata["inputPackageSha256"], "candidate package changed")
            return
        elif args.command == "receipt":
            result = receipt(metadata, load(args.response), args.package, args.submitted_sha256)
        else:
            verify_receipt(load(args.receipt), metadata, args.package)
            return
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
