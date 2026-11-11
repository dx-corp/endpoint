#!/usr/bin/env python3
"""Bind a notarization candidate, trusted producer and final package receipt."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest


MODULE = runpy.run_path(str(Path(__file__).with_name("protected-notarization.py")))


class ProtectedNotarizationTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.package = Path(self.directory.name) / "Merlin-0.1.3.pkg"
        self.package.write_bytes(b"signed candidate fixture")
        self.candidate = MODULE["candidate"](
            "0.1.3", "a" * 40, "refs/tags/merlin-v0.1.3", 123, 2, self.package,
        )
        self.run = {
            "id": 123, "run_attempt": 2, "head_sha": "a" * 40,
            "head_branch": "merlin-v0.1.3", "event": "push",
            "path": ".github/workflows/merlin-sensor-release.yml",
            "repository": {"full_name": "dx-corp/mono"},
            "head_repository": {"full_name": "dx-corp/mono"},
            "status": "completed", "conclusion": "success",
        }

    def admit(self, candidate=None, run=None, tag_sha="a" * 40):
        return MODULE["admit"](
            candidate or self.candidate, run or self.run, self.package, tag_sha,
        )

    def test_tag_cohort_pins_source_run_attempt_and_exact_bytes(self):
        result = self.admit()
        self.assertTrue(result["publish"])
        self.assertEqual(result["tag"], "merlin-v0.1.3")
        self.assertEqual(result["sourceSha"], self.run["head_sha"])
        self.assertEqual(result["sourceRunAttempt"], self.run["run_attempt"])
        self.assertEqual(result["inputPackageSha256"], hashlib.sha256(self.package.read_bytes()).hexdigest())

    def test_main_preflight_never_becomes_publication(self):
        candidate, run = deepcopy(self.candidate), deepcopy(self.run)
        candidate["sourceRef"] = "refs/heads/main"
        run.update(event="workflow_dispatch", head_branch="main")
        result = self.admit(candidate, run, tag_sha=None)
        self.assertFalse(result["publish"])
        self.assertEqual(result["tag"], "")

    def test_rejects_other_or_incomplete_producer(self):
        changes = (
            {"id": 124}, {"run_attempt": 3}, {"head_sha": "b" * 40},
            {"head_branch": "feature"}, {"event": "pull_request"},
            {"path": ".github/workflows/untrusted.yml"},
            {"repository": {"full_name": "someone/mono"}},
            {"head_repository": {"full_name": "someone/mono"}},
            {"status": "in_progress"}, {"conclusion": "failure"},
            {"conclusion": "cancelled"},
        )
        for change in changes:
            with self.subTest(change=change):
                run = {**self.run, **change}
                with self.assertRaises(ValueError):
                    self.admit(run=run)

    def test_rejects_tag_retarget_and_corrupt_candidate(self):
        with self.assertRaises(ValueError):
            self.admit(tag_sha="b" * 40)
        self.package.write_bytes(b"changed after signature verification")
        with self.assertRaises(ValueError):
            self.admit()

    def test_rejects_invalid_candidate_context_and_filename(self):
        for field, value in (
            ("schema", "unexpected"), ("version", "0.1.3\noutput=forged"),
            ("sourceSha", "main"), ("sourceRunId", True),
            ("sourceRunAttempt", 0), ("sourceRef", "refs/heads/feature"),
            ("sourceRepository", "someone/mono"),
        ):
            with self.subTest(field=field):
                bad = {**self.candidate, field: value}
                with self.assertRaises(ValueError):
                    self.admit(candidate=bad)
        other = self.package.with_name("other.pkg")
        other.write_bytes(self.package.read_bytes())
        with self.assertRaises(ValueError):
            MODULE["admit"](self.candidate, self.run, other, "a" * 40)

    def test_accepted_receipt_binds_submitted_and_stapled_bytes(self):
        submitted = self.candidate["inputPackageSha256"]
        self.package.write_bytes(self.package.read_bytes() + b" stapled ticket")
        response = {"status": "Accepted", "id": "075b6948-d231-4ad7-8978-60cbf6868467"}
        receipt = MODULE["receipt"](self.candidate, response, self.package, submitted)
        MODULE["verify_receipt"](receipt, self.candidate, self.package)
        self.assertEqual(receipt["inputPackageSha256"], submitted)
        self.assertNotEqual(receipt["packageSha256"], submitted)
        for field, value in (
            ("status", "In Progress"), ("sourceSha", "b" * 40),
            ("sourceRunId", 124), ("sourceRunAttempt", 3),
            ("version", "0.1.4"), ("inputPackageSha256", "0" * 64),
            ("packageSha256", "0" * 64), ("submissionId", "not-a-submission"),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                MODULE["verify_receipt"]({**receipt, field: value}, self.candidate, self.package)

    def test_refuses_nonaccepted_or_unbound_provider_result(self):
        for response in (
            {"status": "Invalid", "id": "075b6948-d231-4ad7-8978-60cbf6868467"},
            {"status": "Accepted", "id": ""}, {},
        ):
            with self.subTest(response=response), self.assertRaises(ValueError):
                MODULE["receipt"](self.candidate, response, self.package, self.candidate["inputPackageSha256"])
        with self.assertRaises(ValueError):
            MODULE["receipt"](self.candidate, {"status": "Accepted", "id": "075b6948-d231-4ad7-8978-60cbf6868467"}, self.package, "0" * 64)

    def test_actual_notary_wrapper_keeps_key_ephemeral_and_requires_acceptance(self):
        script = Path(__file__).parents[1] / "macos/packaging/notarize-candidate.sh"
        for status, failure, succeeds in (
            ("Accepted", "", True), ("Invalid", "", False),
            ("Accepted", "notarytool", False), ("Accepted", "staple", False),
            ("Accepted", "spctl", False),
        ):
            with self.subTest(status=status, failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary = root / "bin"
                binary.mkdir()
                candidate = root / "candidate.json"
                self.package.write_bytes(b"signed candidate fixture")
                candidate.write_text(json.dumps(self.candidate))
                fake = '''#!/usr/bin/env python3
import json, os, pathlib, stat, sys
assert all(name not in os.environ for name in (
    "MAESTRO_NOTARY_KEY_P8", "MAESTRO_NOTARY_KEY_ID", "MAESTRO_NOTARY_ISSUER_ID"))
args = sys.argv[1:]
name = pathlib.Path(sys.argv[0]).name
operation = args[0] if name == "xcrun" else "spctl"
with open(os.environ["CALL_LOG"], "a") as stream:
    stream.write(operation + "\\n")
if name == "xcrun" and args[:2] == ["notarytool", "submit"]:
    key = pathlib.Path(args[args.index("--key") + 1])
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert key.read_text() == "fixture-private-key-never-log"
    assert args[args.index("--timeout") + 1] == "30m"
    assert "--keychain-profile" not in args
    if os.environ["FAILURE"] == "notarytool": sys.exit(69)
    print(json.dumps({"status": os.environ["NOTARY_STATUS"],
                      "id": "075b6948-d231-4ad7-8978-60cbf6868467"}))
elif name == "xcrun" and args[:2] == ["stapler", "staple"]:
    if os.environ["FAILURE"] == "staple": sys.exit(1)
    with open(args[2], "ab") as stream: stream.write(b" stapled ticket")
elif name == "spctl" and os.environ["FAILURE"] == "spctl": sys.exit(1)
'''
                for name in ("xcrun", "spctl"):
                    tool = binary / name
                    tool.write_text(fake)
                    tool.chmod(0o755)
                output = root / "receipt.json"
                env = {**os.environ, "PATH": str(binary) + ":" + os.environ["PATH"],
                       "RUNNER_TEMP": str(root), "CALL_LOG": str(root / "calls"),
                       "MAESTRO_NOTARY_KEY_P8": "fixture-private-key-never-log",
                       "MAESTRO_NOTARY_KEY_ID": "fixture-key-id",
                       "MAESTRO_NOTARY_ISSUER_ID": "fixture-issuer-id",
                       "NOTARY_STATUS": status, "FAILURE": failure}
                env.pop("BASH_ENV", None)
                result = subprocess.run(["/bin/bash", str(script), str(candidate), str(self.package), str(output)],
                                        env=env, text=True, capture_output=True)
                self.assertEqual(result.returncode == 0, succeeds, result.stdout + result.stderr)
                self.assertNotIn("fixture-private-key-never-log", result.stdout + result.stderr)
                self.assertFalse(list(root.glob("merlin-notary.*")), "private notary scratch survived")
                if succeeds:
                    MODULE["verify_receipt"](json.loads(output.read_text()), self.candidate, self.package)
                else:
                    self.assertFalse(output.exists())
                if status != "Accepted":
                    self.assertNotIn("stapler", (root / "calls").read_text())

    def test_real_git_admission_requires_main_ancestry(self):
        root = Path(self.directory.name) / "repository"
        root.mkdir()
        env = {**os.environ, "GIT_AUTHOR_NAME": "Qualification Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
               "GIT_COMMITTER_NAME": "Qualification Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}

        def git(*arguments, input=None):
            return subprocess.check_output(["git", *arguments], cwd=root, env=env, input=input, text=True).strip()

        git("init", "-q")
        tree = git("mktree", input="")
        source = git("commit-tree", tree, input="candidate source\n")
        git("update-ref", "refs/remotes/origin/main", source)
        git("update-ref", "refs/tags/merlin-v0.1.3", source)
        candidate = {**self.candidate, "sourceSha": source}
        run = {**self.run, "head_sha": source}
        candidate_file, run_file = root / "candidate.json", root / "run.json"
        candidate_file.write_text(json.dumps(candidate))
        run_file.write_text(json.dumps(run))
        output = root / "admitted.json"
        command = [os.sys.executable, str(Path(__file__).with_name("protected-notarization.py")), "admit",
                   "--candidate", str(candidate_file), "--source-run", str(run_file),
                   "--repository-root", str(root), "--package", str(self.package), "--output", str(output)]
        result = subprocess.run(command, env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(output.read_text())["publish"])
        output.unlink()
        unrelated = git("commit-tree", tree, input="unrelated main\n")
        git("update-ref", "refs/remotes/origin/main", unrelated)
        result = subprocess.run(command, env=env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
