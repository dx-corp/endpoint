#!/usr/bin/env python3
"""Exercise the CLT-compatible per-architecture package-build boundary."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).parents[1] / "macos/packaging/build-universal.sh"
PRODUCTS = ("MerlinMacOS", "MerlinEndpointApp")


class UniversalBuildTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.package = self.root / "package with spaces"
        self.package.mkdir()
        tools = self.root / "bin"
        tools.mkdir()
        swift = tools / "swift"
        swift.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['CALL_LOG'], 'a') as log: log.write(json.dumps(['swift', args]) + '\\n')
assert args[0] == 'build'
assert args.count('--arch') == 1, 'Combined architectures require unavailable XCBuild'
arch = args[args.index('--arch') + 1]
output = pathlib.Path.cwd() / '.build' / arch / 'release'
if '--show-bin-path' in args:
    print(output); sys.exit(0)
if os.environ.get('FAIL_ARCH') == arch: sys.exit(17)
output.mkdir(parents=True, exist_ok=True)
for product in ('MerlinMacOS', 'MerlinEndpointApp'):
    path = output / product
    path.write_text(os.environ.get('WRONG_ARCH') or arch)
    path.chmod(0o755)
print('Swift build progress must remain on stderr')
''')
        lipo = tools / "lipo"
        lipo.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['CALL_LOG'], 'a') as log: log.write(json.dumps(['lipo', args]) + '\\n')
if args[0] == '-create':
    marker = args.index('-output')
    arches = set()
    for name in args[1:marker]: arches.update(pathlib.Path(name).read_text().split(','))
    output = pathlib.Path(args[marker + 1])
    output.write_text(','.join(sorted(arches)))
elif len(args) > 2 and args[1] == '-verify_arch':
    # Apple's variadic verify operation requires the input before the flag.
    available = set(pathlib.Path(args[0]).read_text().split(','))
    sys.exit(0 if set(args[2:]) <= available else 1)
else: sys.exit(64)
''')
        for tool in (swift, lipo):
            tool.chmod(0o755)
        self.env = {**os.environ, "PATH": str(tools) + ":" + os.environ["PATH"], "CALL_LOG": str(self.root / "calls")}
        self.env.pop("BASH_ENV", None)

    def build(self, arches, **environment):
        return subprocess.run(["/bin/sh", str(SCRIPT), str(self.package), *arches],
                              env={**self.env, **environment}, text=True, capture_output=True)

    def calls(self):
        return [json.loads(line) for line in (self.root / "calls").read_text().splitlines()]

    def test_universal_build_uses_separate_architectures_and_verifies_both_products(self):
        result = self.build(["x86_64", "arm64"])
        self.assertEqual(result.returncode, 0, result.stderr)
        output = Path(result.stdout.strip())
        self.assertEqual(output.resolve(), (self.package / ".build/merlin-universal-release").resolve())
        for product in PRODUCTS:
            self.assertEqual(set((output / product).read_text().split(',')), {"arm64", "x86_64"})
            self.assertTrue(os.access(output / product, os.X_OK))
        builds = [args for tool, args in self.calls() if tool == "swift" and "--show-bin-path" not in args]
        self.assertEqual([args[args.index("--arch") + 1] for args in builds], ["arm64", "x86_64"])
        self.assertNotIn("Swift build progress", result.stdout)

    def test_single_architecture_reuses_its_ordinary_binary_directory(self):
        result = self.build(["arm64", "arm64"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(result.stdout.strip()).resolve(), (self.package / ".build/arm64/release").resolve())
        self.assertFalse(any(tool == "lipo" and "-create" in args for tool, args in self.calls()))

    def test_invalid_architecture_never_invokes_a_builder(self):
        result = self.build(["arm64", "ppc"])
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "calls").exists())

    def test_wrong_architecture_is_rejected_before_packaging(self):
        result = self.build(["arm64", "x86_64"], WRONG_ARCH="i386")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_second_arch_failure_preserves_cache_and_never_returns_stale_output(self):
        stale = self.package / ".build/merlin-universal-release/MerlinMacOS"
        stale.parent.mkdir(parents=True)
        stale.write_text("previous successful artifact")
        result = self.build(["arm64", "x86_64"], FAIL_ARCH="x86_64")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertTrue((self.package / ".build/arm64/release/MerlinMacOS").exists())
        self.assertEqual(stale.read_text(), "previous successful artifact")
        self.assertFalse(any(tool == "lipo" and "-create" in args for tool, args in self.calls()))


if __name__ == "__main__":
    unittest.main()
