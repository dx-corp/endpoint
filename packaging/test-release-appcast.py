#!/usr/bin/env python3
"""Exercise the public package-update feed, including Sparkle's signature metadata."""

import base64
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET


SCRIPT = Path(__file__).with_name("release-appcast.py")
SPARKLE = "http://www.andymatuschak.org/xml-namespaces/sparkle"


class ReleaseAppcastTest(unittest.TestCase):
    def run_feed(self, fragment=None, version="0.1.3"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / f"Merlin-{version}.pkg"
            package.write_bytes(b"test package payload")
            signature = root / "signature.txt"
            signature.write_text(fragment if fragment is not None else (
                f'sparkle:edSignature="{base64.b64encode(bytes(64)).decode()}" '
                f'length="{package.stat().st_size}"'
            ))
            return subprocess.run(
                [sys.executable, str(SCRIPT), "--version", version,
                 "--package", str(package), "--signature", str(signature)],
                text=True, capture_output=True, check=False,
            )

    def test_feed_installs_the_combined_versioned_package(self):
        result = self.run_feed()
        self.assertEqual(result.returncode, 0, result.stderr)
        item = ET.fromstring(result.stdout).find("channel/item")
        self.assertEqual(item.findtext(f"{{{SPARKLE}}}version"), "0.1.3")
        enclosure = item.find("enclosure")
        self.assertEqual(enclosure.get("url"),
                         "https://github.com/dx-corp/endpoint/releases/download/merlin-v0.1.3/Merlin-0.1.3.pkg")
        self.assertEqual(enclosure.get(f"{{{SPARKLE}}}installationType"), "package")
        self.assertEqual(enclosure.get("length"), str(len(b"test package payload")))
        self.assertEqual(base64.b64decode(enclosure.get(f"{{{SPARKLE}}}edSignature")), bytes(64))
        self.assertEqual(item.findtext(f"{{{SPARKLE}}}minimumSystemVersion"), "13.0")

    def test_rejects_signature_for_different_size(self):
        result = self.run_feed(f'sparkle:edSignature="{base64.b64encode(bytes(64)).decode()}" length="1"')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("length", result.stderr)

    def test_rejects_invalid_signature_and_version(self):
        for fragment in ('', 'sparkle:edSignature="invalid" length="20"',
                         'length="20"', '<!DOCTYPE bad>'):
            with self.subTest(fragment=fragment):
                self.assertNotEqual(self.run_feed(fragment).returncode, 0)
        self.assertNotEqual(self.run_feed(version="0.1.3-beta").returncode, 0)


if __name__ == "__main__":
    unittest.main()
