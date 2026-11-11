#!/usr/bin/env python3
"""Write Sparkle's appcast for the combined, notarized macOS installer.

The signature fragment comes from the pinned Sparkle sign_update tool. The
caller signs and verifies the completed feed before publishing either file.
"""

import argparse
import base64
import binascii
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET


SPARKLE = "http://www.andymatuschak.org/xml-namespaces/sparkle"
ET.register_namespace("sparkle", SPARKLE)


def appcast(version: str, package: Path, signature: Path) -> ET.Element:
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", version):
        raise ValueError("macOS update version must contain decimal components")
    if package.name != f"Merlin-{version}.pkg":
        raise ValueError("package filename must match the update version")
    enclosure = ET.fromstring(
        f'<enclosure xmlns:sparkle="{SPARKLE}" {signature.read_text().strip()}/>'
    )
    if set(enclosure.attrib) != {f"{{{SPARKLE}}}edSignature", "length"}:
        raise ValueError("expected Sparkle edSignature and length attributes")
    encoded = enclosure.get(f"{{{SPARKLE}}}edSignature", "")
    if len(base64.b64decode(encoded, validate=True)) != 64:
        raise ValueError("Sparkle EdDSA signature must be 64 bytes")
    if enclosure.get("length") != str(package.stat().st_size):
        raise ValueError("signed length does not match package length")
    root = ET.Element("rss", {"version": "2.0"})
    channel = ET.SubElement(root, "channel")
    ET.SubElement(channel, "title").text = "Deixic Endpoint updates"
    ET.SubElement(channel, "link").text = "https://github.com/dx-corp/endpoint/releases"
    ET.SubElement(channel, "description").text = "Deixic Endpoint macOS installers"
    item = ET.SubElement(channel, "item")
    ET.SubElement(item, "title").text = f"Deixic Endpoint {version}"
    ET.SubElement(item, f"{{{SPARKLE}}}version").text = version
    ET.SubElement(item, f"{{{SPARKLE}}}shortVersionString").text = version
    ET.SubElement(item, f"{{{SPARKLE}}}minimumSystemVersion").text = "13.0"
    enclosure.set("url", f"https://github.com/dx-corp/endpoint/releases/download/merlin-v{version}/{package.name}")
    enclosure.set("type", "application/octet-stream")
    enclosure.set(f"{{{SPARKLE}}}installationType", "package")
    item.append(enclosure)
    ET.indent(root)
    return root


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    args = parser.parse_args()
    try:
        root = appcast(args.version, args.package, args.signature)
    except (ValueError, OSError, ET.ParseError, binascii.Error) as error:
        print(f"Cannot publish appcast: {error}", file=sys.stderr)
        return 1
    sys.stdout.write(ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
