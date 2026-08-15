#!/usr/bin/env python3
import os
import re
from pathlib import Path


path = Path("Cargo.toml")
content = path.read_text(encoding="utf-8")
section = re.search(
    r"(?ms)^\[workspace\.package\]\r?\n(?P<body>.*?)(?=^\[|\Z)",
    content,
)
if section is None:
    raise SystemExit("Cargo.toml is missing [workspace.package].")
version = re.search(
    r'(?m)^version\s*=\s*"(?P<version>\d+\.\d+\.\d+)"\s*$',
    section.group("body"),
)
if version is None:
    raise SystemExit(
        "Cargo.toml is missing a three-part [workspace.package] version."
    )
start = section.start("body") + version.start("version")
end = section.start("body") + version.end("version")
path.write_text(
    content[:start] + os.environ["VERSION"] + content[end:],
    encoding="utf-8",
)
