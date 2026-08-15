#!/usr/bin/env python3
import os
import re
import subprocess
import tomllib
from pathlib import Path


semver = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
merge_sha = os.environ["MERGE_SHA"]


def command(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def git_file(revision: str, path: str) -> str:
    return subprocess.check_output(
        ("git", "show", f"{revision}:{path}"),
        text=True,
    )


def workspace_version(content: str) -> str:
    section = re.search(
        r"(?ms)^\[workspace\.package\]\r?\n(?P<body>.*?)(?=^\[|\Z)",
        content,
    )
    if section is None:
        raise SystemExit("Cargo.toml is missing [workspace.package].")
    version = re.search(
        r'(?m)^version\s*=\s*"(?P<version>[^"]+)"\s*$',
        section.group("body"),
    )
    if version is None or semver.fullmatch(version.group("version")) is None:
        raise SystemExit(
            "Cargo.toml is missing a numeric three-part [workspace.package] version."
        )
    return version.group("version")


def normalize_manifest(content: str) -> str:
    section = re.search(
        r"(?ms)^\[workspace\.package\]\r?\n(?P<body>.*?)(?=^\[|\Z)",
        content,
    )
    if section is None:
        raise SystemExit("Cargo.toml is missing [workspace.package].")
    version = re.search(
        r'(?m)^version\s*=\s*"(?P<version>[^"]+)"\s*$',
        section.group("body"),
    )
    if version is None:
        raise SystemExit("Cargo.toml is missing [workspace.package].version.")
    start = section.start("body") + version.start("version")
    end = section.start("body") + version.end("version")
    return content[:start] + "<version>" + content[end:]


changed_files = command(
    "gh",
    "api",
    f"repos/{os.environ['GITHUB_REPOSITORY']}/pulls/{os.environ['PULL_NUMBER']}/files?per_page=100",
    "--paginate",
    "--jq",
    ".[].filename",
).splitlines()
initial_release = os.environ["INITIAL_RELEASE"] == "true"
expected_files = ["CHANGELOG.md"] if initial_release else [
    "CHANGELOG.md",
    "Cargo.lock",
    "Cargo.toml",
]
if sorted(changed_files) != expected_files:
    raise SystemExit(
        f"Release PR has unexpected changed files: {changed_files!r}."
    )

base_sha = command("git", "rev-parse", f"{merge_sha}^")
base_manifest = git_file(base_sha, "Cargo.toml")
release_manifest = Path("Cargo.toml").read_text(encoding="utf-8")
base_version = workspace_version(base_manifest)
release_version = workspace_version(release_manifest)
if os.environ["RELEASE_BRANCH"] != f"release/v{release_version}":
    raise SystemExit(
        f"Release branch {os.environ['RELEASE_BRANCH']!r} does not match v{release_version}."
    )
changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
if not changelog.startswith("# Changelog\n") or f"## [{release_version}]" not in changelog:
    raise SystemExit("CHANGELOG.md is not a generated changelog for the release version.")

if initial_release:
    if release_version != base_version:
        raise SystemExit(
            f"Initial release version {release_version} must equal {base_version}."
        )
    release_tags = command(
        "git",
        "tag",
        "--list",
        "v[0-9]*.[0-9]*.[0-9]*",
    ).splitlines()
    expected_tag = f"v{release_version}"
    if release_tags:
        if release_tags != [expected_tag] or command(
            "git",
            "rev-list",
            "-n",
            "1",
            expected_tag,
        ) != merge_sha:
            raise SystemExit(
                "Initial release tags must be limited to the current release commit."
            )
else:
    if tuple(map(int, release_version.split("."))) <= tuple(map(int, base_version.split("."))):
        raise SystemExit(
            f"Release version {release_version} is not greater than {base_version}."
        )
    if normalize_manifest(base_manifest) != normalize_manifest(release_manifest):
        raise SystemExit(
            "Cargo.toml changes outside [workspace.package].version are not allowed."
        )

    base_lock = tomllib.loads(git_file(base_sha, "Cargo.lock"))
    release_lock = tomllib.loads(Path("Cargo.lock").read_text(encoding="utf-8"))
    base_packages = base_lock["package"]
    release_packages = release_lock["package"]
    if len(base_packages) != len(release_packages):
        raise SystemExit("Cargo.lock package membership changed in a release-only PR.")
    workspace_packages = [
        package["name"]
        for package in base_packages
        if package["name"] == "wincred-libsecret"
        or package["name"].startswith("wincred-libsecret-")
    ]
    if not workspace_packages:
        raise SystemExit("Cargo.lock does not contain workspace package entries.")
    for base_entry, release_entry in zip(base_packages, release_packages):
        if base_entry["name"] != release_entry["name"]:
            raise SystemExit("Cargo.lock package ordering changed in a release-only PR.")
        name = base_entry["name"]
        base_package = dict(base_entry)
        release_package = dict(release_entry)
        if name == "wincred-libsecret" or name.startswith("wincred-libsecret-"):
            if base_package.pop("version", None) != base_version:
                raise SystemExit(f"Workspace package {name} does not use {base_version} in the base lockfile.")
            if release_package.pop("version", None) != release_version:
                raise SystemExit(f"Workspace package {name} does not use {release_version} in the release lockfile.")
        if base_package != release_package:
            raise SystemExit(f"Cargo.lock changed non-version data for package {name}.")

with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
    output.write(f"version={release_version}\n")
