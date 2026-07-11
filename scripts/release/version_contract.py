#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The single release-version contract and isolated manifest stamper."""
from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path

DEV_VERSION = "0.0.0"
VERSION_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(alpha|beta|rc)\.(0|[1-9]\d*))?$")
ROOT = Path(__file__).resolve().parents[2]
EXACT_FILES = {"Cargo.toml": 2, "query/Cargo.toml": 2, "bindings/python/Cargo.toml": 1, "bindings/node/Cargo.toml": 1}


def version(value: str) -> str:
    if not VERSION_RE.fullmatch(value):
        raise ValueError("expected X.Y.Z or X.Y.Z-(alpha|beta|rc).N")
    return value


def tag(value: str) -> str:
    if not value.startswith("v"):
        raise ValueError("expected tag vX.Y.Z or vX.Y.Z-(alpha|beta|rc).N")
    version(value[1:])
    return value


def pep440(value: str) -> str:
    match = VERSION_RE.fullmatch(version(value))
    assert match
    return f"{match[1]}.{match[2]}.{match[3]}" + ({"alpha": "a", "beta": "b", "rc": "rc"}.get(match[4], "") + (match[5] or ""))


def replace(path: Path, old: str, new: str, expected: int) -> None:
    source = path.read_text(encoding="utf-8")
    count = source.count(old)
    if count != expected:
        raise ValueError(f"{path}: expected {expected} occurrence(s) of {old!r}, found {count}")
    path.write_text(source.replace(old, new), encoding="utf-8")


def check_template(root: Path) -> None:
    source = (root / "Cargo.toml").read_text(encoding="utf-8")
    if source.count(f'version = "{DEV_VERSION}"') != 1:
        raise ValueError("Cargo.toml: workspace version must be the development sentinel")
    for relative, count in EXACT_FILES.items():
        if (root / relative).read_text(encoding="utf-8").count(f'version = "={DEV_VERSION}"') != count:
            raise ValueError(f"{relative}: exact internal dependency template drift")
    for relative in ("bindings/python/pyproject.toml", "bindings/node/package.json"):
        if f'"{DEV_VERSION}"' not in (root / relative).read_text(encoding="utf-8"):
            raise ValueError(f"{relative}: version must be the development sentinel")


def stamp(root: Path, release: str) -> None:
    check_template(root)
    replace(root / "Cargo.toml", f'version = "{DEV_VERSION}"', f'version = "{release}"', 1)
    for relative, count in EXACT_FILES.items():
        replace(root / relative, f'version = "={DEV_VERSION}"', f'version = "={release}"', count)
    replace(root / "bindings/python/pyproject.toml", f'version = "{DEV_VERSION}"', f'version = "{pep440(release)}"', 1)
    package = root / "bindings/node/package.json"
    data = json.loads(package.read_text(encoding="utf-8"))
    if data.get("version") != DEV_VERSION:
        raise ValueError("bindings/node/package.json: version template drift")
    data["version"] = release
    package.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    loader = root / "bindings/node/index.js"
    loader_source = loader.read_text(encoding="utf-8")
    loader_count = loader_source.count(DEV_VERSION)
    if loader_count == 0:
        raise ValueError("bindings/node/index.js: generated version template drift")
    loader.write_text(loader_source.replace(DEV_VERSION, release), encoding="utf-8")


def verify(root: Path, release: str) -> None:
    release = version(release)
    if (root / "Cargo.toml").read_text(encoding="utf-8").count(f'version = "{release}"') != 1:
        raise ValueError("Cargo.toml: stamped workspace version verification failed")
    pyproject = (root / "bindings/python/pyproject.toml").read_text(encoding="utf-8")
    if pyproject.count(f'version = "{pep440(release)}"') != 1:
        raise ValueError("bindings/python/pyproject.toml: stamped version verification failed")
    package = json.loads((root / "bindings/node/package.json").read_text(encoding="utf-8"))
    if package.get("version") != release:
        raise ValueError("bindings/node/package.json: stamped version verification failed")
    loader = (root / "bindings/node/index.js").read_text(encoding="utf-8")
    compared_versions = re.findall(r"bindingPackageVersion !== '([^']+)'", loader)
    expected_versions = re.findall(r"version mismatch, expected ([^ ]+) but got", loader)
    if not compared_versions or set(compared_versions) != {release} or set(expected_versions) != {release}:
        raise ValueError("bindings/node/index.js: stamped version verification failed")
    for relative, count in EXACT_FILES.items():
        content = (root / relative).read_text(encoding="utf-8")
        if content.count(f'version = "={release}"') != count:
            raise ValueError(f"{relative}: stamped dependency verification failed")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check-template")
    tag_parser = sub.add_parser("validate-tag")
    tag_parser.add_argument("tag", type=tag)
    tag_parser.add_argument("--github-output", type=Path)
    stamp_parser = sub.add_parser("stamp")
    stamp_parser.add_argument("release", type=version)
    stamp_parser.add_argument("--source", type=Path, default=ROOT)
    stamp_parser.add_argument("--destination", type=Path, required=True)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("release", type=version)
    verify_parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    if args.command == "check-template": check_template(ROOT)
    elif args.command == "validate-tag":
        release = args.tag[1:]
        values = {
            "version": release,
            "python_version": pep440(release),
            "is_prerelease": str("-" in release).lower(),
        }
        output = "".join(f"{key}={value}\n" for key, value in values.items())
        if args.github_output:
            with args.github_output.open("a", encoding="utf-8") as file:
                file.write(output)
        else:
            print(output, end="")
    elif args.command == "stamp":
        if args.destination.exists(): raise ValueError(f"destination already exists: {args.destination}")
        shutil.copytree(args.source, args.destination, symlinks=True, ignore=shutil.ignore_patterns(".git", "target", "node_modules"))
        stamp(args.destination, args.release)
        verify(args.destination, args.release)
    else: verify(args.root, args.release)

if __name__ == "__main__":
    try: main()
    except ValueError as error: raise SystemExit(f"version contract error: {error}")
