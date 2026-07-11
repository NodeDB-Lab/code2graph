#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stamp release versions into manifests that Cargo packages or builds."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEV_VERSION = "0.0.0"
VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\.\d+)?$")


def replace_count(path: Path, old: str, new: str, expected: int) -> None:
    source = path.read_text()
    count = source.count(old)
    if count != expected:
        raise SystemExit(f"{path}: expected {expected} {old!r} fields, found {count}")
    path.write_text(source.replace(old, new))


def replace_once(path: Path, old: str, new: str) -> None:
    replace_count(path, old, new, 1)


def check_template() -> None:
    root = ROOT / "Cargo.toml"
    source = root.read_text()
    if source.count(f'version = "{DEV_VERSION}"') != 1:
        raise SystemExit("Cargo.toml: workspace package version must be the development sentinel")
    if source.count(f'version = "={DEV_VERSION}"') != 2:
        raise SystemExit("Cargo.toml: expected exact core and query workspace requirements")
    requirements = {
        "query/Cargo.toml": 2,
        "bindings/python/Cargo.toml": 1,
        "bindings/node/Cargo.toml": 1,
    }
    for relative, expected in requirements.items():
        source = (ROOT / relative).read_text()
        if source.count(f'version = "={DEV_VERSION}"') != expected:
            raise SystemExit(f"{relative}: expected {expected} exact core requirement(s)")


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--check-template":
        check_template()
        return
    if len(sys.argv) != 2 or not VERSION_PATTERN.fullmatch(sys.argv[1]):
        raise SystemExit("usage: stamp-release.py X.Y.Z[-alpha.N|-beta.N|-rc.N]")

    version = sys.argv[1]
    check_template()
    replace_once(ROOT / "Cargo.toml", f'version = "{DEV_VERSION}"', f'version = "{version}"')

    root = ROOT / "Cargo.toml"
    source = root.read_text()
    exact_dev = f'version = "={DEV_VERSION}"'
    if source.count(exact_dev) != 2:
        raise SystemExit("Cargo.toml: expected two exact internal requirements")
    root.write_text(source.replace(exact_dev, f'version = "={version}"'))

    for relative, expected in {
        "query/Cargo.toml": 2,
        "bindings/python/Cargo.toml": 1,
        "bindings/node/Cargo.toml": 1,
    }.items():
        replace_count(ROOT / relative, exact_dev, f'version = "={version}"', expected)

    python_version = re.sub(r"-(alpha|beta|rc)\.", lambda match: {"alpha": "a", "beta": "b", "rc": "rc"}[match[1]], version)
    replace_once(
        ROOT / "bindings/python/pyproject.toml",
        f'version = "{DEV_VERSION}"',
        f'version = "{python_version}"',
    )


if __name__ == "__main__":
    main()
