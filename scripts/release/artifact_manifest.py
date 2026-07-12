#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Create, verify, and compare fail-closed release bundle artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
import zipfile
from pathlib import Path
from typing import Any

SCHEMA = 2
PROVENANCE_KEYS = ("repository", "tag", "source_sha", "prepare_run_id", "workflow", "version")
IGNORED_BUNDLE_FILES = {"release-manifest.json", "SHA256SUMS"}
NODE_TARGETS = {
    "@nodedb-lab/code2graph-linux-x64-gnu": ("linux", "x64", "glibc"),
    "@nodedb-lab/code2graph-linux-arm64-gnu": ("linux", "arm64", "glibc"),
    "@nodedb-lab/code2graph-linux-x64-musl": ("linux", "x64", "musl"),
    "@nodedb-lab/code2graph-darwin-x64": ("darwin", "x64", None),
    "@nodedb-lab/code2graph-darwin-arm64": ("darwin", "arm64", None),
    "@nodedb-lab/code2graph-win32-x64-msvc": ("win32", "x64", None),
}
PYTHON_TARGETS = {
    "linux-x64-gnu": r"manylinux(?:_[0-9_]+)?_x86_64(?:\.manylinux[0-9_]+_x86_64)?",
    "linux-arm64-gnu": r"manylinux(?:_[0-9_]+)?_aarch64(?:\.manylinux[0-9_]+_aarch64)?",
    "linux-x64-musl": r"musllinux_1_2_x86_64",
    "darwin-x64": r"macosx_[0-9_]+_x86_64",
    "darwin-arm64": r"macosx_[0-9_]+_arm64",
    "win32-x64-msvc": r"win_amd64",
}
ROOT_NODE_PACKAGE = "@nodedb-lab/code2graph"
PYTHON_PACKAGE = "code2graph-rs"


def safe_name(name: str) -> str:
    path = Path(name)
    if not name or path.is_absolute() or ".." in path.parts or path.as_posix() != name or name.startswith("./"):
        raise ValueError(f"unsafe artifact path: {name!r}")
    return name


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def inventory(directory: Path, expected: list[str]) -> list[dict[str, object]]:
    names = [safe_name(name) for name in expected]
    if len(names) != len(set(names)):
        raise ValueError("duplicate expected artifact")
    actual: list[str] = []
    for path in directory.rglob("*"):
        relative = path.relative_to(directory).as_posix()
        if path.is_symlink():
            raise ValueError(f"symlink not permitted: {relative}")
        if path.is_file() and relative not in IGNORED_BUNDLE_FILES:
            actual.append(relative)
    if set(actual) != set(names):
        raise ValueError(f"artifact set mismatch: missing={sorted(set(names)-set(actual))}, extra={sorted(set(actual)-set(names))}")
    return [{"path": name, "size": (directory / name).stat().st_size, "sha256": digest(directory / name)} for name in sorted(names)]


def canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def pep440(version: str) -> str:
    match = re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(alpha|beta|rc)\.(0|[1-9]\d*))?", version)
    if not match:
        raise ValueError("invalid release version")
    return f"{match[1]}.{match[2]}.{match[3]}" + ({"alpha": "a", "beta": "b", "rc": "rc"}.get(match[4], "") + (match[5] or ""))


def normalized_archive(path: Path, *, require_package_json: bool = False) -> dict[str, bytes]:
    contents: dict[str, bytes] = {}
    with tarfile.open(path, "r:*") as archive:
        for member in archive.getmembers():
            if member.issym() or member.islnk() or member.isdev():
                raise ValueError(f"archive contains unsupported member: {member.name}")
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError(f"archive contains unsupported member: {member.name}")
            name = safe_name(member.name)
            if name in contents:
                raise ValueError(f"archive contains duplicate member: {name}")
            handle = archive.extractfile(member)
            if handle is None:
                raise ValueError(f"archive member cannot be read: {name}")
            data = handle.read()
            if name == "package/package.json":
                data = canonical(json.loads(data)).encode()
            contents[name] = data
    if require_package_json and "package/package.json" not in contents:
        raise ValueError("npm tarball has no package/package.json")
    return contents


def npm_metadata(path: Path) -> dict[str, Any]:
    raw = normalized_archive(path, require_package_json=True)["package/package.json"]
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{path.name}: invalid package.json")
    return value


def metadata_fields(text: str) -> tuple[str | None, str | None]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            fields.setdefault(key, value)
    return fields.get("Name"), fields.get("Version")


def python_metadata(path: Path) -> tuple[str | None, str | None]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
            if len(names) != 1:
                raise ValueError(f"{path.name}: expected one wheel METADATA")
            return metadata_fields(archive.read(names[0]).decode())
    contents = normalized_archive(path)
    names = [name for name in contents if name.endswith("/PKG-INFO")]
    if len(names) != 1:
        raise ValueError(f"{path.name}: expected one sdist PKG-INFO")
    return metadata_fields(contents[names[0]].decode())


def bundle_contract(directory: Path, version: str) -> dict[str, Any]:
    python_version = pep440(version)
    npm_files = sorted((directory / "npm").glob("*.tgz"))
    if len(npm_files) != 7:
        raise ValueError(f"expected 7 npm tarballs, found {len(npm_files)}")
    packages: dict[str, str] = {}
    root_metadata: dict[str, Any] | None = None
    for path in npm_files:
        contents = normalized_archive(path, require_package_json=True)
        metadata = json.loads(contents["package/package.json"])
        native_members = sorted(name for name in contents if name.endswith(".node"))
        name = metadata.get("name")
        if name == ROOT_NODE_PACKAGE:
            if root_metadata is not None:
                raise ValueError("duplicate root npm package")
            root_metadata = metadata
            if metadata.get("dependencies") is not None:
                raise ValueError("root npm package must not carry regular dependencies")
            if native_members:
                raise ValueError("root npm package must not embed platform binaries")
        elif name in NODE_TARGETS:
            os_name, cpu, libc = NODE_TARGETS[name]
            target = name.removeprefix(f"{ROOT_NODE_PACKAGE}-")
            if native_members != [f"package/code2graph-node.{target}.node"]:
                raise ValueError(f"{path.name}: platform package must contain exactly its native binary")
            if metadata.get("version") != version or metadata.get("os") != [os_name] or metadata.get("cpu") != [cpu]:
                raise ValueError(f"{path.name}: platform package metadata mismatch")
            if (metadata.get("libc") if libc else None) != ([libc] if libc else None):
                raise ValueError(f"{path.name}: platform libc metadata mismatch")
            if metadata.get("dependencies") is not None or metadata.get("optionalDependencies") is not None:
                raise ValueError(f"{path.name}: platform package must not carry dependencies")
        else:
            raise ValueError(f"unexpected npm package name: {name!r}")
        if not isinstance(name, str) or name in packages or metadata.get("version") != version:
            raise ValueError(f"{path.name}: duplicate package or version mismatch")
        expected_filename = f"{name.removeprefix('@').replace('/', '-')}-{version}.tgz"
        if path.name != expected_filename:
            raise ValueError(f"{path.name}: npm filename does not match package identity")
        packages[name] = path.name
    if set(packages) != {ROOT_NODE_PACKAGE, *NODE_TARGETS} or root_metadata is None:
        raise ValueError("npm package target set mismatch")
    expected_optional = {name: version for name in NODE_TARGETS}
    if root_metadata.get("optionalDependencies") != expected_optional:
        raise ValueError("root npm optionalDependencies do not exactly match platform matrix")

    python_files = sorted((directory / "python").iterdir())
    if len(python_files) != 7 or any(not path.is_file() for path in python_files):
        raise ValueError("expected exactly six wheels and one sdist")
    sdist_pattern = re.compile(rf"code2graph_rs-{re.escape(python_version)}\.tar\.gz")
    wheel_prefix = rf"code2graph_rs-{re.escape(python_version)}-cp39-abi3-"
    targets: dict[str, str] = {}
    sdist: str | None = None
    for path in python_files:
        name, metadata_version = python_metadata(path)
        if name != PYTHON_PACKAGE or metadata_version != python_version:
            raise ValueError(f"{path.name}: Python metadata mismatch")
        if sdist_pattern.fullmatch(path.name):
            if sdist is not None:
                raise ValueError("duplicate Python sdist")
            sdist = path.name
            continue
        matched = [target for target, pattern in PYTHON_TARGETS.items() if re.fullmatch(wheel_prefix + pattern + r"\.whl", path.name)]
        if len(matched) != 1 or matched[0] in targets:
            raise ValueError(f"{path.name}: unexpected or duplicate Python wheel target")
        targets[matched[0]] = path.name
    if sdist is None or set(targets) != set(PYTHON_TARGETS):
        raise ValueError("Python distribution target set mismatch")
    return {
        "npm": {"root": ROOT_NODE_PACKAGE, "packages": packages, "targets": sorted(NODE_TARGETS)},
        "python": {"package": PYTHON_PACKAGE, "version": python_version, "sdist": sdist, "targets": targets},
    }


def create(args: argparse.Namespace) -> None:
    contract = bundle_contract(args.directory, args.version)
    files = inventory(args.directory, args.file)
    payload = {"schema": SCHEMA, "provenance": {key: str(getattr(args, key)) for key in PROVENANCE_KEYS}, "contract": contract, "files": files}
    args.output.write_text(canonical(payload), encoding="utf-8")


def verify(args: argparse.Namespace) -> None:
    manifest_text = args.manifest.read_text(encoding="utf-8")
    payload = json.loads(manifest_text)
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA or set(payload) != {"schema", "provenance", "contract", "files"}:
        raise ValueError("unsupported manifest schema")
    provenance = payload["provenance"]
    if not isinstance(provenance, dict) or set(provenance) != set(PROVENANCE_KEYS):
        raise ValueError("invalid manifest provenance")
    for key in PROVENANCE_KEYS:
        expected = getattr(args, key)
        if expected is not None and provenance[key] != str(expected):
            raise ValueError(f"provenance mismatch for {key}")
    if payload["contract"] != bundle_contract(args.directory, provenance["version"]):
        raise ValueError("distribution contract mismatch")
    files = payload["files"]
    if not isinstance(files, list) or not all(isinstance(entry, dict) and set(entry) == {"path", "size", "sha256"} and isinstance(entry["path"], str) and isinstance(entry["size"], int) and entry["size"] >= 0 and isinstance(entry["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) for entry in files):
        raise ValueError("invalid manifest files")
    if inventory(args.directory, [entry["path"] for entry in files]) != files:
        raise ValueError("artifact hash or size mismatch")
    if manifest_text != canonical(payload):
        raise ValueError("manifest is not canonical")


def verify_checksums(args: argparse.Namespace) -> None:
    payload = json.loads(args.manifest.read_text(encoding="utf-8"))
    files = payload.get("files")
    if not isinstance(files, list):
        raise ValueError("manifest has no file inventory")
    expected = {"release-manifest.json", *(entry.get("path") for entry in files if isinstance(entry, dict))}
    recorded: dict[str, str] = {}
    for line in args.checksums.read_text(encoding="utf-8").splitlines():
        try: checksum, name = line.split("  ", 1)
        except ValueError as error: raise ValueError(f"invalid checksum entry: {line!r}") from error
        if not re.fullmatch(r"[0-9a-f]{64}", checksum) or name in recorded or safe_name(name) != name:
            raise ValueError(f"invalid checksum entry: {line!r}")
        recorded[name] = checksum
    if set(recorded) != expected:
        raise ValueError("checksum file does not cover exactly the bundle inventory")
    for name, checksum in recorded.items():
        if digest(args.directory / name) != checksum:
            raise ValueError(f"checksum mismatch for {name}")


def compare_archive(args: argparse.Namespace) -> None:
    if normalized_archive(args.local) != normalized_archive(args.remote):
        raise ValueError("archives differ after normalized comparison")


def compare_npm(args: argparse.Namespace) -> None:
    if normalized_archive(args.local, require_package_json=True) != normalized_archive(args.remote, require_package_json=True):
        raise ValueError("npm tarballs differ after normalized package metadata comparison")


def main() -> None:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)
    create_parser, verify_parser = subcommands.add_parser("create"), subcommands.add_parser("verify")
    checksum_parser = subcommands.add_parser("verify-checksums")
    archive_parser, compare_parser = subcommands.add_parser("compare-archive"), subcommands.add_parser("compare-npm")
    for command in (create_parser, verify_parser): command.add_argument("--directory", type=Path, required=True)
    create_parser.add_argument("--output", type=Path, required=True)
    create_parser.add_argument("--file", action="append", required=True)
    for command in (create_parser, verify_parser):
        for key in PROVENANCE_KEYS: command.add_argument("--" + key.replace("_", "-"), dest=key, required=command is create_parser)
    verify_parser.add_argument("--manifest", type=Path, required=True)
    for command in (checksum_parser,):
        command.add_argument("--directory", type=Path, required=True); command.add_argument("--manifest", type=Path, required=True); command.add_argument("--checksums", type=Path, required=True)
    for command in (archive_parser, compare_parser): command.add_argument("--local", type=Path, required=True); command.add_argument("--remote", type=Path, required=True)
    args = parser.parse_args()
    try:
        {"create": create, "verify": verify, "verify-checksums": verify_checksums, "compare-archive": compare_archive, "compare-npm": compare_npm}[args.command](args)
    except (OSError, ValueError, json.JSONDecodeError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise SystemExit(f"artifact manifest error: {error}")


if __name__ == "__main__": main()
