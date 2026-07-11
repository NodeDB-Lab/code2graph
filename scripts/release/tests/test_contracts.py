#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Release helper unit tests and parsed workflow contracts."""
from __future__ import annotations

import argparse
import importlib.util
import io
import json
import shutil
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts/release" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


version_contract = load("version_contract")
artifact_manifest = load("artifact_manifest")


def workflow(name: str) -> dict:
    return yaml.load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


class VersionContractTests(unittest.TestCase):
    def test_versions_tags_and_pep440_include_zero_prereleases(self):
        expected = {
            "1.2.3": "1.2.3",
            "1.2.3-alpha.0": "1.2.3a0",
            "1.2.3-beta.0": "1.2.3b0",
            "1.2.3-rc.0": "1.2.3rc0",
            "0.0.0-beta.0": "0.0.0b0",
        }
        for value, python_value in expected.items():
            self.assertEqual(version_contract.version(value), value)
            self.assertEqual(version_contract.tag("v" + value), "v" + value)
            self.assertEqual(version_contract.pep440(value), python_value)
        for value in ("1.2", "1.2.3-dev.1", "01.2.3", "1.2.3-rc.-1", "1.2.3-rc.0/x", "v1.2.3", "1.2.3\nnext=x"):
            with self.assertRaises(ValueError):
                version_contract.version(value)
        for value in ("1.2.3", "vv1.2.3", "v1.2.3+meta", "v1.2.3\nsource_sha=x"):
            with self.assertRaises(ValueError):
                version_contract.tag(value)

    def test_template_is_current_and_rejects_drift(self):
        version_contract.check_template(ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            copy = Path(temporary) / "source"
            shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns(".git", "target", "node_modules"))
            package = copy / "bindings/node/package.json"
            package.write_text(package.read_text().replace('"version": "0.0.0"', '"version": "0.0.1"'))
            with self.assertRaises(ValueError):
                version_contract.check_template(copy)

    def test_stamping_prerelease_zero_is_isolated_and_verifiable(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            destination = Path(temporary) / "stamped"
            shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns(".git", "target", "node_modules"))
            shutil.copytree(source, destination)
            version_contract.stamp(destination, "0.0.0-beta.0")
            version_contract.verify(destination, "0.0.0-beta.0")
            self.assertEqual(json.loads((destination / "bindings/node/package.json").read_text())["version"], "0.0.0-beta.0")
            self.assertEqual(json.loads((source / "bindings/node/package.json").read_text())["version"], "0.0.0")


class ManifestTests(unittest.TestCase):
    VERSION = "1.2.3-rc.0"

    def npm_tarball(self, path: Path, metadata: dict) -> None:
        data = json.dumps(metadata).encode()
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo("package/package.json")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))

    def make_bundle(self, root: Path) -> list[str]:
        npm = root / "npm"
        python = root / "python"
        npm.mkdir(); python.mkdir()
        optional = {name: self.VERSION for name in artifact_manifest.NODE_TARGETS}
        root_name = "nodedb-lab-code2graph-1.2.3-rc.0.tgz"
        self.npm_tarball(npm / root_name, {"name": artifact_manifest.ROOT_NODE_PACKAGE, "version": self.VERSION, "optionalDependencies": optional})
        for name, (os_name, cpu, libc) in artifact_manifest.NODE_TARGETS.items():
            metadata = {"name": name, "version": self.VERSION, "os": [os_name], "cpu": [cpu]}
            if libc: metadata["libc"] = [libc]
            filename = f"{name.removeprefix('@').replace('/', '-')}-{self.VERSION}.tgz"
            self.npm_tarball(npm / filename, metadata)
        py_version = artifact_manifest.pep440(self.VERSION)
        wheel_tags = {
            "linux-x64-gnu": "manylinux_2_17_x86_64.manylinux2014_x86_64",
            "linux-arm64-gnu": "manylinux_2_17_aarch64.manylinux2014_aarch64",
            "linux-x64-musl": "musllinux_1_2_x86_64",
            "darwin-x64": "macosx_10_12_x86_64",
            "darwin-arm64": "macosx_11_0_arm64",
            "win32-x64-msvc": "win_amd64",
        }
        metadata = f"Name: code2graph-rs\nVersion: {py_version}\n".encode()
        for tag in wheel_tags.values():
            path = python / f"code2graph_rs-{py_version}-cp39-abi3-{tag}.whl"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(f"code2graph_rs-{py_version}.dist-info/METADATA", metadata)
        sdist = python / f"code2graph_rs-{py_version}.tar.gz"
        with tarfile.open(sdist, "w:gz") as archive:
            info = tarfile.TarInfo(f"code2graph_rs-{py_version}/PKG-INFO")
            info.size = len(metadata)
            archive.addfile(info, io.BytesIO(metadata))
        return sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())

    def args(self, root: Path, files: list[str]) -> argparse.Namespace:
        return argparse.Namespace(directory=root, output=root / "release-manifest.json", file=files, repository="nodedb-lab/code2graph", tag="v" + self.VERSION, source_sha="a" * 40, prepare_run_id="42", workflow="release-prepare.yml", version=self.VERSION)

    def test_manifest_encodes_and_revalidates_exact_distribution_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            create = self.args(root, self.make_bundle(root))
            artifact_manifest.create(create)
            payload = json.loads(create.output.read_text())
            self.assertEqual(set(payload["contract"]["npm"]["targets"]), set(artifact_manifest.NODE_TARGETS))
            self.assertEqual(set(payload["contract"]["python"]["targets"]), set(artifact_manifest.PYTHON_TARGETS))
            verify = argparse.Namespace(**{key: getattr(create, key) for key in ("directory", "repository", "tag", "source_sha", "prepare_run_id", "workflow", "version")}, manifest=create.output)
            artifact_manifest.verify(verify)
            checksums = root / "SHA256SUMS"
            checksum_names = ["release-manifest.json", *create.file]
            checksums.write_text("".join(f"{artifact_manifest.digest(root / name)}  {name}\n" for name in checksum_names))
            artifact_manifest.verify_checksums(argparse.Namespace(directory=root, manifest=create.output, checksums=checksums))
            hostile = argparse.Namespace(**vars(verify)); hostile.workflow = "hostile.yml"
            with self.assertRaises(ValueError): artifact_manifest.verify(hostile)
            platform = next(path for path in (root / "npm").glob("*.tgz") if "linux-" in path.name)
            platform.unlink()
            with self.assertRaises(ValueError): artifact_manifest.verify(verify)

    def test_matrix_rejects_extra_target_and_root_dependency_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.make_bundle(root)
            self.npm_tarball(root / "npm" / "extra.tgz", {"name": "hostile", "version": self.VERSION})
            with self.assertRaises(ValueError): artifact_manifest.bundle_contract(root, self.VERSION)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.make_bundle(root)
            root_tarball = root / "npm" / "nodedb-lab-code2graph-1.2.3-rc.0.tgz"
            root_tarball.unlink()
            self.npm_tarball(root_tarball, {"name": artifact_manifest.ROOT_NODE_PACKAGE, "version": self.VERSION, "optionalDependencies": {}})
            with self.assertRaises(ValueError): artifact_manifest.bundle_contract(root, self.VERSION)

    def test_inventory_and_archive_comparison_reject_hostile_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / "a").write_text("a")
            for name in ("../escape", "/absolute", "./relative"):
                with self.assertRaises(ValueError): artifact_manifest.safe_name(name)
            (root / "extra").write_text("x")
            with self.assertRaises(ValueError): artifact_manifest.inventory(root, ["a"])


class WorkflowContractTests(unittest.TestCase):
    def test_prepare_is_complete_nonpublishing_and_runs_equivalent_binding_gates(self):
        prepare = workflow("release-prepare.yml")
        self.assertEqual(prepare["on"]["push"]["tags"], ["v*"])
        self.assertEqual(prepare["jobs"]["ci"]["with"]["skip_bindings"], "true")
        text = (ROOT / ".github/workflows/release-prepare.yml").read_text()
        for required in ("npm run harden-loader", "npm run harden-types", "npm test", "unittest discover", "npm run test:all", "BUNDLE_NPM=\"$GITHUB_WORKSPACE/bundle/npm\""):
            self.assertIn(required, text)
        self.assertLess(text.index("npx napi artifacts"), text.rindex("npm run harden-loader"))
        for forbidden in ("npm publish", "cargo publish"):
            self.assertNotIn(forbidden, text)

    def test_validation_uses_only_canonical_tag_helper(self):
        text = (ROOT / ".github/workflows/release-validate.yml").read_text()
        self.assertIn('version_contract.py validate-tag "$TAG"', text)
        self.assertNotIn("=~", text)

    def test_distribution_provenance_source_and_no_build_contracts(self):
        release = workflow("release.yml")
        self.assertEqual(set(release["on"]["workflow_dispatch"]["inputs"]), {"tag", "prepare_run_id", "distribution_ref", "crates", "pypi", "npm", "github"})
        text = (ROOT / ".github/workflows/release.yml").read_text()
        for required in (".repository.full_name", ".head_repository.full_name", ".head_sha", ".path", "tagged-source", "cmp --silent", "unexpected PyPI artifact", "GitHub release attachment set mismatch"):
            self.assertIn(required, text)
        self.assertNotIn(".head_branch", text)
        for forbidden in ("maturin build", "maturin-action", "napi build", "cargo test", "npm test", "cargo build"):
            self.assertNotIn(forbidden, text)
        self.assertLess(text.index('for file in "${platform_tarballs[@]}"'), text.index('publish "${roots[0]}"'))

    def test_action_versions_and_actionlint_invocation_match_repository(self):
        test_text = (ROOT / ".github/workflows/test.yml").read_text()
        self.assertIn("docker://rhysd/actionlint:1.7.7", test_text)
        for workflow_path in (ROOT / ".github/workflows").glob("*.yml"):
            text = workflow_path.read_text()
            self.assertNotIn("actions/checkout@v5", text)
            self.assertNotIn("actions/upload-artifact@v6", text)
            self.assertNotIn("actions/download-artifact@v7", text)


if __name__ == "__main__": unittest.main()
