#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Scoped real Ed25519 and Git admission checks for the detached Node envelope."""

import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
from node_admission import NODE_REPO, main_ancestry
from signed import ARCHIVE_NAMES, archive_digest, authenticate, host_rid, openssl, openssl_path, seal

VERIFY = Path(__file__).resolve().parents[1] / "mxc" / "verify_install.py"


class SignedDistributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rid = host_rid()
        if cls.rid is None:
            raise RuntimeError("Distribution tests require a native Windows or Linux x64 host")
        cls.executable = openssl_path(None)
        cls._scratch = tempfile.TemporaryDirectory(prefix="arcforges-distribution-fixture-")
        cls.addClassCleanup(cls._scratch.cleanup)
        directory = Path(cls._scratch.name)
        cls.key = directory / "fixture.private.pem"
        cls.trust = directory / "fixture.public.pem"
        cls.other = directory / "wrong.public.pem"
        openssl(cls.executable, "genpkey", "-algorithm", "Ed25519", "-out", cls.key)
        openssl(cls.executable, "pkey", "-in", cls.key, "-pubout", "-out", cls.trust)
        other_private = directory / "wrong.private.pem"
        openssl(cls.executable, "genpkey", "-algorithm", "Ed25519", "-out", other_private)
        openssl(cls.executable, "pkey", "-in", other_private, "-pubout", "-out", cls.other)

    def setUp(self):
        scratch = tempfile.TemporaryDirectory(dir=self._scratch.name)
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.archive = self.root / ARCHIVE_NAMES[self.rid]
        self.archive.write_bytes(b"detached signature application fixture")
        self.output = self.root / "output"
        self.manifest = {
            "schema": 1, "kind": "node", "rid": self.rid, "archive": archive_digest(self.archive),
            "producers": [{"repo": NODE_REPO, "commit": "1" * 40, "tree": "2" * 40}],
            "qualification": "candidate",
            **{key: "3" * 64 for key in ("buildInfoSha256", "sbomSha256", "dependencyAdmissionSha256",
                                         "dependencyEvidenceSha256")},
        }

    def sign(self):
        seal(self.archive, self.executable, self.key, self.trust, self.manifest)

    def authenticate(self, key=None, **requirements):
        return authenticate(self.archive, self.rid, key or self.trust, self.executable, **requirements)

    def check_cli(self, *arguments, rid=None):
        return subprocess.run([sys.executable, str(VERIFY), "--rid", rid or self.rid, "--archive", str(self.archive),
                               "--output", str(self.output), *arguments], capture_output=True, text=True,
                              encoding="utf-8", timeout=30)

    def test_candidate_requires_explicit_admission_and_exact_source(self):
        self.sign()
        with self.assertRaisesRegex(ValueError, "explicit admission"):
            self.authenticate()
        verified = self.authenticate(allow_candidate=True, commit="1" * 40, tree="2" * 40)
        self.assertEqual(self.manifest, verified)
        with self.assertRaisesRegex(ValueError, "source tree"):
            self.authenticate(allow_candidate=True, tree="5" * 40)
        with self.assertRaisesRegex(ValueError, "source commit"):
            self.authenticate(allow_candidate=True, commit="5" * 40)

    def test_wrong_trust_root_cannot_admit_candidate(self):
        self.sign()
        with self.assertRaisesRegex(ValueError, "OpenSSL rejected"):
            self.authenticate(self.other, allow_candidate=True)

    def test_tampered_manifest_does_not_verify(self):
        self.sign()
        path = Path(f"{self.archive}.manifest.json")
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "OpenSSL rejected"):
            self.authenticate(allow_candidate=True)

    def test_tampered_archive_is_refused_before_extraction_or_target_creation(self):
        self.sign()
        self.archive.write_bytes(b"x" * self.manifest["archive"]["length"])
        result = self.check_cli("--trusted-key", str(self.trust), "--allow-candidate")
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("Signed archive length or digest does not match", result.stderr)
        self.assertFalse(self.output.exists())

    def test_signed_input_does_not_fall_back_when_key_is_absent(self):
        self.sign()
        result = self.check_cli()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("separately trusted public key", result.stderr)
        self.assertFalse(self.output.exists())

    def test_wrong_native_rid_and_foreign_producer_are_refused(self):
        self.manifest["producers"][0]["repo"] = "ArcForges/Contracts"
        self.sign()
        other_rid = next(rid for rid in ARCHIVE_NAMES if rid != self.rid)
        result = self.check_cli("--trusted-key", str(self.trust), "--allow-candidate", rid=other_rid)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("matching native x64 host", result.stderr)
        self.assertFalse(self.output.exists())
        with self.assertRaisesRegex(ValueError, "Invalid signed Node producer"):
            self.authenticate(allow_candidate=True)

    def test_verified_copy_is_independent_of_later_source_changes(self):
        expected = self.archive.read_bytes()
        with io.BytesIO() as snapshot:
            self.assertEqual(self.manifest["archive"], archive_digest(self.archive, copy=snapshot, length=len(expected)))
            self.archive.write_bytes(b"a replacement at the original path")
            self.assertEqual(expected, snapshot.getvalue())

    def test_main_requires_canonical_origin_and_actual_ancestry(self):
        def git(*args):
            return subprocess.run(["git", "-C", str(self.root), *args], capture_output=True,
                                  text=True, check=True, timeout=20).stdout.strip()

        git("init")
        git("remote", "add", "origin", f"https://github.com/{NODE_REPO}.git")
        git("-c", "user.name=fixture", "-c", "user.email=fixture@example.test", "commit", "--allow-empty", "-m", "main")
        main = git("rev-parse", "HEAD")
        git("update-ref", "refs/remotes/origin/main", main)
        git("-c", "user.name=fixture", "-c", "user.email=fixture@example.test", "commit", "--allow-empty", "-m", "later")
        later = git("rev-parse", "HEAD")
        self.assertEqual(main, main_ancestry(self.root, NODE_REPO, [main]))
        with self.assertRaisesRegex(ValueError, "merge-base"):
            main_ancestry(self.root, NODE_REPO, [later])
        git("remote", "set-url", "origin", "https://github.com/ArcForges/Contracts.git")
        with self.assertRaisesRegex(ValueError, "origin"):
            main_ancestry(self.root, NODE_REPO, [main])


if __name__ == "__main__":
    unittest.main()
