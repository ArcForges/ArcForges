#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Scoped real Ed25519 and Git admission checks for the detached Node envelope."""

from contextlib import redirect_stdout
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from zipfile import ZIP_LZMA, ZipFile

sys.dont_write_bytecode = True
from node_admission import NODE_REPO, main_ancestry
from signed import ARCHIVE_NAMES, archive_digest, authenticate, host_rid, openssl, openssl_path, seal

VERIFY = Path(__file__).resolve().parents[1] / "mxc" / "verify_install.py"
sys.path.insert(0, str(VERIFY.parent))
import verify_install


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

    def test_main_signature_requires_a_separately_admitted_archive(self):
        self.manifest["qualification"] = "main"
        self.sign()
        with self.assertRaisesRegex(ValueError, "independently admitted"):
            self.authenticate()
        with self.assertRaisesRegex(ValueError, "independently admitted"):
            self.authenticate(admitted_archive_sha256="9" * 64, allow_candidate=True)
        self.assertEqual(self.manifest, self.authenticate(admitted_archive_sha256=self.manifest["archive"]["sha256"]))

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

    def test_explicit_unsigned_mode_still_refuses_a_stripped_signed_marker(self):
        manifest = b'{"runtimeIdentifier":"win-x64","distribution":"signed-mxc-cohort"}'
        archive = self.root / ARCHIVE_NAMES["win-x64"]
        with ZipFile(archive, "w") as package:
            package.writestr("build-info.json", manifest)
        sha = archive_digest(archive)["sha256"]
        Path(f"{archive}.sha256").write_text(f"{sha}  {archive.name}\n", encoding="ascii")
        result = subprocess.run([sys.executable, str(VERIFY), "--rid", "win-x64", "--archive", str(archive),
                                 "--allow-unsigned-preview", "--output", str(self.output)], capture_output=True,
                                text=True, encoding="utf-8", timeout=30)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("selected authentication", result.stderr)
        self.assertFalse(self.output.exists())

    def test_preview_reads_the_checked_private_copy(self):
        expected = self.archive.read_bytes()
        sha = self.manifest["archive"]["sha256"]
        Path(f"{self.archive}.sha256").write_text(f"{sha}  {self.archive.name}\n", encoding="ascii")
        args = SimpleNamespace(archive=self.archive, rid=self.rid, output=self.output, commit=None, tree=None,
                               allow_unsigned_preview=True, allow_candidate=False, admitted_archive_sha256=None)

        def observe_copy(archive, _rid, _root, *, source):
            archive.write_bytes(b"later replacement")
            self.assertEqual(expected, source.read())
            raise ValueError("checked snapshot observed")

        with patch.object(verify_install, "extract", side_effect=observe_copy):
            with self.assertRaisesRegex(ValueError, "checked snapshot observed"):
                verify_install.check_unsigned(args)
        self.assertFalse(self.output.exists())

    def test_archive_limits_include_directories_and_actual_member_declarations(self):
        archive = self.root / "bounded.zip"
        with ZipFile(archive, "w") as package:
            package.writestr("first/", b"")
            package.writestr("second/", b"")
            package.writestr("ordinary", b"1234")
        with patch.object(verify_install, "MAX_MEMBERS", 2):
            with archive.open("rb") as source, self.assertRaisesRegex(ValueError, "ZIP directory exceeds"):
                verify_install.extract(archive, "win-x64", self.output, source=source)
        self.assertFalse(self.output.exists())
        with patch.object(verify_install, "MAX_MEMBER_BYTES", 3):
            with archive.open("rb") as source, self.assertRaisesRegex(ValueError, "member exceeds"):
                verify_install.extract(archive, "win-x64", self.output, source=source)
        self.assertFalse(self.output.exists())

    def test_zip64_local_header_is_refused_before_zip_parser(self):
        archive = self.root / "test.zip"
        with ZipFile(archive, "w") as writer:
            with writer.open("ordinary.txt", "w", force_zip64=True) as member:
                member.write(b"fixture")
        with patch.object(verify_install.zipfile, "ZipFile") as reader, archive.open("rb") as source:
            with self.assertRaisesRegex(ValueError, "ZIP64"):
                verify_install.extract(archive, "win-x64", self.output, source=source)
        reader.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_other_zip_compression_is_refused_before_zip_parser(self):
        archive = self.root / "test.zip"
        with ZipFile(archive, "w", compression=ZIP_LZMA) as writer:
            writer.writestr("ordinary.txt", b"fixture")
        with patch.object(verify_install.zipfile, "ZipFile") as reader, archive.open("rb") as source:
            with self.assertRaisesRegex(ValueError, "Unsupported ZIP compression"):
                verify_install.extract(archive, "win-x64", self.output, source=source)
        reader.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_tar_declarations_are_bounded_before_reading_member_contents(self):
        archive = self.root / "bounded.tar.gz"
        with tarfile.open(archive, "w:gz", format=tarfile.GNU_FORMAT) as package:
            for name in ("first", "second"):
                member = tarfile.TarInfo(name)
                member.size = 4
                package.addfile(member, io.BytesIO(b"1234"))
        with patch.object(verify_install, "MAX_EXPANDED_BYTES", 7):
            with archive.open("rb") as source, self.assertRaisesRegex(ValueError, "expanded size limit"):
                verify_install.extract(archive, "linux-x64", self.output, source=source)
        self.assertEqual(b"1234", (self.output / "first").read_bytes())
        self.assertFalse((self.output / "second").exists())

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

    def test_failed_linux_publish_worker_cannot_record_old_outputs(self):
        sys.path.insert(0, str(VERIFY.parents[2] / "eng"))
        import verify_linux

        output = self.root / "artifacts/publish/linux-x64"
        output.mkdir(parents=True)
        receipt = output / "distribution-build.json"
        receipt.write_text("old receipt", encoding="utf-8")
        with (patch.object(verify_linux, "PUBLISH", output),
              patch.object(verify_linux, "signed_publish_path"),
              patch.object(verify_linux.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="1" * 40)),
              patch.object(verify_linux, "publish_group", side_effect=PermissionError("old output cannot be cleared")),
              patch.object(verify_linux, "run") as record, redirect_stdout(io.StringIO())):
            with self.assertRaisesRegex(verify_linux.Failure, "old output cannot be cleared"):
                verify_linux.publish(["host", "run-supervisor"], record_distribution=True)
        record.assert_not_called()
        self.assertFalse(receipt.exists())


if __name__ == "__main__":
    unittest.main()
