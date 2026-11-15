# SPDX-License-Identifier: AGPL-3.0-only
"""Offline adversarial configuration/archive checks; no native success is simulated."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import native_toolchain as native


class NativeToolchainGuards(unittest.TestCase):
    def test_arm_and_x64_select_distinct_official_archives_and_cache_roots(self):
        with patch.object(native.platform, 'machine', return_value='x86_64'):
            amd64 = native.load_lock()
        with patch.object(native.platform, 'machine', return_value='aarch64'):
            arm64 = native.load_lock()
        self.assertEqual('linux-amd64', amd64['platform'])
        self.assertEqual('linux-arm64', arm64['platform'])
        self.assertNotEqual(amd64['llvm']['archive']['sha256'], arm64['llvm']['archive']['sha256'])
        self.assertEqual({}, arm64['llvm']['binaries'])
        self.assertTrue(amd64['llvm']['binaries'])
        self.assertNotEqual(native.tool_roots(amd64)[1:], native.tool_roots(arm64)[1:])
        self.assertEqual(amd64['binutils'], arm64['binutils'])

    def test_unsupported_native_architecture_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported native Linux'):
            native.native_platform('s390x')

    def test_exact_formal_banner_is_not_truncated_or_normalized(self):
        self.assertTrue(native.exact_version('GNU ld 2.47.20260726', '2.47.20260726'))
        self.assertFalse(native.exact_version('GNU ld 2.47.20260726', '2.47'))
        self.assertFalse(native.exact_version('clang version 23.1.50', '23.1.5'))

    def test_wrong_default_linker_and_compiler_aliases_fail_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'bin').mkdir()
            (root / 'bin/ld.bfd').write_bytes(b'expected file identity')
            (root / 'bin/ld').write_bytes(b'different file identity')
            with self.assertRaisesRegex(ValueError, 'default GNU ld'):
                native.verify_default_linker_alias(root)
            (root / 'bin/clang-23').write_bytes(b'expected file identity')
            (root / 'bin/clang').write_bytes(b'different alias')
            (root / 'bin/clang++').write_bytes(b'different alias')
            with self.assertRaisesRegex(ValueError, 'compiler alias'):
                native.verify_clang_aliases(root, '23')

    def test_archive_receipt_cannot_omit_core_compiler_and_resource_inputs(self):
        value = native.load_lock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'provision-receipt.json').write_text(json.dumps({
                'sourceCommit': value['llvm']['sourceCommit'],
                'sourceArchive': {'actualSha256': value['llvm']['archive']['sha256']},
                'archiveFiles': []}))
            with self.assertRaisesRegex(ValueError, 'required compiler/resource'):
                native.verify_llvm_files(root, value)

    def test_external_source_recipe_binds_full_input_and_result_bytes(self):
        before, after = b'first\nunused\nlast\n', b'first\nlast\n'
        row = {'beforeSha256': hashlib.sha256(before).hexdigest(), 'afterSha256': hashlib.sha256(after).hexdigest(),
               'edits': [{'offset': 6, 'length': 7, 'insert': ''}]}
        self.assertEqual(after, native.edited_bytes(before, row))
        with self.assertRaisesRegex(ValueError, 'signed source'):
            native.edited_bytes(before + b'changed', row)
        changed = copy.deepcopy(row)
        changed['edits'][0]['insert'] = 'unreviewed source'
        with self.assertRaisesRegex(ValueError, 'Invalid source byte edit'):
            native.edited_bytes(before, changed)

    def test_wrong_archive_root_is_rejected_before_extracting_material(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / 'input.tar.xz'
            with tarfile.open(archive, 'w:xz') as bundle:
                member = tarfile.TarInfo('unexpected-root/bin/clang-23')
                data = b'not executable test input'
                member.size = len(data)
                bundle.addfile(member, io.BytesIO(data))
            with self.assertRaisesRegex(ValueError, 'Unsafe native archive'):
                native.extract(archive, root / 'out', 'expected-root', llvm=True)

    def test_aot_arguments_preserve_exact_environmental_tools_without_warning_waivers(self):
        self.assertEqual(['-p:CppCompilerAndLinker=clang', '-p:CppLibCreator=ar', '-p:LinkerFlavor=bfd', '-p:ObjCopyName=llvm-objcopy'],
                         native.aot_arguments())


if __name__ == '__main__':
    unittest.main()
