# SPDX-License-Identifier: AGPL-3.0-only
"""Offline static scan for GOV.30 (P2-023, P2-017, P2-024): no macOS RID, lock section or admission remains in owned files.

Runs without SDK, network or build output. Only the files GOV.30 writes are scanned. Shared fail-closed macOS
host detection, immutable dependency-review, provenance and patch records are history or shared code and are not
owned here. The only exempt occurrences are the two current.json candidate rows pinned to the Design receipt.
"""
import json
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
DESKTOP_RIDS = 'win-x64;win-arm64;linux-x64'
OSX = re.compile(r'osx', re.IGNORECASE)

# Files GOV.30 owns (record writes list), in addition to the reconciliation source count it regenerates.
OWNED = (
    'eng/build/desktop-rids.props',
    'CMakePresets.json',
    'src/DesktopHelpers/ArcForges.ContentSandbox/packages.lock.json',
    'src/DesktopHelpers/ArcForges.ContentSandbox/Fixture/packages.lock.json',
    'tests/LocalRpcAotTests/Program.cs',
    'tests/LocalRpcAotTests/README.md',
    'tests/LocalRpcAotTests/packages.lock.json',
    'tests/ReleaseArtifactTests/GrpcWeb/packages.lock.json',
    'tests/ReleaseArtifactTests/Realtime/packages.lock.json',
    'eng/policy/dependency-policy.json',
    'eng/policy/dependency-reviews/gov-30-r1.json',
    'eng/policy/reconciliation/directories.json',
    'eng/policy/reconciliation/source.json',
    'eng/provenance/files.json',
)
LOCKS = tuple(path for path in OWNED if path.endswith('packages.lock.json'))
# current.json keeps the ArcScope 0.1.0-ci.8.1 candidate nativeRuns as immutable history (coordinator adjudication, 2026-10-08).
HISTORY = 'eng/policy/reconciliation/current.json'
HISTORY_EXEMPT = {('ArcScope', 'osx-arm64'), ('ArcScope', 'osx-x64')}


class DesktopRidResidueTests(unittest.TestCase):
    def read(self, relative):
        return (ROOT / relative).read_text(encoding='utf-8')

    def test_desktop_rid_set_is_win_x64_win_arm64_linux_x64(self):
        props = ET.fromstring(self.read('eng/build/desktop-rids.props'))
        values = [element.text for element in props.iter('RuntimeIdentifiers')]
        self.assertEqual(values, [DESKTOP_RIDS])

    def test_owned_files_contain_no_osx_token(self):
        found = []
        for relative in OWNED:
            for number, line in enumerate(self.read(relative).splitlines(), 1):
                if OSX.search(line):
                    found.append(f'{relative}:{number}')
        self.assertEqual(found, [], 'osx residue in files owned by GOV.30')

    def test_locks_have_no_osx_section_or_runtime_admission(self):
        for relative in LOCKS:
            with self.subTest(lock=relative):
                dependencies = json.loads(self.read(relative))['dependencies']
                for target, packages in dependencies.items():
                    self.assertNotIn('osx', target.lower())
                    for package in packages:
                        self.assertFalse(package.lower().startswith('runtime.osx-'), package)

    def test_dependency_policy_has_no_osx_admission_and_names_the_successor(self):
        policy = json.loads(self.read('eng/policy/dependency-policy.json'))
        self.assertEqual([key for key in policy['nugetClosure'] if OSX.search(key)], [])
        self.assertEqual(policy['reviewReceipt'], 'eng/policy/dependency-reviews/gov-30-r1.json')
        self.assertTrue((ROOT / policy['reviewReceipt']).is_file())

    def test_directory_inventory_has_no_osx_row_and_its_count_matches(self):
        rows = json.loads(self.read('eng/policy/reconciliation/directories.json'))
        self.assertEqual([row['path'] for row in rows if OSX.search(row['path'])], [])
        counts = json.loads(self.read('eng/policy/reconciliation/source.json'))['counts']
        self.assertEqual(counts['directories'], len(rows))

    def test_current_inventory_osx_text_is_only_the_pinned_history_rows(self):
        text = self.read(HISTORY)
        exempt = set()
        for row in json.loads(text):
            for run in row['candidate'].get('nativeRuns', []):
                if OSX.search(run['rid']):
                    exempt.add((row['repository'], run['rid']))
        self.assertEqual(exempt, HISTORY_EXEMPT)
        self.assertEqual(len(OSX.findall(text)), len(HISTORY_EXEMPT))


if __name__ == '__main__':
    unittest.main()
