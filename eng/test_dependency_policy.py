# SPDX-License-Identifier: AGPL-3.0-only
"""Offline adversarial admission and publisher checks; no artifacts or registries."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from dependency_policy import ROOT, POLICY, audit, check_admission, check_history, check_python, closure, exact, framework_upgrade, hashes, python_closure
sys.path.insert(0, str(Path(__file__).resolve().parent / 'packaging'))
from release_channels import authorized, bound_candidate, publication, selected, verified_tag


class SecretScanAllowlistTests(unittest.TestCase):
    POLICY_PATH = 'eng/policy/dependency-policy.json'
    RECEIPT_PATH = 'eng/policy/dependency-reviews/plt-40-r1.json'
    PLT44_RECEIPT_PATH = 'eng/policy/dependency-reviews/plt-44-r1.json'
    RECEIPT_DIRECTORY_PATH_REGEX = '^eng/policy/dependency-reviews/[A-Za-z0-9._-]+[.]json$'
    ANY_RECEIPT_DESCRIPTION = 'Exact mirrored Security.Secrets project lines in any dependency-review receipt'
    PROJECT_PATHS = (
        'src/BuildingBlocks/ArcForges.Security.Secrets/ArcForges.Security.Secrets.csproj',
        'src/BuildingBlocks/ArcForges.Security.Secrets/Tests/ArcForges.Security.Secrets.Tests.csproj',
    )
    PROJECT_HASHES = (
        '8ff03fdcaf23b09386fac47dd5e3e4f9689a665a569137f726456c9e59a9ecef',
        'd6798bbbcf980fab4467c6d831871b075e55aeef6e09c7df67c4d72cd2334120',
    )

    @classmethod
    def setUpClass(cls):
        cls.config = tomllib.loads((ROOT / '.gitleaks.toml').read_text(encoding='utf-8'))
        cls.groups = cls.config['allowlists']

    @staticmethod
    def _matches(group, path, line, rule='generic-api-key'):
        return (
            rule in group.get('targetRules', ())
            and any(re.fullmatch(pattern, path) is not None for pattern in group.get('paths', ()))
            and any(re.fullmatch(pattern, line) is not None for pattern in group.get('regexes', ()))
        )

    def _allowed(self, path, line, rule='generic-api-key'):
        return any(self._matches(group, path, line, rule) for group in self.groups)

    @staticmethod
    def _line(path, digest, indent):
        return f'{" " * indent}"{path}": "{digest}",'

    @staticmethod
    def _exact_regex(line):
        # Gitleaks reports every added line after the first of a fragment with its preceding newline.
        return '^\\n?' + re.escape(line).replace(r'\ ', ' ').replace(r'\.', '[.]') + '$'

    def test_allowlist_has_only_the_exact_path_bound_task_groups(self):
        self.assertTrue(self.config['extend']['useDefault'])
        self.assertNotIn('allowlist', self.config)
        self.assertEqual(len(self.groups), 4)
        baseline, *task_groups = self.groups
        self.assertEqual(baseline['description'], 'Generated outputs and public test fixtures')
        self.assertEqual(baseline['paths'], [
            '(^|/)artifacts/',
            '(^|/)(bin|obj)/',
            '(^|/)tests/.*/Fixtures/',
        ])
        expected = (
            (self.POLICY_PATH, 4),
            (self.RECEIPT_PATH, 2),
        )
        self.assertEqual(len(task_groups), len(expected) + 1)
        for group, (path, count) in zip(task_groups, expected):
            with self.subTest(path=path):
                self.assertEqual(group['paths'], ['^' + path.replace('.', '[.]') + '$'])
                self.assertEqual(group['targetRules'], ['generic-api-key'])
                self.assertEqual(group['condition'], 'AND')
                self.assertEqual(group['regexTarget'], 'line')
                self.assertEqual(len(group['regexes']), count)
                indentations = (4, 6) if path == self.POLICY_PATH else (6,)
                expected_regexes = {
                    self._exact_regex(self._line(project_path, digest, indent))
                    for indent in indentations
                    for project_path, digest in zip(self.PROJECT_PATHS, self.PROJECT_HASHES)
                }
                self.assertEqual(set(group['regexes']), expected_regexes)
        any_receipt = task_groups[-1]
        self.assertEqual(any_receipt['description'], self.ANY_RECEIPT_DESCRIPTION)
        self.assertEqual(any_receipt['paths'], [self.RECEIPT_DIRECTORY_PATH_REGEX])
        self.assertEqual(any_receipt['targetRules'], ['generic-api-key'])
        self.assertEqual(any_receipt['condition'], 'AND')
        self.assertEqual(any_receipt['regexTarget'], 'line')
        self.assertEqual(set(any_receipt['regexes']), {
            self._exact_regex(self._line(project_path, digest, 6))
            for project_path, digest in zip(self.PROJECT_PATHS, self.PROJECT_HASHES)
        })
        self.assertEqual(len(any_receipt['regexes']), 2)

    def test_exact_six_observed_lines_match_only_the_generic_api_key_rule(self):
        policy_lines = [
            self._line(path, digest, 4)
            for path, digest in zip(self.PROJECT_PATHS, self.PROJECT_HASHES)
        ] + [
            self._line(path, digest, 6)
            for path, digest in zip(self.PROJECT_PATHS, self.PROJECT_HASHES)
        ]
        receipt_lines = [
            self._line(path, digest, 6)
            for path, digest in zip(self.PROJECT_PATHS, self.PROJECT_HASHES)
        ]
        self.assertEqual(sum(self._allowed(self.POLICY_PATH, line) for line in policy_lines), 4)
        self.assertEqual(sum(self._allowed(self.RECEIPT_PATH, line) for line in receipt_lines), 2)
        for line in policy_lines:
            self.assertTrue(self._allowed(self.POLICY_PATH, line))
            self.assertTrue(self._allowed(self.POLICY_PATH, '\n' + line))
            self.assertFalse(self._allowed(self.POLICY_PATH, line, 'another-rule'))
        for line in receipt_lines:
            self.assertTrue(self._allowed(self.RECEIPT_PATH, line))
            self.assertTrue(self._allowed(self.RECEIPT_PATH, '\n' + line))
            self.assertFalse(self._allowed(self.RECEIPT_PATH, line, 'another-rule'))

    def test_actual_files_carry_exactly_the_allowlisted_project_lines(self):
        for path, count in ((self.POLICY_PATH, 4), (self.RECEIPT_PATH, 2)):
            with self.subTest(path=path):
                lines = (ROOT / path).read_text(encoding='utf-8').split('\n')
                observed = [line for line in lines if any(project in line for project in self.PROJECT_PATHS)]
                self.assertEqual(len(observed), count)
                for line in observed:
                    self.assertTrue(self._allowed(path, line))
                    self.assertTrue(self._allowed(path, '\n' + line))

    def test_receipt_directory_group_accepts_only_the_two_exact_lines_in_any_receipt_file(self):
        lines = [
            self._line(path, digest, 6)
            for path, digest in zip(self.PROJECT_PATHS, self.PROJECT_HASHES)
        ]
        receipts = (
            self.RECEIPT_PATH,
            self.PLT44_RECEIPT_PATH,
            'eng/policy/dependency-reviews/plt-09-r1.json',
            'eng/policy/dependency-reviews/future-task.r2.json',
        )
        group = self.groups[-1]
        for path in receipts:
            with self.subTest(path=path):
                for line in lines:
                    self.assertTrue(self._matches(group, path, line))
                    self.assertTrue(self._matches(group, path, '\n' + line))
                    self.assertFalse(self._matches(group, path, line, 'another-rule'))
                    self.assertFalse(self._matches(group, path, '\n\n' + line))
                    self.assertFalse(self._matches(group, path, line + '\n'))
                    self.assertFalse(self._matches(group, path, ' ' + line))
        for path in (
            self.POLICY_PATH,
            'eng/policy/other.json',
            'eng/policy/dependency-reviews/sub/plt-09-r1.json',
            'eng/policy/dependency-reviews/plt-09-r1.json.bak',
            'eng/policy/dependency-reviews/plt-09-r1.txt',
            'eng/policy/dependency-reviews/.json',
            'eng/policy/dependency-reviews/',
            'README.md',
            'src/BuildingBlocks/ArcForges.Security.Secrets/README.md',
            'x/eng/policy/dependency-reviews/plt-09-r1.json',
        ):
            with self.subTest(rejected_path=path):
                for line in lines:
                    self.assertFalse(self._matches(group, path, line))

    def test_actual_receipts_carry_only_allowlisted_secrets_project_lines(self):
        directory = ROOT / 'eng/policy/dependency-reviews'
        lines = {
            self._line(path, digest, 6)
            for path, digest in zip(self.PROJECT_PATHS, self.PROJECT_HASHES)
        }
        found = 0
        for receipt in sorted(directory.glob('*.json')):
            relative = receipt.relative_to(ROOT).as_posix()
            for line in receipt.read_text(encoding='utf-8').split('\n'):
                if any(project in line for project in self.PROJECT_PATHS):
                    found += 1
                    with self.subTest(path=relative, line=line):
                        self.assertIn(line, lines)
                        self.assertTrue(self._allowed(relative, line))
                        self.assertTrue(self._allowed(relative, '\n' + line))
        self.assertGreaterEqual(found, 4)

    def test_wrong_key_digest_path_swaps_suffix_and_unrelated_hash_are_rejected(self):
        project_path, tests_path = self.PROJECT_PATHS
        project_hash, tests_hash = self.PROJECT_HASHES
        valid_project = self._line(project_path, project_hash, 4)
        candidates = (
            (self.POLICY_PATH, valid_project.replace(project_path, project_path.replace('.csproj', '.other'))),
            (self.POLICY_PATH, self._line(project_path, tests_hash, 4)),
            (self.POLICY_PATH, self._line(tests_path, project_hash, 4)),
            ('eng/policy/other.json', valid_project),
            (self.POLICY_PATH, valid_project + ' credential=example-not-a-secret'),
            (self.POLICY_PATH, self._line(project_path, 'a' * 64, 4)),
            (self.POLICY_PATH, '\n\n' + valid_project),
            (self.POLICY_PATH, valid_project + '\n'),
            (self.POLICY_PATH, '\n' + valid_project + '\n' + valid_project),
            (self.POLICY_PATH, ' ' + valid_project),
            (self.POLICY_PATH, self._line(project_path, project_hash, 5)),
            (self.RECEIPT_PATH, self._line(project_path, project_hash, 4)),
            (self.PLT44_RECEIPT_PATH, self._line(project_path, project_hash, 4)),
            (self.PLT44_RECEIPT_PATH, self._line(project_path, tests_hash, 6)),
            (self.PLT44_RECEIPT_PATH, self._line(tests_path, project_hash, 6)),
            (self.PLT44_RECEIPT_PATH, self._line(project_path, 'a' * 64, 6)),
            (self.PLT44_RECEIPT_PATH, self._line(project_path, project_hash, 6) + ' credential=example-not-a-secret'),
            ('eng/policy/dependency-reviews/plt-09-r1.json', self._line(project_path, project_hash, 4)),
            ('eng/policy/dependency-reviews/plt-09-r1.json', self._line(project_path, tests_hash, 6)),
            ('eng/policy/dependency-reviews/plt-09-r1.json', self._line(tests_path, project_hash, 6)),
            ('eng/policy/dependency-reviews/plt-09-r1.json', self._line(project_path, 'b' * 64, 6)),
            ('eng/policy/dependency-reviews/plt-09-r1.json', self._line(project_path, project_hash, 6) + ' credential=example-not-a-secret'),
            ('eng/policy/dependency-reviews/sub/plt-09-r1.json', self._line(project_path, project_hash, 6)),
            ('README.md', self._line(project_path, project_hash, 6)),
        )
        for path, line in candidates:
            with self.subTest(path=path, line=line):
                self.assertFalse(self._allowed(path, line))


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / POLICY).read_text())
        self.actual = closure(ROOT)

    def test_actual_candidate_passes_development_and_refuses_stable(self):
        self.assertEqual(audit()['result'], 'passed')
        with self.assertRaisesRegex(ValueError, 'Stable closure contains prerelease'):
            audit(stable=True)

    def test_reviewed_stable_fixture_passes_full_audit(self):
        # An isolated repository exercises the real audit, including receipt/input integrity.
        # It copies one admitted stable dependency, without restoring or downloading it.
        coordinate = next(key for key in sorted(self.actual) if '-' not in key.rsplit('/', 1)[1])
        package, version = coordinate.rsplit('/', 1)
        with tempfile.TemporaryDirectory(prefix='arcforges-stable-admission-') as directory:
            root = Path(directory)
            def git(*args):
                subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)
            git('init', '-b', 'main')
            for name in ['global.json', 'NuGet.config', 'eng/requirements-ci.txt']:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / name).read_bytes())
            (root / 'packages.lock.json').write_text(json.dumps({'version': 1, 'dependencies': {
                'net10.0': {package: {'type': 'Direct', 'requested': f'[{version}, {version}]',
                                    'resolved': version, 'contentHash': self.actual[coordinate]}}}}))
            policy = copy.deepcopy(self.policy)
            policy['nugetClosure'] = {coordinate: policy['nugetClosure'][coordinate]}
            policy['reviewReceipt'] = 'eng/policy/dependency-reviews/stable-fixture.json'
            policy['review']['previousReceipt'] = None
            policy['inputHashes'] = hashes(root)
            policy['review']['inputHashes'] = policy['inputHashes']
            receipt = root / policy['reviewReceipt']
            receipt.parent.mkdir(parents=True, exist_ok=True)
            receipt.write_text(json.dumps({key: policy[key] for key in ['review', 'nugetClosure', 'pythonClosure']}))
            (root / POLICY).write_text(json.dumps(policy))
            git('add', '.')
            git('-c', 'user.name=Admission fixture', '-c', 'user.email=fixture@example.invalid',
                'commit', '-m', 'Create isolated stable admission fixture')
            # A fixture repository cannot resolve the outer CI event's unrelated base SHA.
            with patch.dict(os.environ, {'GITHUB_EVENT_NAME': '', 'GITHUB_EVENT_PATH': '', 'GITHUB_REF': ''}):
                self.assertEqual(audit(root=root, stable=True)['result'], 'passed')

    def test_forbidden_licence(self):
        next(iter(self.policy['nugetClosure'].values()))['licence'] = 'GPL-3.0-only'
        with self.assertRaisesRegex(ValueError, 'Forbidden'):
            check_admission(self.policy, self.actual)

    def test_exact_foundation_acceptance_refuses_changed_boundary(self):
        key = 'arcforges.foundation/1.0.0-ci.29.1'
        check_admission(self.policy, self.actual)
        for field, value in [('licence', 'MIT'), ('source', 'https://example.invalid/source'),
                             ('internalPublisher', {'repository': 'someone/DesktopPlatform'})]:
            with self.subTest(field=field):
                policy = copy.deepcopy(self.policy)
                policy['nugetClosure'][key][field] = value
                with self.assertRaises(ValueError):
                    check_admission(policy, self.actual)
        for replacement in ['other.foundation/1.0.0-ci.29.1', 'arcforges.foundation/1.0.0-ci.30.1']:
            with self.subTest(coordinate=replacement):
                policy, actual = copy.deepcopy(self.policy), dict(self.actual)
                policy['nugetClosure'][replacement] = policy['nugetClosure'].pop(key)
                actual[replacement] = actual.pop(key)
                with self.assertRaises(ValueError):
                    check_admission(policy, actual)
        policy, actual = copy.deepcopy(self.policy), dict(self.actual)
        policy['nugetClosure'][key]['contentHash'] = actual[key] = 'changed-together'
        with self.assertRaises(ValueError):
            check_admission(policy, actual)
        for field in ['repository', 'workflow', 'sourceCommit', 'feed']:
            policy = copy.deepcopy(self.policy)
            policy['nugetClosure'][key]['internalPublisher'][field] = 'changed'
            with self.subTest(publisher_field=field), self.assertRaises(ValueError):
                check_admission(policy, self.actual)

    def test_mutable_admitted_version(self):
        self.actual[next(iter(self.actual))] = 'different-content'
        with self.assertRaisesRegex(ValueError, 'Mutable'):
            check_admission(self.policy, self.actual)

    def test_unknown_dependency(self):
        self.actual['unreviewed/1.0.0'] = 'digest'
        with self.assertRaisesRegex(ValueError, 'Unadmitted'):
            check_admission(self.policy, self.actual)

    def test_floating_versions(self):
        for value in ['latest', 'main', '1.*', '[1.0.0,)', '1.0.0-SNAPSHOT', 'git+https://example.test/repo#v1']:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'Floating'):
                exact(value)

    def test_source_tag_and_missing_upgrade_review(self):
        for field, value in [('baselineCommit', 'v1.0.0'), ('upgradeChecks', {}), ('inputHashes', {})]:
            policy = copy.deepcopy(self.policy)
            policy['review'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                check_admission(policy, self.actual)

    def test_wrong_publisher(self):
        self.policy['publisher']['repository'] = 'someone/DesktopPlatform'
        with self.assertRaisesRegex(ValueError, 'Wrong publisher'):
            check_admission(self.policy, self.actual)

    def test_python_licence_and_immutable_hashes(self):
        actual = python_closure(ROOT)
        row = next(iter(self.policy['pythonClosure'].values()))
        row['licence'] = 'GPL-3.0-only'
        with self.assertRaisesRegex(ValueError, 'Forbidden Python'):
            check_python(self.policy, actual)
        row['licence'] = 'MIT'
        row['hashes'] = ['0' * 64]
        with self.assertRaisesRegex(ValueError, 'Mutable Python'):
            check_python(self.policy, actual)

    def test_major_upgrade_requires_runtime_assessment(self):
        before = {'frameworkVersions': {'dotnetSdk': '10.0.400'}}
        after = {'frameworkVersions': {'dotnetSdk': '11.0.100'}}
        with self.assertRaisesRegex(ValueError, 'framework major'):
            framework_upgrade(before, after)
        after['frameworkMajorReview'] = {'changed': ['dotnetSdk'], 'owner': 'Architecture owner',
            'nativeAotTrim': 'fixture', 'nativeAbi': 'fixture', 'androidKotlinArtR8': 'fixture', 'localCoverage': 'not run: fixture'}
        framework_upgrade(before, after)

    def test_review_cannot_authorize_rewriting_an_existing_version(self):
        old = copy.deepcopy(self.policy)
        next(iter(self.policy['nugetClosure'].values()))['contentHash'] = 'new-reviewed-hash'
        with self.assertRaisesRegex(ValueError, 'Historical immutable'):
            check_history(self.policy, [old])

    def test_tag_ancestry_and_candidate_selection(self):
        env = {'GITHUB_REPOSITORY': 'ArcForges/DesktopPlatform', 'GITHUB_EVENT_NAME': 'push',
               'GITHUB_SHA': 'a' * 40, 'GITHUB_REF': 'refs/heads/main',
               'GITHUB_RUN_NUMBER': '22', 'GITHUB_RUN_ATTEMPT': '1'}
        seen = []
        self.assertEqual(selected(env, seen.append), '1.0.0-ci.22.1')
        self.assertEqual(seen, [])
        env['GITHUB_REF'] = 'refs/tags/v1.2.3'
        self.assertEqual(selected(env, seen.append), '1.2.3')
        self.assertEqual(seen, ['a' * 40])
        def unmerged(commit):
            raise ValueError('Tag is not on main')
        with self.assertRaisesRegex(ValueError, 'not on main'):
            selected(env, unmerged)
        for field, value in [('GITHUB_REF', 'refs/tags/v01.2.3'), ('GITHUB_REF', 'refs/tags/v1.2.3-rc.1'),
                             ('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_REPOSITORY', 'fork/DesktopPlatform')]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                selected({**env, field: value}, seen.append)

    def test_tag_is_peeled_and_matches_checked_source(self):
        seen = []
        def resolve(ref):
            self.assertEqual(ref, 'refs/tags/v1.2.3^{commit}')
            return 'a' * 40
        verified_tag('refs/tags/v1.2.3', 'a' * 40, resolve, seen.append)
        self.assertEqual(seen, ['a' * 40])
        with self.assertRaisesRegex(ValueError, 'tag target'):
            verified_tag('refs/tags/v1.2.3', 'b' * 40, resolve, seen.append)

    PUBLISHER = {'GITHUB_REPOSITORY': 'ArcForges/DesktopPlatform', 'GITHUB_EVENT_NAME': 'push',
                 'GITHUB_SHA': 'a' * 40, 'GITHUB_REF': 'refs/heads/main', 'GITHUB_RUN_ID': '9001',
                 'GITHUB_RUN_NUMBER': '24', 'GITHUB_RUN_ATTEMPT': '1'}

    @staticmethod
    def candidate(version, producer_attempt, run_id='9001'):
        return {'version': version, 'sourceCommit': 'a' * 40,
                'build': {'runId': run_id, 'runAttempt': str(producer_attempt)}}

    def test_publication_keeps_the_allocated_candidate_across_supported_retries(self):
        seen = []
        # Initial execution: preflight allocates in attempt 1 and the same attempt publishes it.
        env = dict(self.PUBLISHER)
        version = selected(env, seen.append)
        self.assertEqual(version, '1.0.0-ci.24.1')
        self.assertEqual(publication(env, version, self.candidate(version, 1), 'nuget-candidate-9001-1', seen.append),
                         ('1.0.0-ci.24.1', 1, 1))
        # Failed-jobs-only retry: preflight is not re-run, so attempt 2 publishes the retained allocation,
        # whether the producer artifact is retained from attempt 1 or packing was re-run in attempt 2.
        retry = {**env, 'GITHUB_RUN_ATTEMPT': '2'}
        self.assertEqual(publication(retry, version, self.candidate(version, 1), 'nuget-candidate-9001-1', seen.append),
                         ('1.0.0-ci.24.1', 1, 1))
        self.assertEqual(publication(retry, version, self.candidate(version, 2), 'nuget-candidate-9001-2', seen.append),
                         ('1.0.0-ci.24.1', 1, 2))
        # Re-running all jobs is an intentional new candidate: preflight allocates the new attempt suffix.
        rerun = {**env, 'GITHUB_RUN_ATTEMPT': '3'}
        fresh = selected(rerun, seen.append)
        self.assertEqual(fresh, '1.0.0-ci.24.3')
        self.assertEqual(publication(rerun, fresh, self.candidate(fresh, 3), 'nuget-candidate-9001-3', seen.append),
                         ('1.0.0-ci.24.3', 3, 3))
        # Stable tags select the tag version in every attempt.
        tag = {**retry, 'GITHUB_REF': 'refs/tags/v1.2.3'}
        self.assertEqual(publication(tag, '1.2.3', self.candidate('1.2.3', 1), 'nuget-candidate-9001-1', seen.append),
                         ('1.2.3', None, 1))
        self.assertEqual(seen, ['a' * 40])

    def test_publication_rejects_mismatched_candidate_identities(self):
        seen = []
        env = {**self.PUBLISHER, 'GITHUB_RUN_ATTEMPT': '2'}
        for expected in ('1.0.0-ci.23.1', '1.0.0-ci.24.3', '1.0.0-ci.24', '1.0.0-ci.24.0', '1.0.0-ci.024.1',
                         '1.0.0-ci.24.1.1', '1.0.0-ci.24.1-rc', '1.2.3', '', None):
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, 'does not match publisher identity'):
                authorized(env, expected, seen.append)
        with self.assertRaisesRegex(ValueError, 'does not match publisher identity'):
            authorized({**env, 'GITHUB_REF': 'refs/tags/v1.2.3'}, '1.2.4', seen.append)
        version, good = '1.0.0-ci.24.1', self.candidate('1.0.0-ci.24.1', 2)
        cases = [
            ('other version', dict(good, version='1.0.0-ci.24.2'), 'nuget-candidate-9001-2', 'version and source'),
            ('other source', dict(good, sourceCommit='b' * 40), 'nuget-candidate-9001-2', 'version and source'),
            ('other run', self.candidate(version, 2, run_id='9000'), 'nuget-candidate-9000-2', 'this workflow run'),
            ('no producer', dict(good, build={}), 'nuget-candidate-9001-2', 'this workflow run'),
            ('future producer', self.candidate(version, 3), 'nuget-candidate-9001-3', 'outside its allocation'),
            ('artifact of another attempt', good, 'nuget-candidate-9001-1', 'artifact name'),
            ('artifact of another run', good, 'nuget-candidate-9000-2', 'artifact name'),
            ('unbound latest artifact', good, 'nuget-candidate-latest', 'artifact name'),
        ]
        for label, manifest, artifact, message in cases:
            with self.subTest(label), self.assertRaisesRegex(ValueError, message):
                bound_candidate(env, version, 1, manifest, artifact)
        with self.assertRaisesRegex(ValueError, 'outside its allocation'):
            bound_candidate(env, '1.0.0-ci.24.2', 2, self.candidate('1.0.0-ci.24.2', 1), 'nuget-candidate-9001-1')


if __name__ == '__main__':
    unittest.main()
