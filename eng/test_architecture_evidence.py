# SPDX-License-Identifier: AGPL-3.0-only
"""Offline identity/refusal tests; no network and no local secret-scan substitute."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import architecture_evidence as evidence


class ArchitectureEvidence(unittest.TestCase):
    def setUp(self):
        self.ctx = {'sourceCommit': 'a' * 40, 'runId': '123', 'runAttempt': '2', 'hosted': True}
        self.naming = evidence.receipt(self.ctx, 'runtime-policy',
                                      [evidence.row(rule, self.ctx['sourceCommit'], True) for rule in ('RP-01', 'RP-08')])
        self.secret = evidence.secret_receipt(self.ctx, 'success', 'secret-scan')

    def test_exact_same_source_gates_pass(self):
        result = evidence.combine(self.ctx, self.naming, self.secret)
        self.assertEqual([r['rule'] for r in result['evidence']], ['RP-01', 'RP-08', 'RP-09'])
        self.assertTrue(all(r['passed'] for r in result['evidence']))

    def test_missing_gate_never_passes_hosted(self):
        with self.assertRaisesRegex(ValueError, 'missing'):
            evidence.combine(self.ctx, self.naming)

    def test_local_missing_secret_remains_unverified(self):
        ctx = {**self.ctx, 'hosted': False, 'runId': None, 'runAttempt': None}
        naming = {**self.naming, **ctx}
        result = evidence.combine(ctx, naming)
        self.assertFalse(result['evidence'][-1]['passed'])
        self.assertTrue(result['evidence'][-1]['findings'])
        with self.assertRaises(ValueError):
            evidence.combine(ctx, naming, {**self.secret, **ctx})

    def test_other_source_run_attempt_and_producer_are_refused(self):
        for key, value in [('sourceCommit', 'b' * 40), ('runId', '124'), ('runAttempt', '3'),
                           ('hosted', False), ('producer', 'other'), ('schemaVersion', 2)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                evidence.combine(self.ctx, self.naming, {**self.secret, key: value})

    def test_failed_cancelled_skipped_and_local_scan_are_not_evidence(self):
        for outcome in ['failure', 'cancelled', 'skipped', '', None]:
            with self.subTest(outcome=outcome), self.assertRaises(ValueError):
                evidence.secret_receipt(self.ctx, outcome, 'secret-scan')
        for ctx, job in [({**self.ctx, 'hosted': False}, 'secret-scan'), (self.ctx, 'other')]:
            with self.assertRaises(ValueError):
                evidence.secret_receipt(ctx, 'success', job)

    def test_claimed_pass_with_findings_or_wrong_row_source_is_rejected(self):
        for key, value in [('passed', False), ('passed', 1), ('sourceCommit', 'b' * 40),
                           ('findings', [{'rule': 'RP-09', 'path': 'x', 'message': 'failure', 'line': 1}])]:
            secret = copy.deepcopy(self.secret)
            secret['evidence'][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                evidence.combine(self.ctx, self.naming, secret)

    def test_missing_duplicate_extra_rules_are_rejected(self):
        for rows in [[], self.naming['evidence'] * 2, list(reversed(self.naming['evidence'])),
                     self.naming['evidence'] + self.secret['evidence']]:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                evidence.combine(self.ctx, {**self.naming, 'evidence': rows}, self.secret)

    def test_real_context_requires_checkout_and_clean_source(self):
        env = {'GITHUB_ACTIONS': 'true', 'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2'}
        with patch.object(evidence, 'git', side_effect=['a' * 40, '']):
            self.assertEqual(evidence.context(env=env), self.ctx)
        for sha, dirty in [('b' * 40, ''), ('a' * 40, ' M source.cs')]:
            with patch.object(evidence, 'git', side_effect=[sha, dirty]), self.assertRaises(ValueError):
                evidence.context(env=env)
        with patch.object(evidence, 'git', side_effect=['a' * 40, '']), self.assertRaises(ValueError):
            evidence.context(env={**env, 'GITHUB_RUN_ATTEMPT': ''})

    def test_naming_receipt_checks_pin_source_and_real_fixture_result(self):
        runtime = {'result': 'passed', 'namingPackage': {'version': 'exact'},
                   'repositories': [{'repository': 'DesktopPlatform', 'commit': 'a' * 40, 'dirty': False}],
                   'naming': [{'repository': 'DesktopPlatform', 'commit': 'a' * 40, 'dirty': False,
                               'status': 'pass', 'findings': []}], 'namingAssets': {}}
        with patch.object(evidence, 'load_scanner'), patch.object(evidence, 'naming_fixtures', return_value={'positive': 1, 'negative': 8}):
            result = evidence.naming_receipt(self.ctx, runtime, {'version': 'exact'}, Path('.'), 'runtime-policy')
            self.assertEqual(result['fixtures']['negative'], 8)
            for section, field, value in [('repositories', 'commit', 'b' * 40), ('naming', 'dirty', True),
                                           ('naming', 'findings', ['bad']), ('naming', 'status', 'fail')]:
                modified = copy.deepcopy(runtime)
                modified[section][0][field] = value
                with self.subTest(section=section, field=field), self.assertRaises(ValueError):
                    evidence.naming_receipt(self.ctx, modified, {'version': 'exact'}, Path('.'), 'runtime-policy')
            with self.assertRaises(ValueError):
                evidence.naming_receipt(self.ctx, runtime, {'version': 'different'}, Path('.'), 'runtime-policy')

    def test_changed_canonical_assets_fail_before_execution(self):
        paths = ['tools/naming/eng/check_naming.py', 'tools/naming/eng/policy/product-names.json']
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for path in paths:
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b'synthetic')
            with self.assertRaisesRegex(ValueError, 'changed'):
                evidence.load_scanner(root, dict.fromkeys(paths, '0' * 64))
            with self.assertRaisesRegex(ValueError, 'Incomplete'):
                evidence.load_scanner(root, {})

    def test_duplicate_json_evidence_keys_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'receipt.json'
            path.write_text('{"passed":false,"passed":true}')
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                evidence.read(path)


if __name__ == '__main__':
    unittest.main()
