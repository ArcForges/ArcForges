# SPDX-License-Identifier: AGPL-3.0-only
"""Independent corruption and real Git-tree fixtures for planning inputs."""
import copy
import json
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import reference_baselines as r


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.registry = r.read(r.ROOT / r.POLICY)
        self.metadata = r.read(r.ROOT / r.META)

    def test_current_closed_registration(self):
        r.validate(self.registry, self.metadata)
        self.assertEqual(self.registry['metadata']['sha256'], r.sha(r.normalized((r.ROOT / r.META).read_bytes())))

    def test_missing_duplicate_and_misassigned_matrix(self):
        for mutation in ['missing', 'duplicate', 'owner', 'rows', 'source']:
            with self.subTest(mutation=mutation):
                data = copy.deepcopy(self.registry)
                if mutation == 'missing': data['matrices'].pop()
                elif mutation == 'duplicate': data['matrices'][1] = data['matrices'][0]
                elif mutation == 'owner': data['matrices'][0]['owner'] = 'Cloud'
                elif mutation == 'rows': data['matrices'][0]['rows'] = 29
                else: data['matrices'][0]['sources'] = ['s2']
                with self.assertRaises(ValueError): r.validate(data, self.metadata)

    def test_invalid_metadata_and_identity(self):
        mutations = [lambda d: d['sources'].pop('s6'),
                     lambda d: d['sources']['s1'].update(commit='HEAD'),
                     lambda d: d['sources']['s1'].update(abbreviation='0000000'),
                     lambda d: d['sources']['s1'].update(repository='https://example.com/wrong'),
                     lambda d: d['matrices']['assistant'].update(sha256='0'),
                     lambda d: d['matrices']['assistant'].update(path='../escape.md'),
                     lambda d: d['design'].update(repository='somewhere/else'),
                     lambda d: d.update(extra=True)]
        for mutation in mutations:
            data = copy.deepcopy(self.metadata); mutation(data)
            with self.assertRaises(ValueError): r.validate(self.registry, data)

    def test_packaged_schema_rejects_missing_version_and_binary_notice(self):
        for mutation in [lambda p: p['versions'].clear(),
                         lambda p: p['observation']['notices'].update({'AionUi/AionUi.exe': '0'*64}),
                         lambda p: p['observation']['directories']['AFFiNE'].pop('affine-0.27.2-stable-windows-x64.nsis.exe')]:
            data = copy.deepcopy(self.metadata); mutation(data['packaged'])
            with self.assertRaises(ValueError): r.validate(self.registry, data)

    def test_windows_reparse_entries_are_rejected_before_read(self):
        with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_file_attributes=1024)):
            with self.assertRaisesRegex(ValueError, 'linked observation'):
                r.no_link(Path('junction'))

    def test_duplicate_json_key(self):
        with self.assertRaises(ValueError): json.loads('{"id":1,"id":2}', object_pairs_hook=r.unique)

    def test_altered_metadata_fails_before_network(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for path in (r.META, r.POLICY):
                target = root / path; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((r.ROOT / path).read_bytes())
            data = copy.deepcopy(self.metadata); data['review']['rationale'] = 'Changed'
            (root/r.META).write_text(json.dumps(data), encoding='utf-8')
            with patch.object(r, 'remote_snapshot', side_effect=AssertionError('must not fetch')):
                with self.assertRaisesRegex(ValueError, 'metadata digest mismatch'): r.verify(root, {})

    def test_retired_references_are_not_resolved(self):
        from contextlib import contextmanager
        requested=[]
        @contextmanager
        def snapshot(repository, revision):
            requested.append(repository)
            yield r.ROOT
        with patch.object(r,'remote_snapshot',snapshot), patch.object(r,'origin'), \
             patch.object(r,'state',return_value={}), patch.object(r,'commit',side_effect=lambda root, revision: revision), \
             patch.object(r,'matrix_check'):
            result=r.verify(r.ROOT,{})
        expected={self.metadata['design']['repository'],self.metadata['sources']['s1']['repository'],
                  self.metadata['sources']['s4']['repository']}
        self.assertEqual(set(requested),expected)
        self.assertEqual(result['gitReferences'],2)
        self.assertEqual(result['matrices'],3)

    def test_packaged_observation_reads_notices_only(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); product = root/'product'; product.mkdir()
            notice = product/'LICENSE'; notice.write_text('notice', encoding='utf-8')
            binary = product/'app.exe'; binary.write_bytes(b'not to be read')
            packaged = {'observation': {'notices': {'product/LICENSE': 'unused'}}}
            original = Path.read_bytes
            def read(path):
                self.assertEqual(path.name, 'LICENSE')
                return original(path)
            with patch.object(Path, 'read_bytes', read): baseline = r.observe(root, packaged)
            notice.write_text('different notice', encoding='utf-8')
            self.assertNotEqual(baseline, r.observe(root, packaged))
            notice.write_text('notice', encoding='utf-8'); (product/'new.exe').touch()
            self.assertNotEqual(baseline, r.observe(root, packaged))
            (product/'new.exe').unlink(); binary.unlink()
            self.assertNotEqual(baseline, r.observe(root, packaged))
            notice.unlink()
            with self.assertRaises(OSError): r.observe(root, packaged)


class GitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        r.git(self.root, 'init', '--quiet')
        r.git(self.root, 'config', 'user.name', 'Fixture')
        r.git(self.root, 'config', 'user.email', 'fixture@example.invalid')
        r.git(self.root, 'config', 'core.autocrlf', 'false')
        r.git(self.root, 'remote', 'add', 'origin', 'https://github.com/fixture/reference.git')
        (self.root/'keep').write_text('old')
        (self.root/'remove').write_text('remove')
        self.save()
        self.baseline = r.commit(self.root, 'HEAD')
        self.source = {'repository':'fixture/reference', 'commit':self.baseline}

    def save(self):
        r.git(self.root, 'add', '.')
        r.git(self.root, 'commit', '--quiet', '-m', 'fixture')

    def test_real_git_add_modify_remove_and_dirty_separation(self):
        (self.root/'keep').write_text('new')
        (self.root/'remove').unlink()
        (self.root/'add').write_text('added')
        self.save()
        (self.root/'local-only').write_text('untracked')
        report = r.drift(self.root,self.source,'HEAD')
        self.assertEqual([(x['path'],x['kind']) for x in report['changes']],
                         [('add','added'),('keep','modified'),('remove','removed')])
        self.assertTrue(report['workingTree']['dirty'])
        self.assertEqual(report['assessment'],'required')
        self.assertEqual(report['baseline'],self.baseline)
        self.assertFalse(report['contentsRead'])

    def test_no_change_dry_run(self):
        report = r.drift(self.root,self.source,'HEAD')
        self.assertEqual(report['changes'],[])
        self.assertEqual(report['assessment'],'no-source-delta')

    def test_wrong_origin_missing_and_non_commit(self):
        with self.assertRaises(ValueError): r.origin(self.root,'wrong/repository')
        with self.assertRaises(subprocess.CalledProcessError): r.commit(self.root,'0'*40)
        blob = r.textgit(self.root,'rev-parse','HEAD:keep')
        with self.assertRaises(subprocess.CalledProcessError): r.commit(self.root,blob)
        with self.assertRaises(ValueError): r.commit(self.root,'--help')

    def test_matrix_hash_and_row_rejection_at_committed_identity(self):
        r.git(self.root,'remote','set-url','origin','https://github.com/ArcForges/ArcForges-Design.git')
        path = 'docs/assurance/reference-coverage/fixture.md'
        target=self.root/path; target.parent.mkdir(parents=True)
        data='<a id="rule-ac-01"></a>\n`1234567` github.com/fixture/reference\n'
        target.write_text(data,encoding='utf-8',newline='\n'); self.save()
        metadata={'design':{'repository':'ArcForges/ArcForges-Design','commit':r.commit(self.root,'HEAD')},
                  'matrices':{'assistant':{'path':path,'sha256':r.sha(data.encode())}},
                  'sources':{'s1':{'repository':'fixture/reference','abbreviation':'1234567'}}}
        registry={'matrices':[{'id':'assistant','prefix':'ac','rows':1,'sources':['s1']}]}
        r.matrix_check(self.root,metadata,registry)
        target.write_text('local edits must not affect committed evidence')
        r.matrix_check(self.root,metadata,registry)
        metadata['matrices']['assistant']['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'digest mismatch'): r.matrix_check(self.root,metadata,registry)
        metadata['matrices']['assistant']['sha256']=r.sha(data.encode())
        registry['matrices'][0]['rows']=2
        with self.assertRaisesRegex(ValueError,'row set mismatch'): r.matrix_check(self.root,metadata,registry)


if __name__ == '__main__':
    unittest.main()
