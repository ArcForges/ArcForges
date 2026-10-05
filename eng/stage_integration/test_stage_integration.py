# SPDX-License-Identifier: AGPL-3.0-only
"""Offline tests for the cross-repository integration graph: positive world, one negative per rule."""
import copy
import io
import json
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import stage_integration as si

POLICY = si.load_policy()
TODAY = '2026-10-05'
ORDER = POLICY['repositories']
BOUNDARY = POLICY['licenceBoundaries']


def j(value):
    return json.dumps(value).encode()


def nuget_lock(entries, projects=()):
    deps = {}
    for name, version, kind, children in entries:
        deps[name] = {'type': kind, 'resolved': version, 'dependencies': {c: '1.0.0' for c in children}}
    for name in projects:
        deps[name] = {'type': 'Project', 'dependencies': {}}
    return j({'version': 2, 'dependencies': {'net10.0': deps}})


WORKFLOW = """name: CI
on:
  pull_request:
  push:
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - name: Run the gate
        run: |
          GATE_COMMAND
"""


def workflow(command, extra=''):
    return (WORKFLOW.replace('GATE_COMMAND', command) + extra).encode()


def base_files(repository):
    """Smallest valid published-metadata set for a repository."""
    files = {'eng/policy/licence-boundary.json': j({
        'repository': repository, 'spdxLicense': 'x', 'licenceBoundary': BOUNDARY[repository],
        'projects': [{'path': f'src/{repository}.Core/{repository}.Core.csproj', 'kind': 'msbuild'}]})}
    for gate in POLICY['gates'][repository]:
        files.setdefault(gate['workflow'], b'')
    by_workflow = {}
    for gate in POLICY['gates'][repository]:
        by_workflow.setdefault(gate['workflow'], []).append(' && '.join(gate['runContains']))
    for path, commands in by_workflow.items():
        files[path] = workflow('\n          '.join(commands))
    for marker in POLICY['markers'][repository]:
        text = marker.get('contains') or 'x'
        files[marker['path']] = j({'scripts': {'check': text}}) if marker['path'].endswith('.json') else text.encode()
    return files


def world_files():
    files = {name: base_files(name) for name in ORDER}
    files['DesktopPlatform']['eng/packaging/packages.json'] = j({'packages': [
        {'id': 'ArcForges.Build.Policy', 'kind': 'build'},
        {'id': 'ArcForges.Foundation', 'kind': 'managed', 'dependencies': []},
        {'id': 'ArcForges.Native.Image', 'kind': 'managed', 'dependencies': ['ArcForges.Foundation']},
        {'id': 'ArcForges.Native.Image.Runtime.win-x64', 'kind': 'native', 'dependencies': ['ArcForges.Native.Image']},
        {'id': 'ArcForges.Capabilities', 'kind': 'managed', 'dependencies': ['ArcForges.Foundation']},
    ]})
    files['Contracts']['eng/contract-packages.json'] = j({'packages': [
        {'id': 'ArcForges.Contracts.Foundation', 'kind': 'nuget', 'access': 'public', 'dependencies': []},
        {'id': 'ArcForges.Contracts.PublicApi', 'kind': 'nuget', 'access': 'public',
         'dependencies': ['ArcForges.Contracts.Foundation']},
        {'id': 'ArcForges.Contracts.CloudInternal', 'kind': 'nuget', 'access': 'internal',
         'dependencies': ['ArcForges.Contracts.PublicApi']},
        {'id': '@arcforges/proto', 'kind': 'npm', 'access': 'public', 'dependencies': []},
        {'id': 'io.github.arcforges:contracts-proto', 'kind': 'maven', 'access': 'public', 'dependencies': []},
    ]})
    files['ArcScope']['src/ArcScope/packages.lock.json'] = nuget_lock([
        ('ArcForges.Native.Image', '1.0.0', 'Direct', ['ArcForges.Foundation']),
        ('ArcForges.Contracts.PublicApi', '1.0.0', 'Direct', ['ArcForges.Contracts.Foundation']),
        ('ArcForges.Foundation', '1.0.0', 'Transitive', [])])
    files['Cloud']['src/Cloud/packages.lock.json'] = nuget_lock([
        ('ArcForges.Contracts.CloudInternal', '1.0.0', 'Direct', ['ArcForges.Contracts.PublicApi']),
        ('ArcForges.Build.Policy', '1.0.0', 'Direct', [])], projects=['cloud.core'])
    files['Contracts']['tests/ArchitectureTests/packages.lock.json'] = nuget_lock([
        ('ArcForges.Build.Policy', '1.0.0', 'Direct', [])])
    files['Contracts']['eng/policy/exceptions.json'] = j([
        {'rule': 'RP-03', 'path': 'tests/ArchitectureTests/Host.csproj', 'owner': 'Contracts', 'expires': '2027-04-04'}])
    files['Web']['package.json'] = j({'name': '@arcforges/web', 'scripts': {'check': 'npm run policy'},
                                         'dependencies': {'@arcforges/proto': '1.0.0'}})
    files['Web']['package-lock.json'] = j({'packages': {
        '': {}, 'node_modules/@arcforges/proto': {'version': '1.0.0'}}})
    files['Mobile']['app/gradle.lockfile'] = (
        b'# lock\nio.github.arcforges:contracts-proto:1.0.0=releaseRuntimeClasspath\n'
        b'org.jetbrains.kotlin:kotlin-stdlib:2.0.0=releaseRuntimeClasspath\n')
    files['AI']['wrangler.json'] = j({'name': 'ai', 'workflows': [{'name': 'a', 'class_name': 'RunWorkflow'}]})
    files['Cloud']['wrangler.json'] = j({'name': 'cloud', 'durable_objects': {'bindings': [{'class_name': 'CloudContainer'}]}})
    return files


class FakeProvider:
    def __init__(self, files, commits=None):
        self.files = files
        self.calls = []
        self.commits = commits or {}

    def tree(self, repository, commit):
        self.calls.append(('tree', repository, commit))
        return sorted(self.files[repository])

    def read(self, repository, commit, path):
        self.calls.append(('read', repository, path))
        return self.files[repository][path]

    def head(self, repository, ref='main'):
        return self.commits[repository]


def snapshot_of(files, policy=POLICY):
    return {'schemaVersion': 1, 'policySha256': si.digest(policy), 'repositories': {
        name: {'commit': 'a' * 40,
               'sources': [{'path': 'x', 'sha256': 'b' * 64}],
               'facts': si.extract_facts(name, files[name], policy)} for name in ORDER}}


def run(files, today=TODAY):
    return si.evaluate(snapshot_of(files), POLICY, today)


def rules(findings):
    return sorted({row['rule'] for row in findings})


def messages(findings, rule):
    return [row['message'] for row in findings if row['rule'] == rule]


class PositiveWorld(unittest.TestCase):
    def test_a_conforming_world_has_zero_findings(self):
        self.assertEqual(run(world_files()), [])

    def test_the_one_declared_apache_to_agpl_exception_is_accepted_only_while_valid(self):
        files = world_files()
        files['Contracts']['eng/policy/exceptions.json'] = j([
            {'rule': 'RP-03', 'path': 'tests/ArchitectureTests/Host.csproj', 'owner': 'Contracts', 'expires': '2026-10-01'}])
        found = run(files)
        self.assertEqual(rules(found), ['SI-05', 'SI-11'])

    def test_reach_reports_the_path_and_locks(self):
        world = si.World(snapshot_of(world_files()), POLICY)
        reached = world.reach('Cloud')
        key = ('nuget', 'arcforges.contracts.foundation')
        self.assertEqual(si.show(reached[key]['path']),
                         'arcforges.contracts.cloudinternal -> arcforges.contracts.publicapi -> arcforges.contracts.foundation')


class NegativeFixtures(unittest.TestCase):
    def test_si01_unregistered_and_duplicate_producers(self):
        files = world_files()
        files['Cloud']['src/Cloud/packages.lock.json'] = nuget_lock([('ArcForges.Mystery', '1.0.0', 'Direct', [])])
        self.assertIn('SI-01', rules(run(files)))
        files = world_files()
        files['Contracts']['eng/contract-packages.json'] = j({'packages': [
            {'id': 'ArcForges.Foundation', 'kind': 'nuget', 'access': 'public', 'dependencies': []}]})
        self.assertIn('SI-01', rules(run(files)))

    def test_si02_project_reference_to_another_repository(self):
        files = world_files()
        files['ArcScope']['src/ArcScope/packages.lock.json'] = nuget_lock([], projects=['arcforges.foundation'])
        self.assertEqual(rules(run(files)), ['SI-02'])

    def test_si02_submodule_link_and_include_build(self):
        for path, content in [('.gitmodules', b'[submodule "x"]'),
                              ('settings.gradle.kts', b'includeBuild("../Contracts")'),
                              ('package.json', j({'name': 'w', 'dependencies': {'@arcforges/proto': 'file:../../Contracts/p'}})),
                              ('package.json', j({'name': 'w', 'dependencies': {'x': 'github:ArcForges/Contracts'}})),
                              ('package-lock.json', j({'packages': {'node_modules/@arcforges/proto': {'link': True, 'resolved': '../Contracts/p'}}}))]:
            with self.subTest(path=path, content=content):
                files = world_files()
                files['Web'][path] = content
                self.assertIn('SI-02', rules(run(files)))

    def test_si02_inside_repository_file_link_is_accepted(self):
        files = world_files()
        files['Web']['apps/app/package.json'] = j({'name': 'a', 'dependencies': {'@arcforges/web-ui': 'file:../../packages/ui'}})
        self.assertEqual(run(files), [])

    def test_si03_internal_package_outside_its_audience(self):
        files = world_files()
        files['Web']['package-lock.json'] = j({'packages': {'node_modules/@arcforges/operator-client': {'version': '1'}}})
        files['Web']['package.json'] = j({'name': 'w', 'dependencies': {'@arcforges/operator-client': '1'}})
        files['Contracts']['eng/contract-packages.json'] = j({'packages': [
            {'id': '@arcforges/operator-client', 'kind': 'npm', 'access': 'internal', 'dependencies': []}]})
        self.assertIn('SI-03', rules(run(files)))

    def test_si04_transitive_edge_through_published_producer_metadata(self):
        files = world_files()
        files['Contracts']['eng/contract-packages.json'] = j({'packages': [
            {'id': 'ArcForges.Contracts.Foundation', 'kind': 'nuget', 'access': 'public', 'dependencies': []},
            {'id': 'ArcForges.Contracts.PublicApi', 'kind': 'nuget', 'access': 'public',
             'dependencies': ['ArcForges.Contracts.Foundation']},
            {'id': 'ArcForges.Contracts.CloudInternal', 'kind': 'nuget', 'access': 'internal',
             'dependencies': ['ArcForges.Contracts.PublicApi', 'ArcForges.Capabilities']}]})
        found = run(files)
        self.assertIn('SI-04', rules(found))
        self.assertIn('arcforges.contracts.cloudinternal -> arcforges.capabilities', ' '.join(messages(found, 'SI-04')))

    def test_si04_transitive_edge_recorded_only_in_a_lock(self):
        files = world_files()
        files['Cloud']['src/Cloud/packages.lock.json'] = nuget_lock([
            ('ArcForges.Contracts.CloudInternal', '1.0.0', 'Direct', ['ArcForges.Contracts.PublicApi', 'ArcForges.Capabilities']),
            ('ArcForges.Capabilities', '1.0.0', 'Transitive', [])])
        self.assertIn('SI-04', rules(run(files)))

    def test_si05_agpl_package_in_an_apache_repository(self):
        files = world_files()
        files['Contracts']['src/Product/packages.lock.json'] = nuget_lock([('ArcForges.Foundation', '1', 'Direct', [])])
        self.assertIn('SI-05', rules(run(files)))

    def test_si05_exception_for_another_project_does_not_cover(self):
        files = world_files()
        files['Contracts']['eng/policy/exceptions.json'] = j([
            {'rule': 'RP-03', 'path': 'tests/Other/Other.csproj', 'owner': 'Contracts', 'expires': '2027-04-04'}])
        self.assertIn('SI-05', rules(run(files)))

    def test_si06_cloud_reaches_a_desktop_native_package(self):
        files = world_files()
        files['Cloud']['src/Cloud/packages.lock.json'] = nuget_lock([
            ('ArcForges.Contracts.CloudInternal', '1.0.0', 'Direct', ['ArcForges.Native.Image.Runtime.win-x64'])])
        found = run(files)
        self.assertIn('SI-06', rules(found))
        self.assertIn('SI-04', rules(found))

    def test_si06_foreign_ui_package_in_cloud(self):
        files = world_files()
        files['Cloud']['src/Cloud/packages.lock.json'] = nuget_lock([('Avalonia', '11.0.0', 'Direct', [])])
        self.assertEqual(rules(run(files)), ['SI-06'])

    def test_si07_mobile_imports_an_agpl_implementation(self):
        files = world_files()
        files['Mobile']['app/gradle.lockfile'] += b'io.github.arcforges:desktop-bridge:1=releaseRuntimeClasspath\n'
        files['DesktopPlatform']['eng/packaging/packages.json'] = j({'packages': [
            {'id': 'io.github.arcforges:desktop-bridge', 'kind': 'managed', 'dependencies': []}]})
        snapshot = snapshot_of(files)
        snapshot['repositories']['DesktopPlatform']['facts']['produces'][0]['ecosystem'] = 'maven'
        found = si.evaluate(snapshot, POLICY, TODAY)
        self.assertIn('SI-07', rules(found))

    def test_si07_mobile_unregistered_arcforges_coordinate(self):
        files = world_files()
        files['Mobile']['app/gradle.lockfile'] += b'io.github.arcforges:ghost:1=releaseRuntimeClasspath\n'
        self.assertIn('SI-07', rules(run(files)))

    def test_si08_second_harness_owner_and_missing_owner(self):
        files = world_files()
        files['Cloud']['wrangler.json'] = j({'name': 'cloud', 'workflows': [{'class_name': 'W'}]})
        self.assertEqual(rules(run(files)), ['SI-08'])
        files = world_files()
        files['Web']['wrangler.json'] = j({'name': 'web-harness'})
        self.assertEqual(rules(run(files)), ['SI-08'])
        files = world_files()
        files['AI']['wrangler.json'] = j({'name': 'ai'})
        self.assertEqual(rules(run(files)), ['SI-08'])

    def test_si09_gate_wiring_failures(self):
        for label, mutate in {
            'missing step': lambda f: f.__setitem__('.github/workflows/ci.yml', workflow('echo nothing')),
            'not pull request': lambda f: f.__setitem__(
                '.github/workflows/ci.yml',
                f['.github/workflows/ci.yml'].replace(b'  pull_request:\n', b'')),
            'continue on error': lambda f: f.__setitem__(
                '.github/workflows/ci.yml',
                f['.github/workflows/ci.yml'].replace(b'      - name: Run the gate\n',
                                                      b'      - name: Run the gate\n        continue-on-error: true\n')),
            'suppressed': lambda f: f.__setitem__(
                '.github/workflows/ci.yml', f['.github/workflows/ci.yml'].replace(b'spotlessCheck', b'spotlessCheck || true')),
            'conditional': lambda f: f.__setitem__(
                '.github/workflows/ci.yml',
                f['.github/workflows/ci.yml'].replace(b'      - name: Run the gate\n',
                                                      b"      - name: Run the gate\n        if: github.event_name == 'push'\n")),
            'missing marker': lambda f: f.pop('build.gradle.kts'),
        }.items():
            with self.subTest(label):
                files = world_files()
                mutate(files['Mobile'])
                self.assertEqual(rules(run(files)), ['SI-09'])

    def test_si09_a_called_reusable_workflow_counts_as_pull_request_reachable(self):
        files = world_files()
        pr = (b'name: PR\non:\n  pull_request:\njobs:\n  call:\n    uses: ./.github/workflows/reusable.yml\n')
        reusable = files['Mobile']['.github/workflows/ci.yml'].replace(b'  pull_request:\n  push:\n', b'  workflow_call:\n')
        files['Mobile']['.github/workflows/ci.yml'] = b''
        files['Mobile']['.github/workflows/reusable.yml'] = reusable
        files['Mobile']['.github/workflows/pr.yml'] = pr
        found = run(files)
        self.assertEqual(rules(found), ['SI-09'])  # the declared workflow path no longer holds the gate
        policy = copy.deepcopy(POLICY)
        policy['gates']['Mobile'][0]['workflow'] = '.github/workflows/reusable.yml'
        snap = snapshot_of(files, policy)
        self.assertEqual(si.evaluate(snap, policy, TODAY), [])
        files['Mobile']['.github/workflows/pr.yml'] = b'name: PR\non:\n  push:\njobs:\n  call:\n    uses: ./.github/workflows/reusable.yml\n'
        snap = snapshot_of(files, policy)
        self.assertEqual(rules(si.evaluate(snap, policy, TODAY)), ['SI-09'])

    def test_si10_snapshot_integrity(self):
        snapshot = snapshot_of(world_files())
        for label, mutate in {
            'policy drift': lambda s: s.__setitem__('policySha256', '0' * 64),
            'short commit': lambda s: s['repositories']['Web'].__setitem__('commit', 'abc'),
            'missing repository': lambda s: s['repositories'].pop('Web'),
            'no digests': lambda s: s['repositories']['Web'].__setitem__('sources', []),
            'wrong boundary': lambda s: s['repositories']['Web']['facts'].__setitem__('boundary', 'Apache'),
        }.items():
            with self.subTest(label):
                broken = copy.deepcopy(snapshot)
                mutate(broken)
                try:
                    found = si.evaluate(broken, POLICY, TODAY)
                except KeyError:
                    continue
                self.assertIn('SI-10', rules(found))

    def test_si11_exception_data(self):
        for row in [{'rule': 'RP-03', 'path': 'p', 'owner': 'Other', 'expires': '2027-01-01'},
                    {'rule': 'RP-03', 'path': 'p', 'owner': 'Web', 'expires': '2020-01-01'},
                    {'rule': 'RP-03', 'path': 'p', 'owner': 'Web'}]:
            with self.subTest(row=row):
                files = world_files()
                files['Web']['eng/policy/exceptions.json'] = j({'exceptions': [row]})
                self.assertEqual(rules(run(files)), ['SI-11'])


class Extraction(unittest.TestCase):
    def test_workflow_parser_reads_triggers_jobs_steps_and_calls(self):
        text = ("name: x\non: [push, pull_request]\njobs:\n  a:\n    if: github.ref == 'x'\n    steps:\n"
                "      - run: one\n      - name: two\n        continue-on-error: true\n        run: >-\n          a\n          b\n"
                "  b:\n    uses: ./.github/workflows/y.yml\n")
        workflow = si.parse_workflow(text)
        self.assertEqual(workflow['triggers'], ['pull_request', 'push'])
        self.assertEqual(workflow['calls'], ['.github/workflows/y.yml'])
        self.assertEqual(workflow['jobs'][0]['if'], "github.ref == 'x'")
        self.assertEqual([s['run'] for s in workflow['jobs'][0]['steps']], ['one', 'a\nb'])
        self.assertEqual(workflow['jobs'][0]['steps'][1]['continueOnError'], 'true')

    def test_npm_gradle_and_nuget_inputs(self):
        files = world_files()
        facts = si.extract_facts('Web', {**files['Web'], 'app/gradle.lockfile': b'io.github.arcforges:a:1=x,y\n'}, POLICY)
        relations = {(row['ecosystem'], row['id']): row['relation'] for row in facts['consumes']}
        self.assertEqual(relations[('npm', '@arcforges/proto')], 'Direct')
        self.assertEqual(relations[('maven', 'io.github.arcforges:a')], 'Direct')

    def test_duplicate_json_keys_are_refused(self):
        with self.assertRaises(si.PolicyError):
            si.read_json('{"a": 1, "a": 2}')

    def test_only_published_metadata_is_selected_and_nothing_is_cloned(self):
        files = world_files()
        files['Web']['src/secret.ts'] = b'source'
        files['Web']['node_modules/x/package.json'] = b'{}'
        provider = FakeProvider(files)
        collected = si.collect_repository(provider, 'Web', 'c' * 40, POLICY)
        read = {path for kind, repo, path in provider.calls if kind == 'read'}
        self.assertNotIn('src/secret.ts', read)
        self.assertNotIn('node_modules/x/package.json', read)
        self.assertEqual(sum(1 for call in provider.calls if call[0] == 'tree'), 1)
        self.assertEqual([item['path'] for item in collected['sources']], sorted(read))

    def test_snapshot_building_is_deterministic(self):
        files = world_files()
        commits = {name: 'd' * 40 for name in ORDER}
        first = si.build_snapshot(FakeProvider(files), commits, POLICY)
        second = si.build_snapshot(FakeProvider(files), commits, POLICY)
        self.assertEqual(si.dump(first), si.dump(second))
        self.assertEqual(si.evaluate(first, POLICY, TODAY), [])


class Transport(unittest.TestCase):
    def test_bounded_retry_then_refusal(self):
        class Opener:
            calls = 0

            def open(self, request, timeout):
                Opener.calls += 1
                raise urllib.error.URLError('down')
        provider = si.GitHubProvider(attempts=3, opener=Opener(), sleep=lambda _: None)
        with self.assertRaises(si.PolicyError):
            provider._get('https://example.invalid/x')
        self.assertEqual(Opener.calls, 3)

    def test_client_errors_are_not_retried(self):
        class Opener:
            calls = 0

            def open(self, request, timeout):
                Opener.calls += 1
                raise urllib.error.HTTPError('u', 404, 'nf', {}, None)
        provider = si.GitHubProvider(attempts=3, opener=Opener(), sleep=lambda _: None)
        with self.assertRaises(si.PolicyError):
            provider._get('https://example.invalid/x')
        self.assertEqual(Opener.calls, 1)


class CommittedSnapshot(unittest.TestCase):
    def test_committed_snapshot_has_zero_findings_and_every_repository(self):
        snapshot = si.read_json(si.SNAPSHOT_PATH.read_text(encoding='utf-8'))
        self.assertEqual(set(snapshot['repositories']), set(ORDER))
        self.assertEqual(si.evaluate(snapshot, POLICY, TODAY), [])

    def test_committed_snapshot_detects_an_injected_forbidden_edge(self):
        snapshot = si.read_json(si.SNAPSHOT_PATH.read_text(encoding='utf-8'))
        facts = snapshot['repositories']['Cloud']['facts']
        facts['consumes'].append({'ecosystem': 'nuget', 'id': 'ArcForges.Native.Image', 'version': '1',
                                  'relation': 'Direct', 'locks': ['src/ArcForges.Cloud']})
        found = si.evaluate(snapshot, POLICY, TODAY)
        self.assertTrue({'SI-03', 'SI-06'} <= set(rules(found)))

    def test_cli_exit_codes_and_report(self):
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            self.assertEqual(si.main(['--as-of', TODAY, 'verify']), 0)
        tmp = Path(self.id() + '.json')
        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(si.main(['--as-of', '2999-01-01', 'verify', '--report', str(tmp)]), 1)
            report = json.loads(tmp.read_text(encoding='utf-8'))
            self.assertGreater(report['findingCount'], 0)
            self.assertEqual([r['id'] for r in report['rules']], list(si.RULES))
        finally:
            tmp.unlink(missing_ok=True)


if __name__ == '__main__':
    unittest.main()
