# SPDX-License-Identifier: AGPL-3.0-only
"""Independent invalid runtime/ownership fixtures; no provider or model calls."""

import copy
import base64
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import runtime_ownership as policy


class RuntimeOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='arcforges-runtime-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.files = set()

    def write(self, path, value):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value if isinstance(value, str) else json.dumps(value), encoding='utf-8')
        self.files.add(path)

    def check(self, owner):
        policy.check_runtime_configuration(self.root, owner, self.files)

    def test_registry_rejects_missing_duplicate_and_extra_owner(self):
        original = policy.document(policy.ROOT, policy.POLICY)
        policy.validate_policy(original)
        for mutation in ('missing', 'duplicate', 'unknown', 'runtime', 'role', 'digest', 'field', 'retired'):
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(original)
                if mutation == 'missing': value['owners'].pop()
                if mutation == 'duplicate': value['owners'].append(value['owners'][0])
                if mutation == 'unknown': value['owners'][0]['repository'] = 'ArcChat'
                if mutation == 'runtime': value['owners'][0]['runtime'] = 'managed-jit'
                if mutation == 'role': value['owners'][0]['projects'][0]['role'] = 'test-or-build-tool'
                if mutation == 'digest': value['design']['commit'] = 'main'
                if mutation == 'field': value['allowEverything'] = True
                if mutation == 'retired': value['retiredScaffolds'].pop()
                with self.assertRaises(ValueError): policy.validate_policy(value)

    def test_published_naming_assets_are_exact_and_never_extract_other_entries(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('tools/naming/eng/check_naming.py', '# canonical fixture')
            archive.writestr('tools/naming/eng/policy/product-names.json', '{}')
            archive.writestr('../outside.py', 'unselected')
        body = stream.getvalue()
        pin = dict(package='ArcForges.Contracts.Validation', version='1.0.0-ci.123.1',
                   contentHash=base64.b64encode(hashlib.sha512(body).digest()).decode(), sourceCommit='a' * 40)
        with patch.object(policy.urllib.request, 'urlopen', return_value=io.BytesIO(body)) as download:
            scanner = policy.naming_package(pin, self.root)
        self.assertEqual(scanner.read_text(), '# canonical fixture')
        self.assertEqual(sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob('*') if p.is_file()),
                         ['tools/naming/eng/check_naming.py', 'tools/naming/eng/policy/product-names.json'])
        self.assertEqual(download.call_args.args[0], 'https://api.nuget.org/v3-flatcontainer/arcforges.contracts.validation/1.0.0-ci.123.1/arcforges.contracts.validation.1.0.0-ci.123.1.nupkg')
        with patch.object(policy.urllib.request, 'urlopen', return_value=io.BytesIO(body + b'changed')):
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                policy.naming_package(pin, self.root)
        for key, value in [('package', 'Other.Package'), ('version', 'latest'), ('contentHash', 'bad')]:
            with self.subTest(key=key), self.assertRaises(ValueError), patch.object(policy.urllib.request, 'urlopen') as download:
                policy.naming_package(dict(pin, **{key: value}), self.root)
            download.assert_not_called()

    def test_published_naming_asset_missing_after_verified_download_fails(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('tools/naming/eng/check_naming.py', '# missing canonical policy')
        body = stream.getvalue()
        pin = dict(package='ArcForges.Contracts.Validation', version='1.0.0',
                   contentHash=base64.b64encode(hashlib.sha512(body).digest()).decode(), sourceCommit='a' * 40)
        with patch.object(policy.urllib.request, 'urlopen', return_value=io.BytesIO(body)):
            with self.assertRaisesRegex(ValueError, 'canonical naming asset'):
                policy.naming_package(pin, self.root)

    def test_unsafe_policy_paths_and_ambiguous_json(self):
        for path in ('../outside', '/absolute', 'C:/absolute', 'src\\app', 'a/../b', './src'):
            with self.subTest(path=path), self.assertRaises(ValueError): policy.path(path)
        self.write('duplicate.json', '{"owner":1,"owner":2}')
        with self.assertRaises(ValueError): policy.document(self.root, 'duplicate.json')

    def test_complete_aot_host_then_false_missing_and_conditional_values(self):
        project = 'src/Host/Host.csproj'
        for properties, passes in [('<PublishAot>true</PublishAot>', True), ('', False),
                                   ('<PublishAot>false</PublishAot>', False),
                                   ('<PublishAot Condition="false">true</PublishAot>', False),
                                   ('<PublishAot>true</PublishAot><IsAotCompatible>false</IsAotCompatible>', False)]:
            self.write(project, '<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework>' + properties + '</PropertyGroup></Project>')
            if passes: policy.check_managed(self.root, project, 'aot-host', self.files)
            else:
                with self.assertRaises(ValueError): policy.check_managed(self.root, project, 'aot-host', self.files)

    def test_false_override_in_automatic_targets_is_not_hidden_by_true_project(self):
        self.write('src/Host.csproj', '<Project><PropertyGroup><PublishAot>true</PublishAot></PropertyGroup></Project>')
        self.write('Directory.Build.targets', '<Project><PropertyGroup Condition="false"><PublishAot>false</PublishAot></PropertyGroup></Project>')
        with self.assertRaisesRegex(ValueError, 'AOT property'):
            policy.check_managed(self.root, 'src/Host.csproj', 'aot-host', self.files)

    def test_imports_are_followed_and_cannot_escape_or_be_conditional(self):
        self.write('aot.props', '<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework><PublishAot>true</PublishAot></PropertyGroup></Project>')
        self.write('src/Host.csproj', '<Project><Import Project="../aot.props" /></Project>')
        policy.check_managed(self.root, 'src/Host.csproj', 'aot-host', self.files)
        for imported in ('../../outside.props', '$(External)/aot.props', 'missing.props'):
            self.write('src/Host.csproj', '<Project><Import Project="' + imported + '" /></Project>')
            with self.assertRaises(ValueError): policy.check_managed(self.root, 'src/Host.csproj', 'aot-host', self.files)
        self.write('src/Host.csproj', '<Project><Import Project="../aot.props" Condition="false" /></Project>')
        with self.assertRaises(ValueError): policy.check_managed(self.root, 'src/Host.csproj', 'aot-host', self.files)

    def test_library_cannot_become_unassigned_executable(self):
        self.write('Library.csproj', '<Project><PropertyGroup><IsAotCompatible>true</IsAotCompatible><OutputType>Exe</OutputType></PropertyGroup></Project>')
        with self.assertRaisesRegex(ValueError, 'unassigned executable'):
            policy.check_managed(self.root, 'Library.csproj', 'aot-library', self.files)
        with self.assertRaisesRegex(ValueError, 'unassigned runtime host'):
            policy.role('Cloud', 'src/AnotherHost/AnotherHost.csproj')

    def test_nested_test_role_requires_explicit_unconditional_test_identity(self):
        project = 'src/BuildingBlocks/ArcForges.Foundation/Tests/ArcForges.Foundation.Tests.csproj'
        self.assertEqual(policy.role('DesktopPlatform', project), 'test-or-build-tool')
        for declaration, passes in [('<IsTestProject>true</IsTestProject>', True), ('', False),
                                    ('<IsTestProject>false</IsTestProject>', False),
                                    ('<IsTestProject Condition="false">true</IsTestProject>', False)]:
            self.write(project, '<Project><PropertyGroup><OutputType>Exe</OutputType>' + declaration + '</PropertyGroup></Project>')
            if passes:
                policy.check_managed(self.root, project, 'test-or-build-tool', self.files)
            else:
                with self.assertRaisesRegex(ValueError, 'IsTestProject'):
                    policy.check_managed(self.root, project, 'test-or-build-tool', self.files)
        self.assertEqual(policy.role('DesktopPlatform', 'src/BuildingBlocks/ArcForges.Foundation/Foundation.csproj'), 'aot-library')

    def test_javascript_ide_never_inherits_managed_runtime(self):
        self.write('Web.esproj', '<Project><PropertyGroup><PublishAot>true</PublishAot></PropertyGroup></Project>')
        with self.assertRaisesRegex(ValueError, 'IDE adapter'):
            policy.check_managed(self.root, 'Web.esproj', 'javascript-ide', self.files)

    def test_old_ui_and_database_manifests_fail(self):
        for xml, owner in [('<Project Sdk="Microsoft.NET.Sdk.BlazorWebAssembly"/>', 'Web'),
                           ('<Project><PropertyGroup><UseMaui>true</UseMaui></PropertyGroup></Project>', 'ArcNotes'),
                           ('<Project><ItemGroup><PackageReference Include="Npgsql"/></ItemGroup></Project>', 'Cloud')]:
            self.write('app.csproj', xml)
            with self.assertRaisesRegex(ValueError, 'retired'): self.check(owner)

    def test_obsolete_npm_dependencies_include_aliases(self):
        for name, version in [('react-native', '1.0.0'), ('alias', 'npm:react-native@1.0.0'),
                              ('alias', 'npm:@react-native/runtime'), ('hermes-engine', '1.0.0'), ('electron', '1.0.0')]:
            self.write('package.json', {'dependencies': {name: version}})
            with self.assertRaisesRegex(ValueError, 'retired runtime'): self.check('AI')

    def workflow(self):
        return {'main': 'src/index.ts', 'ai': {'binding': 'AI'}, 'workflows': [
            {'name': 'arcforges-ai-hello', 'binding': 'HELLO_AGENT', 'class_name': 'HelloAgentWorkflow'}]}

    def test_exact_workflow_binding_and_direct_ai_are_required(self):
        self.write('wrangler.json', self.workflow())
        self.check('AI')
        for mutation in ('missing', 'second', 'binding', 'ai', 'container', 'environment'):
            value = self.workflow()
            if mutation == 'missing': value['workflows'] = []
            if mutation == 'second': value['workflows'].append(dict(value['workflows'][0]))
            if mutation == 'binding': value['workflows'][0]['binding'] = 'OTHER'
            if mutation == 'ai': del value['ai']
            if mutation == 'container': value['containers'] = [{}]
            if mutation == 'environment': value['env'] = {'production': {'workflows': [{}]}}
            self.write('wrangler.json', value)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.check('AI')

    def test_cloud_cannot_acquire_an_ai_loop_or_second_host(self):
        base = {'main': 'worker/index.ts', 'containers': [{'class_name': 'CloudContainer'}]}
        self.write('wrangler.json', base)
        self.check('Cloud')
        for value in ({**base, 'ai': {'binding': 'AI'}}, {**base, 'workflows': [{}]},
                      {**base, 'containers': []}, {**base, 'containers': [{}, {}]}):
            self.write('wrangler.json', value)
            with self.assertRaises(ValueError): self.check('Cloud')

    def test_web_requires_react_static_assets_not_runtime_server(self):
        self.write('apps/site/package.json', {'dependencies': {'react': '19.3.0'}})
        self.write('wrangler.json', {'assets': {'directory': './apps/site/build/client'}})
        self.check('Web')
        self.write('wrangler.json', {'assets': {'directory': './apps/site/build/client'}, 'main': 'server.js'})
        with self.assertRaises(ValueError): self.check('Web')

    def test_mobile_retired_targets_and_false_comment_declarations(self):
        for text in ('kotlin { iosArm64() }', 'plugins { id("com.facebook.react") }', 'nativeDistributions {}'):
            self.write('build.gradle.kts', text)
            with self.assertRaises(ValueError): self.check('Mobile')
        self.write('build.gradle.kts', '// no extra target\n')
        self.write('app/build.gradle.kts', '// applicationId = "io.github.arcforges.mobile"\n// compose = true\n')
        with self.assertRaisesRegex(ValueError, 'identity'): self.check('Mobile')

    def fixture(self):
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        subprocess.run(['git', '-C', str(self.root), 'remote', 'add', 'origin', 'https://github.com/ArcForges/DesktopPlatform.git'], check=True)
        subprocess.run(['git', '-C', str(self.root), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        '-c', 'commit.gpgsign=false', 'commit', '--allow-empty', '-qm', 'fixture'], check=True)
        project = 'src/BuildingBlocks/Library/Library.csproj'
        self.write(project, '<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework><IsAotCompatible>true</IsAotCompatible><PackageLicenseExpression>AGPL-3.0-only</PackageLicenseExpression><LicenceBoundary>AGPL</LicenceBoundary></PropertyGroup></Project>')
        self.write('eng/policy/licence-boundary.json', {'schemaVersion': 1, 'repository': 'DesktopPlatform',
                   'spdxLicense': 'AGPL-3.0-only', 'licenceBoundary': 'AGPL', 'projects': [{'path': project, 'kind': 'msbuild'}]})
        self.register()
        return {'repository': 'DesktopPlatform', 'runtime': policy.RUNTIMES['DesktopPlatform'],
                'projects': [{'path': project, 'role': 'aot-library'}]}

    def register(self):
        self.files.add('eng/provenance/files.json')
        self.write('eng/provenance/files.json', {'schemaVersion': 1, 'repository': 'DesktopPlatform',
                   'firstParty': sorted(self.files), 'reused': {}, 'artifacts': []})

    def test_real_git_inventory_rejects_new_unassigned_source(self):
        row = self.fixture()
        self.assertEqual(policy.audit(self.root, row)['result'], 'passed')
        self.write('src/BuildingBlocks/Library/Unexpected.cs', 'class Unexpected {}')
        with self.assertRaisesRegex(ValueError, 'unassigned'): policy.audit(self.root, row)

    def test_aot_flag_does_not_allow_old_or_missing_framework(self):
        for framework in ('', '<TargetFramework>net8.0</TargetFramework>', '<TargetFrameworks>net10.0;net8.0</TargetFrameworks>'):
            self.write('Host.csproj', '<Project><PropertyGroup><PublishAot>true</PublishAot>' + framework + '</PropertyGroup></Project>')
            with self.assertRaisesRegex(ValueError, 'framework'):
                policy.check_managed(self.root, 'Host.csproj', 'aot-host', self.files)

    def test_retired_path_fails_even_if_inventory_claims_ownership(self):
        row = self.fixture()
        self.write('src/ArcChat/Program.cs', 'class Program {}')
        self.register()
        with self.assertRaisesRegex(ValueError, 'retired scaffold'): policy.audit(self.root, row)

    def test_new_project_fails_even_if_provenance_is_registered(self):
        row = self.fixture()
        self.write('src/BuildingBlocks/Other/Other.csproj', '<Project/>')
        self.register()
        with self.assertRaises(ValueError): policy.audit(self.root, row)

    def test_missing_tracked_file_is_never_omitted(self):
        row = self.fixture()
        subprocess.run(['git', '-C', str(self.root), 'add', '.'], check=True)
        (self.root / row['projects'][0]['path']).unlink()
        with self.assertRaises(ValueError): policy.audit(self.root, row)


if __name__ == '__main__':
    unittest.main()
