# SPDX-License-Identifier: AGPL-3.0-only
"""Independent failing inventories and actual build-system declaration tests."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import licence_boundary as policy


class LicenceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='arcforges-licence-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.run_tool('git', 'init', '-q')
        self.run_tool('git', '-c', 'user.name=Policy Test', '-c', 'user.email=policy@example.invalid',
                      '-c', 'commit.gpgsign=false', 'commit', '--allow-empty', '-qm', 'fixture')

    def run_tool(self, *args, success=True):
        result = subprocess.run(args, cwd=self.root, capture_output=True, text=True, encoding='utf-8')
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text if isinstance(text, str) else json.dumps(text), encoding='utf-8')

    def project(self, name='app.csproj', spdx='Apache-2.0', boundary='Apache', extra=''):
        self.write(name, f'<Project><PropertyGroup><PackageLicenseExpression>{spdx}</PackageLicenseExpression>'
                        f'<LicenceBoundary>{boundary}</LicenceBoundary></PropertyGroup>{extra}</Project>')

    def register(self, owner='Contracts', projects=None):
        spdx, boundary = policy.OWNERS[owner]
        self.write(policy.POLICY, {'schemaVersion': 1, 'repository': owner,
                   'spdxLicense': spdx, 'licenceBoundary': boundary,
                   'projects': projects or [{'path': 'app.csproj', 'kind': 'msbuild'}]})

    def test_complete_inventory_then_new_project_rejected(self):
        self.register()
        self.project()
        self.assertEqual(policy.audit(self.root, 'Contracts')['result'], 'passed')
        self.project('new.csproj')
        with self.assertRaisesRegex(ValueError, 'inventory drift'):
            policy.audit(self.root, 'Contracts')

    def test_missing_inconsistent_and_overridden_metadata(self):
        self.register()
        for boundary, spdx in [('', 'Apache-2.0'), ('Apache', 'AGPL-3.0-only'), ('AGPL', 'Apache-2.0')]:
            self.project(boundary=boundary, spdx=spdx)
            with self.assertRaisesRegex(ValueError, 'incorrect licence'):
                policy.audit(self.root, 'Contracts')
        self.project()
        self.write('Directory.Build.props', '<Project><PropertyGroup><LicenceBoundary>AGPL</LicenceBoundary></PropertyGroup></Project>')
        with self.assertRaisesRegex(ValueError, 'property override'):
            policy.audit(self.root, 'Contracts')

    def test_owner_assignment_cannot_be_changed_in_policy(self):
        self.register('DesktopPlatform')
        self.project(spdx='AGPL-3.0-only', boundary='AGPL')
        with self.assertRaisesRegex(ValueError, 'Design assignment'):
            policy.audit(self.root, 'Contracts')

    def test_escaped_project_reference(self):
        self.register()
        self.project(extra='<ItemGroup><ProjectReference Include="../outside.csproj" /></ItemGroup>')
        with self.assertRaisesRegex(ValueError, 'escapes repository'):
            policy.audit(self.root, 'Contracts')

    def test_transitive_apache_to_agpl_and_unknown_node(self):
        with self.assertRaisesRegex(ValueError, 'Apache-to-AGPL'):
            policy.check_graph({'a': 'Apache', 'b': 'Apache', 'c': 'AGPL'}, {'a': ['b'], 'b': ['c']})
        with self.assertRaisesRegex(ValueError, 'unregistered reference'):
            policy.check_graph({'a': 'Apache'}, {'a': ['absent']})

    def test_locked_transitive_first_party_owner(self):
        self.register()
        self.project()
        for name, error in [('ArcForges.Native.Media', 'Apache-to-AGPL'), ('ArcForges.Unknown', 'unknown first-party')]:
            self.write('packages.lock.json', {'dependencies': {'net10.0': {name: {'type': 'Transitive'}}}})
            with self.assertRaisesRegex(ValueError, error):
                policy.audit(self.root, 'Contracts')

    def test_npm_alias_without_version_is_a_real_dependency(self):
        self.register(projects=[{'path': 'package.json', 'kind': 'npm'}])
        self.write('package.json', {'name': '@arcforges/proto', 'license': 'Apache-2.0',
                   'arcforges': {'licenceBoundary': 'Apache'}, 'dependencies': {'alias': 'npm:@arcforges/ai'}})
        with self.assertRaisesRegex(ValueError, 'Apache-to-AGPL'):
            policy.audit(self.root, 'Contracts')

    def test_gradle_declaration(self):
        self.register('Mobile', [{'path': 'build.gradle.kts', 'kind': 'gradle'}])
        self.write('build.gradle.kts', 'extra["spdxLicense"] = "Apache-2.0"\nextra["licenceBoundary"] = "Apache"\n')
        self.assertEqual(policy.audit(self.root, 'Mobile')['result'], 'passed')
        self.write('build.gradle.kts', 'extra["spdxLicense"] = "Apache-2.0"\n')
        with self.assertRaisesRegex(ValueError, 'missing/duplicate'):
            policy.audit(self.root, 'Mobile')

    def test_actual_msbuild_rejects_effective_global_override(self):
        targets = (policy.ROOT / 'Directory.Build.targets').as_posix()
        self.project(spdx='AGPL-3.0-only', boundary='AGPL', extra=f'<Import Project="{targets}" />')
        self.run_tool('dotnet', 'msbuild', 'app.csproj', '-t:ArcForgesVerifyLicenceBoundary', '-v:q')
        output = self.run_tool('dotnet', 'msbuild', 'app.csproj', '-t:ArcForgesVerifyLicenceBoundary',
                               '-p:LicenceBoundary=Apache', '-v:q', success=False)
        self.assertIn('AFL001', output)

    def test_actual_cmake_rejects_missing_or_overridden_target(self):
        module = (policy.ROOT / 'eng/cmake/LicenceBoundary.cmake').as_posix()
        source = f'''cmake_minimum_required(VERSION 4.3.3)
project(LicenceFixture LANGUAGES NONE)
set(ARCFORGES_SPDX_LICENSE "AGPL-3.0-only")
set(ARCFORGES_LICENCE_BOUNDARY "AGPL")
include("{module}")
add_custom_target(owned)
arcforges_declare_target_licence(owned)
cmake_language(DEFER CALL arcforges_verify_native_licences)
'''
        self.write('CMakeLists.txt', source)
        self.run_tool('cmake', '-S', '.', '-B', 'valid')
        report = json.loads((self.root / 'valid/licence-boundary.json').read_text())
        self.assertEqual(report['targets'][0]['licenceBoundary'], 'AGPL')
        for directory, addition in [('missing', 'add_custom_target(unregistered)'),
                                    ('override', 'set_property(TARGET owned PROPERTY ARCFORGES_LICENCE_BOUNDARY Apache)')]:
            self.write('CMakeLists.txt', source + addition + '\n')
            self.assertIn('AFL001', self.run_tool('cmake', '-S', '.', '-B', directory, success=False))

    def test_real_root_does_not_exempt_owned_targets_before_ctest(self):
        source = (policy.ROOT / 'CMakeLists.txt').read_text(encoding='utf-8')
        source = source.replace('LANGUAGES C CXX', 'LANGUAGES NONE')
        source = source.replace('include(eng/cmake/LicenceBoundary.cmake)',
                                f'include("{(policy.ROOT / "eng/cmake/LicenceBoundary.cmake").as_posix()}")')
        source = source.replace('add_subdirectory(native)',
                                'add_custom_target(registered)\narcforges_declare_target_licence(registered)')
        source = source.replace('option(ARCFORGES_BUILD_TESTS',
                                'add_custom_target(early_unregistered)\noption(ARCFORGES_BUILD_TESTS')
        self.write('CMakeLists.txt', source)
        self.write('toolchain.cmake', '# Empty toolchain for a LANGUAGES NONE policy fixture.\n')
        for enabled in ('ON', 'OFF'):
            output = self.run_tool('cmake', '-S', '.', '-B', 'ctest-' + enabled,
                '-DARCFORGES_NATIVE_PROFILE=shim-static', '-DVCPKG_TARGET_TRIPLET=fixture',
                '-DCMAKE_TOOLCHAIN_FILE=' + str(self.root / 'toolchain.cmake'),
                '-DARCFORGES_BUILD_TESTS=' + enabled, success=False)
            self.assertIn('AFL001: missing or incorrect native target licence: early_unregistered', output)


if __name__ == '__main__':
    unittest.main()
