# SPDX-License-Identifier: AGPL-3.0-only
"""WP00.05 read-only runtime/source audit; not product or deployment acceptance."""

from __future__ import annotations

import argparse
import base64
from datetime import date, datetime, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

import licence_boundary as inventory

ROOT = Path(__file__).resolve().parents[1]
POLICY = 'eng/policy/runtime-ownership.json'
RUNTIMES = {
    'DesktopPlatform': 'dotnet-nativeaot-libraries-and-native-cabi',
    'Contracts': 'proto-generated-clients',
    'ArcScope': 'avalonia-nativeaot',
    'Cloud': 'dotnet-nativeaot-cloudflare-container', 'AI': 'cloudflare-workflow-workers-ai',
    'Web': 'react-typescript-static', 'Mobile': 'kotlin-compose-android',
}
RETIRED = {'ArcChat': ('retired', 'DesktopPlatform'), 'ArcScope': ('extracted', 'ArcScope'),
           'Cloud': ('replaced', 'Cloud'), 'Mobile': ('replaced', 'Mobile'), 'Web': ('replaced', 'Web'),
           'Contracts': ('extracted', 'Contracts'), 'SDK': ('extracted', 'Contracts'),
           'Extensions': ('extracted', 'DesktopPlatform')}
TRUE = {'PublishAot', 'IsAotCompatible'}
HOSTS = {'DesktopPlatform': 'src/DesktopHelpers/ArcForges.ContentSandbox/ArcForges.ContentSandbox.csproj',
         'Cloud': 'src/ArcForges.Cloud/ArcForges.Cloud.csproj',
         **{name: f'src/ArcForges.{name}/ArcForges.{name}.csproj' for name in ('ArcScope',)}}


def require(value, message):
    if not value:
        raise ValueError(message)


def fields(value, names):
    require(isinstance(value, dict) and set(value) == set(names.split()), 'invalid schema fields')


def path(value):
    require(isinstance(value, str) and value and '\\' not in value and ':' not in value,
            'invalid policy path')
    p = PurePosixPath(value)
    require(not p.is_absolute() and '..' not in p.parts and value == p.as_posix(), 'unsafe policy path')
    return value


def digest(value, length=40):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(length) + '}', value), 'invalid digest')


def document(root, relative):
    return json.loads(inventory.read(root, path(relative)), object_pairs_hook=inventory.unique)


def role(owner, relative):
    if relative.endswith('.csproj'):
        if relative.startswith(('tests/', 'eng/')) or (relative.startswith('src/') and '/Tests/' in relative):
            return 'test-or-build-tool'
        require(relative.startswith('src/'), 'unassigned managed source project')
        if '/Build/' in relative or '.Runtime.' in relative:
            require(owner == 'DesktopPlatform', 'unassigned runtime package')
            return 'package-container'
        if owner == 'Cloud' or (owner in {'ArcScope'} and '.Core/' not in relative) or '/DesktopHelpers/' in relative:
            require(HOSTS.get(owner) == relative, 'unassigned runtime host')
            return 'aot-host'
        require(owner in {'DesktopPlatform', 'Contracts', 'ArcScope'}, 'unassigned managed runtime')
        return 'aot-library'
    if relative.endswith('.esproj'):
        require(owner == 'Web', 'unassigned JavaScript IDE project')
        return 'javascript-ide'
    if relative.endswith('.vcxproj') or relative.endswith('CMakeLists.txt'):
        require(owner == 'DesktopPlatform', 'native build outside its owner')
        return 'native-build'
    if relative.endswith('package.json'):
        require(owner in {'Contracts', 'Cloud', 'AI', 'Web'}, 'unassigned npm runtime')
        return 'typescript-build'
    if relative.endswith('build.gradle.kts'):
        require(owner in {'Contracts', 'Cloud', 'Mobile'}, 'unassigned Gradle runtime')
        return 'android-build' if owner == 'Mobile' else 'contract-or-test-build'
    raise ValueError('unassigned project kind: ' + relative)


def validate_policy(value):
    fields(value, 'schemaVersion reviewedOn design owners retiredScaffolds bootstrapBoundaries')
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1, 'invalid schema version')
    require(date.fromisoformat(value['reviewedOn']).isoformat() == value['reviewedOn'], 'invalid review date')
    fields(value['design'], 'commit path sha256')
    digest(value['design']['commit'])
    digest(value['design']['sha256'], 64)
    require(value['design']['path'] == 'docs/architecture/30-runtime-and-source-ownership-policy.md', 'wrong Design authority')
    require(isinstance(value['owners'], list), 'invalid owners')
    seen = set()
    for row in value['owners']:
        fields(row, 'repository runtime sourceCommit projects')
        owner = row['repository']
        require(owner in RUNTIMES and owner not in seen, 'unknown or duplicate owner')
        seen.add(owner)
        require(row['runtime'] == RUNTIMES[owner], 'runtime selection changed: ' + owner)
        digest(row['sourceCommit'])
        require(isinstance(row['projects'], list) and row['projects'], 'missing project ownership')
        projects = set()
        for project in row['projects']:
            fields(project, 'path role')
            relative = path(project['path'])
            require(relative not in projects, 'duplicate project')
            projects.add(relative)
            require(project['role'] == role(owner, relative), 'project role does not match owner')
    require(seen == set(RUNTIMES), 'missing repository owner')
    require(isinstance(value['bootstrapBoundaries'], dict) and set(value['bootstrapBoundaries']) == seen,
            'missing bootstrap boundary')
    require(all(isinstance(x, str) and x.strip() for x in value['bootstrapBoundaries'].values()), 'empty bootstrap boundary')
    require(isinstance(value['retiredScaffolds'], list), 'missing retired dispositions')
    seen = set()
    for row in value['retiredScaffolds']:
        fields(row, 'path observedRepository sourceCommit disposition owner reason')
        relative = path(row['path'])
        group = relative.removeprefix('src/')
        require(relative == 'src/' + group and group in RETIRED and group not in seen, 'invalid retired path')
        seen.add(group)
        require((row['disposition'], row['owner']) == RETIRED[group], 'retired owner/disposition changed')
        require(row['observedRepository'] == 'DesktopPlatform' and row['sourceCommit'] == '99bfe7d695ed0d65a0d035af7d219fc9b86100f5',
                'historical extraction identity changed')
        require(isinstance(row['reason'], str) and row['reason'].strip(), 'missing disposition reason')
    require(seen == set(RETIRED), 'missing historical disposition')


def managed_inputs(root, project, files):
    """Walk explicit local imports and nearest automatic directory build inputs.

    Conditions cannot make required AOT declarations optional. This intentionally
    rejects unsupported dynamic imports rather than claiming to evaluate MSBuild.
    """
    result = []
    visited = set()

    def visit(relative, conditional=False):
        identity = (relative, conditional)
        require(relative in files, 'unregistered build input: ' + relative)
        if identity in visited:
            return
        visited.add(identity)
        tree = ET.fromstring(inventory.read(root, relative))
        require(tree.tag == 'Project', 'unexpected MSBuild namespace/root')

        def walk(element, condition):
            condition = condition or bool(element.get('Condition')) or element.tag in {'Choose', 'When', 'Otherwise'}
            result.append((relative, element, condition))
            if element.tag == 'Import':
                target = element.get('Project', '')
                require(target and not any(c in target for c in '$@*?;'), 'dynamic import requires review: ' + relative)
                resolved = (root / PurePosixPath(relative).parent / target.replace('\\', '/')).resolve()
                require(resolved.is_relative_to(root.resolve()), 'build import escapes owner')
                visit(resolved.relative_to(root.resolve()).as_posix(), condition)
            for child in element:
                walk(child, condition)
        walk(tree, conditional)

    for name in ('Directory.Build.props', 'Directory.Build.targets'):
        parent = PurePosixPath(project).parent
        while True:
            candidate = (parent / name).as_posix()
            if candidate in files:
                visit(candidate)
                break
            if parent == PurePosixPath('.'):
                break
            parent = parent.parent
    visit(project)
    return result


def check_managed(root, project, selected_role, files):
    rows = managed_inputs(root, project, files)
    nested_test = project.startswith('src/') and '/Tests/' in project
    if nested_test:
        require(selected_role == 'test-or-build-tool', 'nested test project role mismatch')
        declarations = [(element, conditional) for _, element, conditional in rows if element.tag == 'IsTestProject']
        require(bool(declarations) and all((element.text or '').strip().lower() == 'true' and not conditional
                                         for element, conditional in declarations),
                'nested test project requires unconditional IsTestProject=true: ' + project)
    needed = {'PublishAot'} if selected_role == 'aot-host' else {'IsAotCompatible'} if selected_role == 'aot-library' else set()
    observed = set()
    framework = False
    for relative, element, conditional in rows:
        if selected_role in {'aot-host', 'aot-library'} and element.tag in {'TargetFramework', 'TargetFrameworks'}:
            require(element.tag == 'TargetFramework' and (element.text or '').strip() == 'net10.0' and not conditional,
                    'unregistered managed framework: ' + project)
            framework = True
        if selected_role == 'aot-host' and element.tag == 'IsAotCompatible':
            require((element.text or '').strip().lower() == 'true' and not conditional, 'host AOT compatibility override')
        if element.tag in needed:
            require((element.text or '').strip().lower() == 'true' and not conditional,
                    'required AOT property absent, false or conditional: ' + project + ': ' + element.tag)
            observed.add(element.tag)
        if selected_role == 'aot-library' and element.tag == 'OutputType':
            require((element.text or '').strip().lower() == 'library', 'unassigned executable: ' + project)
        if selected_role == 'javascript-ide':
            require(element.tag not in TRUE | {'TargetFramework', 'TargetFrameworks'}, 'IDE adapter inherited managed runtime')
    require(observed == needed, 'missing AOT declaration: ' + project)
    require(not needed or framework, 'missing managed framework: ' + project)
    return {'path': project, 'role': selected_role, 'requiredProperties': sorted(needed),
            'sourceInputs': sorted({x[0] for x in rows})}


def check_runtime_configuration(root, owner, files):
    for relative in files:
        p = PurePosixPath(relative)
        if p.suffix in {'.csproj', '.props', '.targets', '.esproj'}:
            tree = ET.fromstring(inventory.read(root, relative))
            require('BlazorWebAssembly' not in tree.get('Sdk', ''), 'retired browser runtime')
            for element in tree.iter():
                if element.tag in {'UseMaui', 'UseWPF', 'UseWindowsForms'}:
                    require((element.text or '').strip().lower() == 'false', 'retired UI runtime')
                if element.tag in {'PackageReference', 'PackageVersion'}:
                    name = (element.get('Include') or element.get('Update') or '').lower()
                    require(not name.startswith(('reactnative', 'electronnet', 'microsoft.aspnetcore.components.webassembly')),
                            'retired dependency: ' + name)
                    if owner == 'Cloud':
                        require(not name.startswith(('npgsql', 'microsoft.entityframeworkcore.sqlserver', 'mysql')),
                                'retired Cloud database provider: ' + name)
        elif p.name == 'package.json':
            package = document(root, relative)
            for section in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
                for name, version in package.get(section, {}).items():
                    names = [name]
                    if str(version).startswith('npm:'):
                        alias = str(version)[4:]
                        end = alias.find('@', 1)
                        names.append(alias if end < 0 else alias[:end])
                    for dependency in names:
                        require(not dependency.lower().startswith(('react-native', '@react-native/', 'hermes-engine', 'electron', 'ollama')),
                                'retired runtime dependency: ' + dependency)
        elif p.name in {'build.gradle.kts', 'build.gradle', 'settings.gradle.kts', 'settings.gradle'} and owner == 'Mobile':
            text = inventory.read(root, relative)
            text = re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)
            require(not re.search(r'\b(?:iosArm64|iosX64|iosSimulatorArm64|macosArm64|macosX64)\s*\(', text), 'unsupported Mobile product target')
            require('com.facebook.react' not in text and 'nativeDistributions' not in text, 'retired Mobile runtime/distribution')
    if owner in {'AI', 'Cloud', 'Web'}:
        config = document(root, 'wrangler.json')
        require(not config.get('env'), 'unregistered runtime environment override')
        if owner == 'AI':
            require(config.get('ai', {}).get('binding') == 'AI', 'missing direct Workers AI binding')
            workflows = config.get('workflows')
            require(isinstance(workflows, list) and len(workflows) == 1 and workflows[0] == {
                'name': 'arcforges-ai-hello', 'binding': 'HELLO_AGENT', 'class_name': 'HelloAgentWorkflow'},
                'missing or extra model-loop Workflow binding')
            require(config.get('main') == 'src/index.ts' and not config.get('containers'), 'incorrect AI host')
        else:
            require(not config.get('ai') and not config.get('workflows'), 'AI runtime outside its owner')
            if owner == 'Cloud':
                require(config.get('main') == 'worker/index.ts' and len(config.get('containers', [])) == 1,
                        'missing or extra Cloud host')
                require(config['containers'][0].get('class_name') == 'CloudContainer', 'incorrect Cloud Container owner')
            else:
                require(not config.get('main') and not config.get('containers') and config.get('assets', {}).get('directory') == './apps/site/build/client',
                        'Web must deploy its static browser candidate')
                require('react' in document(root, 'apps/site/package.json').get('dependencies', {}), 'missing React browser runtime')
    if owner == 'Mobile':
        app = inventory.read(root, 'app/build.gradle.kts')
        app = re.sub(r'/\*.*?\*/|//[^\n]*', ' ', app, flags=re.S)
        require(re.search(r'\bapplicationId\s*=\s*"io.github.arcforges.mobile"', app), 'prerelease identity changed before WP30')
        require('libs.plugins.compose.compiler' in app and re.search(r'\bcompose\s*=\s*true', app), 'missing Android Compose runtime')
        require('JavaVersion.VERSION_21' in app and 'JvmTarget.JVM_21' in app, 'Android compiler target changed')


def audit(root, row):
    owner = row['repository']
    files = inventory.inventory(root)
    before = {'commit': inventory.git(root, 'rev-parse', 'HEAD'), 'dirty': bool(inventory.git(root, 'status', '--porcelain'))}
    require(inventory.git(root, 'remote', 'get-url', 'origin').removesuffix('.git') == 'https://github.com/ArcForges/' + owner,
            'incorrect repository origin: ' + owner)
    declared = document(root, 'eng/provenance/files.json')
    require(declared.get('repository') == owner and len(declared['firstParty']) == len(set(declared['firstParty'])), 'invalid source owner')
    require(not set(declared['firstParty']) & set(declared['reused']), 'duplicate source assignment')
    require(set(files) == set(declared['firstParty']) | set(declared['reused']), 'unassigned or stale source inventory: ' + owner)
    licence = inventory.audit(root, owner)
    require({p['path'] for p in licence['projects']} == {p['path'] for p in row['projects']}, 'unassigned or stale project: ' + owner)
    if owner == 'DesktopPlatform':
        require(not any(p.startswith(tuple('src/' + x + '/' for x in RETIRED)) for p in files), 'retired scaffold restored')
    require(not any('/ArcNotes.Edgeless/' in '/' + p or '/ArcNotes.Slides/' in '/' + p for p in files), 'excluded Notes scaffold restored')
    managed = []
    for project in row['projects']:
        if project['path'].endswith(('.csproj', '.esproj')):
            managed.append(check_managed(root, project['path'], project['role'], set(files)))
    check_runtime_configuration(root, owner, files)
    require(before == {'commit': inventory.git(root, 'rev-parse', 'HEAD'), 'dirty': bool(inventory.git(root, 'status', '--porcelain'))}, 'source state changed during audit')
    return {'repository': owner, **before, 'files': len(files), 'projects': len(row['projects']),
            'runtime': row['runtime'], 'managedSourceChecks': managed, 'result': 'passed'}


def checkout(parent, owner, commit):
    target = parent / owner
    subprocess.run(['git', 'init', '-q', str(target)], check=True)
    subprocess.run(['git', '-C', str(target), 'remote', 'add', 'origin', 'https://github.com/ArcForges/' + owner + '.git'], check=True)
    for attempt in range(3):
        try:
            subprocess.run(['git', '-C', str(target), '-c', 'core.autocrlf=false', 'fetch', '--quiet', '--depth=1', 'origin', commit], check=True)
            break
        except subprocess.CalledProcessError:
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)
    subprocess.run(['git', '-C', str(target), '-c', 'core.autocrlf=false', 'checkout', '--quiet', '--detach', 'FETCH_HEAD'], check=True)
    require(inventory.git(target, 'rev-parse', 'HEAD') == commit, 'fetched snapshot identity mismatch')
    return target


def naming_package(pin, parent):
    fields(pin, 'package version contentHash sourceCommit')
    require(pin['package'] == 'ArcForges.Contracts.Validation', 'wrong canonical naming package')
    require(isinstance(pin['version'], str) and re.fullmatch(r'\d+\.\d+\.\d+(?:-ci\.\d+\.\d+)?', pin['version']),
            'naming package must have an exact version')
    digest(pin['sourceCommit'])
    try:
        expected = base64.b64decode(pin['contentHash'], validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError('invalid naming package content hash') from error
    require(len(expected) == 64, 'invalid naming package content hash')
    package, version = pin['package'].lower(), pin['version'].lower()
    url = f'https://api.nuget.org/v3-flatcontainer/{package}/{version}/{package}.{version}.nupkg'
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                body = response.read(32 * 1024 * 1024 + 1)
            break
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)
    require(len(body) <= 32 * 1024 * 1024 and hashlib.sha512(body).digest() == expected,
            'canonical naming package identity mismatch')
    # Consume only the canonical published build-time scanner and data. No sibling
    # source execution and no whole-archive extraction or second naming registry.
    selected = ('tools/naming/eng/check_naming.py', 'tools/naming/eng/policy/product-names.json')
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        for relative in selected:
            entries = [entry for entry in archive.infolist() if entry.filename == relative]
            require(len(entries) == 1 and not entries[0].is_dir() and entries[0].file_size <= 4 * 1024 * 1024,
                    'missing or ambiguous canonical naming asset')
            target = parent / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(entries[0]))
    return parent / selected[0]


def naming(roots, source):
    spec = importlib.util.spec_from_file_location('owned_naming', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    policy = module.load_policy()
    return [module.scan_repository(root, owner, policy) for owner, root in roots.items()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', action='append', help='Owner=absolute-root; supply all seven for fresh family audit')
    parser.add_argument('--design-root', type=Path)
    parser.add_argument('--evaluate-managed', action='store_true', help='evaluate only this DesktopPlatform checkout')
    parser.add_argument('--report', type=Path, default=ROOT / 'artifacts/evidence/runtime-ownership.json')
    args = parser.parse_args()
    result = {'substep': 'WP00.05', 'checkedAt': datetime.now(timezone.utc).isoformat(),
              'evidenceClass': 'source-runtime-and-ownership-policy', 'repositories': [],
              'limitations': 'No product, deployment, store or commercial completion inferred; evaluated builds and real candidates are separate evidence.'}
    try:
        value = document(ROOT, POLICY)
        validate_policy(value)
        result['policySha256'] = hashlib.sha256(inventory.read(ROOT, POLICY).encode()).hexdigest()
        with tempfile.TemporaryDirectory(prefix='arcforges-runtime-') as directory:
            temporary = Path(directory)
            design = args.design_root.resolve() if args.design_root else checkout(temporary, 'ArcForges-Design', value['design']['commit'])
            body = subprocess.check_output(['git', '-C', str(design), 'show', value['design']['commit'] + ':' + value['design']['path']])
            require(hashlib.sha256(body.replace(b'\r\n', b'\n')).hexdigest() == value['design']['sha256'], 'Design identity mismatch')
            roots = {}
            if args.repository:
                for entry in args.repository:
                    owner, separator, location = entry.partition('=')
                    require(separator and owner in RUNTIMES and owner not in roots and Path(location).is_absolute(), 'invalid selected root')
                    roots[owner] = Path(location).resolve()
                require(set(roots) == set(RUNTIMES), 'fresh audit requires all seven roots')
            else:
                roots = {row['repository']: ROOT if row['repository'] == 'DesktopPlatform' else checkout(temporary, row['repository'], row['sourceCommit']) for row in value['owners']}
            historical = value['retiredScaffolds'][0]['sourceCommit']
            tree = set(inventory.git(roots['DesktopPlatform'], 'ls-tree', '--name-only', historical, 'src/').splitlines())
            require({'src/' + group for group in RETIRED} <= tree, 'historical disposition source does not resolve')
            result['historicalDispositionSource'] = historical
            for row in value['owners']:
                result['repositories'].append(audit(roots[row['repository']], row))
            naming_pin = document(ROOT, 'eng/policy/naming-package.json')
            scanner = naming_package(naming_pin, temporary / 'naming-package')
            result['namingPackage'] = naming_pin
            result['naming'] = naming(roots, scanner)
            require(all(not row['findings'] for row in result['naming']), 'naming policy failed')
            if args.evaluate_managed:
                managed = []
                row = next(x for x in value['owners'] if x['repository'] == 'DesktopPlatform')
                for project in row['projects']:
                    if project['role'] not in {'aot-host', 'aot-library'}:
                        continue
                    for configuration in ('Debug', 'Release'):
                        prop = 'PublishAot' if project['role'] == 'aot-host' else 'IsAotCompatible'
                        output = subprocess.check_output(['dotnet', 'msbuild', project['path'], '-getProperty:' + prop, '-p:Configuration=' + configuration, '-verbosity:quiet'], cwd=ROOT, text=True).strip()
                        require(output.lower() == 'true', 'evaluated runtime mismatch: ' + project['path'])
                        managed.append({'path': project['path'], 'configuration': configuration, prop: output})
                result['evaluatedManaged'] = managed
        result['result'] = 'passed'
        code = 0
    except (ValueError, OSError, KeyError, TypeError, ET.ParseError, subprocess.CalledProcessError) as error:
        result.update(result='failed', error=str(error))
        code = 1
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'result': result['result'], 'repositories': len(result['repositories']), 'error': result.get('error')}))
    return code


if __name__ == '__main__':
    sys.exit(main())
