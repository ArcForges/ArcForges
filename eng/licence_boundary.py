# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only first-party project inventory/reference audit for WP00.02.

Owner builds separately verify evaluated metadata. This tool never executes an
adjacent build and does not substitute for a distributable third-party audit.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
POLICY = 'eng/policy/licence-boundary.json'
OWNERS = {name: ('Apache-2.0', 'Apache') if name in {'Contracts', 'Mobile'}
          else ('AGPL-3.0-only', 'AGPL') for name in
          ('DesktopPlatform', 'Contracts', 'ArcScope', 'Cloud', 'AI', 'Web', 'Mobile')}
MSBUILD = {'.csproj', '.fsproj', '.vbproj', '.vcxproj', '.esproj'}


def require(value, message):
    if not value:
        raise ValueError(message)


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, f'duplicate JSON key: {key}')
        value[key] = item
    return value


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True, encoding='utf-8').strip()


def kind(path):
    p = PurePosixPath(path)
    if p.suffix in MSBUILD:
        return 'msbuild'
    return {'package.json': 'npm', 'build.gradle.kts': 'gradle',
            'build.gradle': 'gradle', 'CMakeLists.txt': 'cmake'}.get(p.name)


def read(root, relative):
    p = PurePosixPath(relative)
    require(relative == p.as_posix() and not p.is_absolute() and '..' not in p.parts
            and '\\' not in relative and ':' not in relative, f'unsafe inventory path: {relative}')
    path = root / relative
    require(path.is_file(), f'missing file: {relative}')
    require(path.resolve().is_relative_to(root.resolve()), f'path escapes repository: {relative}')
    require(not any(x.is_symlink() or getattr(x, 'is_junction', lambda: False)() for x in [path, *path.parents] if x != root.parent),
            f'linked inventory path: {relative}')
    return path.read_text(encoding='utf-8-sig')


def inventory(root):
    require(Path(git(root, 'rev-parse', '--show-toplevel')).resolve() == root.resolve(),
            'selected root is not the Git worktree root')
    files = sorted(set(git(root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard').split('\0')) - {''})
    for entry in git(root, 'ls-files', '--stage').splitlines():
        mode, _, path = entry.partition('\t')
        require(mode.split()[0] not in {'120000', '160000'}, f'linked source/submodule: {path}')
    return files


def fields(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys.split()), f'{label}: invalid fields')


def first_party(name):
    """Closed current owner families; unknown family names require review."""
    lower = name.lower()
    if lower.startswith('arcforges.'):
        if lower.startswith(('arcforges.contracts.', 'arcforges.sdk.')) or lower == 'arcforges.cli':
            return 'Apache'
        if lower.startswith(('arcforges.arcscope',)):
            return 'AGPL'
        platform = ('foundation', 'application.', 'localrpc', 'capabilities', 'observability',
                    'persistence.', 'security', 'update', 'execution', 'designsystem', 'desktop.',
                    'cloud.client', 'device.runtime', 'assistant.', 'native.', 'nativeinterop',
                    'contentsandbox', 'build.policy')
        require(any(lower.removeprefix('arcforges.').startswith(p) for p in platform),
                f'unknown first-party package owner: {name}')
        return 'AGPL'
    if lower.startswith('@arcforges/'):
        if lower in {'@arcforges/proto', '@arcforges/api-client', '@arcforges/contract-fixtures', '@arcforges/ai-internal'}:
            return 'Apache'
        require(lower in {'@arcforges/ai', '@arcforges/cloud-workspace', '@arcforges/web-workspace',
                          '@arcforges/web-site', '@arcforges/web-ui'}, f'unknown first-party package owner: {name}')
        return 'AGPL'
    if lower.startswith('io.github.arcforges:'):
        require(lower in {'io.github.arcforges:' + n for n in
                         ('contracts-proto', 'contracts-client', 'contracts-connect-client', 'contract-fixtures')},
                f'unknown first-party package owner: {name}')
        return 'Apache'
    return None


def check_graph(nodes, edges):
    for source in nodes:
        pending = list(edges.get(source, []))
        seen = set()
        while pending:
            target = pending.pop()
            require(target in nodes, f'unregistered reference: {source} -> {target}')
            require(nodes[source] != 'Apache' or nodes[target] == 'Apache',
                    f'Apache-to-AGPL dependency: {source} -> {target}')
            if target not in seen:
                seen.add(target)
                pending.extend(edges.get(target, []))


def xml_values(text, tag):
    return [(e.text or '').strip() for e in ET.fromstring(text).iter() if e.tag.split('}')[-1] == tag]


def metadata(root, path, project_kind):
    text = read(root, path)
    if project_kind == 'msbuild':
        result = [xml_values(text, key) for key in ('PackageLicenseExpression', 'LicenceBoundary')]
    elif project_kind == 'npm':
        doc = json.loads(text, object_pairs_hook=unique)
        fields(doc.get('arcforges'), 'licenceBoundary', path)
        result = [[doc.get('license')], [doc['arcforges']['licenceBoundary']]]
    elif project_kind == 'gradle':
        result = [re.findall(r'extra\["' + key + r'"\]\s*=\s*"([^"\n]+)"', text)
                  for key in ('spdxLicense', 'licenceBoundary')]
    else:
        result = [re.findall(r'set\(\s*' + key + r'\s+"([^"\n]+)"\s*\)', text)
                  for key in ('ARCFORGES_SPDX_LICENSE', 'ARCFORGES_LICENCE_BOUNDARY')]
    require(all(len(v) == 1 and isinstance(v[0], str) for v in result), f'missing/duplicate project declaration: {path}')
    return tuple(v[0] for v in result)


def audit(root, owner):
    require(owner in OWNERS, f'unknown repository owner: {owner}')
    files = inventory(root)
    before = {'commit': git(root, 'rev-parse', 'HEAD'), 'dirty': bool(git(root, 'status', '--porcelain'))}
    policy = json.loads(read(root, POLICY), object_pairs_hook=unique)
    fields(policy, 'schemaVersion repository spdxLicense licenceBoundary projects', POLICY)
    require(type(policy['schemaVersion']) is int and policy['schemaVersion'] == 1, 'unsupported licence inventory schema')
    expected = OWNERS[owner]
    require(policy['repository'] == owner and (policy['spdxLicense'], policy['licenceBoundary']) == expected,
            'repository boundary differs from the enumerated Design assignment')
    require(isinstance(policy['projects'], list) and policy['projects'], 'empty/malformed project inventory')
    declared = {}
    for row in policy['projects']:
        fields(row, 'path kind', 'project row')
        require(isinstance(row['path'], str) and isinstance(row['kind'], str), 'invalid project row values')
        require(row['path'] not in declared, 'duplicate project registration')
        declared[row['path']] = row['kind']
    actual = {p: kind(p) for p in files if kind(p)}
    require(declared == actual, 'project inventory drift: ' + repr(sorted(set(declared.items()) ^ set(actual.items()))))
    nodes, edges, packages = {}, {}, []
    for p, system in actual.items():
        value = metadata(root, p, system)
        require(value == expected, f'incorrect licence/boundary in {p}: {value}')
        nodes[p] = value[1]
        edges[p] = []
    npm_names = {}
    managed_names = set()
    for p, system in actual.items():
        if system == 'msbuild':
            managed_names.add(PurePosixPath(p).stem.casefold())
            for key in ('AssemblyName', 'PackageId'):
                managed_names.update(x.casefold() for x in xml_values(read(root, p), key) if '$' not in x)
        if system == 'npm':
            name = json.loads(read(root, p))['name']
            require(name not in npm_names, f'duplicate npm project identity: {name}')
            npm_names[name] = p

    def package(source, name, origin):
        boundary = first_party(name)
        if boundary:
            require(expected[1] != 'Apache' or boundary == 'Apache', f'Apache-to-AGPL package: {source}: {name}')
            packages.append({'source': source, 'name': name, 'boundary': boundary, 'evidence': origin})

    for p in files:
        path = PurePosixPath(p)
        if path.suffix in MSBUILD | {'.props', '.targets'}:
            doc = ET.fromstring(read(root, p))
            for element in doc.iter():
                tag = element.tag.split('}')[-1]
                if tag in {'PackageLicenseExpression', 'LicenceBoundary'}:
                    require((element.text or '').strip() == expected[0 if tag == 'PackageLicenseExpression' else 1],
                            f'licence property override: {p}')
                if tag == 'ProjectReference':
                    value = element.get('Include', '')
                    require(value and not any(c in value for c in '$@*?;'), f'nonliteral project reference: {p}')
                    target = (root / path.parent / value.replace('\\', '/')).resolve()
                    require(target.is_relative_to(root.resolve()), f'project reference escapes repository: {p}: {value}')
                    relative = target.relative_to(root.resolve()).as_posix()
                    require(relative in nodes, f'unregistered project reference: {p}: {relative}')
                    require(p in nodes, f'project references in shared build inputs require explicit owner review: {p}')
                    edges[p].append(relative)
                if tag in {'PackageReference', 'PackageVersion'}:
                    package(p, element.get('Include') or element.get('Update') or '', p)
        elif path.name == 'package.json':
            doc = json.loads(read(root, p), object_pairs_hook=unique)
            for section in ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'):
                for name, version in doc.get(section, {}).items():
                    require(not str(version).startswith(('file:', 'link:', 'git+', '../', './')), f'adjacent/unpublished npm reference: {p}: {name}')
                    if name in npm_names:
                        edges[p].append(npm_names[name])
                    else:
                        package(p, name, p)
                    if str(version).startswith('npm:'):
                        alias = str(version)[4:]
                        end = alias.find('@', 1)
                        package(p, alias if end < 0 else alias[:end], p)
        elif path.name == 'packages.lock.json':
            doc = json.loads(read(root, p), object_pairs_hook=unique)
            for framework in doc['dependencies'].values():
                for name, entry in framework.items():
                    if entry.get('type', '').casefold() == 'project':
                        require(name.casefold() in managed_names, f'unregistered locked project: {p}: {name}')
                    else:
                        package(p, name, p)
        elif path.name == 'package-lock.json':
            doc = json.loads(read(root, p), object_pairs_hook=unique)
            for name, entry in doc.get('packages', {}).items():
                package(p, entry.get('name') or name.rsplit('node_modules/', 1)[-1], p)
        elif path.name.endswith('.lockfile'):
            for line in read(root, p).splitlines():
                if not line.startswith('#') and ':' in line:
                    package(p, ':'.join(line.split(':')[:2]), p)
        elif path.name in {'build.gradle.kts', 'build.gradle', 'settings.gradle.kts', 'settings.gradle'}:
            text = read(root, p)
            require('includeBuild(' not in text and 'mavenLocal(' not in text, f'adjacent/composite or local Maven source: {p}')
            for match in re.finditer(r'io\.github\.arcforges:([a-zA-Z0-9_.-]+)', text):
                package(p, match[0], p)
            if p in nodes:
                for name in re.findall(r'\bproject\(\s*"(:[^"\n]*)"\s*\)', text):
                    # Resolve only within this build's nearest settings root.
                    build_root = (root / path).parent
                    while build_root != root and not any((build_root / f).is_file() for f in ('settings.gradle.kts', 'settings.gradle')):
                        build_root = build_root.parent
                    settings = next((x for x in ('settings.gradle.kts', 'settings.gradle') if (build_root / x).is_file()), None)
                    require(settings is not None, f'missing Gradle settings: {p}')
                    settings_text = (build_root / settings).read_text(encoding='utf-8')
                    mapped = re.search(r'project\("' + re.escape(name) + r'"\)\.projectDir\s*=\s*file\("([^"]+)"\)', settings_text)
                    convention = re.search(r'rootProject\.children\.forEach\s*\{\s*it\.projectDir\s*=\s*file\("([^"\n]*)\$\{it\.name\}"\)\s*\}', settings_text)
                    relative_dir = (mapped[1] if mapped else convention[1] + name.lstrip(':') if convention
                                    else name.lstrip(':').replace(':', '/'))
                    target = (build_root / relative_dir / 'build.gradle.kts').resolve()
                    require(target.is_relative_to(root.resolve()), f'Gradle reference escapes repository: {p}')
                    relative = target.relative_to(root.resolve()).as_posix()
                    require(relative in nodes, f'unregistered Gradle project reference: {p}: {name}')
                    edges[p].append(relative)
    check_graph(nodes, edges)
    require(before == {'commit': git(root, 'rev-parse', 'HEAD'), 'dirty': bool(git(root, 'status', '--porcelain'))},
            'source state changed during audit')
    return {'repository': owner, **before, 'spdxLicense': expected[0], 'licenceBoundary': expected[1],
            'projects': [{'path': p, 'kind': actual[p], 'spdxLicense': expected[0], 'licenceBoundary': nodes[p]}
                         for p in sorted(nodes)], 'projectReferences': edges, 'firstPartyPackages': packages,
            'result': 'passed', 'findings': [], 'evidenceClass': 'source-project-inventory-and-reference-audit'}


def evaluated_projects(root, source, ide=False):
    """Execute only this owner's declared projects; family audit stays read-only."""
    require(source['repository'] == 'DesktopPlatform' and root.resolve() == ROOT,
            'evaluated builds are restricted to the owning DesktopPlatform checkout')
    executable = ['dotnet', 'msbuild']
    if ide:
        require(os.name == 'nt', 'IDE project evaluation requires Windows Visual Studio')
        locator = Path(os.environ['ProgramFiles(x86)']) / 'Microsoft Visual Studio/Installer/vswhere.exe'
        found = subprocess.check_output([str(locator), '-latest', '-products', '*', '-requires',
                                         'Microsoft.Component.MSBuild', '-find', 'MSBuild/**/Bin/MSBuild.exe'],
                                        text=True).splitlines()
        require(found, 'Visual Studio MSBuild was not found')
        executable = [found[0]]
    rows = []
    for project in source['projects']:
        if project['kind'] != 'msbuild' or (project['path'].endswith('.vcxproj') != ide):
            continue
        for configuration in ('Debug', 'Release'):
            for platform in (('x64', 'ARM64') if ide else ('AnyCPU',)):
                command = [*executable, project['path'], '-t:ArcForgesVerifyLicenceBoundary',
                           f'-p:Configuration={configuration}', f'-p:Platform={platform}',
                           '-getProperty:PackageLicenseExpression,LicenceBoundary',
                           '-getItem:ProjectReference', '-verbosity:quiet']
                result = json.loads(subprocess.check_output(command, cwd=root, text=True, encoding='utf-8'))
                require(result['Properties'] == {'PackageLicenseExpression': 'AGPL-3.0-only', 'LicenceBoundary': 'AGPL'},
                        f'evaluated licence mismatch: {project["path"]}')
                references = []
                for item in result['Items']['ProjectReference']:
                    path = Path(item['FullPath']).resolve()
                    require(path.is_relative_to(root), 'evaluated project reference escapes repository')
                    relative = path.relative_to(root).as_posix()
                    require(any(p['path'] == relative for p in source['projects']), 'unregistered evaluated reference')
                    references.append(relative)
                rows.append({'path': project['path'], 'configuration': configuration, 'platform': platform,
                             'properties': result['Properties'], 'projectReferences': references})
    require(rows, 'no owned projects were evaluated')
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', action='append', help='Owner=absolute-root (read-only); default DesktopPlatform only')
    parser.add_argument('--report', type=Path, default=ROOT / 'artifacts/evidence/licence-boundary.json')
    parser.add_argument('--evaluate-managed', action='store_true')
    parser.add_argument('--evaluate-ide', action='store_true')
    args = parser.parse_args()
    rows = []
    try:
        selected = args.repository or [f'DesktopPlatform={ROOT}']
        seen = set()
        for entry in selected:
            owner, sep, location = entry.partition('=')
            require(sep and owner not in seen and Path(location).is_absolute(), 'duplicate or malformed repository argument')
            seen.add(owner)
            rows.append(audit(Path(location).resolve(), owner))
        report = {'result': 'passed', 'repositories': rows}
        if args.evaluate_managed or args.evaluate_ide:
            require(not args.repository, 'family inventory must never execute adjacent projects')
            report['evaluatedProjects'] = evaluated_projects(ROOT, rows[0], args.evaluate_ide)
        code = 0
    except (ValueError, OSError, KeyError, TypeError, ET.ParseError, subprocess.CalledProcessError) as error:
        report = {'result': 'failed', 'repositories': rows, 'error': str(error)}
        code = 1
    report.update(substep='WP00.02', checkedAt=datetime.now(timezone.utc).isoformat(),
                  limitations='Source inventory only. Owner evaluated-build receipts and distributable dependency licence audits are separate evidence.')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'result': report['result'], 'projects': sum(len(r['projects']) for r in rows),
                      'error': report.get('error')}))
    return code


if __name__ == '__main__':
    sys.exit(main())
