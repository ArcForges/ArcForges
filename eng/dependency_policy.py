# SPDX-License-Identifier: AGPL-3.0-only
"""Offline dependency admission; existing native/source gates retain legal authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
POLICY = 'eng/policy/dependency-policy.json'
# Exact existing publication admitted only for FND.07's local acceptance consumer.
FOUNDATION_ACCEPTANCE = {
    'arcforges.foundation/1.0.0-ci.29.1': 'P5FRjzq8/DOhNS4bI4PAtjjnkIN2XPufXV0vnfyRFyDN12A/QcV1nteBCu4q/Kxg9R0Enlftut9QxYNtMPzDTg==',
    'arcforges.application.abstractions/1.0.0-ci.29.1': '8ICXm8LvJsaXgNz6RfiHSoxxqxE3jLJMz8IWCcweW0FIzv6isEl3SMH+pbBATNKIqApDmCN78FT/csCAqMBMRA==',
}
FOUNDATION_PUBLISHER = {
    'repository': 'ArcForges/DesktopPlatform',
    'workflow': 'publish-nuget.yml',
    'sourceCommit': 'ace60538849047184954baed09fb05ec7676d367',
    'feed': 'https://api.nuget.org/v3/index.json',
}

UPGRADE_CHECKS = {'compilation', 'aot-trim', 'compatibility', 'licence-provenance',
                  'security-sbom', 'runtime-performance-migration', 'framework-runtime-posture'}


def require(value, message):
    if not value:
        raise ValueError(message)


def exact(value):
    require(isinstance(value, str) and re.fullmatch(r'\d+\.\d+\.\d+(?:[.-][A-Za-z0-9.-]+)?', value)
            and 'SNAPSHOT' not in value, 'Floating or mutable version: ' + str(value))


def files(root):
    return sorted(set(subprocess.check_output(['git', '-C', str(root), 'ls-files', '--cached',
                  '--others', '--exclude-standard'], text=True).splitlines()))


def inputs(root):
    return [p for p in files(root) if p.endswith(('.csproj', '.props', '.targets', 'packages.lock.json'))
            or p in {'global.json', 'NuGet.config', '.python-version', 'eng/requirements-ci.txt',
                     'eng/native-toolchain.json', 'eng/packaging/packages.json', 'eng/policy/naming-package.json',
                     'eng/acceptance/foundation/package.json', 'eng/acceptance/foundation/package-lock.json', 'vcpkg.json',
                     'vcpkg-configuration.json'}
            or p.startswith(('eng/native/vcpkg/', 'eng/provenance/artifact-profiles/',
                             'eng/provenance/records/'))]


def hashes(root):
    return {p: hashlib.sha256((root / p).read_bytes().replace(b'\r\n', b'\n')).hexdigest() for p in inputs(root)}


def closure(root):
    result = {}
    for name in inputs(root):
        if not name.endswith('packages.lock.json'):
            continue
        for graph in json.loads((root / name).read_text())['dependencies'].values():
            for package, entry in graph.items():
                if entry['type'].lower() == 'project':
                    continue
                exact(entry['resolved'])
                key = package.lower() + '/' + entry['resolved']
                require(entry.get('contentHash'), 'Missing locked checksum: ' + key)
                require(key not in result or result[key] == entry['contentHash'], 'Mutable version: ' + key)
                result[key] = entry['contentHash']
    return result


def check_admission(policy, actual):
    admitted = policy['nugetClosure']
    require(set(actual) == set(admitted), 'Unadmitted dependency closure')
    for key, content in actual.items():
        row = admitted[key]
        exact(key.rsplit('/', 1)[1])
        require(row['contentHash'] == content, 'Mutable admitted version: ' + key)
        if key in FOUNDATION_ACCEPTANCE:
            package, version = key.rsplit('/', 1)
            require(row['licence'] == 'AGPL-3.0-only'
                    and content == FOUNDATION_ACCEPTANCE[key]
                    and row.get('internalPublisher') == FOUNDATION_PUBLISHER
                    and row['source'] == f'https://api.nuget.org/v3-flatcontainer/{package}/{version}/{package}.nuspec',
                    'Forbidden or invalid exact Foundation acceptance admission: ' + key)
        else:
            require(row['licence'] in {'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC'},
                    'Forbidden or unreviewed licence: ' + key)
        require(re.fullmatch('[0-9a-f]{64}', row['nuspecSha256']) and row['source'], 'Missing source evidence')
    review = policy['review']
    require(review['owner'] and review['reviewer'] and review['maintenanceAssessment'], 'Missing admission review')
    require(set(review['upgradeChecks']) == UPGRADE_CHECKS and all(review['upgradeChecks'].values()),
            'Missing upgrade evidence')
    require(re.fullmatch('[0-9a-f]{40}', review['baselineCommit']), 'Floating source tag')
    require(review['inputHashes'] == policy['inputHashes'], 'Review does not bind current inputs')
    require(policy['publisher'] == {'repository': 'ArcForges/DesktopPlatform', 'workflow': 'publish-nuget.yml',
                                  'environment': 'nuget', 'credential': 'github-oidc',
                                  'feed': 'https://api.nuget.org/v3/index.json'}, 'Wrong publisher or feed')
    require(policy['nativeGate'] == 'eng/native_provenance.py' and policy['sourceGate'] == 'eng/check_provenance.py',
            'Missing native/source gate')


def python_closure(root):
    result, current = {}, None
    for line in (root / 'eng/requirements-ci.txt').read_text().splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = re.fullmatch(r'([A-Za-z0-9_-]+)==([^\s]+)\s*\\?', line)
        if match:
            exact(match[2])
            current = match[1].lower().replace('_', '-') + '/' + match[2]
            require(current not in result, 'Duplicate Python requirement')
            result[current] = []
        else:
            match = re.fullmatch(r'\s+--hash=sha256:([0-9a-f]{64})\s*\\?', line)
            require(match and current, 'Floating Python requirement or missing checksum')
            result[current].append(match[1])
    require(result and all(result.values()), 'Incomplete Python checksum closure')
    return {key: sorted(value) for key, value in result.items()}


def check_python(policy, actual):
    require(set(policy['pythonClosure']) == set(actual), 'Unadmitted Python closure')
    for key, hashes in actual.items():
        row = policy['pythonClosure'][key]
        require(row['hashes'] == hashes, 'Mutable Python coordinate: ' + key)
        require(row['licence'] in {'MIT', 'BSD-3-Clause', 'PSF-2.0'}, 'Forbidden Python licence')
        require(row['evidence'] and all(re.fullmatch('[0-9a-f]{64}', e['sha256']) and e['source']
                                      for e in row['evidence']), 'Missing Python licence evidence')


def check_history(policy, receipts):
    seen, python = {}, {}
    for receipt in receipts:
        for key, row in receipt['nugetClosure'].items():
            require(key not in seen or seen[key] == row['contentHash'], 'Historical immutable version changed: ' + key)
            seen[key] = row['contentHash']
        for key, row in receipt['pythonClosure'].items():
            require(key not in python or python[key] == row['hashes'], 'Historical Python coordinate changed: ' + key)
            python[key] = row['hashes']
    for key, row in policy['nugetClosure'].items():
        require(key not in seen or seen[key] == row['contentHash'], 'Historical immutable version changed: ' + key)
    for key, row in policy['pythonClosure'].items():
        require(key not in python or python[key] == row['hashes'], 'Historical Python coordinate changed: ' + key)


def framework_upgrade(previous, current):
    changes = {key for key, value in current['frameworkVersions'].items()
               if key in previous['frameworkVersions'] and
               value.split('.')[0] != previous['frameworkVersions'][key].split('.')[0]}
    if changes:
        assessment = current.get('frameworkMajorReview', {})
        require(set(assessment.get('changed', [])) == changes and assessment.get('owner')
                and all(assessment.get(key) for key in ['nativeAotTrim', 'nativeAbi', 'androidKotlinArtR8', 'localCoverage']),
                'Missing framework major runtime-posture review')


def history(root, policy):
    from check_provenance import baseline, git
    base = baseline(root, os.environ.get('GITHUB_SHA') if os.environ.get('GITHUB_REF', '').startswith('refs/tags/') else None)
    prefix = 'eng/policy/dependency-reviews/'
    for path in git(root, 'ls-tree', '-r', '--name-only', base, '--', prefix).decode().splitlines():
        require((root / path).is_file() and (root / path).read_bytes().replace(b'\r\n', b'\n')
                == git(root, 'show', base + ':' + path).replace(b'\r\n', b'\n'), 'Deleted or modified historical review: ' + path)
    paths = [p for p in files(root) if p.startswith(prefix) and p.endswith('.json')]
    require(policy['reviewReceipt'] in paths, 'Missing immutable review receipt')
    receipt = json.loads((root / policy['reviewReceipt']).read_text())
    require(receipt == {key: policy[key] for key in ['review', 'nugetClosure', 'pythonClosure']}, 'Active receipt mismatch')
    receipts, visited, current = [], set(), policy['reviewReceipt']
    while current is not None:
        require(current in paths and current not in visited, 'Invalid review predecessor chain')
        visited.add(current)
        item = json.loads((root / current).read_text())
        receipts.insert(0, item)
        current = item['review']['previousReceipt']
    require(visited == set(paths), 'Dropped historical review from chain')
    require(policy['review']['frameworkVersions'] == {'dotnetSdk': json.loads((root / 'global.json').read_text())['sdk']['version']},
            'Framework selection does not match review')
    for before, after in zip(receipts, receipts[1:]):
        framework_upgrade(before['review'], after['review'])
    check_history(policy, receipts)


def audit(root=ROOT, stable=False):
    policy = json.loads((root / POLICY).read_text())
    require(policy['schemaVersion'] == 1 and policy['repository'] == 'DesktopPlatform', 'Wrong policy owner')
    require(policy['inputHashes'] == hashes(root), 'Dependency inputs changed; record reviewed upgrade evidence')
    actual = closure(root)
    check_admission(policy, actual)
    check_python(policy, python_closure(root))
    history(root, policy)
    config = ET.parse(root / 'NuGet.config')
    require([(e.get('key'), e.get('value')) for e in config.findall('./packageSources/add')]
            == [('nuget.org', policy['publisher']['feed'])], 'Untrusted restore feed')
    for name in inputs(root):
        if name.endswith(('.csproj', '.props', '.targets')):
            for e in ET.parse(root / name).iter():
                if e.tag.split('}')[-1] == 'PackageVersion' and e.get('Include'):
                    exact(e.get('Version'))
    # No first-party candidate dependency exception is admitted in this producer.
    if stable:
        require(all('-' not in key.rsplit('/', 1)[1] for key in actual), 'Stable closure contains prerelease')
    return {'result': 'passed', 'repository': 'DesktopPlatform', 'dependencies': len(actual),
            'pythonToolDependencies': len(policy['pythonClosure']),
            'inputs': len(policy['inputHashes']), 'stable': stable,
            'nativeAndSourceEvidence': 'Existing independent native/provenance gates remain required'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stable', action='store_true')
    args = parser.parse_args()
    print(json.dumps(audit(stable=args.stable), indent=2))
