# SPDX-License-Identifier: AGPL-3.0-only
"""Bind existing canonical naming and secret gates to the exact architecture source."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / 'eng/policy/architecture-evidence.json'


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate evidence key: ' + key)
            result[key] = value
        return result
    return json.loads(Path(path).read_text(encoding='utf-8'), object_pairs_hook=unique)


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.PIPE).decode().strip()


def context(root=ROOT, env=None):
    env = os.environ if env is None else env
    source = git(root, 'rev-parse', 'HEAD')
    require(re.fullmatch('[0-9a-f]{40}', source), 'Invalid source commit')
    hosted = env.get('GITHUB_ACTIONS') == 'true'
    if hosted:
        require(env.get('GITHUB_SHA') == source, 'CI checkout differs from source commit')
        require(not git(root, 'status', '--porcelain', '--untracked-files=no'), 'CI tracked source is dirty')
        for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
            require(re.fullmatch('[1-9][0-9]*', env.get(key, '')), 'Missing CI identity: ' + key)
    return {'sourceCommit': source, 'runId': env.get('GITHUB_RUN_ID') if hosted else None,
            'runAttempt': env.get('GITHUB_RUN_ATTEMPT') if hosted else None, 'hosted': hosted}


def row(rule, source, passed, findings=None):
    return {'rule': rule, 'sourceCommit': source, 'passed': passed, 'findings': findings or []}


def receipt(ctx, producer, evidence, **extra):
    return {'schemaVersion': 1, **ctx, 'producer': producer, 'evidence': evidence, **extra}


def secret_receipt(ctx, outcome, producer):
    require(ctx['hosted'] and producer == 'secret-scan' and outcome == 'success',
            'RP-09 needs the successful existing hosted secret-scan job')
    return receipt(ctx, producer, [row('RP-09', ctx['sourceCommit'], True)])


def load_scanner(assets, expected):
    assets = Path(assets).resolve()
    require(set(expected) == {'tools/naming/eng/check_naming.py', 'tools/naming/eng/policy/product-names.json'},
            'Incomplete canonical naming assets')
    for relative, digest in expected.items():
        require(re.fullmatch('[0-9a-f]{64}', digest), 'Invalid naming asset digest')
        require(hashlib.sha256((assets / relative).read_bytes()).hexdigest() == digest,
                'Canonical naming asset changed: ' + relative)
    spec = importlib.util.spec_from_file_location('architecture_canonical_naming', assets / 'tools/naming/eng/check_naming.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def naming_fixtures(scanner, root=ROOT):
    policy = scanner.load_policy()
    with tempfile.TemporaryDirectory(prefix='architecture-naming-') as folder:
        target = Path(folder)
        git(target, 'init', '-q')
        git(target, 'remote', 'add', 'origin', 'https://github.com/ArcForges/DesktopPlatform.git')
        git(target, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
            '-c', 'commit.gpgsign=false', 'commit', '--allow-empty', '-qm', 'fixture')
        # Preserve canonical exact provenance exceptions rather than replacing its policy.
        for exception in policy['provenanceExceptions']:
            if exception['repository'] == 'DesktopPlatform':
                relative = exception['path']
                output = target / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes((root / relative).read_bytes())
        probe = target / 'src/fixture.txt'
        probe.parent.mkdir(parents=True, exist_ok=True)
        probe.write_text('ArcForges ArcScope', encoding='utf-8')
        require(not scanner.scan_repository(target, 'DesktopPlatform', policy)['findings'],
                'Canonical positive naming fixture failed')
        count = 0
        for item in policy['forbiddenNames']:
            probe.write_text(item['name'], encoding='utf-8')
            found = scanner.scan_repository(target, 'DesktopPlatform', policy)['findings']
            require(any(f.get('path') == 'src/fixture.txt' and f.get('name') == item['name']
                        and f.get('kind') == 'forbidden content' for f in found),
                    'Canonical forbidden term was not rejected')
            count += 1
        require(count > 0, 'No canonical negative naming fixtures')
        return {'positive': 1, 'negative': count}


def naming_receipt(ctx, runtime, pin, assets, producer, root=ROOT):
    require(runtime.get('result') == 'passed' and runtime.get('namingPackage') == pin,
            'Missing successful exact canonical naming package evidence')
    require(producer == 'runtime-policy' or not ctx['hosted'], 'Incorrect naming producer job')
    for section in ('repositories', 'naming'):
        owners = [item for item in runtime.get(section, []) if item.get('repository') == 'DesktopPlatform']
        require(len(owners) == 1 and owners[0].get('commit') == ctx['sourceCommit'],
                'Naming/runtime evidence differs from current source')
        require(not ctx['hosted'] or owners[0].get('dirty') is False, 'Naming source was dirty')
    naming = next(item for item in runtime['naming'] if item['repository'] == 'DesktopPlatform')
    require(naming.get('status') == 'pass' and naming.get('findings') == [], 'Canonical naming gate did not pass')
    scanner = load_scanner(assets, runtime.get('namingAssets', {}))
    fixtures = naming_fixtures(scanner, root)
    return receipt(ctx, producer, [row(rule, ctx['sourceCommit'], True) for rule in ('RP-01', 'RP-08')],
                   namingPackage=pin, fixtures=fixtures)


def combine(ctx, naming, secret=None):
    evidence = []
    for value, producer, rules in [(naming, 'runtime-policy', ['RP-01', 'RP-08']),
                                   (secret, 'secret-scan', ['RP-09'])]:
        if value is None:
            require(not ctx['hosted'], 'Required hosted secret evidence is missing')
            evidence.append(row('RP-09', ctx['sourceCommit'], False,
                                [{'rule': 'RP-09', 'path': '.github/workflows/pr-gate.yml',
                                  'message': 'Existing hosted secret-scan evidence is required; not locally verified.', 'line': 0}]))
            continue
        require(producer != 'secret-scan' or ctx['hosted'], 'Local RP-09 evidence is not trusted')
        require(value.get('schemaVersion') == 1 and value.get('producer') == producer,
                'Incorrect external evidence producer')
        for key in ('sourceCommit', 'runId', 'runAttempt', 'hosted'):
            require(value.get(key) == ctx[key], 'External evidence identity mismatch: ' + key)
        rows = value.get('evidence')
        require(isinstance(rows, list) and [item.get('rule') for item in rows] == rules,
                'Missing, duplicate or unexpected external evidence rule')
        for item in rows:
            require(set(item) == {'rule', 'sourceCommit', 'passed', 'findings'} and
                    item['sourceCommit'] == ctx['sourceCommit'] and item['passed'] is True and item['findings'] == [],
                    'External evidence contains failures or inconsistent identity')
        evidence.extend(rows)
    return receipt(ctx, 'architecture-adapter', evidence)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['secret', 'naming', 'combine'])
    parser.add_argument('--runtime-report', type=Path)
    parser.add_argument('--assets', type=Path)
    parser.add_argument('--naming', type=Path)
    parser.add_argument('--secret', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    config = read(CONFIG)
    require(config == {'schemaVersion': 1, 'license': 'AGPL-3.0-only',
                       'namingPin': 'eng/policy/naming-package.json',
                       'namingRules': ['RP-01', 'RP-08'], 'secretRule': 'RP-09'}, 'Invalid evidence adapter configuration')
    ctx = context()
    if args.mode == 'secret':
        result = secret_receipt(ctx, os.environ.get('SECRET_SCAN_OUTCOME'), os.environ.get('GITHUB_JOB'))
    elif args.mode == 'naming':
        result = naming_receipt(ctx, read(args.runtime_report), read(ROOT / config['namingPin']),
                                args.assets, os.environ.get('GITHUB_JOB', 'runtime-policy'))
    else:
        result = combine(ctx, read(args.naming), read(args.secret) if args.secret else None)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'sourceCommit': ctx['sourceCommit'], 'rules': [r['rule'] for r in result['evidence']],
                      'passed': all(r['passed'] for r in result['evidence'])}))
    return 0 if all(r['passed'] for r in result['evidence']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
