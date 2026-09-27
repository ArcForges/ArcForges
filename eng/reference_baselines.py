# SPDX-License-Identifier: AGPL-3.0-only
"""Verify immutable planning references without executing or reading reference code."""
from __future__ import annotations

import argparse
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
META = 'eng/provenance/reference-inputs.json'
POLICY = 'eng/policy/reference-baselines.json'
EXPECTED = {
    'assistant': ('DesktopPlatform', ['15.07'], 30, 'ac', ['s1']),
    'scope': ('ArcScope', ['33.07'], 31, 'as', ['s4']),
    'distribution': ('DesktopPlatform', ['50.01', '50.02'], 12, 'sd', []),
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def fields(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys.split()), 'unexpected or missing fields: ' + keys)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def read(path):
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def normalized(data):
    return data.decode('utf-8').replace('\r\n', '\n').encode('utf-8')


def digest(value, size=64):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(size) + '}', value), 'invalid digest')


def relative(value):
    require(isinstance(value, str) and value and '\\' not in value and ':' not in value
            and not PurePosixPath(value).is_absolute() and '..' not in PurePosixPath(value).parts
            and str(PurePosixPath(value)) == value, 'unsafe relative path')
    return value


def git(root, *args):
    result = subprocess.run(['git', '-c', 'core.hooksPath=', '-C', str(root), *args],
                            capture_output=True, check=True)
    return result.stdout


def textgit(root, *args):
    return git(root, *args).decode('utf-8').strip()


def origin(root, repository):
    actual = textgit(root, 'remote', 'get-url', 'origin')
    require(actual in {f'https://github.com/{repository}', f'https://github.com/{repository}.git',
                      f'git@github.com:{repository}.git'}, 'wrong repository origin: ' + repository)


def commit(root, value):
    require(isinstance(value, str) and value and not value.startswith('-'), 'invalid revision')
    resolved = textgit(root, 'rev-parse', '--verify', '--end-of-options', value + '^{commit}')
    digest(resolved, 40)
    return resolved


def state(root):
    if textgit(root, 'rev-parse', '--is-bare-repository') == 'true':
        return {'kind': 'bare', 'head': None, 'dirty': None, 'status': []}
    require(Path(textgit(root, 'rev-parse', '--show-toplevel')).resolve() == root.resolve(), 'not a repository root')
    entries = git(root, 'status', '--porcelain=v1', '-z', '--untracked-files=all').decode('utf-8').split('\0')
    return {'kind': 'working-tree', 'head': commit(root, 'HEAD'), 'dirty': bool(entries[0]),
            'status': list(filter(None, entries))}


@contextmanager
def remote_snapshot(repository, revision):
    with tempfile.TemporaryDirectory(prefix='arcforges-reference-') as directory:
        root = Path(directory)
        git(root, 'init', '--bare', '--quiet')
        git(root, 'remote', 'add', 'origin', f'https://github.com/{repository}.git')
        git(root, 'fetch', '--quiet', '--depth=1', '--filter=blob:none', 'origin', revision)
        yield root


def validate(registry, metadata):
    fields(registry, 'schemaVersion license metadata matrices')
    require(type(registry['schemaVersion']) is int and registry['schemaVersion'] == 1
            and registry['license'] == 'AGPL-3.0-only', 'invalid registry version/license')
    fields(registry['metadata'], 'path sha256')
    require(registry['metadata']['path'] == META, 'wrong metadata path')
    digest(registry['metadata']['sha256'])
    require(isinstance(registry['matrices'], list) and len(registry['matrices']) == len(EXPECTED), 'three retained matrices required')
    seen = set()
    for item in registry['matrices']:
        fields(item, 'id owner maintenance rows prefix sources')
        matrix_id = item['id']
        require(isinstance(matrix_id, str) and matrix_id in EXPECTED and matrix_id not in seen, 'unknown/duplicate matrix')
        require((item['owner'], item['maintenance'], item['rows'], item['prefix'], item['sources']) == EXPECTED[matrix_id]
                and type(item['rows']) is int, 'matrix ownership/count/source mismatch: ' + matrix_id)
        seen.add(matrix_id)
    fields(metadata, 'schemaVersion design matrices sources packaged review')
    require(type(metadata['schemaVersion']) is int and metadata['schemaVersion'] == 1, 'invalid metadata version')
    fields(metadata['design'], 'repository commit')
    require(metadata['design']['repository'] == 'ArcForges/ArcForges-Design', 'wrong Design identity')
    digest(metadata['design']['commit'], 40)
    require(isinstance(metadata['matrices'], dict) and set(metadata['matrices']) == set(EXPECTED) | {'notes', 'slate'}, 'matrix set mismatch')
    paths = set()
    for item in metadata['matrices'].values():
        fields(item, 'path sha256')
        path = relative(item['path'])
        require(path.startswith('docs/assurance/reference-coverage/') and path.endswith('.md')
                and path not in paths, 'wrong or duplicate matrix path')
        paths.add(path)
        digest(item['sha256'])
    require(isinstance(metadata['sources'], dict) and set(metadata['sources']) == {f's{x}' for x in range(1, 7)}, 'six sources required')
    repos = set()
    names = set()
    for item in metadata['sources'].values():
        fields(item, 'repository commit abbreviation localName')
        repo = item['repository']
        require(isinstance(repo, str) and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo)
                and repo not in repos, 'wrong/duplicate reference repository')
        repos.add(repo)
        digest(item['commit'], 40)
        require(re.fullmatch('[0-9a-f]{7,12}', item['abbreviation'])
                and item['commit'].startswith(item['abbreviation']), 'source abbreviation mismatch')
        name = relative(item['localName'])
        require('/' not in name and name not in names, 'invalid local reference name')
        names.add(name)
    fields(metadata['review'], 'date reviewer rationale')
    require(all(isinstance(v, str) and v.strip() for v in metadata['review'].values())
            and re.fullmatch(r'\d{4}-\d{2}-\d{2}', metadata['review']['date']), 'missing review')
    packaged = metadata['packaged']
    fields(packaged, 'observedOn versions observation')
    require(re.fullmatch(r'\d{4}-\d{2}-\d{2}', packaged['observedOn']), 'missing observation date')
    require(packaged['versions'] == {'AFFiNE/affine-0.27.2-stable-windows-x64.nsis.exe': '0.27.2-stable',
            'AionUi/AionUi-2.1.35-win-x64.exe': '2.1.35', 'siyuan/siyuan-3.7.3-win.exe': '3.7.3'}, 'packaged versions changed')
    observation = packaged['observation']
    fields(observation, 'directories notices')
    require(set(observation['directories']) == names, 'packaged product directory mismatch')
    for name, children in observation['directories'].items():
        require(isinstance(children, dict) and children, 'empty packaged directory')
        for child, kind in children.items():
            require('/' not in relative(child) and kind in {'file', 'directory'}, 'invalid child entry')
    require(isinstance(observation['notices'], dict) and observation['notices'], 'notices missing')
    for path, value in observation['notices'].items():
        parts = PurePosixPath(relative(path)).parts
        require(len(parts) == 2 and parts[0] in names and parts[1] in
                {'LICENSE', 'LICENSE.electron.txt', 'LICENSES.chromium.html'}, 'notice outside text boundary')
        require(observation['directories'][parts[0]].get(parts[1]) == 'file', 'notice not in observation')
        digest(value)
    for path in packaged['versions']:
        parent, name = path.split('/')
        require(observation['directories'][parent].get(name) == 'file', 'version artifact missing')


def no_link(path):
    attributes = getattr(path.lstat(), 'st_file_attributes', 0)
    require(not (attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT) and not path.is_symlink(),
            'linked observation entry')


def observe(root, packaged):
    no_link(root)
    root = root.resolve()
    require(root.is_dir(), 'packaged root unavailable')
    directories = {}
    for directory in sorted(root.iterdir()):
        no_link(directory)
        require(directory.is_dir(), 'unexpected packaged root entry')
        children = {}
        for path in sorted(directory.iterdir()):
            no_link(path)
            require(path.is_file() or path.is_dir(), 'unsupported packaged entry')
            children[path.name] = 'directory' if path.is_dir() else 'file'
        directories[directory.name] = children
    notices = {}
    for name in packaged['observation']['notices']:
        path = root / name
        no_link(path)
        notices[name] = sha(path.read_bytes())
    return {'directories': directories, 'notices': notices}


def matrix_check(root, metadata, registry):
    revision = metadata['design']['commit']
    origin(root, metadata['design']['repository'])
    require(commit(root, revision) == revision, 'Design commit mismatch')
    for matrix in registry['matrices']:
        identity = metadata['matrices'][matrix['id']]
        data = normalized(git(root, 'show', revision + ':' + identity['path']))
        require(sha(data) == identity['sha256'], 'matrix digest mismatch: ' + matrix['id'])
        text = data.decode('utf-8')
        rows = re.findall(r'<a id="rule-' + matrix['prefix'] + r'-(\d{2})"></a>', text)
        require(rows == [f'{x:02}' for x in range(1, matrix['rows'] + 1)], 'matrix row set mismatch')
        for key in matrix['sources']:
            source = metadata['sources'][key]
            require('`' + source['abbreviation'] + '`' in text and 'github.com/' + source['repository'] in text,
                    'matrix source identity mismatch: ' + key)
        if matrix['id'] == 'distribution':
            require('Not a git repository' in text and all(v in text for v in metadata['packaged']['versions'].values()),
                    'packaged matrix identity mismatch')


def tree(root, revision):
    result = {}
    for entry in filter(None, git(root, 'ls-tree', '-r', '-z', revision).split(b'\0')):
        data, path = entry.split(b'\t', 1)
        mode, kind, oid = data.decode().split()
        result[path.decode('utf-8')] = {'mode': mode, 'type': kind, 'object': oid}
    return result


def drift(root, source, candidate):
    origin(root, source['repository'])
    before = state(root)
    baseline = commit(root, source['commit'])
    target = commit(root, candidate)
    old, new = tree(root, baseline), tree(root, target)
    changes = []
    for path in sorted(old.keys() | new.keys()):
        if old.get(path) != new.get(path):
            kind = 'added' if path not in old else 'removed' if path not in new else 'modified'
            changes.append({'path': path, 'kind': kind, 'before': old.get(path), 'after': new.get(path)})
    require(state(root) == before, 'reference changed during drift inspection')
    return {'repository': source['repository'], 'baseline': baseline, 'candidate': target,
            'workingTree': before, 'changes': changes,
            'assessment': 'required' if changes or before['dirty'] else 'no-source-delta',
            'scopeAssessment': 'owned-by-consuming-maintenance-substep',
            'contentsRead': False}


def verify(root, local, packaged_root=None, drift_id=None, candidate=None):
    registry, metadata = read(root / POLICY), read(root / META)
    validate(registry, metadata)
    require(sha(normalized((root / META).read_bytes())) == registry['metadata']['sha256'], 'metadata digest mismatch')
    active_sources = {s for row in registry['matrices'] for s in row['sources']}
    allowed = {'design'} | active_sources
    require(set(local) <= allowed, 'unknown local source')
    receipts = {}
    with ExitStack() as stack:
        identities = {'design': metadata['design'], **{k: metadata['sources'][k] for k in active_sources}}
        roots = {}
        for key, identity in identities.items():
            target = local.get(key)
            if target is None:
                target = stack.enter_context(remote_snapshot(identity['repository'], identity['commit']))
            require(target.is_dir(), 'source root unavailable: ' + key)
            origin(target, identity['repository'])
            snapshot = state(target)
            require(commit(target, identity['commit']) == identity['commit'], 'source commit mismatch')
            receipts[key] = {'repository': identity['repository'], 'commit': identity['commit'],
                             'inspectionRoot': str(target.resolve()),
                             'state': snapshot, 'result': 'resolved'}
            roots[key] = target
        matrix_check(roots['design'], metadata, registry)
        report = {'result': 'passed', 'matrices': len(registry['matrices']), 'gitReferences': len(active_sources),
                  'registrySha256': sha(normalized((root / POLICY).read_bytes())),
                  'metadataSha256': registry['metadata']['sha256'], 'sources': receipts,
                  'packaged': {'result': 'registered-not-reobserved', 'observedOn': metadata['packaged']['observedOn']}}
        if packaged_root is not None:
            require(observe(packaged_root, metadata['packaged']) == metadata['packaged']['observation'], 'packaged observation drift')
            report['packaged']['result'] = 'live-observation-matched'
        if drift_id is not None:
            require(drift_id in active_sources and candidate, 'drift requires source ID and candidate')
            report['drift'] = drift(roots[drift_id], metadata['sources'][drift_id], candidate)
        for key, target in roots.items():
            require(state(target) == receipts[key]['state'], 'source state changed during verification')
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', action='append', default=[], metavar='ID=PATH')
    parser.add_argument('--packaged-root', type=Path)
    parser.add_argument('--drift', choices=[f's{x}' for x in range(1, 7)])
    parser.add_argument('--candidate')
    parser.add_argument('--report', type=Path, default=ROOT / 'artifacts/evidence/reference-baselines.json')
    args = parser.parse_args()
    try:
        local = {}
        for entry in args.source:
            key, sep, path = entry.partition('=')
            require(sep and path and key not in local, 'invalid/duplicate local source mapping')
            local[key] = Path(path).resolve()
        require(bool(args.drift) == bool(args.candidate), 'drift and candidate must be supplied together')
        result = verify(ROOT, local, args.packaged_root, args.drift, args.candidate)
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        result = {'result': 'failed', 'error': str(error) if isinstance(error, ValueError) else type(error).__name__}
    result['verifiedAt'] = datetime.now(timezone.utc).isoformat()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in result.items() if k in {'result', 'error', 'matrices', 'gitReferences', 'packaged'}}))
    return int(result['result'] != 'passed')


if __name__ == '__main__':
    sys.exit(main())
