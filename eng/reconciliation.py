# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only WP01.00 current/historical project and directory reconciliation."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import licence_boundary as inventory
import runtime_ownership as runtime

ROOT = Path(__file__).resolve().parents[1]
STORE = 'eng/policy/reconciliation/'
OWNERS = set(inventory.OWNERS)
ACTIONS = {'Keep', 'Move', 'Retire'}


def require(value, message):
    if not value:
        raise ValueError(message)


def read(name):
    return json.loads(inventory.read(ROOT, STORE + name + '.json'), object_pairs_hook=inventory.unique)


def tree(root, ref):
    result = {}
    for line in inventory.git(root, 'ls-tree', '-r', ref).splitlines():
        metadata, name = line.split('\t', 1)
        mode, kind, blob = metadata.split()
        require(mode not in {'160000', '120000'}, 'linked source/submodule: ' + name)
        require(kind == 'blob', 'unexpected tree entry')
        result[name] = blob
    return result


def decisions(rows, fields, key, *, historical=False):
    seen = set()
    for row in rows:
        runtime.fields(row, fields)
        identity = tuple(row[k] for k in key)
        require(identity not in seen, 'duplicate item: ' + repr(identity))
        seen.add(identity)
        runtime.path(row['path'])
        require(row['disposition'] in ACTIONS, 'invalid disposition')
        require(isinstance(row['producer'], str) and re.fullmatch(r'WP\d{2}(?:\.\d{2})?', row['producer']), 'missing producer')
        require(isinstance(row['reason'], str) and row['reason'].strip(), 'missing reason')
        if 'owner' in row:
            require(row['owner'] in (OWNERS | {'ArcNotes', 'ArcSlate'} if historical else OWNERS), 'unknown owner')
    return seen


def validate(source, current, historical, directories, native):
    runtime.fields(source, 'schemaVersion substep observedOn historicalCommit designCommit designFiles counts')
    require(source['schemaVersion'] == 1 and source['substep'] == 'WP01.00', 'invalid source schema')
    runtime.digest(source['historicalCommit']); runtime.digest(source['designCommit'])
    require(source['historicalCommit'] == 'ede43db5b2237104dd0008b99398090c54a2cf94', 'historical baseline changed')
    require(set(source['designFiles']) == {'docs/assurance/wp01-00-inventory-policy.md', 'docs/assurance/wp00-stage-acceptance.json', 'docs/architecture/27-platform-projects-and-application-assistants.md', 'docs/architecture/01-solution-and-project-layout.md'}, 'incomplete authority')
    for digest in source['designFiles'].values(): runtime.digest(digest, 64)
    require(len(current) == len(OWNERS) and {r['repository'] for r in current} == OWNERS, 'missing or duplicate owner')
    for row in current:
        runtime.fields(row, 'repository origin commit tree clean worktrees candidate mainCi projects')
        require(row['origin'] == 'https://github.com/ArcForges/' + row['repository'] + '.git', 'wrong origin')
        runtime.digest(row['commit']); runtime.digest(row['tree'])
        require(row['clean'] is True, 'unclean recorded primary')
        require(row['candidate']['sourceCommit'] == row['commit'], 'candidate source mismatch')
        require(row['mainCi'].startswith('https://github.com/ArcForges/' + row['repository'] + '/actions/runs/'), 'wrong CI owner')
        require(row['worktrees'], 'missing worktree observations')
        for worktree in row['worktrees']:
            runtime.fields(worktree, 'path commit branch clean')
            runtime.digest(worktree['commit'])
            require(type(worktree['clean']) is bool and worktree['path'] and worktree['branch'], 'invalid worktree observation')
        decisions(row['projects'], 'path blob disposition producer reason', ['path'])
        for project in row['projects']: runtime.digest(project['blob'])
    decisions(historical, 'path blob observedInDesktopPlatform owner target disposition producer reason', ['path'], historical=True)
    for row in historical:
        runtime.digest(row['blob']); runtime.path(row['target'])
        require(row['observedInDesktopPlatform'] in {'absent', 'changed', 'unchanged'}, 'invalid historical observation')
    keys = decisions(directories, 'owner path disposition present producer reason', ['owner', 'path'])
    for row in directories: require(type(row['present']) is bool, 'invalid presence')
    for row in historical:
        if row['owner'] in OWNERS: require((row['owner'], row['target']) in keys, 'unassigned historical target')
    for row in current:
        for project in row['projects']:
            parent = Path(project['path']).parent.as_posix()
            require(parent == '.' or (row['repository'], parent) in keys, 'unassigned current project directory')
    decisions(native, 'path owner disposition producer present reason', ['path'])
    require({r['path'] for r in native} == {'native/' + n for n in ['arcgraphics-metal-abi', 'arcmedia-ffmpeg-abi', 'arcscope-mdf-abi', 'arcslate-color-abi', 'arcslate-image-abi', 'arcslate-otio-abi', 'shared']}, 'incomplete historical native inventory')
    require(all(r['owner'] == 'DesktopPlatform' for r in native), 'native producer outside platform')
    require(len(historical) == 166, 'incomplete historical project inventory')
    require(source['counts'] == {'owners':len(current), 'projects':sum(len(r['projects']) for r in current), 'historical':len(historical), 'directories':len(directories), 'native':len(native)}, 'inventory count drift')


def check_projects(root, row, files, pinned):
    require(inventory.git(root, 'remote', 'get-url', 'origin').removesuffix('.git') == row['origin'].removesuffix('.git'), 'origin drift')
    expected = {r['path']: r['blob'] for r in row['projects']}
    actual = {p:b for p,b in files.items() if inventory.kind(p)}
    require(set(actual) == set(expected), 'current project set drift: ' + row['repository'])
    require(not pinned or actual == expected, 'pinned project blob drift')
    # The established checker rejects escaped project references, local npm/Gradle imports and gitlinks.
    audited = inventory.audit(root, row['repository'])
    require({p['path'] for p in audited['projects']} == set(expected), 'working project inventory drift')
    return audited


def reviewed_projects(row, updates):
    expected = {p['path']:p['blob'] for p in row['projects']}
    seen = set()
    for update in updates:
        runtime.fields(update, 'repository path originalBlob reviewedBlob producer authorityCommit authorityPath reason')
        require(update['repository'] == 'DesktopPlatform', 'project update outside implementation owner')
        runtime.path(update['path']); runtime.path(update['authorityPath'])
        for key in ['originalBlob', 'reviewedBlob', 'authorityCommit']: runtime.digest(update[key])
        require(re.fullmatch(r'WP\d{2}\.\d{2}', update['producer']) and update['reason'].strip(), 'unowned project update')
        require(update['path'] not in seen, 'duplicate project update')
        seen.add(update['path'])
        if row['repository'] == update['repository']:
            require(expected.get(update['path']) == update['originalBlob'], 'project update baseline mismatch')
            require(update['reviewedBlob'] != update['originalBlob'], 'empty project update')
            expected[update['path']] = update['reviewedBlob']
    return dict(row, projects=[dict(project, blob=expected[project['path']]) for project in row['projects']])


def check_history(files, historical, platform_files):
    actual = {p:b for p,b in files.items() if p.endswith('.csproj')}
    require(actual == {r['path']:r['blob'] for r in historical}, 'historical project/blob drift')
    for row in historical:
        observed = 'absent' if row['path'] not in platform_files else 'unchanged' if platform_files[row['path']] == row['blob'] else 'changed'
        require(row['observedInDesktopPlatform'] == observed, 'historical disposition observation drift: ' + row['path'])


def check_directories(directories, trees):
    for row in directories:
        present = any(p.startswith(row['path'] + '/') for p in trees[row['owner']])
        require(row['present'] == present, 'directory presence drift: ' + row['owner'] + '/' + row['path'])



# Frozen current/native/directories are accepted historical receipts. This separate
# reviewed active inventory evolves by producer tasks without inventing a new
# publication receipt for the historical source snapshot.
RETIRED_NATIVE = ('native/arcmedia-ffmpeg-abi/', 'native/arcslate-color-abi/',
                  'native/arcslate-otio-abi/', 'native/arcgraphics-metal-abi/',
                  'native/arcslate-image-abi/', 'src/Native/ArcForges.Native.Media',
                  'src/Native/ArcForges.Native.Colour', 'src/Native/ArcForges.Native.Otio')

def check_retirement(files):
    require(not any(path.startswith(RETIRED_NATIVE) for path in files), 'retired native binding restored')
    require(any(path.startswith('native/arcimage-abi/') for path in files), 'retained image family missing')


def active_projects(row):
    value = read('active-projects')
    runtime.fields(value, 'schemaVersion authority projects')
    require(value['schemaVersion'] == 1 and value['authority'] == 'GOV.18', 'invalid active inventory authority')
    projects = value['projects']
    require(isinstance(projects, list) and projects, 'empty active project inventory')
    seen = set()
    for item in projects:
        runtime.fields(item, 'path blob'); runtime.path(item['path']); runtime.digest(item['blob'])
        require(item['path'] not in seen and inventory.kind(item['path']), 'duplicate or invalid active project')
        require(not item['path'].startswith(RETIRED_NATIVE), 'retired native project in active inventory')
        seen.add(item['path'])
    return dict(row, projects=projects)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', action='append', help='Owner=absolute-root; all seven, read-only, fresh observation')
    parser.add_argument('--design-root', type=Path)
    parser.add_argument('--report', type=Path, default=ROOT/'artifacts/evidence/reconciliation.json')
    args = parser.parse_args()
    report = {'substep':'WP01.00', 'checkedAt':datetime.now(timezone.utc).isoformat(), 'mode':'fresh-family' if args.repository else 'immutable-snapshots-with-current-platform', 'repositories':[], 'limitations':'Inventory/policy only; candidate identities refer to the bound WP00 receipt, not a new provider/device/product run.'}
    try:
        source, current, historical, directories, native = [read(n) for n in ['source','current','historical','directories','native']]
        validate(source, current, historical, directories, native)
        with tempfile.TemporaryDirectory(prefix='arcforges-reconciliation-') as temp:
            parent = Path(temp)
            design = args.design_root.resolve() if args.design_root else runtime.checkout(parent, 'ArcForges-Design', source['designCommit'])
            bodies = {}
            for path, digest in source['designFiles'].items():
                body = subprocess.check_output(['git','-C',str(design),'show',source['designCommit']+':'+path]).replace(b'\r\n',b'\n')
                require(hashlib.sha256(body).hexdigest() == digest, 'authority drift: ' + path)
                bodies[path] = body
            receipt = json.loads(bodies['docs/assurance/wp00-stage-acceptance.json'])
            expected_receipts = {r['owner']:r for r in receipt['owners']}
            roots = {}
            if args.repository:
                for entry in args.repository:
                    owner, sep, location = entry.partition('=')
                    require(sep and owner in OWNERS and owner not in roots and Path(location).is_absolute(), 'invalid repository selection')
                    roots[owner] = Path(location).resolve()
                require(set(roots) == OWNERS and len({str(p) for p in roots.values()}) == len(OWNERS), 'fresh audit requires seven independent roots')
            else:
                for row in current:
                    n = row['repository']
                    roots[n] = ROOT if n == 'DesktopPlatform' else runtime.checkout(parent, n, row['commit'])
            before = {n:(inventory.git(p,'rev-parse','HEAD'),inventory.git(p,'status','--porcelain')) for n,p in roots.items()}
            pinned_trees = {}
            actual_trees = {}
            for row in current:
                n = row['repository']; root = roots[n]
                require(row['candidate'] == expected_receipts[n]['candidate'] and row['mainCi'] == expected_receipts[n]['mainCi'], 'published receipt mismatch')
                require(inventory.git(root,'rev-parse',row['commit']+'^{tree}') == row['tree'], 'snapshot tree identity mismatch')
                pinned_trees[n] = tree(root, row['commit'])
                require({p:b for p,b in pinned_trees[n].items() if inventory.kind(p)} == {p['path']:p['blob'] for p in row['projects']}, 'recorded project blob mismatch')
                files = tree(root, 'HEAD')
                actual_trees[n] = files
                active_row = active_projects(row) if n == 'DesktopPlatform' else row
                audit = check_projects(root, active_row, files, pinned=True)
                report['repositories'].append({'repository':n,'commit':before[n][0],'clean':not bool(before[n][1]),'snapshotCommit':row['commit'],'snapshotIsHead':before[n][0]==row['commit'],'projects':len(audit['projects']),'result':'passed'})
            check_history(tree(roots['DesktopPlatform'], source['historicalCommit']), historical, pinned_trees['DesktopPlatform'])
            check_directories(directories, pinned_trees)
            check_directories(native, pinned_trees)
            check_directories([x for x in directories if x['owner'] != 'DesktopPlatform'], actual_trees)
            check_retirement(actual_trees['DesktopPlatform'])
            require(before == {n:(inventory.git(p,'rev-parse','HEAD'),inventory.git(p,'status','--porcelain')) for n,p in roots.items()}, 'source changed during audit')
            report.update(result='passed',counts=source['counts'],historicalCommit=source['historicalCommit'],designCommit=source['designCommit'])
        code = 0
    except (ValueError,OSError,KeyError,TypeError,subprocess.CalledProcessError) as error:
        report.update(result='failed',error=str(error)); code=1
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:report[k] for k in ['result','counts','error'] if k in report}))
    return code


if __name__ == '__main__':
    sys.exit(main())
