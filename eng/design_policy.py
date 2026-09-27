# SPDX-License-Identifier: AGPL-3.0-only
"""Export and verify Design policy data at a reviewed immutable source commit."""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import design_corpus as corpus
from design_graph import graph, GRAPH_REL

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'eng/policy'
REPOSITORY = 'ArcForges/ArcForges-Design'
GLOSSARY = 'docs/requirements/01-normative-glossary-and-invariants.md'
COVERAGE = 'docs/assurance/invariant-coverage.md'
CLASSIFICATIONS = 'docs/assurance/citation-classifications.json'
SPACES = {'domain', 'wire', 'UI', 'storage', 'commercial'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def closed(value, names, label):
    require(isinstance(value, dict) and set(value) == set(names.split()), f'{label}: unexpected/missing fields')


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f'duplicate JSON key: {key}')
        result[key] = value
    return result


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique_keys)


def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':')).encode()).hexdigest()


def text_hash(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root).decode('utf-8').strip()


def state(root):
    require(Path(git(root, 'rev-parse', '--show-toplevel')).resolve() == root, 'Design root must be a Git repository root')
    remote = git(root, 'remote', 'get-url', 'origin')
    require(remote in {f'https://github.com/{REPOSITORY}.git', f'https://github.com/{REPOSITORY}',
                       f'git@github.com:{REPOSITORY}.git'}, 'incorrect Design repository identity')
    return {'commit': git(root, 'rev-parse', 'HEAD'), 'status': git(root, 'status', '--porcelain=v1')}


@contextmanager
def checkout(pin):
    """Only documentation is read; no Design program or repository hook is run."""
    with tempfile.TemporaryDirectory(prefix='arcforges-design-policy-') as directory:
        root = Path(directory)
        commands = [
            ['init', '--quiet'],
            ['remote', 'add', 'origin', f'https://github.com/{REPOSITORY}.git'],
            ['-c', 'core.autocrlf=false', 'fetch', '--quiet', '--depth=1', 'origin', pin['commit']],
            ['-c', 'core.autocrlf=false', '-c', 'core.hooksPath=' + str(root / 'no-hooks'),
             'checkout', '--quiet', '--detach', 'FETCH_HEAD'],
        ]
        for command in commands:
            subprocess.run(['git', *command], cwd=root, check=True)
        yield root


def validate_pin(pin):
    closed(pin, 'schemaVersion license repository commit sourceHashes corpusSha256', 'Design pin')
    require(pin['schemaVersion'] == 1 and type(pin['schemaVersion']) is int, 'unsupported pin schema')
    require(pin['license'] == 'AGPL-3.0-only' and pin['repository'] == REPOSITORY, 'incorrect pin ownership')
    require(isinstance(pin['commit'], str) and re.fullmatch('[0-9a-f]{40}', pin['commit']), 'invalid Design commit')
    require(isinstance(pin['sourceHashes'], dict) and set(pin['sourceHashes']) == {GLOSSARY, COVERAGE, CLASSIFICATIONS, GRAPH_REL},
            'incomplete policy sources')
    for value in [pin['corpusSha256'], *pin['sourceHashes'].values()]:
        require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'invalid Design source hash')
    return pin


def source_ref(path, docs, commit):
    return {'repository': REPOSITORY, 'commit': commit, 'path': path, 'sha256': text_hash(docs[path])}


def glossary(docs, commit):
    terms, aliases, spaces = [], [], []
    section = None
    names_seen = set()
    for number, line in corpus.lines(docs[GLOSSARY]):
        heading = re.match(r'^#{2,3} (\d+(?:\.\d+)*)\.?\s', line)
        if heading:
            section = heading[1]
        if not line.startswith('|') or section is None:
            continue
        cs = corpus.cells(line)
        if not cs or all(re.fullmatch(r':?-+:?', c) for c in cs):
            continue
        if cs[0] in {'Term', 'Space', 'Forbidden / obsolete', '#'}:
            continue
        if int(section.split('.')[0]) in range(1, 6):
            require(len(cs) == 3, f'{GLOSSARY}:{number}: term row must have three cells')
            spellings = re.findall(r'\*\*([^*]+)\*\*|`([^`]+)`', cs[0])
            names = [name for pair in spellings for part in pair if part for name in part.split(' / ')]
            require(names and all(name and name == name.strip() for name in names), f'invalid term at {number}')
            require(not (set(names) & names_seen) and len(names) == len(set(names)), f'duplicate canonical term at {number}')
            names_seen.update(names)
            retired = cs[1] == 'retired'
            term_spaces = [] if retired else cs[1].split(', ')
            require(retired or (set(term_spaces) <= SPACES and len(set(term_spaces)) == len(term_spaces)),
                    f'invalid term spaces at {number}')
            require(retired or term_spaces, f'missing term spaces at {number}')
            namespaces = {name.rsplit('.', 1)[0] if '.' in name else 'shared' for name in names}
            require(len(namespaces) == 1, f'mixed term namespaces at {number}')
            if section.split('.', 1)[0] == '5':
                require(all('.' in name for name in names), f'unqualified product term at {number}')
            terms.append({'section': section, 'line': number, 'term': cs[0], 'names': names,
                          'namespace': next(iter(namespaces)), 'spaces': term_spaces,
                          'status': 'retired' if retired else 'active', 'definition': cs[2]})
        elif section == '6':
            require(len(cs) == 2, f'invalid space row at {number}')
            name = corpus.visible(cs[0])
            spaces.append({'name': name if name == 'UI' else name.lower(), 'label': cs[0], 'rule': cs[1]})
        elif section == '8':
            require(len(cs) == 3 and all(cs), f'invalid forbidden-alias row at {number}')
            aliases.append({'section': section, 'line': number, 'term': cs[0], 'reason': cs[1], 'instead': cs[2]})
    require(terms and aliases and len(spaces) == len(SPACES) and {x['name'] for x in spaces} == SPACES,
            'missing glossary tables or term-space definitions')
    return {'schemaVersion': 1, 'license': 'AGPL-3.0-only', 'source': source_ref(GLOSSARY, docs, commit),
            'spaces': spaces, 'terms': terms, 'forbiddenAliases': aliases}


def invariants(root, docs, commit, active):
    catalogue, mapping = {}, {}
    for number, line in corpus.lines(docs[GLOSSARY]):
        if line.startswith('|') and (m := re.fullmatch(r'I-\d{3}', corpus.visible(corpus.cells(line)[0]).strip())):
            key = m[0]
            require(key not in catalogue, f'duplicate catalogue invariant {key}')
            cs = corpus.cells(line)
            require(len(cs) == 2, f'invalid catalogue row {key}')
            catalogue[key] = (cs[1], number)
    section = docs[COVERAGE].split('## 7. Item-level mapping', 1)
    require(len(section) == 2, 'missing invariant coverage section 7')
    body = section[1].split('\n## ', 1)[0]
    first_line = docs[COVERAGE].split('## 7. Item-level mapping', 1)[0].count('\n') + 1
    for coverage_line, line in enumerate(body.splitlines(), first_line):
        if not line.startswith('|'):
            continue
        cs = corpus.cells(line)
        key = corpus.visible(cs[0])
        if not re.fullmatch(r'I-\d{3}', key):
            continue
        require(key not in mapping and len(cs) == 7 and all(cs), f'duplicate/incomplete mapping {key}')
        require(key in catalogue, f'catalogue/mapping ID sets differ: missing {key} from catalogue')
        require(corpus.visible(catalogue[key][0]) == corpus.visible(cs[1]),
                f'catalogue/mapping statement mismatch {key}')
        owners = {a or b for a, b in re.findall(r'WP-(\d{2})|`(\d{2})`', cs[5])}
        require(owners and owners <= active, f'invalid invariant owner {key}: {sorted(owners)}')
        retired = corpus.visible(cs[1]).startswith('Retired by ')
        mechanism = corpus.visible(cs[3])
        require(not retired or mechanism == 'Absence test', f'retired invariant lacks absence test: {key}')
        for name in re.findall(r'`([^`]+\.md)`', cs[2]):
            path = (root / 'docs/architecture' / name).resolve()
            require(path.is_relative_to(root) and path.is_file(), f'missing architecture home {key}: {name}')
        mapping[key] = {'id': key, 'status': 'retired' if retired else 'active',
                        'section': '7', 'catalogueLine': catalogue[key][1], 'coverageLine': coverage_line,
                        'statement': catalogue[key][0],
                        'architectureHome': cs[2], 'mechanism': mechanism, 'plannedVerification': cs[4],
                        'owningPackages': sorted(owners), 'ownerCell': cs[5], 'completionGate': cs[6]}
    require(catalogue and catalogue.keys() == mapping.keys(), 'catalogue/mapping ID sets differ or are empty')
    counts = Counter(x['mechanism'] for x in mapping.values())
    summary = docs[COVERAGE].split('### 4.2 Mechanism distribution', 1)[1].split('\n### ', 1)[0]
    declared = {}
    for line in summary.splitlines():
        cs = corpus.cells(line)
        if len(cs) == 3 and corpus.visible(cs[1]).isdigit():
            name = corpus.visible(cs[0]); require(name not in declared, 'duplicate mechanism summary')
            declared[name] = int(corpus.visible(cs[1]))
    require(declared.pop('Total', None) == len(mapping) and declared == dict(counts), 'mechanism distribution mismatch')
    return {'schemaVersion': 1, 'license': 'AGPL-3.0-only',
            'sources': [source_ref(p, docs, commit) for p in [GLOSSARY, COVERAGE]],
            'verificationState': 'planned-only', 'records': list(mapping.values())}


def classification_context(item, docs):
    """An exact hash cannot turn a current rule into an unrelated exception kind."""
    path, token, kind = item['path'], item['token'], item['kind']
    require(path in docs, 'classification source missing: ' + path)
    matching = [line for _, line in corpus.lines(docs[path]) if text_hash(line) == item['lineSha256']]
    require(matching, 'classification line changed: ' + path)
    if kind == 'standard-name':
        valid = token in corpus.STANDARD
    elif kind == 'reserved-allocation':
        valid = (path == COVERAGE and re.fullmatch(r'I-\d{3}', token)
                 and all(len(corpus.cells(line)) == 5 and f'`{token}`' in corpus.cells(line)[-1]
                         for line in matching))
    elif kind == 'historical-excerpt':
        valid = path == 'docs/assurance/review-remediation-term-ledger.md'
    elif kind == 'historical-review-finding':
        valid = (path == 'docs/decisions/phase-2-specification-decisions.md'
                 and re.fullmatch(r'IRF-\d{2}', token)
                 and all(line in docs[path].split('## P2-013 ', 1)[-1].split('\n## ', 1)[0]
                         for line in matching))
    else:
        valid = (path == 'docs/decisions/phase-1-foundation-decisions.md'
                 and all(line.startswith('> ') for line in matching))
    require(valid, f'invalid {kind} context: {path}: {token}')


def classify(docs, report, register):
    closed(register, 'schemaVersion license authority classifications', 'citation register')
    require(type(register['schemaVersion']) is int and register['schemaVersion'] == 1
            and register['license'] == 'AGPL-3.0-only', 'invalid citation register')
    require(register['authority'] == 'docs/architecture/29-design-policy-export.md', 'invalid classification authority')
    observed = Counter((p, text_hash(line), key) for p, _, key, _, line in report['raw'])
    for p, text in docs.items():
        for _, line in corpus.lines(text):
            spans = [m.span() for m in corpus.LINK.finditer(line)] + [m.span() for m in corpus.ANCHOR.finditer(line)]
            for match in corpus.ID.finditer(line):
                if match[0] in corpus.STANDARD and not any(a <= match.start() < b for a, b in spans):
                    observed[p, text_hash(line), match[0]] += 1
    expected = {}
    kinds = {'reserved-allocation', 'historical-excerpt', 'historical-review-finding', 'historical-quotation', 'standard-name'}
    require(isinstance(register['classifications'], list), 'classification records must be an array')
    for item in register['classifications']:
        closed(item, 'path lineSha256 token occurrences kind reason reviewOwner reviewed', 'classification')
        require(all(isinstance(item[k], str) and item[k].strip() for k in
                    ('path', 'lineSha256', 'token', 'kind', 'reason', 'reviewOwner', 'reviewed')),
                'invalid classification values')
        require(re.fullmatch('[0-9a-f]{64}', item['lineSha256']), 'invalid classification line hash')
        key = item['path'], item['lineSha256'], item['token']
        require(key not in expected, 'duplicate occurrence classification')
        require(item['kind'] in kinds and type(item['occurrences']) is int and item['occurrences'] > 0,
                'invalid classification kind/count')
        require(item['reason'].strip() and item['reviewOwner'].strip() and re.fullmatch(r'\d{4}-\d{2}-\d{2}', item['reviewed']),
                'classification lacks review/rationale')
        classification_context(item, docs)
        expected[key] = item['occurrences']
    require(observed == Counter(expected), 'unclassified citation or changed/unused occurrence classification: '
            + repr(list((observed - Counter(expected)).keys())[:3]) + ' / '
            + repr(list((Counter(expected) - observed).keys())[:3]))
    return {'records': len(expected), 'occurrences': sum(observed.values()), 'items': register['classifications']}


def verify(root, policy_root, *, refresh=False, preview=False):
    pin = validate_pin(read_json(policy_root / 'design-source.json'))
    before = state(root)
    require(preview or (not before['status'] and before['commit'] == pin['commit']),
            'immutable export requires the exact clean pinned Design commit')
    docs = corpus.load(root)
    register_text = corpus.read_document(root, CLASSIFICATIONS)
    inputs = {GLOSSARY: text_hash(docs[GLOSSARY]), COVERAGE: text_hash(docs[COVERAGE]), CLASSIFICATIONS: text_hash(register_text), GRAPH_REL: text_hash(corpus.read_document(root, GRAPH_REL))}
    inventory = [{'path': p, 'sha256': text_hash(text)} for p, text in docs.items()]
    digest = canonical_hash(inventory)
    require(preview or (inputs == pin['sourceHashes'] and digest == pin['corpusSha256']), 'pinned Design source hashes differ')
    report = corpus.audit(root, docs)
    require(not report['errors'] and not report['missingAnchors'], 'corpus integrity failure: ' + repr((report['errors'] + report['missingAnchors'])[:5]))
    classifications = classify(docs, report, json.loads(register_text, object_pairs_hook=unique_keys))
    dependency = graph(root, docs)
    require(not dependency['errors'], 'delivery graph failure: ' + repr(dependency['errors'][:5]))
    vocabulary = glossary(docs, before['commit'])
    mapping = invariants(root, docs, before['commit'], set(dependency['activePackages']))
    outputs = {'glossary-terms.json': encode(vocabulary), 'invariants.json': encode(mapping)}
    require(state(root) == before, 'Design changed during verification')
    if refresh:
        require(not preview, 'preview cannot write immutable exports')
        for name, data in outputs.items():
            (policy_root / name).write_bytes(data)
    elif not preview:
        for name, data in outputs.items():
            require((policy_root / name).is_file() and (policy_root / name).read_bytes() == data,
                    f'export drift: {name}; regenerate only after reviewing the pinned source')
    report.pop('raw')
    return {'schemaVersion': 1, 'result': 'passed', 'mode': 'preview' if preview else 'immutable',
            'source': {'repository': REPOSITORY, **before, 'corpusSha256': digest, 'sourceHashes': inputs},
            'counts': {'terms': len(vocabulary['terms']), 'names': sum(len(x['names']) for x in vocabulary['terms']),
                       'invariants': len(mapping['records']), 'forbiddenAliases': len(vocabulary['forbiddenAliases'])},
            'outputs': {name: hashlib.sha256(data).hexdigest() for name, data in outputs.items()},
            'forbiddenAliasesSha256': canonical_hash(vocabulary['forbiddenAliases']),
            'corpus': report, 'classifications': classifications, 'graph': dependency,
            'limitations': 'Policy and planned-verification data only; no implemented invariant or product readiness claim.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--design-root', type=Path, help='Read-only Git source; otherwise fetch the pinned public commit in isolation')
    parser.add_argument('--policy-root', type=Path, default=POLICY)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--refresh', action='store_true', help='Write reviewed exports from the exact clean pin')
    mode.add_argument('--preview', action='store_true', help='Check a proposed Design revision without updating or comparing exports')
    parser.add_argument('--report', type=Path, default=ROOT / 'artifacts/evidence/design-policy.json')
    args = parser.parse_args()
    try:
        if args.design_root:
            report = verify(args.design_root.resolve(), args.policy_root, refresh=args.refresh, preview=args.preview)
        else:
            pin = validate_pin(read_json(args.policy_root / 'design-source.json'))
            with checkout(pin) as root:
                report = verify(root.resolve(), args.policy_root, refresh=args.refresh, preview=args.preview)
        code = 0
    except (ValueError, OSError, subprocess.CalledProcessError, KeyError, IndexError, TypeError) as error:
        report = {'result': 'failed', 'error': str(error)}
        code = 1
    report['verifiedAt'] = datetime.now(timezone.utc).isoformat()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_bytes(encode(report))
    print(json.dumps({key: report[key] for key in ('result', 'counts', 'error') if key in report}))
    return code


if __name__ == '__main__':
    sys.exit(main())
