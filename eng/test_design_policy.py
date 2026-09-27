# SPDX-License-Identifier: AGPL-3.0-only
"""Independent, deliberately corrupted documentation and real Git/CLI fixtures."""

from copy import deepcopy
import json
import posixpath
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import design_corpus as corpus
import design_policy as policy
from design_graph import graph, Graph, design_views, GRAPH_REL, BEGIN, END


INDEX = 'docs/planning/work-packages/README.md'
SEQUENCE = 'docs/planning/implementation-sequence.md'
WP = 'docs/planning/work-packages/01-second.md'
INVARIANT = '| I-001 | Workspace differs from account |'
MAPPING = ('| [I-001](../requirements/01-normative-glossary-and-invariants.md#rule-i-001) | '
           'Workspace differs from account | `fixture.md` | Unit | Independent assertion | `01` | Unit passes |')


def fixture():
    docs = {
        policy.GLOSSARY: '''# Glossary
## 1. Identity
| Term | Space | Meaning |
|---|---|---|
| **Workspace** | domain, wire | An owned workspace. |
## 5. Product terms
### 5.1 Scope
| **ArcScope.Report** / **ArcScope.Annotation** | domain, storage | Two names, preserved as written. |
| **ArcScope.OldView** | retired | Removed by scope. |
## 6. Term spaces
| Space | Meaning |
|---|---|
| domain | A domain concept. |
| wire | A transport concept. |
| UI | A visible concept. |
| storage | A persisted concept. |
| commercial | A sold concept. |
## 7. Invariant catalogue
<a id="rule-i-001"></a>
''' + INVARIANT + '''
<a id="rule-i-002"></a>
| I-002 | Retired by scope: removed distinction |
## 8. Forbidden aliases
| Forbidden / obsolete | Reason | Instead |
|---|---|---|
| Bare local name | Context matters. | Use the qualified name. |
''',
        policy.COVERAGE: '''# Coverage
### 4.2 Mechanism distribution
| Mechanism | Count | Meaning |
|---|---|---|
| Unit | 1 | Active |
| Absence test | 1 | Retired |
| **Total** | **2** | Rows |
### 4.3 Other
## 7. Item-level mapping
''' + MAPPING + '''
| [I-002](../requirements/01-normative-glossary-and-invariants.md#rule-i-002) | Retired by scope: removed distinction | `fixture.md` | Absence test | No removed type | `02` | Absence passes |
''',
        'docs/architecture/fixture.md': '# Fixture\n',
        'docs/architecture/29-design-policy-export.md': '# Authority fixture\n',
        INDEX: '''# Packages
| 00 | First | — |
| 01 | Second | `00` |
| 02 | Third | `01` |
| 20 | Future | — |
## Downstream dependency index
| 00 | `01` |
| 01 | `02` |
| 02 | — |
## Deferred-gate scheduling
''',
        SEQUENCE: '''# Sequence
All 3 active packages
Serial execution: 00, 01, 02.
WP42.11 precedes 42.10.
Total active dependency edges: 2.
## 9. Dependencies
| 00 | — |
| 01 | `00` |
| 02 | `01` |
''',
        'docs/planning/work-packages/20-future.md': '# Future\nNo active edges.\n',
    }
    for key, title, up, down in [('00', 'first', '—', '`01`'), ('01', 'second', '`00`', '`02`'),
                                  ('02', 'third', '`01`', '—')]:
        text = f'<a id="rule-wp-{key}"></a>\n# WP-{key} — Package\n> Upstream: {up} · Downstream: {down}\n'
        for number in range(1, 10):
            text += f'## {number}. Section\n'
            if number == 6:
                text += f'<a id="rule-wp-{key}.90"></a>\n### WP-{key}.90 — Evidence\n'
            elif number == 7:
                text += f'| [WP-{key}.90](#rule-wp-{key}.90) | Evidence is required |\n'
            elif number == 9:
                text += f'**Upstream:** {up}\n**Downstream:** {down}\n'
        docs[f'docs/planning/work-packages/{key}-{title}.md'] = text
    return docs


def register(items=None):
    return {'schemaVersion': 1, 'license': 'AGPL-3.0-only',
            'authority': 'docs/architecture/29-design-policy-export.md', 'classifications': items or []}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / 'design'
        self.root.mkdir()
        self.output = self.root.parent / 'policy'
        self.output.mkdir()
        self.docs = fixture()
        for name, value in self.docs.items():
            self.write(name, value)
        # Small independently authored delivery graph, not a copy of the production graph.
        self.graph_data = {
            'schemaVersion': 1, 'decision': 'P2-018', 'baselineDate': '2026-09-27',
            'paths': {'design': 'Design', 'plan': 'Plan'}, 'sizeUnits': {'S': 1, 'M': 2, 'L': 4, 'XL': 8},
            'repositories': [{'id': 'DesktopPlatform', 'root': 'DesktopPlatform', 'remote': 'ArcForges/DesktopPlatform',
                              'ci': True, 'integrationOwner': 'Fixture owner'}],
            'lanes': [{'id': 'governance', 'prefix': 'GOV', 'repo': 'DesktopPlatform', 'title': 'Governance', 'description': 'Fixture'}],
            'tasks': [], 'adoptionSlices': [], 'substitutes': [], 'sharedResources': [], 'packageObligations': [], 'gates': []}
        for i in range(3):
            self.graph_data['tasks'].append({'id': f'GOV.{i:02}', 'title': f'Task {i}', 'lane': 'governance',
                'repo': 'DesktopPlatform', 'kind': 'governance', 'size': 'S',
                'obligations': [{'ref': f'WP-{i:02}.90', 'part': 'full'}], 'outcome': 'Fixture result',
                'start': [] if i == 0 else [{'type': 'artifact', 'task': f'GOV.{i-1:02}', 'need': 'Input', 'why': 'Required'}],
                'complete': [], 'writes': [], 'validation': 'Offline', 'evidence': 'Fixture receipt',
                'baseline': {'state': 'accepted', 'evidence': 'Accepted fixture'}})
        self.write(GRAPH_REL, json.dumps(self.graph_data))
        for key in ('00-first', '01-second', '02-third'):
            name = f'docs/planning/work-packages/{key}.md'
            body = self.docs[name]
            body = body.split('## 9. Section')[0] + '## 9. Section\n' + BEGIN + '\n' + END + '\n'
            self.docs[name] = body
            self.write(name, body)
        self.docs['docs/planning/delivery/README.md'] = '# Model\n' + ''.join(
            f'<a id="rule-dlv-{i:02}"></a>\n| DLV-{i:02} | Fixture |\n' for i in range(1,43))
        self.docs['docs/decisions/phase-2-specification-decisions.md'] = '# Decisions\n<a id="rule-p2-018"></a>\n## P2-018 — Fixture\n'
        matrix = 'docs/assurance/traceability-matrix.md'
        rows = ['# Decision mapping']
        active_citations = []
        for identity, home in corpus.DECISION_HOMES.items():
            filename = 'phase-1-foundation-decisions.md' if identity.startswith('D-') else 'phase-2-specification-decisions.md'
            definition_path = 'docs/decisions/' + filename
            self.docs.setdefault(definition_path, '# Decisions\n')
            self.docs[definition_path] += f'<a id="rule-{identity.lower()}"></a>\n## {identity} — Fixture\n'
            decision_link = f'[{identity}](../decisions/{filename}#rule-{identity.lower()})'
            status = 'Withdrawn ordering' if identity == 'P2-002' else 'Adopted fixture'
            rows.append(f'| {decision_link} | {status} | [Primary]({home}) | Historical provenance | Checked gate |')
            active_citations.append(decision_link)
        for home in corpus.DECISION_HOMES.values():
            name, _, fragment = home.partition('#')
            path = posixpath.normpath(posixpath.join('docs/assurance', name))
            self.docs.setdefault(path, '# Home\n')
            if fragment and f'id="{fragment}"' not in self.docs[path]:
                self.docs[path] += f'<a id="{fragment}"></a>\n'
        self.docs[matrix] = '\n'.join(rows) + '\n'
        self.docs['docs/architecture/fixture.md'] += '\n'.join(active_citations) + '\n'
        self.docs['docs/assurance/phase-2-design-closure-review.md'] = '# Closure\n' + '\n'.join(
            f'| {i} | Design repair | Owning producer |' for i in range(1, 13)) + '\n'
        for name, body in self.docs.items(): self.write(name, body)
        for name, body in design_views(Graph(self.root)).items(): self.write(name, body)
        self.docs.update(design_views(Graph(self.root)))
        self.write(policy.CLASSIFICATIONS, policy.encode(register()).decode())
        self.git('init', '--quiet')
        self.git('config', 'core.autocrlf', 'false')
        self.git('remote', 'add', 'origin', 'https://github.com/' + policy.REPOSITORY + '.git')
        self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=' + str(self.root / 'no-hooks'),
                 'commit', '--quiet', '-m', 'Independent fixture')
        self.pin = {'schemaVersion': 1, 'license': 'AGPL-3.0-only', 'repository': policy.REPOSITORY,
                    'commit': self.git('rev-parse', 'HEAD'),
                    'sourceHashes': {p: policy.text_hash(corpus.read_document(self.root, p))
                                     for p in [policy.GLOSSARY, policy.COVERAGE, policy.CLASSIFICATIONS, GRAPH_REL]},
                    'corpusSha256': policy.canonical_hash([{'path': p, 'sha256': policy.text_hash(t)}
                                                          for p, t in sorted(self.docs.items())])}
        self.save_pin()

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf8', newline='\n')

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, stderr=subprocess.PIPE).decode().strip()

    def save_pin(self):
        (self.output / 'design-source.json').write_bytes(policy.encode(self.pin))

    def export(self):
        return policy.verify(self.root, self.output, refresh=True)


class ExportTests(Fixture):
    def test_real_git_round_trip_preserves_rows_and_planned_status(self):
        result = self.export()
        self.assertEqual(result['counts'], {'terms': 3, 'names': 4, 'invariants': 2, 'forbiddenAliases': 1})
        vocabulary = policy.read_json(self.output / 'glossary-terms.json')
        self.assertEqual(vocabulary['terms'][1]['names'], ['ArcScope.Report', 'ArcScope.Annotation'])
        self.assertEqual(vocabulary['terms'][2]['spaces'], [])
        mapping = policy.read_json(self.output / 'invariants.json')
        self.assertEqual(mapping['verificationState'], 'planned-only')
        self.assertEqual(mapping['records'][1]['mechanism'], 'Absence test')
        self.assertEqual(mapping['records'][0]['plannedVerification'], 'Independent assertion')
        self.assertEqual(mapping['records'][0]['owningPackages'], ['01'])
        self.assertEqual(policy.verify(self.root, self.output)['outputs'], result['outputs'])

    def test_missing_duplicate_and_edited_export_records_fail(self):
        self.export()
        for name, key in [('glossary-terms.json', 'terms'), ('invariants.json', 'records')]:
            target = self.output / name
            original = target.read_bytes()
            for mutation in ('missing', 'duplicate', 'extra-field', 'reordered'):
                with self.subTest(name=name, mutation=mutation):
                    value = json.loads(original)
                    if mutation == 'missing': value[key].pop()
                    elif mutation == 'duplicate': value[key].append(value[key][0])
                    elif mutation == 'extra-field': value[key][0]['invented'] = True
                    else: value[key].reverse()
                    target.write_bytes(policy.encode(value))
                    with self.assertRaisesRegex(ValueError, 'export drift: ' + name):
                        policy.verify(self.root, self.output)
                    target.write_bytes(original)
            target.unlink()
            with self.assertRaisesRegex(ValueError, 'export drift: ' + name): policy.verify(self.root, self.output)
            target.write_bytes(original)

    def test_dirty_wrong_commit_and_wrong_source_hash_fail(self):
        self.export()
        self.write('README.md', '# Uncommitted\n')
        with self.assertRaisesRegex(ValueError, 'exact clean pinned'): policy.verify(self.root, self.output)
        (self.root / 'README.md').unlink()
        original = deepcopy(self.pin)
        for key in ('commit', 'corpusSha256', 'sourceHashes'):
            self.pin = deepcopy(original)
            if key == 'sourceHashes': self.pin[key][policy.GLOSSARY] = 'f' * 64
            else: self.pin[key] = 'f' * len(self.pin[key])
            self.save_pin()
            with self.subTest(key=key), self.assertRaises(ValueError): policy.verify(self.root, self.output)

    def test_preview_is_read_only_and_reports_dirty_state(self):
        self.export()
        original = {p: p.read_bytes() for p in self.output.iterdir()}
        self.write('README.md', '# Proposed change\n')
        result = policy.verify(self.root, self.output, preview=True)
        self.assertEqual(result['mode'], 'preview')
        self.assertTrue(result['source']['status'])
        self.assertEqual({p: p.read_bytes() for p in self.output.iterdir()}, original)
        with self.assertRaisesRegex(ValueError, 'preview cannot write'):
            policy.verify(self.root, self.output, preview=True, refresh=True)

    def test_cli_reports_real_failure_and_nonzero_exit(self):
        self.export()
        self.write('README.md', '[missing](no-such-file.md)\n')
        receipt = self.root.parent / 'receipt.json'
        result = subprocess.run([sys.executable, str(Path(policy.__file__)), '--design-root', str(self.root),
                                 '--policy-root', str(self.output), '--preview', '--report', str(receipt)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        evidence = policy.read_json(receipt)
        self.assertEqual(evidence['result'], 'failed')
        self.assertIn('README.md', evidence['error'])
        self.assertIn('no-such-file.md', evidence['error'])

    def test_wrong_repository_and_duplicate_json_keys_fail(self):
        self.git('remote', 'set-url', 'origin', 'https://github.com/example/other.git')
        with self.assertRaisesRegex(ValueError, 'repository identity'): self.export()
        target = self.output / 'duplicate.json'
        target.write_text('{"key":1,"key":2}', encoding='utf8')
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'): policy.read_json(target)

    def test_deprecated_bodies_are_excluded_before_reading(self):
        self.write('docs/deprecated-inputs/README.md', '# Historical filenames\n')
        self.write('docs/deprecated-inputs/body.md', '')
        (self.root / 'docs/deprecated-inputs/body.md').write_bytes(b'\xff\xfe\xfa')
        loaded = corpus.load(self.root)
        self.assertIn('docs/deprecated-inputs/README.md', loaded)
        self.assertNotIn('docs/deprecated-inputs/body.md', loaded)

    def test_path_escape_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'escapes Design root'):
            corpus.read_document(self.root, '../private.md')


class SourceTests(Fixture):
    def check_mapping(self, docs):
        return policy.invariants(self.root, docs, self.pin['commit'], {'00', '01', '02'})

    def test_catalogue_mapping_missing_duplicate_statement_owner_home_and_totals(self):
        cases = [
            (policy.GLOSSARY, INVARIANT, '', 'ID sets'),
            (policy.GLOSSARY, INVARIANT, INVARIANT + '\n' + INVARIANT, 'duplicate catalogue'),
            (policy.COVERAGE, MAPPING, '', 'ID sets'),
            (policy.COVERAGE, MAPPING, MAPPING + '\n' + MAPPING, 'duplicate/incomplete mapping'),
            (policy.COVERAGE, 'Workspace differs from account', 'Workspace equals account', 'statement mismatch'),
            (policy.COVERAGE, '`01`', '`20`', 'invalid invariant owner'),
            (policy.COVERAGE, '`fixture.md`', '`missing.md`', 'missing architecture home'),
            (policy.COVERAGE, '| Unit | 1 |', '| Unit | 2 |', 'distribution mismatch'),
            (policy.COVERAGE, '| Absence test | No removed type', '| Unit | No removed type', 'absence test'),
        ]
        for path, old, new, diagnostic in cases:
            with self.subTest(diagnostic=diagnostic):
                docs = dict(self.docs); self.assertIn(old, docs[path]); docs[path] = docs[path].replace(old, new)
                with self.assertRaisesRegex(ValueError, diagnostic): self.check_mapping(docs)

    def test_glossary_rejects_duplicate_names_missing_spaces_and_unqualified_products(self):
        for old, new, diagnostic in [
            ('**ArcScope.Report** / **ArcScope.Annotation**', '**Workspace**', 'duplicate canonical term'),
            ('**ArcScope.Report** / **ArcScope.Annotation**', '**Document**', 'unqualified product'),
            ('### 5.1 Scope\n| **ArcScope.Report** / **ArcScope.Annotation**', '| **Document**', 'unqualified product'),
            ('| domain, wire |', '| mystery |', 'invalid term spaces'),
            ('| domain, wire |', '|  |', 'invalid term spaces'),
        ]:
            docs = dict(self.docs); docs[policy.GLOSSARY] = docs[policy.GLOSSARY].replace(old, new)
            with self.subTest(diagnostic=diagnostic), self.assertRaisesRegex(ValueError, diagnostic):
                policy.glossary(docs, self.pin['commit'])


class CorpusTests(Fixture):
    def audit_texts(self, values):
        for p, t in values.items(): self.write(p, t)
        return corpus.audit(self.root, values)

    def test_scoped_same_spelling_and_lowercase_suffix_relocations(self):
        texts = {'a.md': '<a id="rule-an-01"></a>\n| AN-01 | First |\n',
                 'b.md': '<a id="rule-an-01"></a>\n| AN-01 | Second |\n<a id="rule-v-05a"></a>\n',
                 'c.md': '[AN-01](a.md#rule-an-01) and [explanation AN-01](b.md#rule-an-01)\n[V-05a](b.md#rule-v-05a)\n'}
        result = self.audit_texts(texts)
        self.assertEqual(result['errors'], [])
        self.assertEqual(result['missingAnchors'], [])
        self.assertEqual(len(result['citations']), 3)
        self.assertEqual([x[3] for x in result['citations']], ['a.md', 'b.md', 'b.md'])
        self.assertEqual(len(result['localLinks']), 3)

    def test_missing_duplicate_wrong_home_wrong_anchor_and_compound_labels(self):
        base = '<a id="rule-an-01"></a>\n| AN-01 | First |\n<a id="rule-an-02"></a>\n| AN-02 | Second |\n'
        cases = [
            ('[AN-01](missing.md#rule-an-01)', 'missing target'),
            ('[AN-03](a.md#rule-an-03)', 'missing rule definition'),
            ('[description AN-01](a.md#rule-an-02)', 'wrong rule anchor'),
            ('[AN-01/AN-02](a.md#rule-an-01)', 'wrong rule anchor'),
            ('[AN-01](https://example.invalid/#rule-an-01)', 'external rule home'),
            ('[file](../outside.md)', 'link escapes'),
            ('![diagram](missing.png)', 'missing target'),
            ('[AN-01][rule]\n[rule]: a.md#rule-an-01', 'reference-link syntax'),
        ]
        for value, diagnostic in cases:
            with self.subTest(value=value):
                result = self.audit_texts({'a.md': base, 'b.md': value})
                self.assertIn(diagnostic, repr(result['errors']))
        result = self.audit_texts({'a.md': base + '<a id="rule-an-01"></a>\n| AN-01 | Duplicate |\n'})
        self.assertIn('duplicate anchor', repr(result['errors']))
        self.assertIn('duplicate definition', repr(result['errors']))
        self.assertTrue(self.audit_texts({'a.md': '| AN-01 | Missing anchor |\n'})['missingAnchors'])

    def test_fences_heading_suffixes_reference_findings_and_unclosed_fence(self):
        text = ('# Same\n# Same\n[second](#same-1)\n````example\n```\n'
                '[AN-99](missing.md)\n````\n<a id="rule-f-an-2"></a>\n| F-AN-2 | Finding |\n')
        result = self.audit_texts({'a.md': text})
        self.assertEqual(result['errors'], [])
        self.assertEqual(result['definitions'], 1)
        self.assertEqual(result['links'], 1)
        self.assertIn('duplicate anchor', repr(self.audit_texts({'a.md': '<a id="same"></a>\n# Same\n'})['errors']))
        with self.assertRaisesRegex(ValueError, 'unclosed code fence'): list(corpus.lines('~~~python\nunclosed'))

    def test_unqualified_rules_and_exact_classification_drift(self):
        line = 'Hash uses SHA-256.'
        docs = {'a.md': line + '\n'}
        report = self.audit_texts(docs)
        item = {'path': 'a.md', 'lineSha256': policy.text_hash(line), 'token': 'SHA-256',
                'occurrences': 1, 'kind': 'standard-name', 'reason': 'A standard, not a rule.',
                'reviewOwner': 'Fixture reviewer', 'reviewed': '2026-09-18'}
        self.assertEqual(policy.classify(docs, report, register([item]))['occurrences'], 1)
        for key, value in [('occurrences', 2), ('lineSha256', 'f' * 64), ('kind', 'historical-excerpt')]:
            changed = {**item, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError): policy.classify(docs, report, register([changed]))
        with self.assertRaisesRegex(ValueError, 'duplicate occurrence'):
            policy.classify(docs, report, register([item, item]))
        with self.assertRaises(ValueError): policy.classify(docs, report, register())
        docs = {'a.md': 'Current AN-01 must resolve.\n'}; report = self.audit_texts(docs)
        self.assertEqual(report['raw'][0][2], 'AN-01')
        changed = {**item, 'lineSha256': policy.text_hash(docs['a.md'].strip()), 'token': 'AN-01'}
        with self.assertRaisesRegex(ValueError, 'invalid standard-name context'):
            policy.classify(docs, report, register([changed]))


class GraphTests(Fixture):
    def test_delivery_edges_coverage_owners_and_generated_views(self):
        self.assertEqual(graph(self.root, self.docs)['errors'], [])
        cases = [
            ('unknown task', lambda d: d['tasks'][1]['start'][0].update(task='GOV.99')),
            ('invalid type', lambda d: d['tasks'][1]['start'][0].update(type='unknown')),
            ('lacks need/why', lambda d: d['tasks'][1]['start'][0].update(why='')),
            ('not mapped', lambda d: d['tasks'][0].update(obligations=[{'ref':'P2-018','part':'fixture'}])),
            ('duplicate identifier', lambda d: d['tasks'].append(deepcopy(d['tasks'][0]))),
            ('duplicate identifier', lambda d: d['lanes'].append(deepcopy(d['lanes'][0]))),
            ('unknown repository', lambda d: d['repositories'][0].update(id='ArcNotes')),
            ('deadlock', lambda d: d['tasks'][0]['start'].append({'type':'artifact','task':'GOV.02','need':'cycle','why':'cycle'})),
        ]
        for diagnostic, mutate in cases:
            with self.subTest(diagnostic=diagnostic):
                data=deepcopy(self.graph_data); mutate(data); self.write(GRAPH_REL,json.dumps(data))
                self.assertIn(diagnostic,repr(graph(self.root,self.docs)['errors']))
        self.write(GRAPH_REL,json.dumps(self.graph_data))
        for name in design_views(Graph(self.root)):
            docs=dict(self.docs); docs[name] = docs[name].replace(BEGIN, BEGIN+'\nDrift', 1) if BEGIN in docs[name] else docs[name]+'\nDrift\n'
            self.assertIn('generated view drift',repr(graph(self.root,docs)['errors']))
        for old,new,diagnostic in [
            ('## 8. Section','## 7. Section','duplicate numbered section'),
            ('## 8. Section','## Missing','mandatory sections'),
            ('| [WP-01.90](#rule-wp-01.90) | Evidence is required |','','owned .90')]:
            docs=dict(self.docs);docs[WP]=docs[WP].replace(old,new)
            self.assertIn(diagnostic,repr(graph(self.root,docs)['errors']))
        docs=dict(self.docs);docs[policy.COVERAGE]=docs[policy.COVERAGE].replace('`01`','`20`')
        with self.assertRaisesRegex(ValueError,'invalid invariant owner'):
            policy.invariants(self.root,docs,self.pin['commit'],set(graph(self.root,self.docs)['activePackages']))

    def test_substitute_requires_real_producer_and_every_consumer(self):
        data=deepcopy(self.graph_data)
        data['substitutes']=[{'id':'SUB-fixture','class':'value','standsInFor':'Value','contract':'Fixture',
            'proves':'Parsing','realProducer':['GOV.01'],'replacedBy':'GOV.00','realEvidence':'Actual result'}]
        data['tasks'][2]['substitutes']=['SUB-fixture']
        self.write(GRAPH_REL,json.dumps(data))
        errors=repr(graph(self.root,self.docs)['errors'])
        self.assertIn('does not depend on real producer',errors)
        self.assertIn('does not depend on consumer',errors)


class SpecificationIntegrityTests(unittest.TestCase):
    def test_new_or_modified_superseded_name_cannot_reuse_a_classification(self):
        path = 'docs/architecture/names.md'
        old = 'ArcCanvas is excluded.'
        exact = {(path, policy.text_hash(old)): 1}
        self.assertEqual(corpus.superseded_names({path: old}, exact)['findings'], [])
        for changed in (old + ' Ship ArcCanvas now.', old + '\n' + old, 'Ship arccanvas now.'):
            self.assertTrue(corpus.superseded_names({path: changed}, exact)['findings'])
        self.assertTrue(corpus.superseded_names({'docs/architecture/new.md': old}, exact)['findings'])
        self.assertEqual(corpus.superseded_names({path: 'ArcImageNative is a logical library.'}, {})['findings'], [])

    def test_archived_inputs_cannot_become_authority_through_tables_or_renames(self):
        bad = [
            ('docs/requirements/new.md', '> Governing authority: I1'),
            ('docs/planning/work-packages/new.md', '| Required input | I2 section III |'),
            ('docs/architecture/data-model/new.md', 'Acceptance: Stage 13 §49'),
            ('docs/assurance/new-gate.md', '[source](../deprecated-inputs/%72enamed.md)'),
            ('docs/architecture/new.md', '[source](../inputs/arbitrary-new-name.md)'),
            ('docs/architecture/new.md', 'Read platform-architecture-concept.md.'),
        ]
        for path, text in bad:
            with self.subTest(path=path, text=text):
                self.assertTrue(corpus.archived_input_dependencies({path: text})['findings'])

    def test_formal_rules_archive_navigation_and_dated_history_remain_distinct(self):
        docs = {
            'docs/architecture/new.md': '[I-001](../requirements/rules.md#rule-i-001)',
            'docs/planning/README.md': '[Archive navigation](../deprecated-inputs/README.md) is not an input.',
            'docs/planning/new.md': 'The Stage 2 repair is historical evidence.',
            'docs/assurance/phase-1-official-verification.md': 'Original input I4 §Stage 11.30.',
        }
        report = corpus.archived_input_dependencies(docs)
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['documents'], 3)
        self.assertEqual(report['historicalRecords'], ['docs/assurance/phase-1-official-verification.md'])

    def test_semantic_decision_home_and_withdrawn_successor_are_checked(self):
        path = 'docs/assurance/traceability-matrix.md'
        row = '| [P2-002](../decisions/phase-2-specification-decisions.md#rule-p2-002) | Withdrawn ordering | [Effective successor](../decisions/phase-2-specification-decisions.md#rule-p2-004) | Historical provenance | No executable obligation |'
        good = corpus.decision_coverage({path: row}, [])
        self.assertFalse(any('wrong primary' in str(x) or 'treated as active' in str(x) for x in good['findings']))
        for broken in (row.replace('#rule-p2-004', '#rule-p2-003'), row.replace('Withdrawn ordering', 'Adopted ordering')):
            result = corpus.decision_coverage({path: broken}, [])
            self.assertTrue(any('wrong primary' in str(x) or 'treated as active' in str(x) for x in result['findings']))

    def test_valid_anchor_for_wrong_decision_and_duplicate_group_fail(self):
        path = 'docs/assurance/traceability-matrix.md'
        row = '| [D-003](../decisions/phase-1-foundation-decisions.md#rule-d-002) | Verification | `open-gates-register.md` | Active references | Gates |'
        closure = 'docs/assurance/phase-2-design-closure-review.md'
        docs = {path: row, closure: '\n'.join(f'| {i} | Design | Producer |' for i in [*range(1, 12), 11])}
        result = corpus.decision_coverage(docs, [])
        self.assertTrue(any('wrong decision definition' in str(x) for x in result['findings']))
        self.assertTrue(any('closure groups' in str(x) for x in result['findings']))
        self.assertTrue(any('active Phase 2 citation' in str(x) for x in result['findings']))


if __name__ == '__main__':
    unittest.main()
