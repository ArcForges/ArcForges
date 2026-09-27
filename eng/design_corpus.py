# SPDX-License-Identifier: AGPL-3.0-only
"""Document-scoped Markdown integrity checks; no historical programs are executed."""

import collections
import html
import hashlib
import posixpath
import re
import subprocess
from urllib.parse import unquote, urlsplit

ID = re.compile(r'(?<![\w-])(?:WP-\d{2}(?:\.\d{2})?|P2-\d{3}|F-[A-Z]{2}-[1-9]\d*|[A-Z][A-Z0-9]{0,5}-(?:[A-Z]\d{1,3}|\d{2,3}[a-z]?))(?![\w-]|\.\d)')
LINK = re.compile(r'\[([^\]\n]+)\]\(([^)\n]+)\)')
ANCHOR = re.compile(r'<a\s+id="([^"]+)"\s*>\s*</a>')
STANDARD = {'SHA-256', 'SHA-512', 'UTF-16', 'UTF-32', 'IEEE-754', 'P-256'}

# SV-09 keeps these dated extraction/review records distinct from current inputs.
HISTORICAL_INPUT_RECORDS = {
    'phase-1-input-review-ledger.md', 'phase-1-official-verification.md',
    'design-repair-verification.md',
    'phase-2-design-closure-review.md', 'web-typescript-redesign-review.md',
}
HISTORICAL_INPUT_LINES = {
    ('docs/assurance/invariant-coverage.md', 'b7a2ad0647b60e571ea807afe775682f98828db4797337e15cfe643666aa9aae'),
}
ARCHIVED_INPUT = re.compile(
    r'\bI[1-4]\b|\bStage\s+\d+\s*(?:§|Invariant|\.\d)|'
    r'\bdocs[/\\]inputs\b|\bFutureAllCSharp\.md\b|'
    r'(?:platform-architecture-concept|product-discovery-record|'
    r'product-discovery-overview|implementation-sequencing-notes)(?:-deprecated)?\.md',
    re.IGNORECASE)


def archived_input_dependencies(docs):
    """Inspect active prose and required-input tables without opening archives."""
    findings = []
    historical = []
    checked = 0
    for path, text in docs.items():
        if path.startswith('docs/assurance/') and path.split('/')[-1] in HISTORICAL_INPUT_RECORDS:
            historical.append(path)
            continue
        if not path.startswith(('docs/requirements/', 'docs/architecture/',
                                'docs/planning/', 'docs/assurance/')):
            continue
        checked += 1
        for number, line in lines(text):
            # Only the original extraction-source statement is historical here;
            # current invariant mappings and gate inputs in this file are checked.
            if (path, hashlib.sha256(line.encode('utf-8')).hexdigest()) in HISTORICAL_INPUT_LINES:
                continue
            decoded = unquote(html.unescape(line))
            if ARCHIVED_INPUT.search(decoded):
                findings.append([path, number, 'archived input used by current specification'])
            for link in LINK.finditer(decoded):
                destination = urlsplit(link[2].strip('<>'))
                target = posixpath.normpath(posixpath.join(posixpath.dirname(path), destination.path))
                if ('/deprecated-inputs/' in '/' + target or '/inputs/' in '/' + target) and not target.endswith('/README.md'):
                    findings.append([path, number, 'archive body is not an active authority', target])
    return {'documents': checked, 'historicalRecords': sorted(historical), 'findings': findings}


DECISION_HOMES = {
    'D-001': '../planning/implementation-sequence.md',
    'D-002': '../requirements/00-product-scope-and-portfolio.md',
    'D-003': 'open-gates-register.md',
    'D-004': '../architecture/11-mobile-architecture.md',
    'D-005': '../architecture/16-billing-and-commerce-architecture.md',
    'D-007': '../architecture/10-web-architecture.md',
    'D-008': '../architecture/14-build-packaging-and-release.md',
    'D-009': '../architecture/02-contracts-and-protocols.md',
    'D-010': '../architecture/00-architecture-overview.md',
    'D-011': 'implementation-state-reconciliation.md',
    'D-012': 'reference-coverage-and-provenance.md',
    'D-013': 'reference-coverage-and-provenance.md',
    'D-014': '../architecture/10-web-architecture.md',
    'D-015': '../architecture/10-web-architecture.md',
    'D-016': 'open-gates-register.md',
    'D-017': '../planning/README.md',
    'D-018': '../requirements/01-normative-glossary-and-invariants.md',
    'D-019': '../planning/implementation-sequence.md',
    'D-020': '../architecture/16-billing-and-commerce-architecture.md',
    'D-021': '../architecture/11-mobile-architecture.md',
    'D-022': '../architecture/11-mobile-architecture.md',
    'D-023': '../architecture/16-billing-and-commerce-architecture.md',
    'P2-001': '../architecture/14-build-packaging-and-release.md#5-packaging',
    'P2-002': '../decisions/phase-2-specification-decisions.md#rule-p2-004',
    'P2-003': '../architecture/10-web-architecture.md#5-browser-session-architecture--p2-003-resolved',
    'P2-004': '../planning/implementation-sequence.md#11-the-d-019-ordering-followed',
    'P2-006': '../requirements/00-product-scope-and-portfolio.md',
    'P2-007': 'phase-2-design-closure-review.md',
    'P2-008': '../architecture/25-web-toolchain-and-sdk.md',
}

# Exact reviewed historical quotations and normative exclusion statements at the
# Design source pin. Neither a negative word nor an entire file grants exemption.
NAME_OCCURRENCES = {
    ('docs/assurance/phase-1-input-review-ledger.md', '6af1575a2ee822936f3ce1b4ad2d6bab7abc62c79fd046f6c20fbade27fa68ab'): 1,
    ('docs/architecture/01-solution-and-project-layout.md', 'e3aa5cda44bbc82ca072c78e0f8cfe060859b415e6a1753007994b0ecc2d2455'): 1,
    ('docs/architecture/28-product-naming-policy.md', '1c6f6141f83ac67642688587f77d6cade460de6a56a7ec3e596e7c9b10e5c486'): 1,
    ('docs/architecture/README.md', 'd457f8ce1b9cee5ec6637cfe3b4f012f9efde3203905e3649fdcc99d070af397'): 1,
    ('docs/assurance/invariant-coverage.md', '0870dcae104992dc6f6ca18b71a7e1b0c9547d846a04c235d768eb30c9928f05'): 1,
    ('docs/assurance/phase-1-input-review-ledger.md', 'ce7e5d259d3410f4247d4539ce102a8615d613d8e88e8f2b35f92d0c35654619'): 1,
    ('docs/assurance/phase-1-input-review-ledger.md', 'aef24498654f7936961a1e11eee93cb0a96658b0b715181e3e842b5382450560'): 1,
    ('docs/assurance/phase-1-input-review-ledger.md', '85dce7fb44f4ae4c0bdf6dd9eaf45acc79f6efd08487004f22e3ac69a2ed8f29'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', '8fda33d83a2385d8c0c6b42aecc9c6b8fd51826ce9e050663a3b9efb8c86f044'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', 'c4de0822674acbf66d9d48c5b8492830cec714f816cef8237b5111cdb623ec5a'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', 'ddac7c3709b1d6fb0ce6af4b149c422fc85fd1410b15f1b3163a8b2532aea32e'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', '6a46b63b048d9f925f677506582e220bdb43ed841578f16533c3d33bb14ee149'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', '7f5447f5df2f2498b6696d828ba1f7a70f201367214dd623556d34d6cffbee85'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', '3d6d8cad3f531d4b7987791fb877854ddbef9e02f40388a9ff61e7623fce1d80'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', '89c5fdbf6f64d15dd1846fd193d5dc7b441105a8464e128e36f6d65e740cf5fd'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', '3900438f420813e77a8825a0e84fbba8165e11cef1adeecbb024000169e33591'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', '72941cb424f163424a6dfe060642dc07e01b4e621171cd1d407af9c77de5e480'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', '3f33bc5120d18c92ab0633e328cc869b55af4697b52a1e555a30482f74acf2c2'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', '619f96d830291e3e048aac2134436c932aca8e2ffc5e26b2c3bbfcd0c5f4266e'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', '5f5176b1ff83c0501f3dc3ff98c68e1c0bb1a6aa02db7741d7b95b5b693e6202'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', 'ebfcf5fd36e5e117722f842c33ee8f27e094e525c94c167bf6512eeb901784b9'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', 'ce32f5ab123b8a92587c90a5e52a15edd2cbdc14e2164ae3d29f4e816068eaa2'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', 'fda241c38f79908c6c87d2e8094bce77130569c4624d7d2982b42159300736f5'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', 'b9e349aef57e7957d39cfd6114a6ff1c63df5a8e68b6a124c41380c5cfbfd4c5'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', '3325d11d4a39476cde4345e7a6a5c53efb67874874330c40a80217dcff13daab'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', 'ae2f6f1bff78bba36c6e462d571a76f37d9239276b7ba0caee6bd0b41b4758c2'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', '6abbf5de0f579c1c3d4e425c7f3594b9f9e83f3978cdc319df291966fa078b4a'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', '0b5612fc94e5f3eba629e6a17e4b52d484422b217fc05d7477766b12924e961b'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', 'c4c3b48d516493d523d8bbd781719db6044fc7ea46cbb8c132a055bef7e663f3'): 1,
    ('docs/decisions/phase-1-foundation-decisions.md', 'e09e43320b7944908652f2c3ae1fd6f3196c623b00a4fda255c2b78d01c0205f'): 1,
    ('docs/planning/work-packages/00-specification-naming-and-rights-freeze.md', 'bbe7a57d031dc235443a1369872e179a8958cbc066b0fc424bac81de6eca5554'): 1,
    ('docs/requirements/00-product-scope-and-portfolio.md', '8b4fddc0e4030770c64fdd7029dca295f84cf296145f5d793d18f76161998473'): 1,
    ('docs/requirements/00-product-scope-and-portfolio.md', '82bc8b42b8beb0905aa64dbcffb21de1018670a82ac2459580cff28db0091e54'): 1,
    ('docs/requirements/00-product-scope-and-portfolio.md', 'a8f4bca66374fff2687a6c91cb06ca84acde46335b8fe94240f40cbaa56e4abf'): 1,
    ('docs/requirements/01-normative-glossary-and-invariants.md', '50f37288036aba04811535a7115bf80cbaccfc7fda9f1eb1379cde9ee33a610d'): 1,
    ('docs/requirements/01-normative-glossary-and-invariants.md', '766dfa0b11edfaf34a00d1f059b799231424fd9ff71dfd2922d1f15ec98f5c36'): 1,
    ('docs/requirements/04-commerce-entitlement-and-credits.md', 'e6ff857410b846bea5723d3414f211eefd1b0b27d716766354fec27a1bf06f40'): 1,
    ('docs/requirements/README.md', 'd457f8ce1b9cee5ec6637cfe3b4f012f9efde3203905e3649fdcc99d070af397'): 1,
    ('docs/requirements/products/arcforges-web.md', 'ed9c4546e5cd6845ca777ff2beaae17b3c54647ce11f528e40c2b08af57884eb'): 1,
    ('docs/requirements/products/arcscope.md', '5d080856b32b5f47f8bec830c98e2e301a3df200e155818ab7b298788f4e360e'): 1,
    ('docs/requirements/products/arcscope.md', '1e81d8c321d50e9d6bd17d61261817bb3a6bc27e8d48580684ee31a3a9b5cc09'): 1,
    ('docs/requirements/products/arcscope.md', 'eb7a8bd1b32897587f6c2cde7c8a1896b2b1ec64e58df2b6a5888a09c1eafe9f'): 1,
}
SUPERSEDED_NAMES = re.compile(r'[A-Za-z0-9_-]*(?:ArcCanvas|ArcMusic|ArcImage|ArcVideo|Waffo)[A-Za-z0-9_-]*', re.IGNORECASE)


def superseded_names(docs, expected=None):
    expected = NAME_OCCURRENCES if expected is None else expected
    observed = collections.Counter()
    findings = []
    for path, text in docs.items():
        for number, line in lines(text):
            # P2-019 admits exactly these complete technical tokens, not prefixes.
            if any(match[0] not in {'ArcImageNative', 'arcimage-abi'}
                   for match in SUPERSEDED_NAMES.finditer(line)):
                key = (path, hashlib.sha256(line.encode('utf-8')).hexdigest())
                observed[key] += 1
                if key not in expected:
                    findings.append([path, number, 'unclassified superseded-name occurrence'])
    for key in sorted(observed):
        if observed[key] != expected.get(key, 0):
            findings.append([key[0], 0, 'superseded-name classification count drift', key[1]])
    return {'classifiedLines': sum(observed.values()), 'findings': findings}


def decision_coverage(docs, citations):
    """Check effective P2-019 mappings, not the retired historical denominator."""
    matrix = 'docs/assurance/traceability-matrix.md'
    findings, observed = [], {}
    for number, line in lines(docs.get(matrix, '')):
        if not line.startswith('|'):
            continue
        row = cells(line)
        identity = visible(row[0]).strip() if row else ''
        if not re.fullmatch(r'(?:D-\d{3}|P2-00[1-8])', identity):
            continue
        if identity in observed:
            findings.append([matrix, number, 'duplicate decision row', identity])
        observed[identity] = row
        if len(row) != 5 or not all(row):
            findings.append([matrix, number, 'incomplete decision mapping', identity])
            continue
        definition_file = 'phase-1-foundation-decisions.md' if identity.startswith('D-') else 'phase-2-specification-decisions.md'
        expected_definition = '../decisions/' + definition_file + '#rule-' + identity.lower()
        links = [match[2] for match in LINK.finditer(row[0])]
        if links != [expected_definition]:
            findings.append([matrix, number, 'wrong decision definition', identity])
        homes = [match[2] for match in LINK.finditer(row[2])]
        homes += re.findall(r'`([^`]+\.md(?:#[^`]*)?)`', row[2])
        if identity not in DECISION_HOMES or DECISION_HOMES[identity] not in homes:
            findings.append([matrix, number, 'wrong primary decision home', identity])
        if identity == 'P2-002' and ('withdrawn' not in row[1].lower() or 'historical' not in row[3].lower()):
            findings.append([matrix, number, 'withdrawn ordering is treated as active'])
    for missing in sorted(set(DECISION_HOMES) - set(observed)):
        findings.append([matrix, 0, 'missing effective decision', missing])
    for decision in sorted(k for k in DECISION_HOMES if k.startswith('D-')):
        if not any(item[2] == decision and item[0] != matrix
                   and item[0].startswith(('docs/requirements/', 'docs/architecture/', 'docs/planning/', 'docs/assurance/'))
                   and item[0].split('/')[-1] not in HISTORICAL_INPUT_RECORDS for item in citations):
            findings.append([matrix, 0, 'decision lacks an active Phase 2 citation', decision])
    closure_path = 'docs/assurance/phase-2-design-closure-review.md'
    groups = []
    for number, line in lines(docs.get(closure_path, '')):
        row = cells(line) if line.startswith('|') else []
        if row and row[0].isdigit():
            groups.append(int(row[0]))
            if len(row) != 3 or not all(row):
                findings.append([closure_path, number, 'incomplete closure group'])
    if sorted(groups) != list(range(1, 13)):
        findings.append([closure_path, 0, 'effective closure groups missing or duplicated'])
    return {'phase1': sum(k.startswith('D-') for k in observed),
            'phase2': sum(k.startswith('P2-') for k in observed),
            'closureGroups': len(groups), 'findings': findings}

def visible(s):
    return re.sub(r'[`*~]', '', html.unescape(LINK.sub(lambda m: m[1], re.sub(r'<[^>]*>', '', s))))

def cells(line):
    return [c.strip() for c in re.split(r'(?<!\\)\|', line.strip())[1:-1]]

def lines(text):
    fence = None
    for n, line in enumerate(text.splitlines(), 1):
        match = re.match(r'^\s{0,3}(`{3,}|~{3,})(.*)$', line)
        if match:
            if fence is None:
                fence = match[1]
            elif match[1][0] == fence[0] and len(match[1]) >= len(fence) and not match[2].strip():
                fence = None
            continue
        if fence is None:
            yield n, line
    if fence:
        raise ValueError('unclosed code fence')

def heading_slug(text):
    return re.sub(r'[^\w\- ]', '', visible(text).lower()).replace(' ', '-')

def anchor_identifier(anchor):
    if not anchor.startswith('rule-'):
        return None
    candidate = anchor[5:].upper()
    if ID.fullmatch(candidate):
        return candidate
    candidate = candidate[:-1] + candidate[-1:].lower()
    return candidate if ID.fullmatch(candidate) else None

def definition(line):
    if line.startswith('|'):
        cs = cells(line)
        if not cs or LINK.search(cs[0]):
            return None
        value = visible(cs[0]).strip()
    else:
        m = re.match(r'^#{1,6} (.+)$|^- (.+)$|^(\*\*[A-Z].+)$', line)
        if not m:
            return None
        value = visible(m[1] or m[2] or m[3]).strip()
        if LINK.match((m[1] or m[2] or m[3]).lstrip('*')): return None
    m = ID.match(value)
    if m and (len(value) == len(m[0]) or re.match(r'\s*[—:·]', value[len(m[0]):])):
        return m[0]
    return None

def load(root):
    entries = subprocess.check_output(['git', 'ls-files', '--stage', '-z'], cwd=root).decode().split('\0')
    paths = []
    for entry in filter(None, entries):
        metadata, path = entry.split('\t', 1)
        mode, _, stage = metadata.split()
        if mode not in {'100644', '100755'} or stage != '0':
            raise ValueError(f'unsupported Git source entry: {path}')
        paths.append(path)
    paths += subprocess.check_output(['git','ls-files','--others','--exclude-standard','-z'],cwd=root).decode().split('\0')
    paths = sorted(set(p for p in paths if p.endswith('.md') and not (p.startswith('docs/deprecated-inputs/') and p != 'docs/deprecated-inputs/README.md')))
    return {p: read_document(root, p) for p in paths}

def read_document(root, path):
    candidate = root / path
    if not candidate.resolve().is_relative_to(root.resolve()):
        raise ValueError(f'source escapes Design root: {path}')
    for current in [candidate, *candidate.parents]:
        if current == root:
            break
        if current.is_symlink() or (hasattr(current, 'is_junction') and current.is_junction()):
            raise ValueError(f'linked source is unsupported: {path}')
    return candidate.read_text(encoding='utf-8')

def collect(root, docs=None):
    docs = load(root) if docs is None else docs
    anchors = {}; defs = {}; errors = []
    for p, text in docs.items():
        parsed = list(lines(text)); existing = {}; counts = collections.Counter(); found = {}
        for n, line in parsed:
            for a in ANCHOR.findall(line):
                if a in existing: errors.append([p,n,'duplicate anchor',a])
                existing[a] = n
            h = re.match(r'^#{1,6} (.*)$', line)
            if h:
                base = heading_slug(h[1]); count = counts[base]; counts[base] += 1
                slug = base + (f'-{count}' if count else '')
                if slug in existing: errors.append([p,n,'duplicate anchor',slug])
                existing[slug] = n
            key = definition(line)
            if key:
                if key in found: errors.append([p,n,'duplicate definition',key])
                found[key] = n
        for a, n in existing.items():
            key = anchor_identifier(a)
            if key: found.setdefault(key,n)
        authored = {definition(line) for _, line in parsed}
        defs[p] = {k: {'line':n, 'anchor':'rule-'+k.lower(), 'stable':'rule-'+k.lower() in existing,
                       'kind':'definition' if k in authored else 'preserved-anchor'} for k,n in found.items()}
        anchors[p] = existing
    return docs, anchors, defs, errors

def audit(root, docs=None):
    docs, anchors, defs, errors = collect(root, docs)
    citations=[]; local_links=[]; raw=[]; missing=[]
    homes=collections.defaultdict(list)
    for p, dd in defs.items():
        for key, d in dd.items():
            homes[key].append(p)
            if not d['stable']: missing.append([p,d['line'],key])
    for p, text in docs.items():
        for n, line in lines(text):
            prose = re.sub(r'`+[^`]*`+', '', line)
            if re.search(r'\[[^\]]+\]\[[^\]]*\]|^\s*\[[^\]]+\]:', prose):
                errors.append([p,n,'unsupported reference-link syntax'])
            for match in LINK.finditer(line):
                uri=match[2].strip('<>')
                label_ids = [key for key in ID.findall(visible(match[1])) if key not in STANDARD]
                if urlsplit(uri).scheme or uri.startswith('//'):
                    if label_ids: errors.append([p,n,'external rule home',uri,label_ids])
                    continue
                name, _, fragment=uri.partition('#')
                target=posixpath.normpath(posixpath.join(posixpath.dirname(p),unquote(name))) if name else p
                local_links.append(dict(document=p, line=n, label=match[1], target=target, anchor=unquote(fragment)))
                if target.startswith('/') or target == '..' or target.startswith('../'):
                    errors.append([p,n,'link escapes Design root',uri])
                    continue
                if not (root/target).exists(): errors.append([p,n,'missing target',uri])
                elif fragment and unquote(fragment) not in anchors.get(target,{}): errors.append([p,n,'missing fragment',uri])
                for label in label_ids:
                    if fragment!='rule-'+label.lower():errors.append([p,n,'wrong rule anchor',uri,label])
                    if label not in defs.get(target,{}):errors.append([p,n,'missing rule definition',uri,label])
                    citations.append([p,n,label,target,fragment])
            spans=[m.span() for m in LINK.finditer(line)]+[m.span() for m in ANCHOR.finditer(line)]
            defid=definition(line)
            firstdef=True
            for m in ID.finditer(line):
                key=m[0]
                if any(a<=m.start()<b for a,b in spans) or key in STANDARD:continue
                if key==defid and firstdef:firstdef=False;continue
                raw.append([p,n,key,homes[key],line])
    return dict(documents=len(docs), links=len(local_links), localLinks=local_links, definitions=sum(map(len,defs.values())),
                index=[dict(document=p, identifier=k, **v) for p,dd in defs.items() for k,v in dd.items()],
                missingAnchors=missing, errors=errors, citations=citations, raw=raw)
