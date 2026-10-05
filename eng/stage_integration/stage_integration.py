# SPDX-License-Identifier: AGPL-3.0-only
"""Cross-repository integration graph for the WP05 stage acceptance (WP-05.90).

Each of the seven implementation repositories enforces its own boundary with its own policy host. This
tool adds the graph none of them can see: it reads only each repository's *published* package and
dependency metadata (lock files, package manifests, producer package registries, wrangler/workflow
declarations) at one pinned commit per repository, never a clone, and rejects a forbidden edge in the
direct or transitive package closure of any repository.

Modes
  verify    offline and deterministic: evaluate the committed snapshot against the policy (the PR gate).
  snapshot  live, local opt-in: read the metadata of one commit per repository and rewrite the snapshot.
  drift     live, local opt-in: re-read the pinned commits (or the current main heads) and report any
            difference from the committed snapshot.
  observe   live, local opt-in: read the hosted CI status of each repository's main head.
"""

from __future__ import annotations

import argparse
import datetime
import fnmatch
import hashlib
import json
import posixpath
import re
import sys
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
POLICY_PATH = HERE / 'policy.json'
SNAPSHOT_PATH = HERE / 'snapshot.json'
ORGANISATION = 'ArcForges'
COMMIT = re.compile(r'^[0-9a-f]{40}$')
SHA256 = re.compile(r'^[0-9a-f]{64}$')

RULES = {
    'SI-01': 'Every ArcForges-owned coordinate a repository consumes has exactly one registered producer',
    'SI-02': 'No repository depends on another repository by project, source, submodule or path',
    'SI-03': 'Direct and transitive consumption follows the producer access matrix',
    'SI-04': 'A transitive edge through published producer metadata cannot reach a forbidden package',
    'SI-05': 'No AGPL-produced package enters an Apache repository closure without an owned, expiring exception',
    'SI-06': 'Cloud has no desktop native or UI asset in its closure',
    'SI-07': 'Mobile imports no AGPL implementation',
    'SI-08': 'There is exactly one Harness owner',
    'SI-09': 'Every repository enforces its boundary independently in the pull-request pipeline',
    'SI-10': 'The snapshot is complete, pinned and bound to the policy',
    'SI-11': 'Policy exceptions are owned data that has not expired',
}


class PolicyError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise PolicyError(message)


# ---------------------------------------------------------------------------------------------- JSON


def read_json(text, label='json'):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f'{label}: duplicate key {key}')
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=unique)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def dump(value):
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + '\n'


def load_policy(path=POLICY_PATH):
    policy = read_json(Path(path).read_text(encoding='utf-8'), 'policy')
    require(policy.get('schemaVersion') == 1, 'policy: unsupported schemaVersion')
    require(isinstance(policy.get('repositories'), list) and len(set(policy['repositories'])) == 7,
            'policy: exactly seven distinct repositories are required')
    return policy


# ------------------------------------------------------------------------------ metadata extraction


def is_owned(ecosystem, name):
    lowered = name.lower()
    if ecosystem == 'nuget':
        return lowered.startswith('arcforges.')
    if ecosystem == 'npm':
        return lowered.startswith('@arcforges/')
    if ecosystem == 'maven':
        return lowered.startswith('io.github.arcforges')
    return False


def matches(patterns, name):
    lowered = name.lower()
    return any(fnmatch.fnmatchcase(lowered, pattern.lower()) for pattern in patterns)


def metadata_kind(path):
    """Classify a repository path as published metadata, or None when it is not an input."""
    parts = path.split('/')
    if any(part in ('node_modules', '.worktree', 'artifacts', 'bin', 'obj', '.git') for part in parts):
        return None
    name = parts[-1]
    if name == 'packages.lock.json':
        return 'nuget-lock'
    if name == 'package-lock.json':
        return 'npm-lock'
    if name == 'package.json':
        return 'npm-manifest'
    if name.endswith('.lockfile') and 'settings-gradle' not in name:
        return 'gradle-lock'
    if name in ('settings.gradle', 'settings.gradle.kts'):
        return 'gradle-settings'
    if name in ('wrangler.json', 'wrangler.jsonc', 'wrangler.toml'):
        return 'wrangler'
    if name == '.gitmodules':
        return 'gitmodules'
    if path == 'eng/policy/licence-boundary.json':
        return 'boundary'
    if path == 'eng/policy/exceptions.json':
        return 'exceptions'
    if path.startswith('.github/workflows/') and name.endswith(('.yml', '.yaml')):
        return 'workflow'
    return None


def select_sources(paths, policy, repository):
    """Metadata files to read: classified paths, producer manifests, markers and gate workflows."""
    wanted = {path for path in paths if metadata_kind(path)}
    wanted.update(item['path'] for item in policy['producerManifests'] if item['repository'] == repository)
    wanted.update(marker['path'] for marker in policy['markers'].get(repository, []))
    wanted.update(gate['workflow'] for gate in policy['gates'].get(repository, []))
    return sorted(path for path in wanted if path in set(paths))


def decode(raw):
    return raw.decode('utf-8-sig').replace('\r\n', '\n')


def strip_jsonc(text):
    """Remove comments and trailing commas from JSON with comments, leaving string contents untouched."""
    out, index, in_string = [], 0, False
    while index < len(text):
        char = text[index]
        if in_string:
            out.append(char)
            if char == '\\' and index + 1 < len(text):
                out.append(text[index + 1])
                index += 1
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
            out.append(char)
        elif text.startswith('//', index):
            while index < len(text) and text[index] != '\n':
                index += 1
            continue
        elif text.startswith('/*', index):
            end = text.find('*/', index + 2)
            index = len(text) if end < 0 else end + 2
            continue
        else:
            out.append(char)
        index += 1
    return re.sub(r',(\s*[}\]])', r'\1', ''.join(out))


def normalise_dir(path):
    directory = posixpath.dirname(path)
    return directory or '.'


def parse_workflow(text):
    """Line-based reader for the small GitHub Actions subset the gates use (no YAML dependency)."""
    lines = [line.rstrip('\r') for line in text.split('\n')]

    def indent(line):
        return len(line) - len(line.lstrip(' '))

    def meaningful(line):
        return bool(line.strip()) and not line.lstrip().startswith('#')

    blocks = {}
    current = None
    for line in lines:
        if not meaningful(line):
            if current is not None:
                blocks[current][1].append(line)
            continue
        if indent(line) == 0:
            match = re.match(r'^(["\']?)([A-Za-z_][\w-]*)\1:\s*(.*)$', line)
            current = match.group(2) if match else None
            if current is not None:
                blocks[current] = (match.group(3).strip(), [])
            continue
        if current is not None:
            blocks[current][1].append(line)

    workflow = {'triggers': [], 'calls': [], 'jobs': [], 'filteredTriggers': []}
    inline, body = blocks.get('on', ('', []))
    triggers = set()
    filtered = set()
    if inline:
        triggers.update(token.strip(' []\'"') for token in inline.split(',') if token.strip(' []\'"'))
    body = [line for line in body if meaningful(line)]
    if body:
        base = min(indent(line) for line in body)
        current_trigger = None
        for line in body:
            if indent(line) == base:
                match = re.match(r'^\s*(?:-\s*)?([A-Za-z_][\w-]*)\s*:?', line)
                current_trigger = match.group(1) if match else None
                if match:
                    triggers.add(current_trigger)
            elif current_trigger and re.match(
                    r'^\s*(branches|branches-ignore|paths|paths-ignore|types|tags|tags-ignore):', line):
                filtered.add(current_trigger)
    workflow['triggers'] = sorted(triggers)
    workflow['filteredTriggers'] = sorted(filtered)

    _, job_lines = blocks.get('jobs', ('', []))
    job_lines = [line for line in job_lines if meaningful(line)]
    if not job_lines:
        return workflow
    base = min(indent(line) for line in job_lines)
    jobs, job = [], None
    for line in job_lines:
        if indent(line) == base:
            match = re.match(r'^\s*([\w-]+):\s*$', line)
            job = {'id': match.group(1) if match else line.strip(), 'lines': []}
            jobs.append(job)
        elif job is not None:
            job['lines'].append(line)
    for job in jobs:
        workflow['jobs'].append(parse_job(job['id'], job['lines'], indent, meaningful))
        for call in workflow['jobs'][-1]['calls']:
            if call not in workflow['calls']:
                workflow['calls'].append(call)
    return workflow


def scalar(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
        value = value[1:-1]
    return value


def parse_job(identifier, lines, indent, meaningful):
    result = {'id': identifier, 'if': '', 'continueOnError': '', 'calls': [], 'steps': []}
    if not lines:
        return result
    key_indent = indent(lines[0])
    step_indent = None
    steps = []
    in_steps = False
    for line in lines:
        pad = indent(line)
        if pad == key_indent:
            in_steps = bool(re.match(r'^\s*steps:\s*$', line))
            match = re.match(r'^\s*([\w-]+):\s*(.*)$', line)
            if match and match.group(1) == 'if':
                result['if'] = scalar(match.group(2))
            elif match and match.group(1) == 'continue-on-error':
                result['continueOnError'] = scalar(match.group(2))
            elif match and match.group(1) == 'uses':
                target = scalar(match.group(2))
                if target.startswith('./.github/workflows/'):
                    result['calls'].append(target[2:])
            continue
        if not in_steps:
            continue
        if step_indent is None and line.lstrip().startswith('- '):
            step_indent = pad
        if step_indent is not None and pad == step_indent and line.lstrip().startswith('- '):
            steps.append([line])
        elif steps:
            steps[-1].append(line)
    for step_lines in steps:
        result['steps'].append(parse_step(step_lines, step_indent, indent))
    return result


def parse_step(step_lines, step_indent, indent):
    step = {'name': '', 'if': '', 'continueOnError': '', 'run': '', 'uses': ''}
    key_indent = step_indent + 2
    first = step_lines[0].replace('- ', '', 1)
    lines = [' ' * key_indent + first.lstrip()] + step_lines[1:]
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if not line.strip() or line.lstrip().startswith('#') or indent(line) != key_indent:
            continue
        match = re.match(r'^\s*([\w-]+):\s*(.*)$', line)
        if not match:
            continue
        key, value = match.group(1), match.group(2)
        if key == 'run':
            if value.strip() in ('|', '|-', '|+', '>', '>-', '>+'):
                block = []
                while index < len(lines) and (not lines[index].strip() or indent(lines[index]) > key_indent):
                    block.append(lines[index].strip())
                    index += 1
                step['run'] = '\n'.join(block).strip()
            else:
                step['run'] = scalar(value)
        elif key in ('name', 'if', 'uses'):
            step[key] = scalar(value)
        elif key == 'continue-on-error':
            step['continueOnError'] = scalar(value)
    return step


def gate_fact(gate, workflows):
    """Locate the one step that satisfies a gate declaration in its declared workflow."""
    fact = {'id': gate['id'], 'workflow': gate['workflow'], 'found': False}
    workflow = workflows.get(gate['workflow'])
    if workflow is None:
        return fact
    candidates = []
    for job in workflow['jobs']:
        for step in job['steps']:
            text = commands(step['run'])
            if text and all(pattern in text for pattern in gate['runContains']):
                candidates.append({
                    'found': True,
                    'job': job['id'],
                    'step': step['name'],
                    'stepIf': step['if'],
                    'stepContinueOnError': step['continueOnError'],
                    'jobIf': job['if'],
                    'jobContinueOnError': job['continueOnError'],
                    'suppressed': suppresses(text, gate['runContains']),
                })
    if not candidates:
        return fact
    # A real, clean step wins over a disabled or suppressed one, so a masking duplicate cannot hide the gate.
    candidates.sort(key=lambda row: (bool(row['suppressed']), bool(row['stepIf']), bool(row['jobIf']),
                                     row['stepContinueOnError'] not in ('', 'false'),
                                     row['jobContinueOnError'] not in ('', 'false')))
    fact.update(candidates[0])
    return fact


PRINT_ONLY = re.compile(r'^\s*(echo|printf|write-host|write-output|write-warning|cat|#)\b', re.IGNORECASE)
LINE_SUPPRESSION = re.compile(
    r'(\|\|\s*(true|:|exit\s+0|echo\b.*)|;\s*(true|exit\s+0|:)\s*($|;)|-ErrorAction\s+SilentlyContinue)',
    re.IGNORECASE)
GLOBAL_SUPPRESSION = re.compile(
    r'(\bset\s+\+e\b|\$ErrorActionPreference\s*=\s*[\'"]?SilentlyContinue)', re.IGNORECASE)


def commands(run):
    """The executable lines of a run block: print-only and comment lines do not run a gate."""
    return '\n'.join(line for line in run.split('\n') if line.strip() and not PRINT_ONLY.match(line))


def suppresses(text, patterns):
    """Failure suppression: a global switch anywhere, or an operator on a line that carries the gate itself."""
    if GLOBAL_SUPPRESSION.search(text):
        return True
    return any(LINE_SUPPRESSION.search(line) for line in text.split('\n')
               if any(pattern in line for pattern in patterns))


def npm_specifier_problem(directory, name, spec):
    spec = str(spec)
    if spec.startswith(('file:', 'link:')):
        target = posixpath.normpath(posixpath.join(directory, spec.split(':', 1)[1]))
        if target == '..' or target.startswith('../'):
            return f'{name} -> {spec} leaves the repository'
        return None
    if spec.startswith(('git+', 'git:', 'github:', 'git@')) or re.match(r'^https?://', spec):
        return f'{name} -> {spec} is a source or URL dependency'
    if re.match(r'^[\w.-]+/[\w.-]+(#.*)?$', spec):
        return f'{name} -> {spec} is a GitHub shorthand source dependency'
    return None


def extract_facts(repository, files, policy):
    """Reduce one repository's published metadata at one commit to its integration facts.

    `files` maps a repository path to its exact bytes."""
    texts = {path: decode(raw) for path, raw in files.items()}
    facts = {
        'boundary': None,
        'spdx': None,
        'localProjects': [],
        'localPackageNames': [],
        'produces': [],
        'consumes': [],
        'edges': [],
        'projectRefs': [],
        'sourceDeps': [],
        'harness': {'workflows': [], 'classes': [], 'workers': []},
        'exceptions': [],
        'workflows': [],
        'gates': [],
        'markers': [],
    }
    consumed = {}
    edges = set()
    npm_direct = set()
    local_names = set()
    project_refs = set()
    source_deps = set()
    foreign = policy.get('foreignWatch', [])

    def consume(ecosystem, name, version, relation, directory):
        if not (is_owned(ecosystem, name) or matches(foreign, name)):
            return
        key = (ecosystem, name, version, relation)
        consumed.setdefault(key, set()).add(directory)

    for path in sorted(texts):
        kind = metadata_kind(path)
        text = texts[path]
        directory = normalise_dir(path)
        if kind == 'boundary':
            data = read_json(text, path)
            facts['boundary'] = data.get('licenceBoundary')
            facts['spdx'] = data.get('spdxLicense')
            facts['localProjects'] = sorted(
                {posixpath.basename(item['path']).rsplit('.', 1)[0].lower()
                 for item in data.get('projects', []) if item.get('kind') == 'msbuild'})
        elif kind == 'exceptions':
            data = read_json(text, path)
            if isinstance(data, dict):
                data = data.get('exceptions', [])
            require(isinstance(data, list), f'{path}: exceptions must be an array')
            for row in data:
                facts['exceptions'].append({key: row.get(key) for key in ('rule', 'path', 'owner', 'expires')})
        elif kind == 'nuget-lock':
            data = read_json(text, path)
            for framework in data.get('dependencies', {}).values():
                for name, entry in framework.items():
                    if entry.get('type') == 'Project':
                        project_refs.add((directory, name.lower()))
                        continue
                    relation = 'Direct' if entry.get('type') == 'Direct' else 'Transitive'
                    consume('nuget', name, entry.get('resolved'), relation, directory)
                    if is_owned('nuget', name):
                        for dependency in entry.get('dependencies', {}):
                            edges.add(('nuget', name, dependency))
        elif kind == 'npm-manifest':
            data = read_json(text, path)
            if data.get('name'):
                local_names.add(data['name'])
            for section in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
                for name, spec in data.get(section, {}).items():
                    npm_direct.add(name)
                    problem = npm_specifier_problem(directory, name, spec)
                    if problem:
                        source_deps.add((path, problem))
        elif kind == 'npm-lock':
            data = read_json(text, path)
            for key, entry in data.get('packages', {}).items():
                if not key:
                    continue
                name = key.rsplit('node_modules/', 1)[-1]
                if entry.get('link'):
                    target = posixpath.normpath(posixpath.join(directory, entry.get('resolved', '')))
                    if target == '..' or target.startswith('../'):
                        source_deps.add((path, f'{name} is linked outside the repository ({entry.get("resolved")})'))
                    continue
                consume('npm', name, entry.get('version'), 'Transitive', directory)
                if is_owned('npm', name):
                    for dependency in entry.get('dependencies', {}):
                        edges.add(('npm', name, dependency))
        elif kind == 'gradle-lock':
            for line in text.split('\n'):
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                coordinate = line.split('=', 1)[0]
                parts = coordinate.split(':')
                if len(parts) >= 3:
                    consume('maven', f'{parts[0]}:{parts[1]}', parts[2], 'Direct', directory)
        elif kind == 'gradle-settings':
            if 'includeBuild' in text:
                source_deps.add((path, 'includeBuild composes another build'))
            for match in re.finditer(r'["\']([^"\']*\.\./[^"\']*)["\']', text):
                source_deps.add((path, f'path {match.group(1)} leaves the build directory'))
        elif kind == 'gitmodules':
            source_deps.add((path, 'git submodule declared'))
        elif kind == 'wrangler':
            data = tomllib.loads(text) if path.endswith('.toml') else read_json(strip_jsonc(text), path)
            if data.get('name'):
                facts['harness']['workers'].append(data['name'])
            facts['harness']['workflows'] += [
                item.get('class_name') or item.get('name') for item in data.get('workflows', [])]
            classes = [item.get('class_name') for item in data.get('durable_objects', {}).get('bindings', [])]
            classes += [item.get('class_name') for item in data.get('containers', [])]
            facts['harness']['classes'] += [name for name in classes if name]

    for item in policy['producerManifests']:
        if item['repository'] != repository or item['path'] not in texts:
            continue
        data = read_json(texts[item['path']], item['path'])
        for package in data.get('packages', []):
            ecosystem = package.get('kind') if item['format'] == 'contract-packages' else item['ecosystem']
            if ecosystem not in ('nuget', 'npm', 'maven'):
                ecosystem = item['ecosystem']
            facts['produces'].append({
                'ecosystem': ecosystem,
                'id': package['id'],
                'kind': package.get('kind') if item['format'] == 'desktop-packages' else 'contract',
                'access': package.get('access', 'public'),
                'dependencies': sorted(package.get('dependencies', [])),
            })
    facts['produces'].sort(key=lambda row: (row['ecosystem'], row['id'].lower()))

    for key in ('workflows', 'classes', 'workers'):
        facts['harness'][key] = sorted(set(facts['harness'][key]))
    facts['localPackageNames'] = sorted(local_names)
    facts['consumes'] = [
        {'ecosystem': eco, 'id': name, 'version': version, 'relation': relation, 'locks': sorted(dirs)}
        for (eco, name, version, relation), dirs in sorted(consumed.items(), key=lambda item: tuple(map(str, item[0])))
    ]
    for row in facts['consumes']:
        if row['ecosystem'] == 'npm' and row['id'] in npm_direct:
            row['relation'] = 'Direct'
    facts['edges'] = [{'ecosystem': eco, 'from': parent, 'to': child} for eco, parent, child in sorted(edges)]
    facts['projectRefs'] = [{'lock': lock, 'project': project} for lock, project in sorted(project_refs)]
    facts['sourceDeps'] = [{'path': path, 'detail': detail} for path, detail in sorted(source_deps)]

    workflows = {}
    for path in sorted(texts):
        if metadata_kind(path) == 'workflow':
            workflows[path] = parse_workflow(texts[path])
            facts['workflows'].append({
                'path': path,
                'triggers': workflows[path]['triggers'],
                'filteredTriggers': workflows[path]['filteredTriggers'],
                'calls': workflows[path]['calls'],
            })
    facts['gates'] = [gate_fact(gate, workflows) for gate in policy['gates'].get(repository, [])]
    for marker in policy['markers'].get(repository, []):
        text = texts.get(marker['path'])
        found = text is not None and (marker.get('contains') is None or marker['contains'] in text)
        facts['markers'].append({'id': marker['id'], 'path': marker['path'], 'found': found})
    return facts


# -------------------------------------------------------------------------------------------- sources


class GitHubProvider:
    """Reads public repository metadata over HTTPS: a tree listing and individual files, never a clone."""

    def __init__(self, organisation=ORGANISATION, attempts=4, timeout=30, opener=None, sleep=time.sleep):
        self.organisation = organisation
        self.attempts = attempts
        self.timeout = timeout
        self.opener = opener or urllib.request.build_opener()
        self.sleep = sleep

    def _get(self, url):
        last = None
        for attempt in range(self.attempts):
            try:
                request = urllib.request.Request(url, headers={'User-Agent': 'ArcForges-stage-integration/1'})
                with self.opener.open(request, timeout=self.timeout) as response:
                    return response.read()
            except urllib.error.HTTPError as error:
                if error.code in (401, 403, 404, 422):
                    raise PolicyError(f'GET {url} failed with HTTP {error.code}') from error
                last = error
            except (urllib.error.URLError, TimeoutError, OSError) as error:
                last = error
            self.sleep(min(2 ** attempt, 8))
        raise PolicyError(f'GET {url} failed after {self.attempts} attempts: {last}')

    def head(self, repository, ref='main'):
        data = read_json(self._get(
            f'https://api.github.com/repos/{self.organisation}/{repository}/commits/{ref}').decode('utf-8'))
        sha = data.get('sha', '')
        require(COMMIT.match(sha), f'{repository}: {ref} did not resolve to a commit')
        return sha

    def tree(self, repository, commit):
        data = read_json(self._get(
            f'https://api.github.com/repos/{self.organisation}/{repository}/git/trees/{commit}?recursive=1'
        ).decode('utf-8'))
        require(not data.get('truncated'), f'{repository}: tree listing is truncated')
        return sorted(item['path'] for item in data['tree'] if item['type'] == 'blob')

    def read(self, repository, commit, path):
        return self._get(f'https://raw.githubusercontent.com/{self.organisation}/{repository}/{commit}/{path}')


def collect_repository(provider, repository, commit, policy):
    require(COMMIT.match(commit), f'{repository}: invalid commit')
    paths = provider.tree(repository, commit)
    selected = select_sources(paths, policy, repository)
    files = {path: provider.read(repository, commit, path) for path in selected}
    facts = extract_facts(repository, files, policy)
    return {
        'commit': commit,
        'sources': [{'path': path, 'sha256': hashlib.sha256(files[path]).hexdigest()} for path in selected],
        'facts': facts,
    }


def build_snapshot(provider, commits, policy):
    repositories = {name: collect_repository(provider, name, commits[name], policy) for name in policy['repositories']}
    return {'schemaVersion': 1, 'collectedOn': today_default(), 'policySha256': digest(policy),
            'repositories': repositories}


# -------------------------------------------------------------------------------------------- rules


def finding(rule, repository, message, path=None):
    row = {'rule': rule, 'repository': repository, 'message': message}
    if path:
        row['path'] = path
    return row


class World:
    """Producer registry plus the package graph assembled from published metadata only."""

    def __init__(self, snapshot, policy):
        self.policy = policy
        self.repos = snapshot['repositories']
        self.boundary = {name: repo['facts']['boundary'] for name, repo in self.repos.items()}
        self.findings = []
        self.producers = {}
        for name in policy['repositories']:
            for package in self.repos[name]['facts']['produces']:
                key = (package['ecosystem'], package['id'].lower())
                if key in self.producers:
                    self.findings.append(finding(
                        'SI-01', name,
                        f'{package["id"]} ({package["ecosystem"]}) is also produced by {self.producers[key]["repository"]}'))
                    continue
                self.producers[key] = {**package, 'repository': name}
        for key, package in self.producers.items():
            if package.get('access', 'public') != 'public' and not any(
                    override['ecosystem'] == key[0] and matches(override['match'], package['id'])
                    for override in policy['consumerOverrides']):
                self.findings.append(finding(
                    'SI-03', package['repository'],
                    f'{package["id"]} is registered as {package["access"]} but policy.json names no audience for it '
                    '(failing closed)'))
        for name in policy['repositories']:
            for local in self.repos[name]['facts']['localPackageNames']:
                key = ('npm', local.lower())
                if key in self.producers and self.producers[key]['repository'] != name:
                    self.findings.append(finding(
                        'SI-01', name,
                        f'package name {local} is also a package produced by {self.producers[key]["repository"]}'))
        self.graph = {}
        for key, package in self.producers.items():
            for dependency in package['dependencies']:
                self.graph.setdefault(key, set()).add((package['ecosystem'], dependency.lower()))
        for name in policy['repositories']:
            for edge in self.repos[name]['facts']['edges']:
                self.graph.setdefault((edge['ecosystem'], edge['from'].lower()), set()).add(
                    (edge['ecosystem'], edge['to'].lower()))

    def consumers(self, key):
        """Repositories allowed to consume a package (None means every repository)."""
        package = self.producers.get(key)
        if package is None:
            return []
        for override in self.policy['consumerOverrides']:
            if override['ecosystem'] == key[0] and matches(override['match'], package['id']):
                return self.expand(override['consumers'])
        return self.expand(self.policy['defaultConsumers'][package['repository']])

    def expand(self, consumers):
        return list(self.policy['repositories']) if consumers == '*' else list(consumers)

    def local(self, repository, ecosystem, name):
        facts = self.repos[repository]['facts']
        if ecosystem == 'npm' and name in facts['localPackageNames']:
            return True
        return any(p['ecosystem'] == ecosystem and p['id'].lower() == name.lower() for p in facts['produces'])

    def roots(self, repository, direct_only=True):
        """Consumed owned coordinates: key -> lock directories.

        A lock lists the complete closure, so a coordinate reached only through a third-party package is still
        a root when `direct_only` is false; its path is then unknown beyond the lock itself."""
        roots = {}
        for row in self.repos[repository]['facts']['consumes']:
            if direct_only and row['relation'] != 'Direct':
                continue
            if not is_owned(row['ecosystem'], row['id']):
                continue
            key = (row['ecosystem'], row['id'].lower())
            roots.setdefault(key, set()).update(row['locks'])
        return roots

    def reach(self, repository):
        """Every owned coordinate reachable from the repository's direct dependencies.

        Maps a node to its shortest path from a root and the lock directories of every root that reaches it."""
        reached = {}
        direct = self.roots(repository)
        ordered = sorted(direct.items()) + sorted(
            (key, locks) for key, locks in self.roots(repository, direct_only=False).items() if key not in direct)
        for root, locks in ordered:
            seen = {root}
            queue = [(root, [root])]
            while queue:
                node, path = queue.pop(0)
                entry = reached.setdefault(node, {'path': path, 'locks': set()})
                entry['locks'].update(locks)
                for child in sorted(self.graph.get(node, ())):
                    if child not in seen:
                        seen.add(child)
                        queue.append((child, path + [child]))
        return reached


def show(path):
    return ' -> '.join(name for _, name in path)


def covered_by_exception(repos, repository, locks, rule, today):
    """A cross-boundary edge is accepted only when the consumer's own exception data covers every lock."""
    rows = [row for row in repos[repository]['facts']['exceptions']
            if row.get('rule') == rule and row.get('expires') and row['expires'] >= today]
    directories = {normalise_dir(row['path']) for row in rows if row.get('path')}
    return bool(locks) and all(lock in directories for lock in locks)


def evaluate(snapshot, policy, today=None):
    today = today or datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    if set(snapshot.get('repositories', {})) != set(policy['repositories']):
        return [finding('SI-10', '*', 'the snapshot does not cover exactly the seven repositories')]
    world = World(snapshot, policy)
    findings = list(world.findings)
    repos = snapshot['repositories']
    desktop_only = policy['desktopOnly']

    def is_desktop_only(key):
        package = world.producers.get(key)
        if package is None:
            return matches(desktop_only['foreignIds'], key[1])
        return package.get('kind') == 'native' or matches(desktop_only['ids'], package['id'])

    for repository in policy['repositories']:
        facts = repos[repository]['facts']

        # SI-01 registry
        for row in facts['consumes']:
            if not is_owned(row['ecosystem'], row['id']):
                continue
            key = (row['ecosystem'], row['id'].lower())
            if key not in world.producers and not world.local(repository, row['ecosystem'], row['id']):
                findings.append(finding('SI-01', repository,
                                        f'{row["id"]} {row["version"]} ({row["ecosystem"]}) has no registered producer'))
        for edge in facts['edges']:
            key = (edge['ecosystem'], edge['to'].lower())
            if is_owned(edge['ecosystem'], edge['to']) and key not in world.producers \
                    and not world.local(repository, edge['ecosystem'], edge['to']):
                findings.append(finding('SI-01', repository, f'{edge["from"]} depends on unregistered {edge["to"]}'))

        # SI-02 no cross-repository project or source dependency
        local_projects = set(facts['localProjects'])
        for ref in facts['projectRefs']:
            if ref['project'] not in local_projects:
                findings.append(finding('SI-02', repository,
                                        f'project reference {ref["project"]} is not a project of this repository',
                                        ref['lock']))
        for source in facts['sourceDeps']:
            findings.append(finding('SI-02', repository, source['detail'], source['path']))

        # SI-03 / SI-04 / SI-05 / SI-06 / SI-07 over the full closure
        direct = world.roots(repository)
        for key, info in sorted(world.reach(repository).items()):
            package = world.producers.get(key)
            if package is None or package['repository'] == repository:
                continue
            transitive = key not in direct
            allowed = world.consumers(key)
            if repository not in allowed:
                rule = 'SI-04' if transitive else 'SI-03'
                findings.append(finding(
                    rule, repository,
                    f'{package["id"]} (produced by {package["repository"]}) is not available to {repository}: '
                    f'{show(info["path"])}'))
            if (policy['licenceBoundaries'].get(repository) == 'Apache'
                    and world.boundary[package['repository']] == 'AGPL'):
                if repository in policy['strictApacheRepositories']:
                    findings.append(finding(
                        'SI-07', repository,
                        f'{package["id"]} is an AGPL implementation produced by {package["repository"]}: '
                        f'{show(info["path"])}'))
                elif not covered_by_exception(repos, repository, info['locks'], 'RP-03', today):
                    findings.append(finding(
                        'SI-05', repository,
                        f'{package["id"]} is AGPL-produced and reaches an Apache closure without an unexpired '
                        f'RP-03 exception for its project: {show(info["path"])}'))
        if repository in policy['noDesktopAssets']:
            for key, info in sorted(world.reach(repository).items()):
                if is_desktop_only(key):
                    findings.append(finding(
                        'SI-06', repository, f'desktop native or UI asset {key[1]} is reachable: {show(info["path"])}'))
            for row in facts['consumes']:
                key = (row['ecosystem'], row['id'].lower())
                if not is_owned(row['ecosystem'], row['id']) and is_desktop_only(key):
                    findings.append(finding(
                        'SI-06', repository, f'desktop native or UI package {row["id"]} {row["version"]} is locked',
                        ','.join(row['locks'])))
        if repository in policy['strictApacheRepositories']:
            for key, info in sorted(world.reach(repository).items()):
                if key not in world.producers and not world.local(repository, key[0], key[1]):
                    findings.append(finding('SI-07', repository,
                                            f'{key[1]} has no Apache-boundary producer: {show(info["path"])}'))

    # SI-08 one Harness owner
    harness = policy['harness']
    owner = harness['owner']
    if not repos[owner]['facts']['harness']['workflows']:
        findings.append(finding('SI-08', owner, 'the Harness owner declares no workflow in its wrangler configuration'))
    for repository in policy['repositories']:
        facts = repos[repository]['facts']
        if repository == owner:
            continue
        if facts['harness']['workflows']:
            findings.append(finding('SI-08', repository,
                                    f'declares workflow classes {facts["harness"]["workflows"]}; only {owner} owns the Harness'))
        for name in facts['harness']['classes'] + facts['harness']['workers']:
            if name and re.search(harness['namePattern'], name, re.IGNORECASE):
                findings.append(finding('SI-08', repository, f'declares a Harness-named class or worker {name}'))
        for package in facts['produces']:
            if re.search(harness['namePattern'], package['id'], re.IGNORECASE):
                findings.append(finding('SI-08', repository, f'produces Harness-named package {package["id"]}'))

    # SI-09 every repository enforces its own boundary in the pull-request pipeline
    for repository in policy['repositories']:
        facts = repos[repository]['facts']
        reachable = pull_request_workflows(facts['workflows'])
        for marker in facts['markers']:
            if not marker['found']:
                findings.append(finding('SI-09', repository, f'policy host marker {marker["id"]} is missing', marker['path']))
        expected = {gate['id'] for gate in policy['gates'].get(repository, [])}
        require(expected, f'{repository}: the policy declares no gate')
        for gate in facts['gates']:
            where = gate['workflow']
            if not gate['found']:
                findings.append(finding('SI-09', repository, f'gate {gate["id"]} is not run by {where}', where))
                continue
            if where not in reachable:
                findings.append(finding('SI-09', repository,
                                        f'gate {gate["id"]} is in a workflow no pull request reaches', where))
            for label, condition in (('step', gate['stepIf']), ('job', gate['jobIf'])):
                if condition and condition not in policy['allowedConditions']:
                    findings.append(finding('SI-09', repository,
                                            f'gate {gate["id"]} {label} is conditional on {condition}', where))
            for label, value in (('step', gate['stepContinueOnError']), ('job', gate['jobContinueOnError'])):
                if value and value.lower() != 'false':
                    findings.append(finding('SI-09', repository,
                                            f'gate {gate["id"]} {label} sets continue-on-error: {value}', where))
            if gate['suppressed']:
                findings.append(finding('SI-09', repository, f'gate {gate["id"]} suppresses its own failure', where))
        if {gate['id'] for gate in facts['gates']} != expected:
            findings.append(finding('SI-09', repository, 'gate facts do not match the declared gates'))

    # SI-10 snapshot completeness
    if snapshot.get('schemaVersion') != 1:
        findings.append(finding('SI-10', '*', 'unsupported snapshot schemaVersion'))
    freshness = policy['freshness']
    collected = snapshot.get('collectedOn', '')
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', collected):
        findings.append(finding('SI-10', '*', 'the snapshot has no collection date'))
    else:
        age = (datetime.date.fromisoformat(today) - datetime.date.fromisoformat(collected)).days
        if age > freshness['maxAgeDays'] or age < 0:
            findings.append(finding(
                'SI-10', '*',
                f'the snapshot was collected {collected} ({age} days before {today}); the limit is '
                f'{freshness["maxAgeDays"]} days and the owner is {freshness["owner"]}: run snapshot, review the diff'))
    if snapshot.get('policySha256') != digest(policy):
        findings.append(finding('SI-10', '*', 'the snapshot is bound to a different policy; re-run snapshot'))
    if set(repos) != set(policy['repositories']):
        findings.append(finding('SI-10', '*', 'the snapshot does not cover exactly the seven repositories'))
    for repository in policy['repositories']:
        repo = repos.get(repository)
        if repo is None:
            continue
        if not COMMIT.match(repo.get('commit', '')):
            findings.append(finding('SI-10', repository, 'the pinned commit is not a full SHA-1'))
        if not repo['sources'] or any(not SHA256.match(item['sha256']) for item in repo['sources']):
            findings.append(finding('SI-10', repository, 'source digests are missing or malformed'))
        if repo['facts']['boundary'] not in ('AGPL', 'Apache'):
            findings.append(finding('SI-10', repository, 'the licence boundary was not read'))
        elif repo['facts']['boundary'] != policy['licenceBoundaries'].get(repository):
            findings.append(finding('SI-10', repository,
                                    f'licence boundary {repo["facts"]["boundary"]} differs from the policy'))

    # SI-11 exceptions are data, owned and unexpired
    for repository in policy['repositories']:
        for row in repos[repository]['facts']['exceptions']:
            if not (row.get('rule') and row.get('path') and row.get('owner') and row.get('expires')):
                findings.append(finding('SI-11', repository, f'exception row is incomplete: {row}'))
            elif row['owner'] != repository:
                findings.append(finding('SI-11', repository, f'exception {row["rule"]} is owned by {row["owner"]}'))
            elif row['expires'] < today:
                findings.append(finding('SI-11', repository, f'exception {row["rule"]} for {row["path"]} expired {row["expires"]}'))

    findings.sort(key=lambda row: (row['rule'], row['repository'], row['message'], row.get('path', '')))
    return findings


def pull_request_workflows(workflows):
    """Workflows triggered by a pull request, directly or through a reusable-workflow call."""
    by_path = {item['path']: item for item in workflows}
    reachable = {item['path'] for item in workflows
                 if 'pull_request' in item['triggers'] and 'pull_request' not in item.get('filteredTriggers', [])}
    changed = True
    while changed:
        changed = False
        for path in sorted(reachable):
            for call in by_path.get(path, {}).get('calls', []):
                if call in by_path and call not in reachable:
                    reachable.add(call)
                    changed = True
    return reachable


def report(snapshot, policy, findings, today):
    by_rule = {rule: [row for row in findings if row['rule'] == rule] for rule in RULES}
    return {
        'schemaVersion': 1,
        'producer': 'eng/stage_integration/stage_integration.py',
        'evaluatedOn': today,
        'policySha256': digest(policy),
        'repositories': {name: {'commit': snapshot['repositories'][name]['commit'],
                                'boundary': snapshot['repositories'][name]['facts']['boundary'],
                                'metadataFiles': len(snapshot['repositories'][name]['sources'])}
                         for name in policy['repositories'] if name in snapshot['repositories']},
        'rules': [{'id': rule, 'title': RULES[rule], 'passed': not rows, 'findings': rows}
                  for rule, rows in by_rule.items()],
        'findingCount': len(findings),
    }


# -------------------------------------------------------------------------------------- hosted status


def observe(provider, policy, commits=None):
    """Hosted CI status of each repository's main head (provider job results only, no downloads)."""
    out = {}
    for name in policy['repositories']:
        commit = (commits or {}).get(name) or provider.head(name)
        runs = read_json(provider._get(
            f'https://api.github.com/repos/{provider.organisation}/{name}/actions/runs?head_sha={commit}&per_page=30'
        ).decode('utf-8'))['workflow_runs']
        out[name] = {
            'commit': commit,
            'runs': [{'id': run['id'], 'workflow': run['name'], 'event': run['event'], 'conclusion': run['conclusion'],
                      'attempt': run['run_attempt'], 'url': run['html_url']} for run in runs
                     if run['status'] == 'completed'],
        }
    return out


# ------------------------------------------------------------------------------------------------ CLI


def today_default():
    return datetime.datetime.now(datetime.timezone.utc).date().isoformat()


def command_verify(args):
    policy = load_policy(args.policy)
    snapshot = read_json(Path(args.snapshot).read_text(encoding='utf-8'), 'snapshot')
    today = args.as_of or today_default()
    findings = evaluate(snapshot, policy, today)
    result = report(snapshot, policy, findings, today)
    if args.report:
        target = Path(args.report)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(dump(result), encoding='utf-8')
    for row in findings:
        print(f'{row["rule"]} {row["repository"]}: {row["message"]}' + (f' [{row["path"]}]' if row.get('path') else ''),
              file=sys.stderr)
    print(f'stage integration: {len(snapshot["repositories"])} repositories, {len(RULES)} rules, '
          f'{len(findings)} findings')
    return 1 if findings else 0


def pins(args, policy, provider, current):
    if args.commit:
        commits = dict(item.split('=', 1) for item in args.commit)
    else:
        commits = {}
    for name in policy['repositories']:
        if name not in commits:
            commits[name] = provider.head(name) if current else current_pin(args.snapshot, name)
    require(set(commits) == set(policy['repositories']), 'a commit is required for every repository')
    return commits


def current_pin(snapshot_path, name):
    return read_json(Path(snapshot_path).read_text(encoding='utf-8'), 'snapshot')['repositories'][name]['commit']


def command_snapshot(args):
    policy = load_policy(args.policy)
    provider = GitHubProvider()
    commits = pins(args, policy, provider, current=True)
    snapshot = build_snapshot(provider, commits, policy)
    Path(args.snapshot).write_text(dump(snapshot), encoding='utf-8')
    findings = evaluate(snapshot, policy, args.as_of or today_default())
    print(f'snapshot written for {len(commits)} repositories; {len(findings)} findings')
    for name, commit in commits.items():
        print(f'  {name} {commit}')
    return 1 if findings else 0


def command_drift(args):
    policy = load_policy(args.policy)
    provider = GitHubProvider()
    committed = read_json(Path(args.snapshot).read_text(encoding='utf-8'), 'snapshot')
    commits = pins(args, policy, provider, current=args.current)
    live = build_snapshot(provider, commits, policy)
    differences = []
    for name in policy['repositories']:
        old, new = committed['repositories'][name], live['repositories'][name]
        if old['commit'] != new['commit']:
            differences.append(f'{name}: pinned {old["commit"][:12]} vs read {new["commit"][:12]}')
        if old['facts'] != new['facts']:
            keys = sorted(key for key in new['facts'] if old['facts'].get(key) != new['facts'][key])
            differences.append(f'{name}: facts differ in {", ".join(keys)}')
    findings = evaluate(live, policy, args.as_of or today_default())
    for line in differences:
        print('drift', line)
    for row in findings:
        print(f'{row["rule"]} {row["repository"]}: {row["message"]}', file=sys.stderr)
    print(f'drift: {len(differences)} differences, {len(findings)} findings in the live metadata')
    return 1 if findings else 0


def command_observe(args):
    policy = load_policy(args.policy)
    commits = dict(item.split('=', 1) for item in args.commit) if args.commit else None
    result = observe(GitHubProvider(), policy, commits)
    text = dump(result)
    if args.output:
        Path(args.output).write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--policy', default=str(POLICY_PATH))
    parser.add_argument('--snapshot', default=str(SNAPSHOT_PATH))
    parser.add_argument('--as-of', help='evaluation date (YYYY-MM-DD); defaults to today (UTC)')
    sub = parser.add_subparsers(dest='command', required=True)
    verify = sub.add_parser('verify')
    verify.add_argument('--report')
    verify.set_defaults(run=command_verify)
    snapshot = sub.add_parser('snapshot')
    snapshot.add_argument('--commit', action='append', metavar='REPO=SHA')
    snapshot.set_defaults(run=command_snapshot)
    drift = sub.add_parser('drift')
    drift.add_argument('--commit', action='append', metavar='REPO=SHA')
    drift.add_argument('--current', action='store_true', help='compare against the current main heads')
    drift.set_defaults(run=command_drift)
    watch = sub.add_parser('observe')
    watch.add_argument('--commit', action='append', metavar='REPO=SHA')
    watch.add_argument('--output')
    watch.set_defaults(run=command_observe)
    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except PolicyError as error:
        print(f'stage integration refused: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
