# SPDX-License-Identifier: Apache-2.0
"""Check reviewed source provenance without fetching or executing upstream source."""

from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
STORE = "eng/provenance/records/"
INVENTORY = "eng/provenance/files.json"
SUMMARY = "eng/provenance/NOTICE.txt"
RETIREMENTS = "eng/provenance/retired-artifacts.json"
POLICY = "eng/policy/reuse-policy.json"
RECORD_FIELDS = "schemaVersion id kind sourceRepository sourceCommit sourcePaths licence attribution targets artifactTargets disposition verification notice lifetime generation review supersedes"
OWNERS = {name: "Apache" if name in {"Contracts", "Mobile"} else "AGPL" for name in
          ("DesktopPlatform", "Contracts", "ArcScope", "Cloud", "AI", "Web", "Mobile")}
DECISIONS = {
    "permissive": {"AGPL": "audit", "Apache": "audit"},
    "agpl-compatible": {"AGPL": "exact-review", "Apache": "prohibited"},
    "gpl-only": {"AGPL": "prohibited", "Apache": "prohibited"},
    "unclear": {"AGPL": "prohibited", "Apache": "prohibited"},
    "incompatible": {"AGPL": "prohibited", "Apache": "prohibited"},
}
LICENCES = {**{name: "permissive" for name in
              ("Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC",
               "Apache-2.0 WITH LLVM-exception", "Apache-2.0 AND BSD-3-Clause", "Apache-2.0 AND MIT")},
            "AGPL-3.0-only": "agpl-compatible", "GPL-2.0-only": "gpl-only",
            "GPL-3.0-only": "gpl-only", "NOASSERTION": "unclear", "EPL-1.0": "incompatible"}

# Additional exact expressions reviewed for this owner's existing native closure.
LICENCES.update({name: "permissive" for name in ('0BSD', 'Zlib', 'MIT-0', 'libpng-2.0', 'bzip2-1.0.6', 'libtiff', 'NCSA', 'BSL-1.0', 'MIT AND BSD-3-Clause', 'BSD-3-Clause AND IJG AND Zlib', 'BSD-3-Clause AND BSD-2-Clause AND LicenseRef-ICC-Software-0.2 AND LicenseRef-SunSoft-1994', 'Apache-2.0 AND BSD-3-Clause AND BSD-2-Clause AND MIT AND NCSA AND BSL-1.0 AND Zlib AND Unlicense', 'libtiff AND LicenseRef-Berkeley-LZW-Rescinded', 'LicenseRef-pkgconf-Permissive')})
LICENCES["LGPL-2.1-or-later"] = "agpl-compatible"
EXTERNAL_TOOL_LICENCES = {
    "make": "GPL-3.0-or-later",
    "perl": "GPL-1.0-or-later OR Artistic-1.0-Perl",
    "text-template": "GPL-1.0-or-later OR Artistic-1.0",
}
EXTERNAL_TOOL_VERSIONS = {"make": "4.3", "perl": "5.38.2", "text-template": "1.56"}
LICENCES.update({expression: "gpl-only" for expression in EXTERNAL_TOOL_LICENCES.values()})
LICENCES["BSD-3-Clause AND BSD-2-Clause AND MIT AND Apache-2.0 AND Apache-2.0 WITH LLVM-exception AND FTL AND Unicode-3.0 AND LicenseRef-AGG-2.3 AND libpng-2.0 AND Zlib AND IJG"] = "permissive"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON field: " + key)
        result[key] = value
    return result


def document(data: bytes) -> dict:
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique)


def fields(value: dict, names: str) -> None:
    require(isinstance(value, dict) and set(value) == set(names.split()), "Missing or unknown fields: " + names)


def text(value: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), "Blank or non-string required value")
    return value


def path(value: str) -> str:
    text(value)
    require(not value.startswith("/") and not any(c in value for c in "\\:*?\x00") and
            all(part not in {"", ".", ".."} for part in value.split("/")), "Nonliteral or escaping path: " + value)
    return value


def digest(value: str, lengths: tuple[int, ...] = (64,)) -> None:
    require(isinstance(value, str) and len(value) in lengths and bool(re.fullmatch("[0-9a-f]+", value)),
            "Expected full immutable hash")


def identifier(value: str) -> None:
    require(isinstance(value, str) and bool(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*-r[1-9][0-9]*", value)),
            "Invalid provenance record ID")


def strings(values: list, validate=text, empty: bool = False) -> None:
    require(isinstance(values, list) and (empty or bool(values)), "Expected nonempty array")
    for value in values:
        validate(value)
    require(len(set(values)) == len(values), "Duplicate array entry")


def repository(value: str) -> None:
    parsed = urlsplit(text(value))
    require(parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username and not parsed.password and
            not parsed.query and not parsed.fragment and len(parsed.path.strip("/")) > 0 and
            not parsed.path.endswith("/") and not any(p in {".", ".."} for p in parsed.path.split("/")),
            "Expected canonical HTTPS source repository")


def licence_evidence(values: list) -> None:
    require(isinstance(values, list) and bool(values), "Missing file-level licence evidence")
    for item in values:
        fields(item, "path sha256 finding")
        path(item["path"])
        digest(item["sha256"])
        text(item["finding"])


def source(value: dict, boundary: str) -> None:
    fields(value, "repository commit paths spdx evidence")
    repository(value["repository"])
    digest(value["commit"], (40, 64))
    strings(value["paths"], path)
    require(value["spdx"] in LICENCES, "Unknown generator/input SPDX expression")
    require(DECISIONS[LICENCES[value["spdx"]]][boundary] != "prohibited", "Incompatible generator/input")
    licence_evidence(value["evidence"])


def external_tools(value: list, expected: list | None = None) -> None:
    """Observe noncopying host tools; this never grants source/generation reuse."""
    require(isinstance(value, list) and 0 < len(value) <= 3, "Missing or unbounded external tools")
    seen = set()
    for item in value:
        fields(item, "id repository commit version role executable licence")
        ident = item["id"]
        require(ident in EXTERNAL_TOOL_LICENCES and ident not in seen, "Unknown or duplicate external tool")
        seen.add(ident)
        repository(item["repository"])
        digest(item["commit"], (40, 64))
        require(item["version"] == EXTERNAL_TOOL_VERSIONS[ident], "Unreviewed external tool version")
        require(item["role"] == "noncopying-external-execution", "External tool cannot authorize copied material")
        executable = item["executable"]
        fields(executable, "name version sha256")
        require(executable["name"] == ("Template.pm" if ident == "text-template" else ident) and
                executable["version"] == item["version"], "External tool executable identity differs")
        digest(executable["sha256"])
        licence = item["licence"]
        fields(licence, "spdx category evidence scope")
        require(licence["spdx"] == EXTERNAL_TOOL_LICENCES[ident] and licence["category"] == "gpl-only",
                "External tool legal expression/category differs")
        licence_evidence(licence["evidence"])
        text(licence["scope"])
    if expected is not None:
        require(value == expected, "External tool identity/version/hash/legal observation differs")


def read(root: Path, relative: str) -> bytes:
    path(relative)
    target = root / relative
    current = target
    while current != root:
        require(not current.is_symlink() and not getattr(current, "is_junction", lambda: False)(), "Linked provenance input: " + relative)
        current = current.parent
    require(target.is_file(), "Missing provenance input: " + relative)
    return target.read_bytes()


def policy(value: dict, owner: str) -> None:
    fields(value, "schemaVersion repository licenceBoundary authority decisions licences")
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and owner in OWNERS and
            value["repository"] == owner and value["licenceBoundary"] == OWNERS[owner], "Incorrect provenance owner")
    require(value["decisions"] == DECISIONS and value["licences"] == LICENCES, "Changed closed licence decision table")
    fields(value["authority"], "repository commit path")
    require(value["authority"]["repository"] == "https://github.com/ArcForges/ArcForges-Design" and
            value["authority"]["path"] == "docs/assurance/reference-coverage-and-provenance.md", "Incorrect provenance authority")
    digest(value["authority"]["commit"], (40, 64))


def record(value: dict, boundary: str) -> None:
    fields(value, RECORD_FIELDS + (" externalTools" if "externalTools" in value else ""))
    if "externalTools" in value:
        external_tools(value["externalTools"])
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1, "Invalid record schema")
    identifier(value["id"])
    require(value["kind"] in {"source", "patch", "generated", "legal-text"}, "Unknown material kind")
    repository(value["sourceRepository"])
    digest(value["sourceCommit"], (40, 64))
    strings(value["sourcePaths"], path)
    licence = value["licence"]
    fields(licence, "spdx category evidence scope copyingPermission")
    require(licence["spdx"] in LICENCES and licence["category"] == LICENCES[licence["spdx"]], "Unknown or mismatched licence category")
    licence_evidence(licence["evidence"])
    text(licence["scope"])
    if value["kind"] == "legal-text":
        text(licence["copyingPermission"])
        require(licence["spdx"] != "NOASSERTION", "Unknown-origin legal text")
    else:
        require(licence["copyingPermission"] is None, "Legal-document permission used for implementation")
        require(DECISIONS[licence["category"]][boundary] != "prohibited", "Prohibited implementation reuse")
    strings(value["attribution"])
    require(value["disposition"] in {"Copy", "Rewrite", "Improve", "Replace", "Reference Only", "Drop"}, "Unknown disposition")
    require(isinstance(value["targets"], list), "Invalid targets")
    target_paths = []
    for target in value["targets"]:
        fields(target, "path sha256 normalization")
        target_paths.append(path(target["path"]))
        digest(target["sha256"])
        require(target["normalization"] in {"lf", "raw"}, "Unknown target normalization")
        require(not target["path"].startswith("eng/provenance/") and target["path"] != POLICY,
                "A record cannot attest its own policy metadata")
        if value["kind"] == "legal-text":
            name = Path(target["path"]).name.lower()
            require(name.startswith(("license", "licence", "copying", "notice")) or
                    (name.endswith(".txt") and target["path"].startswith("third-party/")), "Legal text targets implementation")
    require(len(set(target_paths)) == len(target_paths), "Duplicate record target")
    require(isinstance(value["artifactTargets"], list), "Invalid artifact targets")
    artifact_keys = []
    for target in value["artifactTargets"]:
        fields(target, "project package kind profile sha256")
        for key in ("project", "package", "kind"):
            text(target[key])
        path(target["profile"])
        require(target["profile"].startswith("eng/provenance/artifact-profiles/"), "Artifact profile outside provenance store")
        digest(target["sha256"])
        artifact_keys.append((target["project"], target["package"], target["kind"]))
    require(len(set(artifact_keys)) == len(artifact_keys), "Duplicate artifact target")
    require(not artifact_keys or value["kind"] == "generated", "Artifact requires generator and input positions")
    if value["disposition"] in {"Reference Only", "Drop"}:
        require(not target_paths and not artifact_keys, "Reference-only/drop record binds copied material")
    else:
        require(bool(target_paths or artifact_keys), "Reuse has no target")
    verification = value["verification"]
    fields(verification, "kind command expected artifacts")
    require(verification["kind"] in {"byte-match", "regeneration", "transformation"}, "Unknown verification oracle")
    text(verification["command"])
    text(verification["expected"])
    require(isinstance(verification["artifacts"], list), "Invalid artifact evidence")
    for item in verification["artifacts"]:
        fields(item, "url sha256 members")
        repository(item["url"])
        digest(item["sha256"])
        strings(item["members"], path)
    notice = value["notice"]
    fields(notice, "required text files distribution reason")
    require(type(notice["required"]) is bool, "NOTICE requirement must be boolean")
    text(notice["text"])
    strings(notice["files"], path, empty=not notice["required"])
    require(notice["distribution"] in {"source", "packages", "documentation"}, "Unknown notice distribution")
    text(notice["reason"])
    lifetime = value["lifetime"]
    fields(lifetime, "status owner removalTrigger")
    require(lifetime["status"] in {"temporary", "permanent"}, "Unknown lifetime")
    text(lifetime["owner"])
    if lifetime["status"] == "temporary":
        text(lifetime["removalTrigger"])
    else:
        require(lifetime["removalTrigger"] is None, "Permanent record carries temporary removal trigger")
    generation = value["generation"]
    if value["kind"] == "generated":
        fields(generation, "generators inputs command outputSpdx")
        for role in ("generators", "inputs"):
            require(isinstance(generation[role], list) and bool(generation[role]), "Missing generation " + role)
            for item in generation[role]:
                source(item, boundary)
        text(generation["command"])
        require(generation["outputSpdx"] in LICENCES and
                DECISIONS[LICENCES[generation["outputSpdx"]]][boundary] != "prohibited",
                "Generated output crosses owner licence boundary")
    else:
        require(generation is None, "Non-generated record carries generation metadata")
    review = value["review"]
    fields(review, "owner reviewer reviewedOn decision rationale baselineCommit reconciliation")
    require(review["owner"] == "Licensing and Provenance Owner" and review["decision"] == "approved", "Unapproved disposition")
    text(review["reviewer"])
    text(review["rationale"])
    require(date.fromisoformat(text(review["reviewedOn"])).isoformat() == review["reviewedOn"], "Invalid review date")
    digest(review["baselineCommit"], (40, 64))
    require(type(review["reconciliation"]) is bool, "Missing retrospective/new-use classification")
    if value["supersedes"] is not None:
        identifier(value["supersedes"])
        require(value["supersedes"] != value["id"], "Self-superseding record")


def render(records: dict, active: set[str], packages: bool = False, documentation: bool = False) -> bytes:
    lines = ["ArcForges source provenance notices", "", "Generated from reviewed active records. Original licence files and dependency notices remain authoritative.", ""]
    for name in sorted(active):
        item = records[name]
        if packages and item["notice"]["distribution"] != "packages" or documentation and item["notice"]["distribution"] != "documentation":
            continue
        lines.extend([name, f"Source: {item['sourceRepository']} @ {item['sourceCommit']}",
                      "Material licence: " + item["licence"]["spdx"],
                      "Notice scope: " + item["notice"]["distribution"],
                      *item["attribution"], item["notice"]["text"], ""])
    return ("\n".join(lines).rstrip() + "\n").encode("utf-8")


def retirements(root: Path, owner: str, files: list[str], history: dict[str, bytes],
                records: dict, active_artifacts: list[str]) -> set[tuple[str, str, str, str]]:
    """Admit only the explicitly retired P2-019 native package registrations."""
    if RETIREMENTS not in files:
        return set()
    value = document(read(root, RETIREMENTS))
    fields(value, "schemaVersion repository authority targets")
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and
            owner == value["repository"] == "DesktopPlatform", "Incorrect retirement owner")
    require(value["authority"] == {"decision": "P2-019", "task": "GOV.17"}, "Incorrect retirement authority")
    require(isinstance(value["targets"], list) and bool(value["targets"]), "Missing retirement targets")
    catalogue = document(read(root, "eng/packaging/packages.json"))["packages"]
    allowed = {"ArcForges.Native." + family + ".Runtime.win-x64" for family in ("Media", "Colour", "Otio")}
    result = set()
    for target in value["targets"]:
        fields(target, "record project package kind")
        name = target["record"]
        identifier(name)
        package = text(target["package"])
        project = path(target["project"])
        kind = text(target["kind"])
        require(package in allowed and project == "src/Native/" + package + "/" + package + ".csproj",
                "Unapproved retired package/project")
        require(name.startswith("native-") and name.endswith("-r3") and kind == "native-component-" + name[7:-3],
                "Unapproved retired material")
        original = STORE + name + ".json"
        require(name in records and original in history and any(
            all(row[key] == target[key] for key in ("project", "package", "kind"))
            for row in document(history[original])["artifactTargets"]), "Unregistered retirement target")
        require(project not in files and not (root / project).exists() and not any(
            row["id"] == package or row["project"] == project for row in catalogue),
                "Retired project/package is still present")
        require(not any(row["package"] == package or row["project"] == project
                        for record_id in active_artifacts for row in records[record_id]["artifactTargets"]),
                "Retired artifact is still active")
        key = (name, project, package, kind)
        require(key not in result, "Duplicate retirement target")
        result.add(key)
    return result


def validate(root: Path, owner: str, files: list[str], history: dict[str, bytes], old_inventory: dict | None,
             write_notice: bool = False) -> dict:
    root = root.resolve()
    files = sorted(set(files))
    require(len({p.casefold() for p in files}) == len(files), "Case-colliding inventory")
    for filename in files:
        read(root, filename)
    policy(document(read(root, POLICY)), owner)
    # The template is explanatory data; it is never eligible to bind a target.
    template = document(read(root, "eng/provenance/template.json"))
    fields(template, "schemaVersion instructions example")
    require(type(template["schemaVersion"]) is int and template["schemaVersion"] == 1, "Invalid template schema")
    text(template["instructions"])
    fields(template["example"], RECORD_FIELDS)
    inv = document(read(root, INVENTORY))
    fields(inv, "schemaVersion repository firstParty reused artifacts")
    require(type(inv["schemaVersion"]) is int and inv["schemaVersion"] == 1 and inv["repository"] == owner, "Invalid inventory owner")
    strings(inv["firstParty"], path)
    require(isinstance(inv["reused"], dict), "Invalid reused inventory")
    strings(inv["artifacts"], identifier, empty=True)
    for target, name in inv["reused"].items():
        path(target)
        identifier(name)
    require(not set(inv["firstParty"]) & set(inv["reused"]), "Conflicting file classifications")
    require(set(files) == set(inv["firstParty"]) | set(inv["reused"]), "Unclassified or stale inventory files")
    records = {}
    for filename in files:
        if filename.startswith("eng/provenance/conflicts/"):
            conflict = document(read(root, filename))
            fields(conflict, "id material evidence boundary owner requiredDecision status resolution")
            require(conflict["status"] == "resolved" and bool(text(conflict["resolution"])), "Unresolved provenance conflict")
            for key in ("id", "material", "evidence", "boundary", "owner", "requiredDecision"):
                text(conflict[key])
        if not filename.startswith(STORE):
            continue
        value = document(read(root, filename))
        record(value, OWNERS[owner])
        require(filename == STORE + value["id"] + ".json", "Record path/ID mismatch")
        require(value["id"] not in records, "Duplicate provenance record")
        records[value["id"]] = value
    for filename, original in history.items():
        require(filename in files and read(root, filename).replace(b"\r\n", b"\n") == original.replace(b"\r\n", b"\n"),
                "Used record changed or removed: " + filename)
    for name in records:
        seen = {name}
        parent = records[name]["supersedes"]
        while parent is not None:
            require(parent in records and parent not in seen, "Missing or cyclic superseded record")
            seen.add(parent)
            parent = records[parent]["supersedes"]
    active = set(inv["reused"].values()) | set(inv["artifacts"])
    require(bool(active), "At least one real record must be in use")
    for name in active:
        require(name in records, "Missing provenance record: " + name)
        require({item["path"] for item in records[name]["targets"]} ==
                {target for target, record_id in inv["reused"].items() if record_id == name},
                "Active record targets do not match complete inventory bindings")
        require(bool(records[name]["artifactTargets"]) == (name in inv["artifacts"]),
                "Artifact record is not explicitly registered")
        for target in records[name]["artifactTargets"]:
            require(target["profile"] in files and
                    hashlib.sha256(read(root, target["profile"]).replace(b"\r\n", b"\n")).hexdigest() == target["sha256"],
                    "Untracked or changed artifact profile")
        for notice_file in records[name]["notice"]["files"]:
            require(notice_file in files, "Untracked or missing required notice: " + notice_file)
            read(root, notice_file)
    for target, name in inv["reused"].items():
        require(name in records, "Missing provenance record: " + name)
        item = records[name]
        matches = [row for row in item["targets"] if row["path"] == target]
        require(len(matches) == 1, "Active file not present in record: " + target)
        row = matches[0]
        data = read(root, target)
        if row["normalization"] == "lf":
            data.decode("utf-8")
            data = data.replace(b"\r\n", b"\n")
        require(hashlib.sha256(data).hexdigest() == row["sha256"], "Recorded target bytes changed: " + target)
        for notice_file in item["notice"]["files"]:
            require(notice_file in files, "Untracked or missing required notice: " + notice_file)
            read(root, notice_file)
    retired = retirements(root, owner, files, history, records, inv["artifacts"])
    if old_inventory is not None:
        for old_name in old_inventory["artifacts"]:
            old_targets = document(history[STORE + old_name + ".json"])["artifactTargets"]
            for target in old_targets:
                replacements = [name for name in inv["artifacts"] if any(
                    all(row[key] == target[key] for key in ("project", "package", "kind"))
                    for row in records[name]["artifactTargets"])]
                if (old_name, target["project"], target["package"], target["kind"]) in retired:
                    require(not replacements, "Retired artifact has an active replacement")
                    continue
                require(len(replacements) == 1, "Active artifact silently removed or multiply classified")
                name = replacements[0]
                while name != old_name and name is not None:
                    name = records[name]["supersedes"]
                require(name == old_name, "Replacement artifact record does not preserve provenance")
        for target, old_name in old_inventory["reused"].items():
            if target not in files:
                continue
            require(target in inv["reused"], "Retained external file reclassified as first-party: " + target)
            name = inv["reused"][target]
            while name != old_name and name is not None:
                name = records[name]["supersedes"]
            require(name == old_name, "Replacement record does not preserve active provenance")
    expected_notice = render(records, active)
    if write_notice:
        (root / SUMMARY).write_bytes(expected_notice)
    require(read(root, SUMMARY).replace(b"\r\n", b"\n") == expected_notice, "Stale generated provenance NOTICE")
    return {"result": "passed", "repository": owner, "files": len(files), "reusedFiles": len(inv["reused"]),
            "records": len(records), "activeRecords": sorted(active), "noticeSha256": hashlib.sha256(expected_notice).hexdigest()}


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.PIPE)


def baseline(root: Path, explicit: str | None) -> str:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    event_name = os.environ.get("GITHUB_EVENT_NAME")
    event = document(Path(event_path).read_bytes()) if event_path else {}
    if explicit:
        ref = explicit
    elif event_name == "pull_request":
        ref = event["pull_request"]["base"]["sha"]
    elif event_name == "push":
        ref = event["before"]
    elif event_name == "merge_group":
        ref = event["merge_group"]["base_sha"]
    else:
        branch = git(root, "rev-parse", "--abbrev-ref", "HEAD").decode().strip()
        ref = "HEAD" if branch == "main" else "origin/main"
    resolved = git(root, "rev-parse", "--verify", ref + "^{commit}").decode().strip()
    digest(resolved, (40, 64))
    return resolved


def run(root: Path, owner: str, base: str | None = None, write_notice: bool = False) -> dict:
    files = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").decode("utf-8").split("\0")
    files = [p for p in files if p]
    compared = baseline(root, base)
    history = {p: git(root, "show", compared + ":" + p) for p in
               git(root, "ls-tree", "-r", "--name-only", compared, "--", STORE).decode().splitlines()}
    previous_files = git(root, "ls-tree", "-r", "--name-only", compared, "--", INVENTORY).decode().splitlines()
    previous = document(git(root, "show", compared + ":" + INVENTORY)) if previous_files else None
    result = validate(root, owner, files, history, previous, write_notice)
    return {**result, "sourceCommit": git(root, "rev-parse", "HEAD").decode().strip(), "comparisonCommit": compared,
            "dirty": bool(git(root, "status", "--porcelain"))}


def package_notice(root: Path = ROOT, documentation: bool = False) -> str:
    inv = document(read(root, INVENTORY))
    records = {name: document(read(root, STORE + name + ".json")) for name in set(inv["reused"].values()) | set(inv["artifacts"])}
    return render(records, set(records), packages=not documentation, documentation=documentation).decode("utf-8")


def verify_package_notice(value: bytes, root: Path = ROOT) -> None:
    require(package_notice(root).encode("utf-8") in value.replace(b"\r\n", b"\n"),
            "Package lost recorded source/generator notices")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", required=True, choices=sorted(OWNERS))
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--base")
    parser.add_argument("--write-notice", action="store_true")
    parser.add_argument("--report", type=Path, default=Path("artifacts/evidence/provenance.json"))
    args = parser.parse_args()
    try:
        result = run(args.root.resolve(), args.owner, args.base, args.write_notice)
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
        result = {"result": "failed", "error": str(exc)}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))
    return 0 if result["result"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
