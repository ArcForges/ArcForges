# SPDX-License-Identifier: Apache-2.0
"""Adversarial provenance checks use synthetic material and real temporary Git history."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "eng"))
import check_provenance as provenance


def sha(value):
    return hashlib.sha256(value).hexdigest()


class Fixture:
    def __init__(self, root):
        self.root = root
        self.value = {
            "schemaVersion": 1, "id": "synthetic-library-r1", "kind": "source",
            "sourceRepository": "https://example.org/upstream/library", "sourceCommit": "a" * 40,
            "sourcePaths": ["src/library.txt"],
            "licence": {"spdx": "MIT", "category": "permissive",
                        "evidence": [{"path": "LICENSE", "sha256": "b" * 64, "finding": "Synthetic MIT fixture."}],
                        "scope": "Synthetic test material only.", "copyingPermission": None},
            "attribution": ["Synthetic fixture authors"],
            "targets": [{"path": "vendor/library.txt", "sha256": sha(b"fixture\n"), "normalization": "lf"}],
            "artifactTargets": [],
            "disposition": "Copy",
            "verification": {"kind": "byte-match", "command": "Compare reviewed fixture bytes.",
                             "expected": "Exact UTF-8 text.", "artifacts": []},
            "notice": {"required": True, "text": "Synthetic fixture attribution.",
                       "files": ["LICENSE"], "distribution": "packages", "reason": "Required fixture notice."},
            "lifetime": {"status": "permanent", "owner": "Fixture Owner", "removalTrigger": None},
            "generation": None,
            "review": {"owner": "Licensing and Provenance Owner", "reviewer": "Synthetic test reviewer",
                       "reviewedOn": "2026-09-18", "decision": "approved", "rationale": "Test fixture only.",
                       "baselineCommit": "c" * 40, "reconciliation": False},
            "supersedes": None,
        }
        self.write("vendor/library.txt", b"fixture\n")
        self.write("LICENSE", b"Synthetic licence placeholder, not reused third-party material.\n")
        self.put("eng/provenance/template.json", {"schemaVersion": 1, "instructions": "Synthetic fixture template.",
                                                "example": self.value})
        self.put(provenance.POLICY, {"schemaVersion": 1, "repository": "Contracts", "licenceBoundary": "Apache",
                                   "authority": {"repository": "https://github.com/ArcForges/ArcForges-Design",
                                                 "commit": "d" * 40, "path": "docs/assurance/reference-coverage-and-provenance.md"},
                                   "decisions": provenance.DECISIONS, "licences": provenance.LICENCES})
        self.save()
        self.write(provenance.SUMMARY, provenance.render({self.value["id"]: self.value}, {self.value["id"]}))
        self.inventory()

    @property
    def record_path(self):
        return provenance.STORE + self.value["id"] + ".json"

    def write(self, path, value):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value)

    def put(self, path, value):
        self.write(path, (json.dumps(value, indent=2) + "\n").encode())

    def get(self, path):
        return json.loads((self.root / path).read_bytes())

    def save(self):
        self.put(self.record_path, self.value)

    def files(self):
        return sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob("*")
                      if p.is_file() and ".git" not in p.relative_to(self.root).parts)

    def inventory(self):
        active = {item["path"]: self.value["id"] for item in self.value["targets"]}
        artifacts = [self.value["id"]] if self.value["artifactTargets"] else []
        self.put(provenance.INVENTORY, {"schemaVersion": 1, "repository": "Contracts", "firstParty": [], "reused": active, "artifacts": artifacts})
        self.put(provenance.INVENTORY, {"schemaVersion": 1, "repository": "Contracts",
                                       "firstParty": [p for p in self.files() if p not in active], "reused": active, "artifacts": artifacts})

    def validate(self, history=None, previous=None):
        return provenance.validate(self.root, "Contracts", self.files(), history or {}, previous)

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, stderr=subprocess.PIPE).decode().strip()

    def commit(self):
        self.git("init", "-b", "main")
        self.git("-c", "core.autocrlf=false", "add", ".")
        self.git("-c", "user.name=Provenance Tests", "-c", "user.email=tests@example.invalid", "commit", "-m", "Synthetic baseline")
        return self.git("rev-parse", "HEAD")


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="arcforges-provenance-test-")
        self.addCleanup(self.temp.cleanup)
        self.fixture = Fixture(Path(self.temp.name))

    def test_complete_reviewed_material_passes_and_normalizes_windows_text(self):
        self.fixture.write("vendor/library.txt", b"fixture\r\n")
        result = self.fixture.validate()
        self.assertEqual(result["reusedFiles"], 1)
        self.assertEqual(result["activeRecords"], ["synthetic-library-r1"])

    def test_every_required_field_is_required(self):
        original = copy.deepcopy(self.fixture.value)
        for field in original:
            with self.subTest(field=field):
                broken = copy.deepcopy(original)
                del broken[field]
                self.fixture.put(self.fixture.record_path, broken)
                with self.assertRaisesRegex(ValueError, "Missing or unknown fields"):
                    self.fixture.validate()

    def test_blank_values_and_floating_sources_fail(self):
        cases = [("sourceRepository", " "), ("sourceRepository", "http://example.org/repo"),
                 ("sourceCommit", "main"), ("sourceCommit", "abcd123"), ("sourcePaths", []),
                 ("sourcePaths", ["../other/source.cs"]), ("attribution", []), ("disposition", "Allowed")]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                changed = copy.deepcopy(self.fixture.value)
                changed[key] = value
                self.fixture.put(self.fixture.record_path, changed)
                with self.assertRaises(ValueError):
                    self.fixture.validate()

    def test_unknown_duplicate_or_missing_template_fields_fail(self):
        self.fixture.write(self.fixture.record_path, b'{"schemaVersion":1,"schemaVersion":1}')
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            self.fixture.validate()
        self.fixture.save()
        template = self.fixture.get("eng/provenance/template.json")
        del template["example"]["notice"]
        self.fixture.put("eng/provenance/template.json", template)
        with self.assertRaisesRegex(ValueError, "Missing or unknown fields"):
            self.fixture.validate()

    def test_untracked_new_file_and_missing_record_fail(self):
        self.fixture.write("new-source.cs", b"// New source requires classification.\n")
        with self.assertRaisesRegex(ValueError, "Unclassified or stale"):
            self.fixture.validate()
        (self.fixture.root / "new-source.cs").unlink()
        inv = self.fixture.get(provenance.INVENTORY)
        inv["reused"]["vendor/library.txt"] = "missing-record-r1"
        self.fixture.put(provenance.INVENTORY, inv)
        with self.assertRaisesRegex(ValueError, "Missing provenance record"):
            self.fixture.validate()

    def test_missing_target_changed_bytes_and_notice_drift_fail(self):
        self.fixture.write("vendor/library.txt", b"changed\n")
        with self.assertRaisesRegex(ValueError, "Recorded target bytes changed"):
            self.fixture.validate()
        self.fixture.write("vendor/library.txt", b"fixture\n")
        self.fixture.write(provenance.SUMMARY, b"Incomplete attribution\n")
        with self.assertRaisesRegex(ValueError, "Stale generated provenance NOTICE"):
            self.fixture.validate()
        (self.fixture.root / "vendor/library.txt").unlink()
        with self.assertRaisesRegex(ValueError, "Unclassified or stale"):
            self.fixture.validate()

    def test_policy_edit_cannot_admit_copyleft_in_apache(self):
        data = self.fixture.get(provenance.POLICY)
        data["decisions"]["gpl-only"]["Apache"] = "audit"
        self.fixture.put(provenance.POLICY, data)
        with self.assertRaisesRegex(ValueError, "Changed closed licence decision table"):
            self.fixture.validate()

    def test_incompatible_implementation_licences_fail(self):
        for spdx, category in [("AGPL-3.0-only", "agpl-compatible"), ("GPL-3.0-only", "gpl-only"),
                               ("NOASSERTION", "unclear"), ("EPL-1.0", "incompatible")]:
            with self.subTest(spdx=spdx):
                self.fixture.value["licence"].update(spdx=spdx, category=category)
                self.fixture.save()
                with self.assertRaisesRegex(ValueError, "Prohibited implementation"):
                    self.fixture.validate()

    def test_legal_document_permission_does_not_admit_source(self):
        item = self.fixture.value
        item["kind"] = "legal-text"
        item["licence"].update(spdx="EPL-1.0", category="incompatible", copyingPermission="The synthetic agreement permits reproducing the agreement only.")
        item["targets"][0]["path"] = "vendor/incompatible.cs"
        self.fixture.save()
        with self.assertRaisesRegex(ValueError, "Legal text targets implementation"):
            self.fixture.validate()
        item["kind"] = "source"
        self.fixture.save()
        with self.assertRaisesRegex(ValueError, "Legal-document permission used for implementation"):
            self.fixture.validate()

    def test_temporary_material_requires_owner_and_trigger(self):
        for owner, trigger in [("", "Remove when replaced"), ("Fixture Owner", None), ("Fixture Owner", " ")]:
            with self.subTest(owner=owner, trigger=trigger):
                self.fixture.value["lifetime"] = {"status": "temporary", "owner": owner, "removalTrigger": trigger}
                self.fixture.save()
                with self.assertRaises(ValueError):
                    self.fixture.validate()

    def test_generated_material_requires_admissible_generator_and_input(self):
        src = {"repository": "https://example.org/compiler/source", "commit": "e" * 40,
               "paths": ["compiler.cs"], "spdx": "MIT", "evidence": copy.deepcopy(self.fixture.value["licence"]["evidence"])}
        self.fixture.value["kind"] = "generated"
        generation = {"generators": [src], "inputs": [copy.deepcopy(src)], "command": "Generate fixture", "outputSpdx": "Apache-2.0"}
        for mutation in ("missing-generator", "missing-input", "copyleft-input", "copyleft-output"):
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(generation)
                if mutation == "missing-generator": value["generators"] = []
                if mutation == "missing-input": value["inputs"] = []
                if mutation == "copyleft-input": value["inputs"][0]["spdx"] = "AGPL-3.0-only"
                if mutation == "copyleft-output": value["outputSpdx"] = "AGPL-3.0-only"
                self.fixture.value["generation"] = value
                self.fixture.save()
                with self.assertRaises(ValueError):
                    self.fixture.validate()

    def test_reference_only_cannot_bind_material(self):
        self.fixture.value["disposition"] = "Reference Only"
        self.fixture.save()
        with self.assertRaisesRegex(ValueError, "Reference-only/drop record binds copied material"):
            self.fixture.validate()

    def test_path_escape_and_link_are_rejected(self):
        for filename in ("../outside.txt", "/outside.txt", "C:/outside.txt", "vendor\\outside.txt", "vendor/*.txt"):
            with self.subTest(filename=filename):
                with self.assertRaises(ValueError):
                    provenance.read(self.fixture.root, filename)
        with patch.object(Path, "is_symlink", return_value=True):
            with self.assertRaisesRegex(ValueError, "Linked provenance input"):
                self.fixture.validate()

    def test_unresolved_conflict_fails(self):
        self.fixture.put("eng/provenance/conflicts/example-r1.json", {
            "id": "example-r1", "material": "Unaccepted contribution", "evidence": "Unknown licence",
            "boundary": "Apache", "owner": "Licensing and Provenance Owner", "requiredDecision": "Establish origin",
            "status": "blocked", "resolution": None})
        self.fixture.inventory()
        with self.assertRaisesRegex(ValueError, "Unresolved provenance conflict"):
            self.fixture.validate()

    def test_real_git_history_rejects_record_mutation_deletion_and_missing_base(self):
        commit = self.fixture.commit()
        with patch.dict(os.environ, {"GITHUB_EVENT_PATH": "", "GITHUB_EVENT_NAME": ""}):
            self.assertEqual(provenance.run(self.fixture.root, "Contracts", commit)["result"], "passed")
            self.fixture.value["review"]["rationale"] = "Rewritten history"
            self.fixture.save()
            with self.assertRaisesRegex(ValueError, "Used record changed or removed"):
                provenance.run(self.fixture.root, "Contracts", commit)
            (self.fixture.root / self.fixture.record_path).unlink()
            self.fixture.git("add", "-u")
            self.fixture.inventory()
            with self.assertRaisesRegex(ValueError, "Used record changed or removed"):
                provenance.run(self.fixture.root, "Contracts", commit)
            with self.assertRaises(subprocess.CalledProcessError):
                provenance.run(self.fixture.root, "Contracts", "f" * 40)

    def test_reclassification_cannot_erase_known_external_origin(self):
        previous = self.fixture.get(provenance.INVENTORY)
        # Keep another real target so the at-least-one-record rule cannot mask this failure.
        other = copy.deepcopy(self.fixture.value)
        other["id"] = "other-library-r1"
        other["targets"][0]["path"] = "vendor/other.txt"
        self.fixture.put(provenance.STORE + other["id"] + ".json", other)
        self.fixture.write("vendor/other.txt", b"fixture\n")
        self.fixture.value = other
        self.fixture.inventory()
        self.fixture.write(provenance.SUMMARY, provenance.render({other["id"]: other}, {other["id"]}))
        with self.assertRaisesRegex(ValueError, "Retained external file reclassified as first-party"):
            self.fixture.validate(previous=previous)

    def test_superseding_revision_preserves_history_and_target_group(self):
        original_name = self.fixture.record_path
        history = {original_name: (self.fixture.root / original_name).read_bytes()}
        previous = self.fixture.get(provenance.INVENTORY)
        old = copy.deepcopy(self.fixture.value)
        self.fixture.value["id"] = "synthetic-library-r2"
        self.fixture.value["supersedes"] = old["id"]
        self.fixture.value["sourceCommit"] = "f" * 40
        self.fixture.value["targets"][0]["sha256"] = sha(b"updated fixture\n")
        self.fixture.write("vendor/library.txt", b"updated fixture\n")
        self.fixture.save()
        self.fixture.inventory()
        records = {old["id"]: old, self.fixture.value["id"]: self.fixture.value}
        self.fixture.write(provenance.SUMMARY, provenance.render(records, {self.fixture.value["id"]}))
        self.assertEqual(self.fixture.validate(history, previous)["records"], 2)
        self.fixture.value["supersedes"] = None
        self.fixture.save()
        with self.assertRaisesRegex(ValueError, "Replacement record does not preserve"):
            self.fixture.validate(history, previous)

    def test_package_notice_is_required_and_not_replaced_by_dependency_inventory(self):
        expected = provenance.package_notice(self.fixture.root).encode()
        provenance.verify_package_notice(b"Runtime dependency inventory\n" + expected, self.fixture.root)
        with self.assertRaisesRegex(ValueError, "Package lost recorded source/generator notices"):
            provenance.verify_package_notice(b"Runtime dependency inventory\n", self.fixture.root)

    def test_artifact_requires_registered_profile_generator_and_notice(self):
        value = self.fixture.value
        value["kind"] = "generated"
        origin = {"repository": value["sourceRepository"], "commit": value["sourceCommit"],
                  "paths": value["sourcePaths"], "spdx": "MIT", "evidence": value["licence"]["evidence"]}
        value["generation"] = {"generators": [origin], "inputs": [origin], "command": "Synthetic generation", "outputSpdx": "MIT"}
        filename = "eng/provenance/artifact-profiles/synthetic-r1.json"
        self.fixture.write(filename, b"{}\n")
        value["artifactTargets"] = [{"project": "fixture", "package": "example:fixture", "kind": "test",
                                     "profile": filename, "sha256": sha(b"{}\n")}]
        value["notice"]["distribution"] = "documentation"
        self.fixture.save()
        self.fixture.inventory()
        self.fixture.write(provenance.SUMMARY, provenance.render({value["id"]: value}, {value["id"]}))
        self.fixture.validate()
        self.assertNotIn(value["id"], provenance.package_notice(self.fixture.root))
        self.assertIn(value["id"], provenance.package_notice(self.fixture.root, documentation=True))
        self.fixture.write(filename, b'{"changed":true}\n')
        with self.assertRaisesRegex(ValueError, "changed artifact profile"):
            self.fixture.validate()
        self.fixture.write(filename, b"{}\n")
        inv = self.fixture.get(provenance.INVENTORY)
        inv["artifacts"] = []
        self.fixture.put(provenance.INVENTORY, inv)
        with self.assertRaisesRegex(ValueError, "not explicitly registered"):
            self.fixture.validate()

    def test_ci_event_selects_the_actual_base_commit(self):
        commit = self.fixture.commit()
        event_path = self.fixture.root / ".git" / "test-event.json"
        for event_name, event in [("pull_request", {"pull_request": {"base": {"sha": commit}}}),
                                  ("push", {"before": commit}),
                                  ("merge_group", {"merge_group": {"base_sha": commit}})]:
            with self.subTest(event_name=event_name):
                event_path.write_text(json.dumps(event), encoding="utf-8")
                with patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(event_path), "GITHUB_EVENT_NAME": event_name}):
                    self.assertEqual(provenance.run(self.fixture.root, "Contracts")["comparisonCommit"], commit)


class NativeRetirementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = Fixture(Path(self.temp.name))
        package = "ArcForges.Native.Media.Runtime.win-x64"
        self.target = {"record": "native-ffmpeg-r3", "package": package,
                       "project": "src/Native/" + package + "/" + package + ".csproj",
                       "kind": "native-component-ffmpeg"}
        self.receipt = {"schemaVersion": 1, "repository": "DesktopPlatform",
                        "authority": {"decision": "P2-019", "task": "GOV.17"}, "targets": [self.target]}
        self.records = {"native-ffmpeg-r3": {"artifactTargets": [dict(self.target)]}}
        self.history = {provenance.STORE + "native-ffmpeg-r3.json": json.dumps(self.records["native-ffmpeg-r3"]).encode()}
        self.fixture.put("eng/packaging/packages.json", {"packages": []})

    def validate(self, owner="DesktopPlatform", active=()):
        self.fixture.put(provenance.RETIREMENTS, self.receipt)
        return provenance.retirements(self.fixture.root, owner, self.fixture.files(), self.history, self.records, active)

    def test_exact_deleted_historical_target_can_retire(self):
        self.assertEqual(len(self.validate()), 1)

    def test_retained_artifact_cannot_disappear_from_active_inventory(self):
        value = copy.deepcopy(self.fixture.value)
        value["id"] = "retained-image-r1"
        value["kind"] = "generated"
        value["targets"] = []
        origin = {"repository": value["sourceRepository"], "commit": value["sourceCommit"],
                  "paths": value["sourcePaths"], "spdx": "MIT", "evidence": value["licence"]["evidence"]}
        value["generation"] = {"generators": [origin], "inputs": [origin], "command": "Synthetic generation", "outputSpdx": "MIT"}
        value["artifactTargets"] = [{"project": "retained", "package": "ArcForges.Native.Image.Runtime.win-x64",
                                     "kind": "native-component-image", "profile": "eng/provenance/artifact-profiles/image.json",
                                     "sha256": "a" * 64}]
        filename = provenance.STORE + value["id"] + ".json"
        self.fixture.put(filename, value)
        self.fixture.inventory()
        previous = self.fixture.get(provenance.INVENTORY)
        previous["artifacts"] = [value["id"]]
        with self.assertRaisesRegex(ValueError, "Active artifact silently removed"):
            self.fixture.validate({filename: (self.fixture.root / filename).read_bytes()}, previous)

    def test_retained_image_cannot_retire_even_with_matching_history(self):
        self.target["package"] = "ArcForges.Native.Image.Runtime.win-x64"
        self.target["project"] = "src/Native/" + self.target["package"] + "/" + self.target["package"] + ".csproj"
        with self.assertRaisesRegex(ValueError, "Unapproved retired package/project"):
            self.validate()

    def test_unregistered_and_mismatched_material_fail(self):
        self.history.clear()
        with self.assertRaisesRegex(ValueError, "Unregistered retirement target"):
            self.validate()
        self.target["kind"] = "native-component-other"
        with self.assertRaisesRegex(ValueError, "Unapproved retired material"):
            self.validate()

    def test_live_project_catalogue_or_registration_cannot_retire(self):
        self.fixture.write(self.target["project"], b"<Project />")
        with self.assertRaisesRegex(ValueError, "still present"):
            self.validate()
        (self.fixture.root / self.target["project"]).unlink()
        self.fixture.put("eng/packaging/packages.json", {"packages": [{"id": self.target["package"], "project": self.target["project"]}]})
        with self.assertRaisesRegex(ValueError, "still present"):
            self.validate()
        self.fixture.put("eng/packaging/packages.json", {"packages": []})
        with self.assertRaisesRegex(ValueError, "still active"):
            self.validate(active=["native-ffmpeg-r3"])

    def test_wrong_owner_authority_and_duplicate_fail(self):
        with self.assertRaisesRegex(ValueError, "retirement owner"):
            self.validate(owner="Contracts")
        self.receipt["authority"]["task"] = "OTHER"
        with self.assertRaisesRegex(ValueError, "retirement authority"):
            self.validate()
        self.receipt["authority"]["task"] = "GOV.17"
        self.receipt["targets"].append(dict(self.target))
        with self.assertRaisesRegex(ValueError, "Duplicate retirement"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
