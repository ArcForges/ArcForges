# SPDX-License-Identifier: AGPL-3.0-only
"""Build, inspect and independently consume the explicitly admitted NuGet packages."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile

import native
import build_identity

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "https://github.com/ArcForges/DesktopPlatform"
VERSION = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def version(value):
    match = VERSION.fullmatch(value)
    require(match is not None, "Use canonical major.minor.patch[-prerelease]; no prefix, range or build metadata.")
    if match.group(4):
        require(all(not (part.isdigit() and len(part) > 1 and part[0] == "0")
                    for part in match.group(4).split(".")), "Prerelease numeric identifiers cannot have leading zeroes.")
    return value


def run(*args, cwd=ROOT, env=None, expected_error=None):
    # Argument arrays avoid shell interpolation of user-selected versions and paths.
    result = subprocess.run(args, cwd=cwd, env=env, text=True, encoding="utf-8", errors="replace",
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if expected_error:
        if result.returncode == 0 or expected_error not in result.stdout:
            print(result.stdout, end="", flush=True)
        require(result.returncode != 0 and expected_error in result.stdout,
                f"Expected rejection {expected_error}, got exit {result.returncode}.")
        print(f"PASS: expected rejection: {expected_error}", flush=True)
    else:
        print(result.stdout, end="", flush=True)
        result.check_returncode()
    return result.stdout


def source_commit():
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()


def dependency_versions(entry, package_version):
    """Keep owned release pairs separate from exact, independently published dependencies."""
    owned = entry.get("dependencies", [])
    external = entry.get("externalDependencies", {})
    require(isinstance(owned, list) and isinstance(external, dict), "Invalid dependency declarations.")
    require(not external or entry["kind"] == "managed", "External dependencies require a managed package.")
    names = owned + list(external)
    require(all(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", name) for name in names),
            "Invalid dependency ID.")
    require(len({name.lower() for name in names}) == len(names), "Duplicate or overlapping dependency ID.")
    result = {name: package_version for name in owned}
    for name, pin in external.items():
        require(isinstance(pin, str), "External dependency version must be a canonical exact string.")
        result[name] = version(pin)
    return result


def nuspec_dependencies(metadata):
    rows = metadata.findall(".//{*}dependency")
    names = [node.get("id") for node in rows]
    require(all(isinstance(name, str) and name for name in names), "Missing nuspec dependency ID.")
    require(len({name.lower() for name in names}) == len(names), "Duplicate nuspec dependency ID.")
    return {node.get("id"): node.get("version") for node in rows}


def validate_generated_dependencies(metadata, entry, package_version):
    generated = nuspec_dependencies(metadata)
    pins = dependency_versions(entry, package_version)
    expected = set(pins) if entry["kind"] == "managed" else set()
    require(set(generated) == expected, "Generated dependency set differs from the reviewed package closure.")
    for name, pin in entry.get("externalDependencies", {}).items():
        require(generated[name] in {pin, f"[{pin}]"},
                "Generated external dependency version differs from its exact admitted pin.")
    return pins


def catalogue():
    document = json.loads((ROOT / "eng/packaging/packages.json").read_text())
    require(document["schemaVersion"] == 1 and document["packages"], "Invalid/empty publication allowlist.")
    packages = document["packages"]
    require(len({p["id"].lower() for p in packages}) == len(packages), "Duplicate package ID.")
    owned_ids = {entry["id"].lower() for entry in packages}
    for entry in packages:
        require(entry["kind"] in {"build", "managed", "native"}, "Unreviewed package kind.")
        if entry["kind"] == "native":
            _, exports = native.abi_contract(entry)
            native.verify_abi(entry, entry.get("exports", []), entry.get("abi", {}))
            require(entry.get("exports") == sorted(exports),
                    "Native publication registry must declare its exact implemented ABI inventory.")
        dependency_versions(entry, "0.0.0")
        require(all(name.lower() in owned_ids for name in entry.get("dependencies", [])),
                "Owned dependency is absent from the publication allowlist.")
        require(not any(name.lower() in owned_ids for name in entry.get("externalDependencies", {})),
                "External dependency aliases an owned package.")
        project = (ROOT / entry["project"]).resolve()
        require(project.is_relative_to(ROOT) and project.is_file(), "Package project escapes the repository or is absent.")
        require(not list(project.parent.rglob("*Placeholder.cs")), "A placeholder cannot be published.")
    return packages


def inspect(path, entry, expected_version, commit):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) <= 200000 and all(info.file_size <= 512 * 1024 * 1024 for info in archive.infolist())
                and sum(info.file_size for info in archive.infolist()) <= 4 * 1024 * 1024 * 1024,
                "Unbounded package material.")
        require(len(names) == len(set(names)), "Duplicate archive entries.")
        require(all(not name.startswith("/") and ".." not in Path(name).parts and "\\" not in name
                    for name in names), "Unsafe archive paths.")
        require(set(entry["requiredFiles"]).issubset(names), f"Missing package content: {path.name}")
        specs = [name for name in names if name.endswith(".nuspec")]
        require(len(specs) == 1, "Expected one nuspec.")
        metadata = ET.fromstring(archive.read(specs[0])).find("{*}metadata")
        require(metadata.findtext("{*}id") == entry["id"], "Unexpected package ID.")
        require(metadata.findtext("{*}version") == expected_version, "Unexpected package version.")
        repository = metadata.find("{*}repository")
        require(repository is not None and repository.get("url") == REPOSITORY
                and repository.get("commit") == commit, "Repository source identity mismatch.")
        license_node = metadata.find("{*}license")
        require(license_node is not None and license_node.get("type") == "expression"
                and license_node.text == "AGPL-3.0-only", "Package licence mismatch.")
        require(metadata.findtext("{*}readme") == "README.md", "Missing package readme metadata.")
        expected_dependencies = {name: f"[{pin}]" for name, pin in dependency_versions(entry, expected_version).items()}
        dependencies = nuspec_dependencies(metadata)
        require(dependencies == expected_dependencies, "Package dependency closure/version mismatch.")
        if entry["kind"] == "build":
            require(not any(name.startswith(("lib/", "ref/", "runtimes/")) for name in names),
                    "Build policy must contain no runtime assets.")
            require(not metadata.findall(".//{*}dependency"), "Build policy must contain no package dependencies.")
        elif entry["kind"] == "managed":
            require(not any(name.startswith("runtimes/") for name in names), "Managed bindings must not bundle native assets.")
        else:
            require(not any(name.startswith(("lib/", "ref/")) for name in names), "RID package must not contain managed assemblies.")
            if entry["library"] == "ArcPdfNative":
                require("pdfium-production-input.json" in names, "PDF runtime requires its real sealed producer receipt.")
                native.native_provenance.verify_pdf_package(entry, archive.read, set(names), commit, ROOT)
                return native.digest(path)
            document = json.loads(archive.read("native-manifest.json"))
            require(document["sourceCommit"] == commit and document["rid"] == entry["rid"]
                    and document["library"] == entry["library"], "Native package source/RID/library mismatch.")
            prefix = f"runtimes/{entry['rid']}/native/"
            require(archive.read(prefix + entry["library"] + ".manifest.json") == archive.read("native-manifest.json"),
                    "Runtime deployment manifest differs from audited native manifest.")
            files = {row["name"].lower(): row for row in document["files"]}
            require({name[len(prefix):].lower() for name in names if name.startswith(prefix) and name.endswith(".dll")}
                    == set(files), "Native DLL closure differs from manifest.")
            require(not any(name.startswith("runtimes/") and not name.startswith(prefix) for name in names),
                    "Unexpected native RID assets.")
            for row in files.values():
                data = archive.read(prefix + row["name"])
                require(hashlib.sha256(data).hexdigest() == row["sha256"], "Native DLL hash mismatch.")
                details = native.pe(data)
                require(details["imports"] == row["imports"] and details["exports"] == row["exports"], "PE manifest mismatch.")
                require(all(name in files or native.system_dependency(name) for name in details["imports"]),
                        "Missing non-system native dependency.")
            owned = files[entry["library"].lower() + ".dll"]
            native.verify_abi(entry, owned["exports"], document.get("abi", {}))
            sbom = json.loads(archive.read("sbom.json"))
            require(sbom["sourceCommit"] == commit and sbom["binaryFiles"] == document["files"], "Native SBOM identity mismatch.")
            for dependency in sbom["buildDependencies"]:
                require(dependency["license"] in names and dependency["sbom"] in names, "Missing upstream licence/source record.")
                if dependency["name"] in {"ffmpeg", "libusb"}:
                    require(dependency["sourceArchive"] in names, "Missing corresponding native source archive.")
            native.native_provenance.verify(entry["id"], archive.read, set(names))
    return native.digest(path)


def pack(directory, package_version, native_directory=ROOT / "artifacts/native-packages"):
    directory.mkdir(parents=True, exist_ok=True)
    require(not list(directory.glob("*.nupkg")) and not (directory / "manifest.json").exists(),
            "Output already contains a candidate; choose a new empty --directory, never overwrite tested bytes.")
    run("python", str(ROOT / "eng/licence_boundary.py"))
    audit = native.native_provenance.provenance.run(ROOT, "DesktopPlatform",
        base=os.environ.get("GITHUB_SHA") if os.environ.get("GITHUB_REF", "").startswith("refs/tags/") else None)
    require(not audit["dirty"], "Commit reviewed changes before producing source-bound NuGet candidates.")
    commit = source_commit()
    native.verify_stage(native_directory, commit)
    identity = build_identity.build_identity(ROOT)
    axes = build_identity.resolve_axes(ROOT, json.loads((ROOT / 'eng/version-sources.json').read_text(encoding='utf-8')),
                                      packages=build_identity.dependency_versions(ROOT, native_directory))
    packages = []
    for entry in catalogue():
        args = ["dotnet", "pack", entry["project"], "-c", "Release", "--no-restore", "-o", str(directory),
                f"-p:PackageVersion={package_version}", f"-p:Version={package_version}", f"-p:RepositoryCommit={commit}"]
        if entry["kind"] == "native":
            args.append(f"-p:NativePayloadRoot={native_directory / entry['id']}")
        run(*args)
        name = f"{entry['id']}.{package_version}.nupkg"
        # dotnet pack emits minimum dependency versions. The release set uses exact immutable pairs;
        # finalize the nuspec before recording hashes or testing any candidate bytes.
        package_path = directory / name
        with zipfile.ZipFile(package_path) as original:
            contents = [(info, original.read(info.filename)) for info in original.infolist()]
        for index, (info, data) in enumerate(contents):
            if info.filename == '[Content_Types].xml':
                types = ET.fromstring(data)
                if not any(node.get('Extension') == 'json' for node in types):
                    ET.SubElement(types, '{http://schemas.openxmlformats.org/package/2006/content-types}Default',
                                  Extension='json', ContentType='application/json')
                    contents[index] = (info, ET.tostring(types, encoding='utf-8', xml_declaration=True))
            if info.filename.endswith(".nuspec"):
                specification = ET.fromstring(data)
                namespace = specification.tag.split("}")[0][1:]
                ET.register_namespace("", namespace)
                metadata = specification.find("{*}metadata")
                dependencies = metadata.find("{*}dependencies")
                pins = validate_generated_dependencies(metadata, entry, package_version)
                if dependencies is not None:
                    metadata.remove(dependencies)
                if pins:
                    dependencies = ET.SubElement(metadata, f"{{{namespace}}}dependencies")
                    group = ET.SubElement(dependencies, f"{{{namespace}}}group", targetFramework="net10.0")
                    for dependency, pin in pins.items():
                        ET.SubElement(group, f"{{{namespace}}}dependency", id=dependency, version=f"[{pin}]")
                contents[index] = (info, ET.tostring(specification, encoding="utf-8", xml_declaration=True))
        with zipfile.ZipFile(package_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for info, data in contents:
                archive.writestr(info, data)
            report = {'schema': 'arcforges.build-identity.v1', 'owner': 'DesktopPlatform',
                      'artifact': {'id': entry['id'], 'version': package_version}, 'build': identity, 'axes': axes}
            archive.writestr('build-identity.json', build_identity.canonical(report))
        digest = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        packages.append({"id": entry["id"], "version": package_version, "file": name, "sha256": digest})
    native_artifact = (native_directory / "native-artifact.json").read_bytes()
    (directory / "native-artifact.json").write_bytes(native_artifact)
    native.retain_package_handoff(native_directory, directory, commit)
    manifest = {"schemaVersion": 1, "repository": REPOSITORY, "sourceCommit": commit,
                "version": package_version, "packages": packages,
                "nativeArtifactSha256": hashlib.sha256(native_artifact).hexdigest(), "build": identity}
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    verify(directory, package_version, commit)


def verify(directory, package_version, commit=None):
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    commit = commit or source_commit()
    require(manifest["schemaVersion"] == 1 and manifest["repository"] == REPOSITORY, "Unexpected manifest identity.")
    require(manifest["sourceCommit"] == commit and manifest["version"] == package_version, "Manifest source/version mismatch.")
    native_bytes = (directory / "native-artifact.json").read_bytes()
    require(hashlib.sha256(native_bytes).hexdigest() == manifest["nativeArtifactSha256"], "Native artifact record hash mismatch.")
    native_artifact = json.loads(native_bytes)
    native.verify_identity(native_artifact, commit)
    native.verify_package_handoff(directory, native_artifact, commit)
    entries = catalogue()
    build_identity.verify_source_build(ROOT, manifest['build'])
    documents = []
    for entry in entries:
        if entry['kind'] == 'native':
            with zipfile.ZipFile(directory / f"{entry['id']}.{package_version}.nupkg") as archive:
                documents.append((entry['id'] + '/sbom.json', archive.read('sbom.json')))
    axes = build_identity.resolve_axes(ROOT, json.loads((ROOT / 'eng/version-sources.json').read_text(encoding='utf-8')),
                                      packages=build_identity.dependency_versions(ROOT, native_documents=documents))
    rows = manifest["packages"]
    require(len(rows) == len(entries) and {row["id"] for row in rows} == {entry["id"] for entry in entries},
            "Manifest does not match publication allowlist.")
    expected_files = {f"{entry['id']}.{package_version}.nupkg" for entry in entries}
    actual_files = {p.name for p in directory.iterdir() if p.suffix in (".nupkg", ".snupkg")}
    require(actual_files == expected_files, "Unexpected or missing package files.")
    for entry in entries:
        row = next(row for row in rows if row["id"] == entry["id"])
        name = f"{entry['id']}.{package_version}.nupkg"
        require(row["file"] == name and row["version"] == package_version, "Manifest package name/version mismatch.")
        digest = inspect(directory / name, entry, package_version, commit)
        require(digest == row["sha256"], f"Package hash mismatch: {name}")
        with zipfile.ZipFile(directory / name) as archive:
            report = json.loads(archive.read('build-identity.json'))
            build_identity.verify_report(report, entry['id'], package_version, commit)
            require(report['build'] == manifest['build'], 'Packaged build identity differs from producer.')
            require(report['axes'] == axes, 'Packaged version axes differ from independent sources.')
        if entry["kind"] == "native":
            producer = next(p for p in native_artifact["packages"] if p["id"] == entry["id"])
            with zipfile.ZipFile(directory / name) as archive:
                for file in producer["files"]:
                    require(hashlib.sha256(archive.read(file["path"])).hexdigest() == file["sha256"],
                            "Packed native payload differs from the tested producer artifact.")
    print(f"Verified {len(entries)} package(s), version {package_version}, source {commit}.", flush=True)
    return manifest


def smoke(directory, package_version, commit=None):
    require(not os.environ.get("GITHUB_ACTIONS") and os.environ.get("CI", "").lower() != "true",
            "Package consumers are explicit local diagnostics only; CI execution is prohibited.")
    verify(directory, package_version, commit)
    smoke_policy(directory, package_version)


def smoke_policy(directory, package_version):
    """Exercise the build-only package; complete release acceptance also requires verify()."""
    # Outside every checkout, with no inherited Directory.Build files or shared package cache.
    temporary_root = Path(tempfile.mkdtemp(prefix="arcforges-package-consumer-")).resolve()
    require(not temporary_root.is_relative_to(ROOT), "Consumer must be outside the producer checkout.")
    print(f"Isolated consumer and evidence: {temporary_root}", flush=True)
    env = {key: value for key, value in os.environ.items() if not key.startswith('GITHUB_')}
    env["NUGET_PACKAGES"] = str(temporary_root / ".packages")
    env["NUGET_HTTP_CACHE_PATH"] = str(temporary_root / ".http-cache")
    env["CI"] = "false"  # First fixture restore creates its lock; the next is explicitly locked.
    (temporary_root / "global.json").write_bytes((ROOT / "global.json").read_bytes())
    configuration = ET.Element("configuration")
    sources = ET.SubElement(configuration, "packageSources")
    ET.SubElement(sources, "clear")
    ET.SubElement(sources, "add", key="candidate", value=str(directory))
    ET.SubElement(sources, "add", key="nuget.org", value="https://api.nuget.org/v3/index.json")
    mapping = ET.SubElement(configuration, "packageSourceMapping")
    local = ET.SubElement(mapping, "packageSource", key="candidate")
    ET.SubElement(local, "package", pattern="ArcForges.*")
    public = ET.SubElement(mapping, "packageSource", key="nuget.org")
    ET.SubElement(public, "package", pattern="*")
    ET.ElementTree(configuration).write(temporary_root / "NuGet.config", encoding="utf-8", xml_declaration=True)
    for entry in catalogue():
        if entry["kind"] != "build":
            continue
        consumer = temporary_root / entry["id"]
        consumer.mkdir()
        project = consumer / "Consumer.csproj"
        project_text = f'''<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Exe</OutputType></PropertyGroup>
  <ItemGroup><PackageReference Include="{entry['id']}" PrivateAssets="all" /></ItemGroup>
</Project>
'''
        project.write_text(project_text, encoding="utf-8")
        central = consumer / "Directory.Packages.props"
        central_text = f'''<Project><PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup>
<ItemGroup><PackageVersion Include="{entry['id']}" Version="{package_version}" /></ItemGroup></Project>
'''
        central.write_text(central_text, encoding="utf-8")
        (consumer / "Program.cs").write_text('''using System.Reflection;
var metadata = typeof(Program).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().ToDictionary(a => a.Key, a => a.Value);
if (metadata["ArcForges.BuildKind"] != "local" || metadata["ArcForges.BuildId"] != "local.local" || metadata["ArcForges.SourceDateEpoch"] != "0") throw new Exception("Local fixture metadata mismatch");
Console.WriteLine("package-consumer-ok");
''', encoding="utf-8")
        run("dotnet", "restore", str(project), "--use-lock-file", "--configfile", str(temporary_root / "NuGet.config"), cwd=consumer, env=env)
        env["CI"] = "true"
        run("dotnet", "restore", str(project), "--locked-mode", "--configfile", str(temporary_root / "NuGet.config"), cwd=consumer, env=env)
        run("dotnet", "build", str(project), "-c", "Release", "--no-restore", cwd=consumer, env=env)
        output = run("dotnet", str(consumer / "bin/Release/net10.0/Consumer.dll"), cwd=consumer, env=env)
        require("package-consumer-ok" in output, "Consumer did not execute.")
        # Actual SDK operations against the installed package, not source-text tests.
        project.write_text(project_text.replace('PrivateAssets="all"', 'PrivateAssets="all" VersionOverride="1.0.0"'), encoding="utf-8")
        run("dotnet", "msbuild", str(project), "-t:ArcForgesVerifyPackagePolicy", cwd=consumer, env=env, expected_error="AFP002")
        project.write_text(project_text, encoding="utf-8")
        central.write_text(central_text.replace(f'Version="{package_version}"', 'Version="1.*"'), encoding="utf-8")
        run("dotnet", "msbuild", str(project), "-t:ArcForgesVerifyPackagePolicy", cwd=consumer, env=env, expected_error="AFP003")
        central.write_text(central_text, encoding="utf-8")
        run("dotnet", "build", str(project), "-c", "Release", "--no-restore", "-p:LangVersion=preview", cwd=consumer, env=env, expected_error="AFP004")
        run("dotnet", "build", str(project), "-c", "Release", "--no-restore", "-p:RestoreLockedMode=false", cwd=consumer, env=env, expected_error="AFP005")
        run("dotnet", "build", str(project), "-c", "Release", "--no-restore", "-p:ArcForgesBuildKind=ci", cwd=consumer, env=env, expected_error="AFP006")
        run("dotnet", "build", str(project), "-c", "Release", "--no-restore", "-p:ArcForgesBuildKind=unknown", cwd=consumer, env=env, expected_error="AFP006")
        installed = temporary_root / ".packages" / entry["id"].lower() / package_version.lower()
        restored = installed / f"{entry['id'].lower()}.{package_version.lower()}.nupkg"
        original = directory / f"{entry['id']}.{package_version}.nupkg"
        require(restored.read_bytes() == original.read_bytes(), "Consumer did not restore the tested candidate bytes.")
    print("Independent package consumption and negative policy fixtures passed.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["version", "pack", "verify", "smoke"])
    parser.add_argument("--version", required=True)
    parser.add_argument("--directory", type=Path, default=ROOT / "artifacts/packages")
    parser.add_argument("--commit")
    parser.add_argument("--native-directory", type=Path, default=ROOT / "artifacts/native-packages")
    args = parser.parse_args()
    package_version = version(args.version)
    directory = args.directory.resolve()
    if args.command == "pack":
        pack(directory, package_version, args.native_directory.resolve())
    elif args.command == "verify":
        verify(directory, package_version, args.commit)
    elif args.command == "smoke":
        smoke(directory, package_version, args.commit)
    else:
        print(package_version)


if __name__ == "__main__":
    main()
