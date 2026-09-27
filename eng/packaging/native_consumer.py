# SPDX-License-Identifier: AGPL-3.0-only
"""Consume actual NuGets outside the checkout, including Native AOT and C17 callers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

import packages


def execute(executable, directory, env, failure=False):
    runtime_env = {key: value for key, value in env.items() if not key.upper().startswith(("VCPKG", "DOTNET_ROOT"))}
    runtime_env["PATH"] = str(Path(os.environ["SystemRoot"]) / "System32")
    result = subprocess.run([str(executable)], cwd=directory, env=runtime_env, capture_output=True, text=True)
    if failure:
        packages.require(result.returncode != 0, "Missing/tampered native runtime was silently accepted.")
        packages.require(any(text in result.stderr for text in ["FileNotFoundException", "hash mismatch", "DllNotFoundException"]),
                         "Negative consumer failed for an unrelated reason: " + result.stderr)
    else:
        packages.require(result.returncode == 0 and "package-native-ok" in result.stdout,
                         "Packaged native consumer failed: " + result.stdout + result.stderr)
        print(result.stdout, end="", flush=True)
    return result


def consume(directory, version, commit):
    packages.require(not os.environ.get("GITHUB_ACTIONS") and os.environ.get("CI", "").lower() != "true",
                     "Native consumers are explicit local diagnostics only; CI execution is prohibited.")
    packages.require(os.name == "nt", "win-x64 native consumers require Windows.")
    manifest = packages.verify(directory, version, commit)
    root = Path(tempfile.mkdtemp(prefix="arcforges-native-consumer-")).resolve()
    packages.require(not root.is_relative_to(packages.ROOT), "Consumer must not inherit producer build files.")
    print("Native consumer evidence: " + str(root), flush=True)
    env = {key: value for key, value in os.environ.items() if not key.startswith('GITHUB_')}
    env["NUGET_PACKAGES"] = str(root / ".packages")
    env["NUGET_HTTP_CACHE_PATH"] = str(root / ".http-cache")
    (root / "global.json").write_bytes((packages.ROOT / "global.json").read_bytes())
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
    config = root / "NuGet.config"
    ET.ElementTree(configuration).write(config, encoding="utf-8", xml_declaration=True)
    runtimes = [entry for entry in packages.catalogue() if entry["kind"] == "native"]
    cases = [(entry["library"], [entry]) for entry in runtimes] + [("All", runtimes)]
    evidence = {"sourceCommit": commit, "version": version, "rid": "win-x64", "packages": manifest["packages"], "cases": []}
    native_build = json.loads((directory / 'native-artifact.json').read_text(encoding='utf-8'))['build']
    expected_suffix = packages.build_identity.native_suffix(native_build)
    evidence_root = packages.ROOT / "artifacts/native-consumer-evidence"
    evidence_root.mkdir(parents=True, exist_ok=True)
    published = None
    for case, selected in cases:
        consumer = root / case
        consumer.mkdir()
        ids = ["ArcForges.Build.Policy", "ArcForges.Native.Abstractions"]
        for entry in selected:
            ids.extend([entry["dependencies"][0], entry["id"]])
        (consumer / "Directory.Packages.props").write_text('<Project><PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup><ItemGroup>\n'
            + ''.join(f'<PackageVersion Include="{name}" Version="{version}" />\n' for name in ids)
            + '</ItemGroup></Project>\n', encoding="utf-8")
        project = consumer / "Consumer.csproj"
        project.write_text('''<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework>
    <RuntimeIdentifier>win-x64</RuntimeIdentifier><PublishAot>true</PublishAot>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
  </PropertyGroup><ItemGroup>
''' + ''.join(f'<PackageReference Include="{name}"' + (' PrivateAssets="all"' if name == 'ArcForges.Build.Policy' else '') + ' />\n' for name in ids)
            + '</ItemGroup></Project>\n', encoding="utf-8")
        program = '''using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ArcForges.Native.Abstractions;
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
'''
        faults = []
        for entry in selected:
            name = entry["dependencies"][0]
            family = name.split(".")[-1]
            api = f"{name}.{family}Abi"
            program += f'''if ({api}.GetAbiVersion() != new NativeAbiVersion(1, 0)) throw new Exception("ABI mismatch");
Console.WriteLine({api}.GetBuildInfo());
if (!{api}.GetBuildInfo().EndsWith({json.dumps(expected_suffix)}, StringComparison.Ordinal)) throw new Exception("Native build identity mismatch");
var metadata{family} = System.Reflection.CustomAttributeExtensions.GetCustomAttributes<System.Reflection.AssemblyMetadataAttribute>(typeof({api}).Assembly).ToDictionary(a => a.Key, a => a.Value);
if (metadata{family}["ArcForges.SourceCommit"] != "{commit}" || metadata{family}["ArcForges.BuildId"] != "{manifest['build']['buildId']}" || metadata{family}["ArcForges.PipelineRun"] != "{manifest['build']['pipelineRun'] or 'local'}" || metadata{family}["ArcForges.SourceDateEpoch"] != "{manifest['build']['sourceDateEpoch']}") throw new Exception("Managed build identity mismatch");
if (System.Reflection.CustomAttributeExtensions.GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>(typeof({api}).Assembly)?.InformationalVersion.Split('+')[0] != "{version}") throw new Exception("Managed release mismatch");
if ({api}.GetLastError().Status != NativeStatus.Ok) throw new Exception("Initial error state");
unsafe {{ uint minor; if (Faults.{family}(null, &minor) != -1) throw new Exception("Invalid argument accepted"); }}
var error{family} = {api}.GetLastError();
if (error{family}.Status != NativeStatus.InvalidArgument || error{family}.CorrelationId == 0 || error{family}.Message.Length == 0) throw new Exception("Error snapshot lost");
{api}.GetAbiVersion();
if ({api}.GetLastError() != error{family}) throw new Exception("Error snapshot changed after success");
'''
            faults.append(f'''[LibraryImport("{entry['library']}", EntryPoint = "{entry['prefix']}_get_abi_version")]
[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
internal static unsafe partial int {family}(uint* major, uint* minor);
''')
        program += 'Console.WriteLine("dynamic-code=" + RuntimeFeature.IsDynamicCodeSupported);\nConsole.WriteLine("package-native-ok");\n'
        program += 'internal static partial class Faults {\n' + ''.join(faults) + '}\n'
        (consumer / "Program.cs").write_text(program, encoding="utf-8")
        env["CI"] = "false"
        packages.run("dotnet", "restore", str(project), "--use-lock-file", "--configfile", str(config), cwd=consumer, env=env)
        env["CI"] = "true"
        packages.run("dotnet", "restore", str(project), "--locked-mode", "--configfile", str(config), cwd=consumer, env=env)
        packages.run("dotnet", "build", str(project), "-c", "Release", "--no-restore", "-p:PublishAot=false", cwd=consumer, env=env)
        result = execute(consumer / "bin/Release/net10.0/win-x64/Consumer.exe", root, env)
        packages.require("dynamic-code=True" in result.stdout, "The ordinary consumer did not enable JIT execution.")
        published = consumer / "publish"
        packages.run("dotnet", "publish", str(project), "-c", "Release", "--no-restore", "-o", str(published), cwd=consumer, env=env)
        result = execute(published / "Consumer.exe", root, env)
        packages.require("dynamic-code=False" in result.stdout and not (published / "Consumer.dll").exists(),
                         "The consumer did not execute as a native AOT binary.")
        for entry in selected:
            expected = json.loads((published / (entry["library"] + ".manifest.json")).read_text())
            for file in expected["files"]:
                packages.require(hashlib.sha256((published / file["name"]).read_bytes()).hexdigest() == file["sha256"],
                                 "Published runtime differs from packaged runtime.")
        print(f"PASS: {case}, isolated JIT and Native AOT consumers.", flush=True)
        evidence["cases"].append({"name": case, "jit": "passed", "aot": "passed",
                                  "aotExeSha256": hashlib.sha256((published / "Consumer.exe").read_bytes()).hexdigest()})
        fixture = evidence_root / case
        fixture.mkdir(exist_ok=True)
        for name in ["Consumer.csproj", "Directory.Packages.props", "Program.cs", "packages.lock.json"]:
            shutil.copyfile(consumer / name, fixture / name)

    # Every ArcForges reference, including transitive dependencies, must come from these exact archives.
    for row in manifest["packages"]:
        restored = root / ".packages" / row["id"].lower() / version.lower() / f"{row['id'].lower()}.{version.lower()}.nupkg"
        packages.require(restored.is_file() and restored.read_bytes() == (directory / row["file"]).read_bytes(),
                         "Consumer restored different candidate bytes: " + row["id"])

    # The installed RID target must reject an incompatible RID before compilation.
    packages.run("dotnet", "msbuild", str(project), "-t:RequireArcImageNativeRid", "-p:RuntimeIdentifier=win-arm64",
                 cwd=consumer, env=env, expected_error="requires RuntimeIdentifier=win-x64")

    # Fresh processes ensure the loader cannot reuse a previously loaded image after a negative mutation.
    for name in ["ArcImageNative.dll", "msvcp140.dll"]:
        original = (published / name).resolve()
        backup = (published / (name + ".withheld")).resolve()
        packages.require(original.is_relative_to(published.resolve()) and backup.is_relative_to(published.resolve()), "Unsafe fixture move.")
        original.rename(backup)
        try:
            # A valid copy in the working directory must not substitute for the missing app-local file.
            shutil.copyfile(backup, root / name)
            execute(published / "Consumer.exe", root, env, failure=True)
        finally:
            backup.rename(original)
        print("PASS: missing " + name + " cannot fall back to the working directory.", flush=True)
    original = published / "ArcImageNative.dll"
    content = original.read_bytes()
    try:
        original.write_bytes(content + b"tamper")
        execute(published / "Consumer.exe", root, env, failure=True)
    finally:
        original.write_bytes(content)
    print("PASS: modified native DLL rejected before loading.", flush=True)
    c_consumer(root, published, runtimes, version, env, expected_suffix)
    execute(published / "Consumer.exe", root, env)
    evidence["c17"] = {"result": "passed", "exeSha256": hashlib.sha256((published / "ConsumerC.exe").read_bytes()).hexdigest()}
    evidence["rejections"] = ["wrong-rid", "missing-owned-dll", "missing-transitive-dll", "changed-dll"]
    (evidence_root / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print("Complete packaged native consumer validation passed. Evidence: " + str(root), flush=True)


def c_consumer(root, published, entries, version, env, expected_suffix):
    source = '#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n'
    includes = []
    libraries = []
    body = ''
    for entry in entries:
        installed = root / ".packages" / entry["id"].lower() / version.lower()
        includes.append('/I"' + str(installed / "include") + '"')
        libraries.append('"' + str(installed / "sdk/win-x64/lib" / (entry["library"] + ".lib")) + '"')
        source += '#include <arc/' + Path(entry["header"]).name + '>\n'
        prefix = entry["prefix"]
        body += f'''{{
  uint32_t major = 0, minor = 0;
  if ({prefix}_get_abi_version(&major, &minor) != ARC_OK || major != 1 || minor != 0) return 1;
  arc_mut_buffer_t query = {{0}};
  if ({prefix}_get_build_info(&query) != ARC_BUFFER_TOO_SMALL || query.required > 4096 || query.required == 0) return 2;
  char text[4096] = {{0}};
  arc_mut_buffer_t output = {{text, sizeof(text), 0}};
  if ({prefix}_get_build_info(&output) != ARC_OK || output.required != query.required) return 3;
  if (output.required >= sizeof(text) || strstr(text, {json.dumps(expected_suffix)}) == NULL) return 7;
  if ({prefix}_get_abi_version(NULL, &minor) != ARC_INVALID_ARGUMENT) return 4;
  arc_error_info_t error = {{0}};
  error.struct_size = sizeof(error); error.struct_version = 1;
  if ({prefix}_get_last_error(&error) != ARC_BUFFER_TOO_SMALL || error.status != ARC_INVALID_ARGUMENT) return 5;
  error.message_utf8.data = text; error.message_utf8.capacity = sizeof(text);
  if ({prefix}_get_last_error(&error) != ARC_OK || error.message_utf8.required == 0) return 6;
}}
'''
    source += 'int main(void) {\n' + body + 'puts("package-native-ok"); return 0; }\n'
    file = root / "consumer.c"
    file.write_text(source, encoding="utf-8")
    vswhere = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio/Installer/vswhere.exe"
    vs = subprocess.check_output([str(vswhere), "-latest", "-products", "*", "-requires",
                                  "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], text=True).strip()
    command = root / "compile-c.cmd"
    command.write_text('@echo off\ncall "' + vs + '\\VC\\Auxiliary\\Build\\vcvars64.bat" >nul || exit /b 1\n'
        + 'cl /nologo /TC /std:c17 /W4 /WX ' + ' '.join(includes) + ' "' + str(file) + '" '
        + ' /Fe:"' + str(published / "ConsumerC.exe") + '" /link ' + ' '.join(libraries) + '\nexit /b %errorlevel%\n', encoding="utf-8")
    packages.run("cmd", "/d", "/c", str(command), cwd=root, env=env)
    execute(published / "ConsumerC.exe", root, env)
    print("PASS: independent C17 caller linked packaged headers/import libraries and executed the retained image ABI.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit")
    parser.add_argument("--directory", type=Path, default=packages.ROOT / "artifacts/packages")
    args = parser.parse_args()
    consume(args.directory.resolve(), packages.version(args.version), args.commit or packages.source_commit())
