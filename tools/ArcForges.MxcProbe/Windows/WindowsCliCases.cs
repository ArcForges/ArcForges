// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32;

namespace ArcForges.MxcProbe;

// Two real contained multiprocess CLI fixtures. Nothing here installs a tool,
// restores a package, grants an entire profile, or changes a host configuration.
[SupportedOSPlatform("windows")]
internal static class WindowsCliCases
{
    private static readonly string[] BuildRoles = ["compile", "link", "test"];
    private sealed record InstalledTools(string ToolRoot, string Compiler, string Linker, string SdkVersion, string SdkLibraryRoot, string Kernel32Library);

    internal static async Task<List<WindowsQualificationCase>> RunAsync(string stage, string work)
    {
        var results = new List<WindowsQualificationCase>();
        var pipeName = "afv2-mxc-" + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);
        var pipe = CreatePolicy("cli-named-pipe-roundtrip", stage, work, ["pipe-roundtrip", pipeName], []);
        var pipeResult = await WindowsQualification.RunCaseAsync("cli-named-pipe-roundtrip", stage, pipe.Policy, async (session, capture) =>
        {
            var completed = await capture.WaitForEventAsync("pipe-roundtrip", TimeSpan.FromSeconds(12)).ConfigureAwait(false);
            Require(completed.GetProperty("matched").GetBoolean() && completed.GetProperty("clientExit").GetInt32() == 0,
                "contained_named_pipe_roundtrip_failed");
            var events = capture.ReadFixtureEvents();
            var created = RequireCreated(events, "pipe-client");
            Require(created.GetProperty("childPid").GetUInt32() == completed.GetProperty("childPid").GetUInt32()
                && created.GetProperty("childCreatedUtc").GetString() == completed.GetProperty("childCreatedUtc").GetString(),
                "named_pipe_child_identity_mismatch");
            // Cumulative OS accounting includes exited members; child stdout
            // alone is not treated as proof of containment or descendants.
            RequireOwnedProcessCount(session.ObserveJob(), 3);
        }, fixtureEventsDirectory: pipe.EventsDirectory).ConfigureAwait(false);
        pipeResult.Protocol = "MXC-WIN-04";
        results.Add(pipeResult);

        var tools = FindInstalledTools();
        using var compilerLease = File.Open(tools.Compiler, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var linkerLease = File.Open(tools.Linker, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var libraryLease = File.Open(tools.Kernel32Library, FileMode.Open, FileAccess.Read, FileShare.Read);
        var build = CreatePolicy("cli-native-compile-link-test", stage, work, [], [tools.ToolRoot, tools.SdkLibraryRoot], tools);
        var buildResult = await WindowsQualification.RunCaseAsync("cli-native-compile-link-test", stage, build.Policy, async (session, capture) =>
        {
            var completed = await capture.WaitForEventAsync("build-test", TimeSpan.FromSeconds(20)).ConfigureAwait(false);
            Require(completed.GetProperty("success").GetBoolean()
                && completed.GetProperty("compileExit").GetInt32() == 0
                && completed.GetProperty("linkExit").GetInt32() == 0
                && completed.GetProperty("testExit").GetInt32() == 23, "contained_native_build_test_failed");
            var events = capture.ReadFixtureEvents();
            var identities = new HashSet<(uint Pid, string CreatedUtc)>();
            foreach (var role in BuildRoles)
            {
                var created = RequireCreated(events, role);
                var observed = events.Where(value => IsEvent(value, "build-child") && value.GetProperty("role").GetString() == role).ToArray();
                Require(observed.Length == 1, "build_child_exit_observation_missing_or_duplicate");
                var pid = created.GetProperty("childPid").GetUInt32();
                Require(pid == observed[0].GetProperty("childPid").GetUInt32()
                    && created.GetProperty("childCreatedUtc").GetString() == observed[0].GetProperty("createdUtc").GetString(),
                    "build_child_identity_mismatch");
                Require(identities.Add((pid, created.GetProperty("childCreatedUtc").GetString()!)), "build_child_creation_identity_not_distinct");
                Require(observed[0].GetProperty("exitCode").GetInt32() == (role == "test" ? 23 : 0), "build_child_exit_mismatch");
            }

            RequireOwnedProcessCount(session.ObserveJob(), 5);
        }, fixtureEventsDirectory: build.EventsDirectory).ConfigureAwait(false);
        buildResult.Protocol = "MXC-WIN-04";
        await WriteBuildEvidenceAsync(buildResult, build.Policy, build.OwnedWork, tools).ConfigureAwait(false);
        results.Add(buildResult);
        return results;
    }

    private static JsonElement RequireCreated(JsonElement[] events, string role)
    {
        var observed = events.Where(value => IsEvent(value, "child-created") && value.GetProperty("role").GetString() == role).ToArray();
        Require(observed.Length == 1, "cli_child_creation_observation_missing_or_duplicate");
        Require(observed[0].GetProperty("childPid").GetUInt32() != 0
            && DateTimeOffset.TryParse(observed[0].GetProperty("childCreatedUtc").GetString(), CultureInfo.InvariantCulture,
                DateTimeStyles.None, out _), "cli_child_creation_identity_invalid");
        return observed[0];
    }

    private static bool IsEvent(JsonElement value, string name) => value.GetProperty("event").GetString() == name;

    private static void RequireOwnedProcessCount(ConPtyJobObservation actual, uint minimum)
    {
        // The already qualified launch creates the executor in this no-breakaway
        // Job before resume. Its cumulative process total covers even the tiny
        // compiled program, which may have exited before a live PID sample.
        Require(actual.TotalProcesses >= minimum && actual.UiRestrictions == 0
            && (actual.LimitFlags & (0x0800 | 0x1000)) == 0, "cli_descendants_not_confirmed_by_owned_os_job");
    }

    private static (WindowsPolicyArtifact Policy, string EventsDirectory, string OwnedWork) CreatePolicy(string name, string stage, string work,
        IReadOnlyList<string> args, string[] toolReadOnly, InstalledTools? tools = null)
    {
        var root = Path.Combine(work, name);
        Directory.CreateDirectory(root);
        var fixture = Path.Combine(root, "workspace 工作区");
        var owned = new WindowsOwnedPaths(Path.Combine(fixture, "home"), Path.Combine(fixture, "config"), Path.Combine(fixture, "cache"),
            Path.Combine(fixture, "temp"), Path.Combine(fixture, "work"), Path.Combine(fixture, "data"));
        foreach (var path in new[] { owned.Home, owned.Config, owned.Cache, owned.Temp, owned.Work, owned.Data }) Directory.CreateDirectory(path);
        var control = Path.Combine(root, "private control");
        IReadOnlyList<string> workload = tools is null ? args : ["build-test", tools.Compiler, tools.Linker, tools.Kernel32Library, owned.Work];
        var request = WindowsPolicy.BuildRequest(Path.Combine(stage, "arcforges-mxc-probe.exe"), ["--windows-workload", .. workload],
            owned, [stage, Environment.SystemDirectory, .. toolReadOnly], [control], WindowsNetworkChoice.DenyAll);
        var events = WindowsQualification.EnableFixtureEvents(request, owned.Work);
        return (WindowsPolicy.WritePrivate(control, request), events, owned.Work);
    }

    private static InstalledTools FindInstalledTools()
    {
        Require(RuntimeInformation.ProcessArchitecture == Architecture.X64, "installed_x64_msvc_fixture_required");
        // The designated workstation's admitted VS18 Community installation.
        // Do not search user profiles/PATH, switch its default toolset, or infer
        // that another installation has been qualified by this experiment.
        var vc = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Microsoft Visual Studio", "18", "Community", "VC");
        var defaultVersion = Path.Combine(vc, "Auxiliary", "Build", "Microsoft.VCToolsVersion.default.txt");
        Require(File.Exists(defaultVersion), "installed_msvc_default_toolset_missing");
        var version = File.ReadAllText(defaultVersion).Trim();
        Require(Version.TryParse(version, out _), "installed_msvc_default_toolset_invalid");
        var toolRoot = Path.Combine(vc, "Tools", "MSVC", version);
        var bin = Path.Combine(toolRoot, "bin", "Hostx64", "x64");
        var compiler = Path.Combine(bin, "cl.exe");
        var linker = Path.Combine(bin, "link.exe");
        Require(File.Exists(compiler) && File.Exists(linker), "installed_msvc_compiler_or_linker_missing");

        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
        using var kits = machine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Kits\Installed Roots", writable: false);
        var sdk = kits?.GetValue("KitsRoot10") as string;
        Require(sdk is not null && Path.IsPathFullyQualified(sdk), "installed_windows_sdk_root_missing");
        var libraries = Path.Combine(sdk!, "Lib");
        Require(Directory.Exists(libraries), "installed_windows_sdk_libraries_missing");
        var selected = Directory.EnumerateDirectories(libraries)
            .Select(path => (Path: path, Version: Version.TryParse(Path.GetFileName(path), out var parsed) ? parsed : null))
            .Where(item => item.Version is not null && File.Exists(Path.Combine(item.Path, "um", "x64", "kernel32.lib")))
            .OrderByDescending(item => item.Version).FirstOrDefault();
        Require(selected.Version is not null, "installed_windows_sdk_kernel32_library_missing");
        var libraryRoot = Path.Combine(selected.Path, "um", "x64");
        return new(toolRoot, compiler, linker, selected.Version!.ToString(), libraryRoot, Path.Combine(libraryRoot, "kernel32.lib"));
    }

    private static async Task WriteBuildEvidenceAsync(WindowsQualificationCase result, WindowsPolicyArtifact policy, string ownedWork, InstalledTools tools)
    {
        try
        {
            using var bytes = new MemoryStream();
            using (var writer = new Utf8JsonWriter(bytes))
            {
                writer.WriteStartObject();
                writer.WriteString("toolRoot", tools.ToolRoot);
                writer.WriteString("compilerPath", tools.Compiler);
                writer.WriteString("linkerPath", tools.Linker);
                writer.WriteString("sdkVersion", tools.SdkVersion);
                writer.WriteString("sdkLibraryRoot", tools.SdkLibraryRoot);
                writer.WriteString("kernel32Library", tools.Kernel32Library);
                writer.WriteString("networkMode", "deny_all");
                writer.WriteBoolean("nugetOrUserConfigurationRequired", false);
                writer.WriteString("processEvidence", "Held OS Job cumulative total plus no-breakaway inheritance; not individual PID-only adoption or stdout-only containment.");
                writer.WriteStartArray("files");
                foreach (var path in new[] { tools.Compiler, tools.Linker, tools.Kernel32Library,
                             Path.Combine(ownedWork, "afv2-fixture.c"), Path.Combine(ownedWork, "afv2-fixture.obj"), Path.Combine(ownedWork, "afv2-fixture.exe") })
                {
                    if (!File.Exists(path))
                    {
                        writer.WriteStartObject();
                        writer.WriteString("file", Path.GetFileName(path));
                        writer.WriteString("status", "absent");
                        writer.WriteEndObject();
                        Require(!result.Passed, "successful_build_artifact_missing");
                        continue;
                    }

                    Require((File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0, "build_artifact_or_tool_is_reparse");
                    await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                    writer.WriteStartObject();
                    writer.WriteString("file", Path.GetFileName(path));
                    writer.WriteNumber("bytes", input.Length);
                    writer.WriteString("sha256", Convert.ToHexStringLower(await SHA256.HashDataAsync(input).ConfigureAwait(false)));
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
            }

            var data = bytes.ToArray();
            const string file = "cli-build-observation.json";
            await using var output = new FileStream(Path.Combine(policy.ControlDirectory, file), FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            await output.WriteAsync(data).ConfigureAwait(false);
            result.PrivateDiagnostics.Add(new(file, Convert.ToHexStringLower(SHA256.HashData(data)), data.Length));
        }
        catch (Exception error)
        {
            result.Passed = false;
            result.EvidenceFailure = WindowsQualification.ObserveFailure(error);
        }
    }

    private static void Require(bool condition, string code)
    {
        if (!condition) throw new WindowsQualificationCheckException(code);
    }
}
