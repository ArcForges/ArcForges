// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Mxc.Sdk.V1;

namespace ArcForges.MxcProbe.Linux;

// A bounded native admission experiment. Namespace-denial injection is reported
// separately from the real positive namespace and missing-helper experiments.
[SupportedOSPlatform("linux")]
internal static class LinuxAdmissionCases
{
    private const string ToolPath = "/usr/bin:/bin:/usr/sbin:/sbin";
    private static readonly string[] ToolDirectories = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];
    private static readonly string[] HelperNames = ["bwrap", "slirp4netns", "ip", "unshare", "nsenter", "iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "sh"];
    private static readonly string[] NamespaceNames = ["user", "pid", "mnt", "net", "ipc", "uts"];
    private static readonly char[] VersionSeparators = [' ', '\t', '\r', '\n'];
    private static readonly string[] VersionArguments = ["--version"];
    private static readonly string[] IpVersionArguments = ["-Version"];
    private static readonly string[] ShellArguments = ["-c", "printf 'AFV2_POSIX_SHELL_CHECK\\n'"];
    internal static LinuxSdkSession? UnresolvedSdkOwner { get; private set; }
    internal static List<Process> UnresolvedProcesses { get; } = [];

    internal static async Task<List<LinuxCaseResult>> RunAsync(LinuxOwnerConfiguration config, LinuxEvidence log)
    {
        var results = new List<LinuxCaseResult>();
        var steps = new Func<Task<LinuxCaseResult>>[]
        {
            () => Task.FromResult(Discovery(config, log)),
            () => HelpersAsync(config, log),
            () => NamespaceAsync(config, log),
            () => MissingHelperAsync(config, log),
        };
        foreach (var step in steps)
        {
            LinuxCaseResult result;
            try { result = await step().ConfigureAwait(false); }
            catch (Exception exception)
            {
                log.Failure("admission_setup", exception);
                result = new("admission_setup", false, new(StringComparer.Ordinal) { ["status"] = "partial" });
            }
            results.Add(result);
            if (!result.Passed || UnresolvedSdkOwner is not null || UnresolvedProcesses.Count != 0) break;
        }
        return results;
    }

    private static LinuxCaseResult Discovery(LinuxOwnerConfiguration config, LinuxEvidence log)
    {
        const string id = "admission_public_sdk";
        var facts = new Dictionary<string, string>(StringComparer.Ordinal) { ["status"] = "partial" };
        log.Phase(id, "begin");
        try
        {
            var group = CurrentGroup(config.UnitName);
            using var scope = LinuxCgroup.Open(group);
            var observed = scope.Read();
            Require(observed.ProcessIds.Contains(Environment.ProcessId) && observed.CpuQuotaMicros == config.CpuQuotaMicros
                && observed.MemoryMaxBytes == checked((ulong)config.MemoryMax) && observed.PidsMax == checked((ulong)config.TasksMax), "admission_owner_scope_mismatch");
            facts["kernel"] = RuntimeInformation.OSDescription;
            facts["rid"] = RuntimeInformation.RuntimeIdentifier;
            facts["uid"] = LinuxCgroup.UserId.ToString(CultureInfo.InvariantCulture);
            facts["unit"] = config.UnitName;
            facts["cgroup"] = group;
            facts["controllers"] = File.ReadAllText("/sys/fs/cgroup" + group + "/cgroup.controllers").Trim();
            facts["subtreeControl"] = File.ReadAllText("/sys/fs/cgroup" + group + "/cgroup.subtree_control").Trim();
            Require(Environment.GetEnvironmentVariable("PATH") == ToolPath, "admission_owner_helper_path_mismatch");
            facts["ownerHelperSearchPathVerified"] = "true";
            facts["nativeVersion"] = MxcPlatform.NativeVersion;
            var support = MxcPlatform.GetPlatformSupport();
            facts["platformSupported"] = support.IsSupported.ToString(CultureInfo.InvariantCulture);
            facts["availableMethods"] = string.Join(',', support.AvailableMethods);
            if (support.Reason is not null) facts["supportReasonSha256"] = HashText(support.Reason);
            var backends = MxcPlatform.GetAvailableBackends();
            facts["availableBackends"] = string.Join(',', backends.Select(backend => backend.Backend));
            foreach (var backend in backends)
            {
                log.Phase(id + "/backend", "reported_by_public_sdk", new(StringComparer.Ordinal)
                {
                    ["backend"] = backend.Backend.ToString(),
                    ["tier"] = backend.Tier?.ToString() ?? "none",
                    ["capabilities"] = string.Join(',', backend.Capabilities),
                    ["warningCount"] = backend.Warnings.Count.ToString(CultureInfo.InvariantCulture),
                    ["warningsSha256"] = HashText(string.Join('\n', backend.Warnings)),
                });
            }
            Require(facts["nativeVersion"] == "1.0.1" && support.IsSupported
                && support.AvailableMethods.Any(method => method.ToString() == "Bubblewrap")
                && backends.Any(backend => backend.Backend.ToString() == "Bubblewrap"), "admission_public_bubblewrap_unavailable");
            log.Phase(id, "passed", facts);
            return new(id, true, facts);
        }
        catch (Exception exception) { log.Failure(id, exception); return new(id, false, facts); }
    }

    private static async Task<LinuxCaseResult> HelpersAsync(LinuxOwnerConfiguration config, LinuxEvidence log)
    {
        const string id = "admission_helpers";
        var control = FreshDirectory(Path.Combine(config.Control, id));
        var facts = new Dictionary<string, string>(StringComparer.Ordinal) { ["status"] = "partial", ["searchPath"] = ToolPath };
        var passed = true;
        foreach (var name in HelperNames)
        {
            var phase = id + "/" + name;
            log.Phase(phase, "resolve_begin");
            try
            {
                var path = ResolveHelper(name);
                if (path is null)
                {
                    facts[name] = "missing";
                    passed = false;
                    log.Phase(phase, "missing", new(StringComparer.Ordinal) { ["requiredBy"] = name == "bwrap" ? "all_modes" : "selected_private_network_mode" });
                    continue;
                }
                var resolved = File.ResolveLinkTarget(path, returnFinalTarget: true)?.FullName ?? path;
                var argv = name == "ip" ? IpVersionArguments : name == "sh" ? ShellArguments : VersionArguments;
                var tool = await ToolAsync(path, argv, control, name, log).ConfigureAwait(false);
                var values = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["path"] = path,
                    ["resolvedPath"] = resolved,
                    ["executableSha256"] = FileHash(path),
                    ["exitCode"] = tool.ExitCode.ToString(CultureInfo.InvariantCulture),
                    ["stdoutSha256"] = HashBytes(tool.Stdout),
                    ["stderrSha256"] = HashBytes(tool.Stderr),
                };
                if (name == "sh")
                {
                    Require(tool.ExitCode == 0 && Encoding.UTF8.GetString(tool.Stdout) == "AFV2_POSIX_SHELL_CHECK\n", "admission_posix_shell_probe_failed");
                    values["versionInterface"] = "POSIX_sh_has_no_standard_version_flag";
                    values["versionIdentity"] = "resolved_executable_path_and_sha256";
                }
                else
                {
                    Require(tool.ExitCode == 0, "admission_helper_version_command_failed");
                    values["versionBanner"] = VersionBanner(tool.Stdout, tool.Stderr);
                }
                if (name == "bwrap")
                {
                    var tokens = Encoding.UTF8.GetString(tool.Stdout).Split(VersionSeparators, StringSplitOptions.RemoveEmptyEntries);
                    var version = tokens.Select(token => Version.TryParse(token, out var parsed) ? parsed : null).FirstOrDefault(value => value is not null);
                    Require(version is not null && version >= new Version(0, 5, 0), "admission_bwrap_below_0_5_0");
                    values["minimumSatisfied"] = "0.5.0";
                }
                if (name is "iptables" or "ip6tables")
                    values["firewallBackend"] = values["versionBanner"].Contains("nf_tables", StringComparison.Ordinal) ? "nf_tables"
                        : values["versionBanner"].Contains("legacy", StringComparison.Ordinal) ? "legacy" : "unreported";
                facts[name] = "observed";
                log.Phase(phase, "observed", values);
            }
            catch (Exception exception) { passed = false; facts[name] = "failed"; log.Failure(phase, exception); }
            if (UnresolvedProcesses.Count != 0) break;
        }
        try
        {
            facts["nfConntrackModuleListed"] = File.ReadLines("/proc/modules").Any(line => line.StartsWith("nf_conntrack ", StringComparison.Ordinal)).ToString(CultureInfo.InvariantCulture);
            facts["conntrackInterpretation"] = "module_list_only_not_a_test_of_built_in_or_functional_support";
            log.Phase(id + "/conntrack", "observed", facts);
        }
        catch (Exception exception)
        {
            facts["nfConntrackModuleListed"] = "UNKNOWN";
            facts["conntrackInterpretation"] = "module_list_unavailable_functional_network_test_remains_authority";
            log.Failure(id + "/conntrack_observation", exception);
        }
        return new(id, passed && UnresolvedProcesses.Count == 0, facts);
    }

    private static async Task<LinuxCaseResult> NamespaceAsync(LinuxOwnerConfiguration config, LinuxEvidence log)
    {
        const string id = "admission_namespace_spawn";
        var root = FreshDirectory(Path.Combine(config.Work, id));
        var data = FreshDirectory(Path.Combine(root, "sandbox"));
        var control = FreshDirectory(Path.Combine(config.Control, id));
        var request = LinuxRequestFactory.Create(Environment.ProcessPath!, ["--linux-workload", "load", "5000", "0", "0"], data, control, 10_000);
        var facts = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["status"] = "partial",
            ["namespaceDeniedNegative"] = "NOT_RUN",
            ["namespaceDeniedFeasibility"] = "No_safe_independent_denial_injection_without_host_policy_credentials_or_new_seccomp_framework",
            ["scope"] = "Actual_public_SDK_spawn_and_OS_namespace_observation_not_a_namespace_denial_pass",
        };
        var passed = false;
        LinuxSdkSession? session = null;
        using var scope = LinuxCgroup.Open(CurrentGroup(config.UnitName));
        var before = scope.Read().ProcessIds;
        log.Phase(id + "/start", "begin");
        try
        {
            if (File.Exists("/proc/sys/user/max_user_namespaces")) facts["maxUserNamespaces"] = File.ReadAllText("/proc/sys/user/max_user_namespaces").Trim();
            if (File.Exists("/proc/sys/kernel/unprivileged_userns_clone")) facts["unprivilegedUsernsClone"] = File.ReadAllText("/proc/sys/kernel/unprivileged_userns_clone").Trim();
            session = LinuxSdkSession.Start(request, false, log, id);
            facts["sdkProcessId"] = session.ProcessId.ToString(CultureInfo.InvariantCulture);
            var watch = Stopwatch.StartNew();
            int payload = 0;
            while (payload == 0)
            {
                var matches = scope.Read().ProcessIds.Where(pid => pid != Environment.ProcessId && ExecutableIs(pid, Environment.ProcessPath!)).ToArray();
                Require(matches.Length <= 1, "admission_payload_identity_ambiguous");
                if (matches.Length == 1) payload = matches[0];
                else
                {
                    Require(watch.Elapsed < TimeSpan.FromSeconds(3), "admission_native_payload_not_observed");
                    await Task.Delay(25).ConfigureAwait(false);
                }
            }
            var start = StartTicks(payload);
            facts["observedPayloadPid"] = payload.ToString(CultureInfo.InvariantCulture);
            facts["observedPayloadStartTicks"] = start;
            foreach (var name in NamespaceNames)
            {
                var owner = Namespace(Environment.ProcessId, name);
                var contained = Namespace(payload, name);
                Require(contained != owner, "admission_namespace_shared_with_owner");
                facts[name + "Namespace"] = contained;
                facts[name + "OwnerNamespace"] = owner;
            }
            Require(StartTicks(payload) == start && scope.Read().ProcessIds.Contains(payload), "admission_payload_identity_changed");
            log.Phase(id + "/namespaces", "independently_observed", facts);
            var exited = await session.WaitAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            Require(exited.ExitCode == 0 && !exited.TimedOut && exited.Drained && exited.NativeProcessAbsent, "admission_native_spawn_failed");
            facts["exitCode"] = exited.ExitCode.ToString(CultureInfo.InvariantCulture);
            facts["exitSource"] = exited.ExitSource;
            facts["nativeProcessAbsent"] = exited.NativeProcessAbsent.ToString(CultureInfo.InvariantCulture);
            passed = true;
        }
        catch (LinuxSdkLaunchException exception) { UnresolvedSdkOwner = exception.CleanupOwner; log.Failure(id + "/launch_cleanup", exception, cleanup: true); }
        catch (Exception exception) { log.Failure(id, exception); }
        finally
        {
            if (session is not null)
            {
                try { await session.DisposeAsync().ConfigureAwait(false); log.Phase(id + "/cleanup", "sdk_owner_disposed"); }
                catch (Exception exception) { passed = false; UnresolvedSdkOwner = session; log.Failure(id + "/cleanup", exception, cleanup: true); }
            }
        }
        try
        {
            Require(before.Order().SequenceEqual(scope.Read().ProcessIds.Order()), "admission_spawn_left_scope_members");
            log.Phase(id + "/scope", "returned_to_before_membership");
        }
        catch (Exception exception) { passed = false; log.Failure(id + "/scope", exception, cleanup: true); }
        return new(id, passed && UnresolvedSdkOwner is null, facts);
    }

    private static async Task<LinuxCaseResult> MissingHelperAsync(LinuxOwnerConfiguration config, LinuxEvidence log)
    {
        const string id = "admission_missing_bwrap";
        var root = FreshDirectory(Path.Combine(config.Work, id));
        var data = FreshDirectory(Path.Combine(root, "sandbox"));
        var control = FreshDirectory(Path.Combine(config.Control, id));
        var empty = FreshDirectory(Path.Combine(control, "empty-helper-path"));
        var childConfig = new LinuxAdmissionChildConfig(config.RunId, config.Manifest, data, control, config.UnitName,
            CurrentGroup(config.UnitName), empty, Path.Combine(data, "must-not-enter.txt"));
        var configPath = Path.Combine(control, "child-config.json");
        LinuxQualification.WriteJson(configPath, childConfig, LinuxAdmissionJson.Default.LinuxAdmissionChildConfig);
        var facts = new Dictionary<string, string>(StringComparer.Ordinal) { ["status"] = "partial", ["hostPathChanged"] = "false" };
        Process? process = null;
        var passed = false;
        byte[] output = [], errors = [];
        Task<byte[]>? stdout = null, stderr = null;
        using var scope = LinuxCgroup.Open(childConfig.ControlGroup);
        var before = scope.Read().ProcessIds;
        log.Phase(id + "/child_start", "begin_clean_child_environment");
        try
        {
            var start = StartInfo(Environment.ProcessPath!, control);
            start.ArgumentList.Add("--linux-admission-child");
            start.ArgumentList.Add(configPath);
            start.Environment["PATH"] = empty;
            process = Process.Start(start) ?? throw new LinuxProbeException("admission_child_start_failed");
            _ = process.SafeHandle;
            facts["childPid"] = process.Id.ToString(CultureInfo.InvariantCulture);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            stdout = ReadBoundedAsync(process.StandardOutput.BaseStream, deadline.Token);
            stderr = ReadBoundedAsync(process.StandardError.BaseStream, deadline.Token);
            await LinuxQualification.WaitForFileAsync(Path.Combine(control, "child-ready.json"), TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            var ready = LinuxQualification.ReadJson(Path.Combine(control, "child-ready.json"), LinuxAdmissionJson.Default.LinuxAdmissionChildReady);
            Require(ready.ProcessId == process.Id && ready.RunId == config.RunId && ready.ControlGroup == childConfig.ControlGroup
                && ready.StartTicks == StartTicks(process.Id) && ready.BootId == LinuxCgroup.BootId()
                && CurrentProcessGroup(process.Id) == childConfig.ControlGroup && ExecutableIs(process.Id, Environment.ProcessPath!)
                && scope.Read().ProcessIds.Contains(process.Id), "admission_child_native_identity_mismatch");
            facts["childStartTicks"] = ready.StartTicks;
            facts["childBootId"] = ready.BootId;
            facts["childNativeIdentityVerifiedBeforeSdk"] = "true";
            log.Phase(id + "/child_admission", "same_scope_and_exact_executable", facts);
            WritePrivate(Path.Combine(control, "child-continue"), Encoding.ASCII.GetBytes(config.RunId));
            await Task.WhenAll(stdout, stderr, process.WaitForExitAsync(deadline.Token)).ConfigureAwait(false);
            output = await stdout.ConfigureAwait(false);
            errors = await stderr.ConfigureAwait(false);
            facts["childExitCode"] = process.ExitCode.ToString(CultureInfo.InvariantCulture);
            var child = LinuxQualification.ReadJson(Path.Combine(control, "child-report.json"), LinuxAdmissionJson.Default.LinuxAdmissionChildReport);
            Require(process.ExitCode == 0 && child.RunId == config.RunId && child.ProcessId == process.Id && child.Passed
                && child.ControlGroup == childConfig.ControlGroup && child.CleanupCompleted && child.MarkerAbsent && child.ObservationFiles == 0
                && child.SdkCodeValue is 4 or 12 && child.SdkCode == ((ErrorCode)child.SdkCodeValue).ToString()
                && !File.Exists(childConfig.Marker)
                && !Directory.EnumerateFileSystemEntries(LinuxRequestFactory.OwnedDirectory(Path.Combine(data, "observations"))).Any(),
                "admission_missing_helper_refusal_not_proven");
            facts["refusalSource"] = "official_sdk_in_clean_independent_child";
            facts["sdkCode"] = child.SdkCode;
            facts["sdkCodeValue"] = child.SdkCodeValue.ToString(CultureInfo.InvariantCulture);
            facts["entryFileAbsent"] = "true";
            facts["childEventsSha256"] = FileHash(Path.Combine(control, "child-events.jsonl"));
            facts["childReportSha256"] = FileHash(Path.Combine(control, "child-report.json"));
            facts["childReadySha256"] = FileHash(Path.Combine(control, "child-ready.json"));
            facts["childConfigurationSha256"] = FileHash(configPath);
            passed = true;
        }
        catch (Exception exception) { log.Failure(id, exception); }
        finally
        {
            if (process is not null)
            {
                if (!await CleanupProcessAsync(process, log, id).ConfigureAwait(false)) passed = false;
            }
            if (stdout is not null && stderr is not null)
            {
                try
                {
                    await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
                    output = await stdout.ConfigureAwait(false);
                    errors = await stderr.ConfigureAwait(false);
                    facts["outputCaptureComplete"] = "true";
                }
                catch (Exception exception)
                {
                    passed = false;
                    facts["outputCaptureComplete"] = "false";
                    log.Failure(id + "/output_drain", exception);
                }
            }
            try
            {
                WritePrivate(Path.Combine(control, "child.stdout"), output);
                WritePrivate(Path.Combine(control, "child.stderr"), errors);
                facts["stdoutSha256"] = HashBytes(output);
                facts["stderrSha256"] = HashBytes(errors);
                log.Phase(id + "/private_output", "retained_with_hash", facts);
            }
            catch (Exception exception) { passed = false; log.Failure(id + "/output", exception); }
        }
        try
        {
            Require(before.Order().SequenceEqual(scope.Read().ProcessIds.Order()), "admission_child_left_scope_members");
            log.Phase(id + "/scope", "returned_to_before_membership");
        }
        catch (Exception exception) { passed = false; log.Failure(id + "/scope", exception, cleanup: true); }
        return new(id, passed && UnresolvedProcesses.Count == 0, facts);
    }

    internal static async Task<int> RunChildAsync(string configPath)
    {
        LinuxEvidence? log = null;
        LinuxAdmissionChildConfig? config = null;
        LinuxSdkSession? session = null;
        var report = new LinuxAdmissionChildReport();
        try
        {
            if (!OperatingSystem.IsLinux()) throw new LinuxProbeException("admission_child_linux_required");
            config = LinuxQualification.ReadJson(configPath, LinuxAdmissionJson.Default.LinuxAdmissionChildConfig);
            Require(Path.GetFullPath(configPath) == Path.Combine(config.Control, "child-config.json") && config.RunId.Length == 32
                && config.RunId.All(char.IsAsciiHexDigit) && config.UnitName == "arcforges-mxc03-" + config.RunId + ".service", "admission_child_config_identity");
            _ = LinuxRequestFactory.OwnedDirectory(config.Control);
            _ = LinuxRequestFactory.OwnedDirectory(config.Data);
            Require(config.EmptyHelpers == Path.Combine(config.Control, "empty-helper-path") && !Directory.EnumerateFileSystemEntries(config.EmptyHelpers).Any()
                && config.Marker == Path.Combine(config.Data, "must-not-enter.txt") && !File.Exists(config.Marker), "admission_child_fixture_not_fresh");
            Require(Environment.GetEnvironmentVariable("PATH") == config.EmptyHelpers && CurrentGroup(config.UnitName) == config.ControlGroup,
                "admission_child_environment_or_scope_mismatch");
            log = new LinuxEvidence(Path.Combine(config.Control, "child-events.jsonl"), config.RunId);
            log.Phase("child_stage", "begin");
            Program.ValidateStage(config.Manifest);
            report.RunId = config.RunId;
            report.ProcessId = Environment.ProcessId;
            report.ControlGroup = config.ControlGroup;
            var ready = new LinuxAdmissionChildReady(config.RunId, Environment.ProcessId, LinuxCgroup.BootId(), StartTicks(Environment.ProcessId), config.ControlGroup);
            LinuxQualification.WriteJson(Path.Combine(config.Control, "child-ready.json"), ready, LinuxAdmissionJson.Default.LinuxAdmissionChildReady);
            log.Phase("child_gate", "waiting_for_parent_identity_admission");
            await LinuxQualification.WaitForFileAsync(Path.Combine(config.Control, "child-continue"), TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            Require(File.ReadAllText(Path.Combine(config.Control, "child-continue")) == config.RunId && CurrentGroup(config.UnitName) == config.ControlGroup,
                "admission_child_gate_mismatch");
            var request = LinuxRequestFactory.Create(Environment.ProcessPath!, ["--linux-workload", "persistence", "write", config.Marker], config.Data, config.Control, 10_000);
            log.Phase("child_sdk_spawn", "begin_missing_host_helper");
            try
            {
                session = LinuxSdkSession.Start(request, false, log, "admission_missing_helper");
                throw new LinuxProbeException("admission_missing_helper_returned_session");
            }
            catch (MxcException exception) when (exception.Code is ErrorCode.BackendUnavailable or ErrorCode.BackendError)
            {
                log.Failure("child_expected_sdk_refusal", exception);
                var detail = Encoding.UTF8.GetBytes(exception.Message);
                Require(detail.Length <= 65_536, "admission_sdk_refusal_detail_bound");
                log.Detail("child_expected_sdk_refusal", "sdk_refusal", detail);
                report.SdkCode = exception.Code.ToString();
                report.SdkCodeValue = (int)exception.Code;
                report.Passed = true;
            }
            report.MarkerAbsent = !File.Exists(config.Marker);
            report.ObservationFiles = Directory.EnumerateFileSystemEntries(Path.Combine(config.Data, "observations")).Count();
            Require(report.MarkerAbsent && report.ObservationFiles == 0, "admission_missing_helper_payload_entered");
        }
        catch (LinuxSdkLaunchException exception)
        {
            UnresolvedSdkOwner = exception.CleanupOwner;
            report.Passed = false;
            log?.Failure("child_launch_cleanup", exception, cleanup: true);
        }
        catch (Exception exception)
        {
            report.Passed = false;
            if (log is not null) log.Failure("child_failure", exception);
            else Console.Error.WriteLine("admission_child_setup_failed:" + exception.GetType().Name + ":" + exception.HResult.ToString("X8", CultureInfo.InvariantCulture));
        }
        finally
        {
            if (session is not null)
            {
                try { await session.DisposeAsync().ConfigureAwait(false); log?.Phase("child_cleanup", "sdk_owner_disposed"); }
                catch (Exception exception) { UnresolvedSdkOwner = session; report.Passed = false; log?.Failure("child_cleanup", exception, cleanup: true); }
            }
            else log?.Phase("child_cleanup", UnresolvedSdkOwner is null ? "no_sdk_session_returned" : "owner_retained_unresolved");
            report.CleanupCompleted = UnresolvedSdkOwner is null;
            if (config is not null && log is not null)
            {
                try { LinuxQualification.WriteJson(Path.Combine(config.Control, "child-report.json"), report, LinuxAdmissionJson.Default.LinuxAdmissionChildReport); }
                catch (Exception exception) { report.Passed = false; log.Failure("child_report", exception); }
            }
            log?.Dispose();
        }
        return report.Passed && report.CleanupCompleted ? 0 : 1;
    }

    private static async Task<ToolOutput> ToolAsync(string executable, IReadOnlyList<string> args, string control, string name, LinuxEvidence log)
    {
        Process? process = null;
        ToolOutput? result = null;
        Exception? failure = null;
        var start = StartInfo(executable, control);
        foreach (var argument in args) start.ArgumentList.Add(argument);
        var phase = "admission_helper_" + name;
        log.Phase(phase, "start");
        try
        {
            process = Process.Start(start) ?? throw new LinuxProbeException("admission_helper_start_failed");
            _ = process.SafeHandle;
            // A version command may already have exited before its /proc stat
            // can be sampled. Its retained OS process handle and actual exit
            // are used; absence of a stat is not a helper-capability failure.
            log.Phase(phase, "started", new(StringComparer.Ordinal) { ["pid"] = process.Id.ToString(CultureInfo.InvariantCulture) });
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var stdout = ReadBoundedAsync(process.StandardOutput.BaseStream, deadline.Token);
            var stderr = ReadBoundedAsync(process.StandardError.BaseStream, deadline.Token);
            await Task.WhenAll(stdout, stderr, process.WaitForExitAsync(deadline.Token)).ConfigureAwait(false);
            var output = await stdout.ConfigureAwait(false);
            var error = await stderr.ConfigureAwait(false);
            WritePrivate(Path.Combine(control, name + ".stdout"), output);
            WritePrivate(Path.Combine(control, name + ".stderr"), error);
            log.Detail(phase, "helper_stdout", output);
            log.Detail(phase, "helper_stderr", error);
            log.Phase(phase, "exited", new(StringComparer.Ordinal) { ["exitCode"] = process.ExitCode.ToString(CultureInfo.InvariantCulture) });
            result = new(process.ExitCode, output, error);
        }
        catch (Exception exception) { failure = exception; log.Failure(phase, exception); }
        finally
        {
            if (process is not null && !await CleanupProcessAsync(process, log, phase).ConfigureAwait(false))
                failure ??= new LinuxProbeException("admission_helper_cleanup_unresolved");
        }
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
        return result ?? throw new LinuxProbeException("admission_helper_result_missing");
    }

    private static ProcessStartInfo StartInfo(string executable, string control)
    {
        var start = new ProcessStartInfo(executable)
        {
            WorkingDirectory = control,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.Environment.Clear();
        start.Environment["PATH"] = ToolPath;
        start.Environment["LANG"] = "C.UTF-8";
        start.Environment["LC_ALL"] = "C.UTF-8";
        start.Environment["TMPDIR"] = control;
        return start;
    }

    private static async Task<bool> CleanupProcessAsync(Process process, LinuxEvidence log, string phase)
    {
        try
        {
            if (!process.HasExited)
            {
                log.Phase(phase + "/cleanup", "killing_exact_owned_process_tree");
                process.Kill(entireProcessTree: true);
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
            }
            Require(process.HasExited, "admission_owned_process_not_exited");
            log.Phase(phase + "/cleanup", "owned_process_reaped");
            process.Dispose();
            return true;
        }
        catch (Exception exception)
        {
            UnresolvedProcesses.Add(process);
            log.Failure(phase + "/cleanup", exception, cleanup: true);
            return false;
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = new byte[4096];
        int count;
        while ((count = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) != 0)
        {
            Require(output.Length + count <= 65_536, "admission_tool_output_bound");
            output.Write(buffer, 0, count);
        }
        return output.ToArray();
    }

    private static string? ResolveHelper(string name)
    {
        foreach (var directory in ToolDirectories)
        {
            var path = Path.Combine(directory, name);
            if (File.Exists(path) && (File.GetUnixFileMode(path) & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) != 0) return path;
        }
        return null;
    }

    private static string VersionBanner(byte[] output, byte[] error)
    {
        var text = new UTF8Encoding(false, true).GetString(output.Length > 0 ? output : error);
        var line = text.Split('\n')[0].Trim();
        Require(line.Length is > 0 and <= 256 && line.All(character => character is >= ' ' and <= '~'), "admission_version_banner_invalid");
        return line;
    }

    private static string CurrentGroup(string unit)
    {
        var group = CurrentProcessGroup(Environment.ProcessId);
        Require(group.EndsWith('/' + unit, StringComparison.Ordinal), "admission_not_in_expected_service");
        return group;
    }

    private static string CurrentProcessGroup(int pid)
    {
        var lines = File.ReadAllLines("/proc/" + pid.ToString(CultureInfo.InvariantCulture) + "/cgroup");
        Require(lines.Length == 1 && lines[0].StartsWith("0::/", StringComparison.Ordinal), "admission_cgroup_v2_required");
        return lines[0][3..];
    }

    private static string StartTicks(int pid)
    {
        var stat = File.ReadAllText("/proc/" + pid.ToString(CultureInfo.InvariantCulture) + "/stat");
        var end = stat.LastIndexOf(')');
        Require(end > 0, "admission_process_stat_invalid");
        var parts = stat[(end + 2)..].Split(' ');
        Require(parts.Length > 19, "admission_process_stat_short");
        return parts[19];
    }

    private static string Namespace(int pid, string name)
    {
        var target = new FileInfo("/proc/" + pid.ToString(CultureInfo.InvariantCulture) + "/ns/" + name).LinkTarget;
        Require(target is { Length: > 0 and <= 96 } && target.StartsWith(name + ":[", StringComparison.Ordinal)
            && target.EndsWith(']'), "admission_namespace_identity_invalid");
        return target!;
    }

    private static bool ExecutableIs(int pid, string expected)
    {
        try { return new FileInfo("/proc/" + pid.ToString(CultureInfo.InvariantCulture) + "/exe").LinkTarget == Path.GetFullPath(expected); }
        catch (IOException) { return false; }
    }

    private static string FreshDirectory(string path)
    {
        Require(!Directory.Exists(path) && !File.Exists(path), "admission_fixture_collision");
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return LinuxRequestFactory.OwnedDirectory(path);
    }

    private static void WritePrivate(string path, byte[] bytes)
    {
        using var stream = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.Read,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
    }

    private static string FileHash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }
    private static string HashBytes(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    private static string HashText(string value) => HashBytes(Encoding.UTF8.GetBytes(value));
    private static void Require(bool condition, string code) { if (!condition) throw new LinuxProbeException(code); }
    private sealed record ToolOutput(int ExitCode, byte[] Stdout, byte[] Stderr);
}

internal sealed record LinuxAdmissionChildConfig(string RunId, string Manifest, string Data, string Control,
    string UnitName, string ControlGroup, string EmptyHelpers, string Marker);
internal sealed record LinuxAdmissionChildReady(string RunId, int ProcessId, string BootId, string StartTicks, string ControlGroup);
internal sealed class LinuxAdmissionChildReport
{
    public string RunId { get; set; } = "";
    public int ProcessId { get; set; }
    public string ControlGroup { get; set; } = "";
    public bool Passed { get; set; }
    public string SdkCode { get; set; } = "";
    public int SdkCodeValue { get; set; }
    public bool MarkerAbsent { get; set; }
    public int ObservationFiles { get; set; }
    public bool CleanupCompleted { get; set; }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(LinuxAdmissionChildConfig))]
[JsonSerializable(typeof(LinuxAdmissionChildReady))]
[JsonSerializable(typeof(LinuxAdmissionChildReport))]
internal sealed partial class LinuxAdmissionJson : JsonSerializerContext;
