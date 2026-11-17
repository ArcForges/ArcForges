// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace ArcForges.MxcProbe.Linux;

// One fixed-role experimental user service. The manager establishes its cgroup
// and all resource properties before exec; there is no direct-process fallback.
[SupportedOSPlatform("linux")]
internal sealed class LinuxServiceScope : IAsyncDisposable
{
    private const string ToolPath = "/usr/bin:/bin:/usr/sbin:/sbin";
    private static readonly string[] Properties = ["Id", "Description", "LoadState", "ActiveState", "SubState", "Result",
        "MainPID", "ControlPID", "ExecMainCode", "ExecMainStatus", "ControlGroup", "InvocationID", "Delegate", "KillMode", "Restart", "DisableControllers", "Slice", "FragmentPath", "SourcePath", "Job", "Transient"];
    private readonly string _unit;
    private readonly string _tag = "afv2-mxc03-" + Guid.NewGuid().ToString("N");
    private readonly string _boot = LinuxCgroup.BootId();
    private readonly LinuxEvidence _evidence;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private LinuxCgroup? _cgroup;
    private LinuxScopeIdentity? _identity;
    private LinuxScopeObservation? _last;
    private bool _submitted;
    private bool _disposed;
    internal static List<LinuxServiceScope> UnresolvedStartupScopes { get; } = [];
    internal LinuxScopeIdentity Identity => _identity ?? throw new LinuxProbeException("service_identity_not_established");

    private LinuxServiceScope(string unit, LinuxEvidence evidence) { _unit = unit; _evidence = evidence; }

    internal static Task<LinuxServiceScope> StartAsync(string stage, string privateOwnerConfigPath,
        string unitName, LinuxScopeLimits limits, LinuxEvidence evidence)
        => StartCoreAsync(stage, privateOwnerConfigPath, unitName, limits, evidence, StartFault.None, null);

    // Closed experiment inputs only; ordinary callers cannot select arbitrary
    // manager properties, executables, slices or working directories.
    private enum StartFault { None, MissingWorkingDirectory, MissingCpuController }

    private static async Task<LinuxServiceScope> StartCoreAsync(string stage, string privateOwnerConfigPath,
        string unitName, LinuxScopeLimits limits, LinuxEvidence evidence, StartFault fault, string? ownedSlice)
    {
        ValidateLimits(limits);
        if (!unitName.StartsWith("arcforges-mxc03-", StringComparison.Ordinal) || !unitName.EndsWith(".service", StringComparison.Ordinal)
            || unitName.Length != 56 || !Guid.TryParseExact(unitName[16..^8], "N", out _)) throw new LinuxProbeException("service_unit_name_invalid");
        var control = Path.GetDirectoryName(Path.GetFullPath(privateOwnerConfigPath))!;
        LinuxCgroup.VerifyPrivatePath(control, true);
        LinuxCgroup.VerifyPrivatePath(privateOwnerConfigPath, false);
        foreach (var path in new[] { "/usr/bin/systemd-run", "/usr/bin/systemctl", "/usr/bin/env" }) LinuxCgroup.VerifyTrustedProgram(path);
        global::ArcForges.MxcProbe.Program.ValidateStage(Path.Combine(stage, "mxc-manifest.json"));
        var executable = Path.Combine(stage, "arcforges-mxc-probe");
        if (!File.Exists(executable) || stage.Any(x => x is '%' or '$' or '\n' or '\r')
            || privateOwnerConfigPath.Any(x => x is '%' or '$' or '\n' or '\r')) throw new LinuxProbeException("service_role_path_invalid");
        if (fault == StartFault.MissingWorkingDirectory
            && (File.Exists(Path.Combine(control, "intentionally-missing-working-directory"))
                || Directory.Exists(Path.Combine(control, "intentionally-missing-working-directory"))))
            throw new LinuxProbeException("creation_negative_fault_path_exists");
        using var executableLease = File.Open(executable, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var configLease = File.Open(privateOwnerConfigPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var scope = new LinuxServiceScope(unitName, evidence);
        try
        {
            var previous = await scope.ShowAsync().ConfigureAwait(false);
            if (Get(previous, "LoadState") != "not-found") throw new LinuxProbeException("service_unit_already_exists");
            var bootstrapError = Path.Combine(control, "owner-bootstrap.stderr");
            using (var file = new FileStream(bootstrapError, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.Read,
                Options = FileOptions.WriteThrough,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
            })) file.Flush(true);
            LinuxCgroup.VerifyPrivatePath(bootstrapError, false);
            var arguments = new List<string> { "--user", "--no-block", "--quiet", "--service-type=exec", "--expand-environment=no",
                "--unit=" + unitName, "--description=" + scope._tag,
                "--property=Delegate=yes", "--property=KillMode=control-group", "--property=Restart=no",
                "--property=RemainAfterExit=no", "--property=SendSIGKILL=yes", "--property=TimeoutStopSec=5s",
                // 300s owner-report bound + 30s ready/go + 20s teardown, rounded
                // to a bounded 360s service ceiling for these diagnostic groups.
                "--property=RuntimeMaxSec=360s", "--property=UMask=0077", "--property=CPUAccounting=yes",
                "--property=MemoryAccounting=yes", "--property=TasksAccounting=yes", "--property=CPUQuotaPeriodSec=100ms",
                "--property=MemorySwapMax=0", "--property=StandardInput=null", "--property=StandardOutput=null", "--property=StandardError=append:" + bootstrapError,
                "--working-directory=" + (fault == StartFault.MissingWorkingDirectory ? Path.Combine(control, "intentionally-missing-working-directory") : control) };
            if (fault == StartFault.MissingCpuController)
            {
                LinuxCgroup.VerifyTrustedProgram("/usr/bin/sleep");
                LinuxCgroup.VerifyTrustedProgram("/usr/bin/dash");
                arguments.Add("--slice=" + ownedSlice);
                // This fixed trusted helper always fails after its bounded
                // observation window. Even a lost driver can never admit the
                // owner or an SDK payload in this missing-controller scope.
                arguments.Add("--property=ExecStartPre=/usr/bin/dash -c '/usr/bin/sleep 2; exit 1'");
                arguments.Add("--property=TimeoutStartSec=5s");
            }
            arguments.AddRange(LimitArguments(limits).Select(x => "--property=" + x));
            // A fixed env executable clears the user manager's ambient values
            // without reading them. It execs the fixed owner at the same PID.
            arguments.AddRange(["--", "/usr/bin/env", "-i", "PATH=" + ToolPath, "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
                "HOME=" + control, "TMPDIR=" + control, "XDG_RUNTIME_DIR=" + RuntimeDirectory(), executable,
                "--linux-owner", privateOwnerConfigPath]);
            evidence.Phase("service_start", "before_manager", new()
            {
                ["unit"] = unitName,
                ["launcher"] = "/usr/bin/env",
                ["role"] = "linux-owner",
                ["cpuMillicores"] = Text(limits.CpuMillicores),
                ["memoryMax"] = Text(limits.MemoryBytes),
                ["pidsMax"] = Text(limits.ProcessLimit)
            });
            scope._submitted = true;
            await scope.CommandAsync("/usr/bin/systemd-run", arguments, "service_start", TimeSpan.FromSeconds(8)).ConfigureAwait(false);
            var clock = Stopwatch.StartNew();
            while (clock.Elapsed < TimeSpan.FromSeconds(20))
            {
                var state = await scope.ShowAsync().ConfigureAwait(false);
                scope.RequireTag(state);
                if (fault == StartFault.MissingCpuController && Integer(state, "ControlPID") > 0
                    && Get(state, "ControlGroup").Length > 0)
                {
                    var group = Get(state, "ControlGroup");
                    var controlPid = Integer(state, "ControlPID");
                    var controlStart = LinuxCgroup.ProcessStartTicks(controlPid);
                    var controlGroup = LinuxCgroup.ProcessControlGroup(controlPid);
                    if (Get(state, "Slice") != ownedSlice || Get(state, "InvocationID").Length != 32
                        || !group.EndsWith('/' + ownedSlice + '/' + unitName, StringComparison.Ordinal)
                        || controlGroup != group && !controlGroup.StartsWith(group + '/', StringComparison.Ordinal))
                        throw new LinuxProbeException("controller_negative_scope_identity_mismatch");
                    scope._cgroup = LinuxCgroup.Open(group);
                    var controllers = scope._cgroup.ReadControllerState();
                    var guard = scope._cgroup.ReadControllerAbsenceGuardLimits();
                    evidence.Phase("service_start", "actual_controller_absence", new()
                    {
                        ["unit"] = unitName,
                        ["invocationId"] = Get(state, "InvocationID"),
                        ["controlPid"] = Get(state, "ControlPID"),
                        ["controlStartTicks"] = Text(controlStart),
                        ["bootId"] = scope._boot,
                        ["controlGroup"] = group,
                        ["inode"] = Text(scope._cgroup.Inode),
                        ["mountId"] = Text(scope._cgroup.MountId),
                        ["availableControllers"] = controllers.Available,
                        ["enabledControllers"] = controllers.Enabled,
                        ["cpuMaxPresent"] = controllers.CpuMaxPresent.ToString(CultureInfo.InvariantCulture),
                        ["cpuMaxReadback"] = guard.CpuMax,
                        ["memoryMaxReadback"] = guard.MemoryMaxBytes?.ToString(CultureInfo.InvariantCulture) ?? "unbounded",
                        ["pidsMaxReadback"] = guard.PidsMax?.ToString(CultureInfo.InvariantCulture) ?? "unbounded",
                        ["preExecDeadlineMs"] = "5000",
                        ["ownerAdmission"] = "never"
                    });
                    if (guard.MemoryMaxBytes != limits.MemoryBytes || guard.PidsMax != limits.ProcessLimit || Integer(state, "MainPID") != 0)
                        throw new LinuxProbeException("controller_negative_trusted_preexec_guard_mismatch");
                    if (LinuxCgroup.ProcessStartTicks(controlPid) != controlStart || LinuxCgroup.ProcessControlGroup(controlPid) != controlGroup)
                        throw new LinuxProbeException("controller_negative_control_process_changed");
                    if (controllers.Available.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains("cpu", StringComparer.Ordinal)
                        || controllers.CpuMaxPresent) throw new LinuxProbeException("controller_negative_cpu_still_available");
                    throw new LinuxProbeException("service_required_cpu_controller_absent");
                }
                var pid = Integer(state, "MainPID");
                if (fault == StartFault.MissingWorkingDirectory)
                    evidence.Phase("service_start", "native_preexec_state", new()
                    {
                        ["unit"] = unitName,
                        ["invocationId"] = Get(state, "InvocationID"),
                        ["activeState"] = Get(state, "ActiveState"),
                        ["subState"] = Get(state, "SubState"),
                        ["managerResult"] = Get(state, "Result"),
                        ["execMainCode"] = Get(state, "ExecMainCode"),
                        ["execMainStatus"] = Get(state, "ExecMainStatus"),
                        ["mainPid"] = Get(state, "MainPID"),
                        ["controlPid"] = Get(state, "ControlPID"),
                        ["controlGroup"] = Get(state, "ControlGroup")
                    });
                // With --no-block and Type=exec, MainPID/cgroup may be visible
                // while the manager's child is still performing pre-exec setup.
                // Only active/running establishes that the fixed owner exec
                // succeeded; a transient activating PID is not that owner.
                if (pid > 0 && Get(state, "ActiveState") == "active" && Get(state, "SubState") == "running"
                    && Get(state, "ControlGroup").Length > 0 && Get(state, "InvocationID").Length == 32)
                {
                    var group = Get(state, "ControlGroup");
                    var userPrefix = "/user.slice/user-" + Text(LinuxCgroup.UserId) + ".slice/user@" + Text(LinuxCgroup.UserId) + ".service/";
                    if (!group.StartsWith(userPrefix, StringComparison.Ordinal) || !group.EndsWith('/' + unitName, StringComparison.Ordinal)
                        || LinuxCgroup.ProcessControlGroup(pid) != group) throw new LinuxProbeException("service_process_cgroup_mismatch");
                    scope._cgroup = LinuxCgroup.Open(group);
                    scope._identity = new(unitName, Get(state, "InvocationID"), scope._boot, pid,
                        LinuxCgroup.ProcessStartTicks(pid), group, scope._cgroup.Inode, scope._cgroup.MountId);
                    var observed = await scope.ObserveCoreAsync().ConfigureAwait(false);
                    RequireLimits(observed.Cgroup, limits);
                    scope._last = observed;
                    evidence.Phase("service_start", "resource_readback_confirmed", scope.IdentityFacts());
                    return scope;
                }
                if (Get(state, "ActiveState") is "failed" or "inactive")
                {
                    evidence.Phase("service_start", "native_owner_start_failure", new()
                    {
                        ["unit"] = unitName,
                        ["invocationId"] = Get(state, "InvocationID"),
                        ["managerResult"] = Get(state, "Result"),
                        ["execMainCode"] = Get(state, "ExecMainCode"),
                        ["execMainStatus"] = Get(state, "ExecMainStatus"),
                        ["mainPid"] = Get(state, "MainPID"),
                        ["controlPid"] = Get(state, "ControlPID"),
                        ["controlGroup"] = Get(state, "ControlGroup")
                    });
                    if (fault == StartFault.MissingWorkingDirectory && Get(state, "Result") == "exit-code"
                        && Integer(state, "ExecMainCode") == 1 && Integer(state, "ExecMainStatus") == 200
                        && Integer(state, "MainPID") == 0 && Integer(state, "ControlPID") == 0)
                        throw new LinuxProbeException("service_native_preexec_chdir_refused");
                    throw new LinuxProbeException("service_owner_failed_before_identity");
                }
                await Task.Delay(25).ConfigureAwait(false);
            }
            throw new LinuxProbeException("service_owner_start_deadline");
        }
        catch (Exception original)
        {
            evidence.Failure("service_start", original);
            try { await scope.CleanupFailedStartAsync().ConfigureAwait(false); }
            catch (Exception cleanup) { evidence.Failure("service_start_cleanup", cleanup, true); UnresolvedStartupScopes.Add(scope); }
            throw;
        }
    }

    internal static async Task RequireNativeCreationRefusalAsync(string stage, string ownerConfig,
        string unit, LinuxScopeLimits limits, LinuxEvidence evidence)
    {
        LinuxServiceScope? unexpected = null;
        try
        {
            unexpected = await StartCoreAsync(stage, ownerConfig, unit, limits, evidence, StartFault.MissingWorkingDirectory, null).ConfigureAwait(false);
            throw new LinuxProbeException("creation_negative_native_owner_was_started");
        }
        catch (LinuxProbeException error) when (error.Code == "service_native_preexec_chdir_refused")
        { evidence.Phase("resource_native_creation_refusal", "manager_preexec_200_chdir_confirmed"); }
        finally
        {
            if (unexpected is not null)
            {
                try { await unexpected.DisposeAsync().ConfigureAwait(false); }
                catch (Exception error)
                { evidence.Failure("resource_native_creation_refusal_cleanup", error, true); UnresolvedStartupScopes.Add(unexpected); }
            }
        }
    }

    internal static async Task RequireCpuControllerAbsenceRefusalAsync(string stage, string ownerConfig,
        string unit, LinuxScopeLimits limits, LinuxEvidence evidence)
    {
        LinuxCgroup.VerifyTrustedProgram("/usr/bin/busctl");
        // No '-' means no implicit intermediate slices. This fresh exclusive
        // slice changes only its own descendants, never app.slice/shared state.
        var slice = "arcforgesmxc03n" + Guid.NewGuid().ToString("N") + ".slice";
        var parent = new LinuxServiceScope(slice, evidence);
        LinuxServiceScope? unexpected = null;
        try
        {
            var previous = await parent.ShowAsync().ConfigureAwait(false);
            evidence.Phase("resource_controller_absence", "slice_before_create", new()
            {
                ["slice"] = slice,
                ["loadState"] = Get(previous, "LoadState"),
                ["activeState"] = Get(previous, "ActiveState"),
                ["hasFragment"] = (Get(previous, "FragmentPath").Length > 0).ToString(CultureInfo.InvariantCulture),
                ["hasSource"] = (Get(previous, "SourcePath").Length > 0).ToString(CultureInfo.InvariantCulture),
                ["hasJob"] = (Get(previous, "Job").Length > 0).ToString(CultureInfo.InvariantCulture),
                ["hasControlGroup"] = (Get(previous, "ControlGroup").Length > 0).ToString(CultureInfo.InvariantCulture)
            });
            // A valid unknown slice is synthesized as loaded/inactive without a
            // fragment. It is not an existing running/defined unit. The real
            // StartTransientUnit fail call remains the authoritative creation
            // check; only its random description tag permits later teardown.
            if (Get(previous, "LoadState") is not ("not-found" or "loaded") || Get(previous, "ActiveState") != "inactive"
                || Get(previous, "FragmentPath").Length > 0 || Get(previous, "SourcePath").Length > 0
                || Get(previous, "Job").Length > 0 || Get(previous, "ControlGroup").Length > 0
                || Get(previous, "InvocationID").Length > 0 || Get(previous, "Transient") == "yes")
                throw new LinuxProbeException("controller_negative_slice_not_pristine");
            evidence.Phase("resource_controller_absence", "before_fresh_slice_create", new() { ["slice"] = slice });
            parent._submitted = true;
            await parent.CommandAsync("/usr/bin/busctl",
                ["--user", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
                    "StartTransientUnit", "ssa(sv)a(sa(sv))", slice, "fail", "7",
                    "Description", "s", parent._tag, "DisableControllers", "as", "1", "cpu",
                    "MemoryMax", "t", "536870912", "MemorySwapMax", "t", "0", "TasksMax", "t", "128",
                    "MemoryAccounting", "b", "true", "TasksAccounting", "b", "true", "0"],
                "resource_controller_slice_create", TimeSpan.FromSeconds(8)).ConfigureAwait(false);
            var deadline = Stopwatch.StartNew();
            while (true)
            {
                var state = await parent.ShowAsync().ConfigureAwait(false);
                parent.RequireTag(state);
                if (Get(state, "ActiveState") == "active" && Get(state, "ControlGroup").Length > 0)
                {
                    var group = Get(state, "ControlGroup");
                    var expected = "/user.slice/user-" + Text(LinuxCgroup.UserId) + ".slice/user@" + Text(LinuxCgroup.UserId) + ".service/" + slice;
                    if (group != expected || Get(state, "DisableControllers") != "cpu")
                        throw new LinuxProbeException("controller_negative_slice_identity_mismatch");
                    if (Get(state, "InvocationID").Length != 32) throw new LinuxProbeException("controller_negative_slice_invocation_missing");
                    parent._cgroup = LinuxCgroup.Open(group);
                    var guard = parent._cgroup.ReadControllerAbsenceGuardLimits();
                    var controllers = parent._cgroup.ReadControllerState();
                    evidence.Phase("resource_controller_absence", "actual_negative_scope_guard_before_child", new()
                    {
                        ["slice"] = slice,
                        ["tag"] = parent._tag,
                        ["invocationId"] = Get(state, "InvocationID"),
                        ["controlGroup"] = group,
                        ["inode"] = Text(parent._cgroup.Inode),
                        ["mountId"] = Text(parent._cgroup.MountId),
                        ["cpuMaxReadback"] = guard.CpuMax,
                        ["cpuPolicy"] = "missing_controller_negative_only",
                        ["memoryMaxReadback"] = guard.MemoryMaxBytes?.ToString(CultureInfo.InvariantCulture) ?? "unbounded",
                        ["pidsMaxReadback"] = guard.PidsMax?.ToString(CultureInfo.InvariantCulture) ?? "unbounded",
                        ["availableControllers"] = controllers.Available,
                        ["enabledControllers"] = controllers.Enabled,
                        ["preExecDeadlineMs"] = "5000",
                        ["ownerAdmission"] = "never"
                    });
                    if (!parent._cgroup.EmptyProof() || guard.MemoryMaxBytes != 536870912 || guard.PidsMax != 128
                        || controllers.Enabled.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains("cpu", StringComparer.Ordinal))
                        throw new LinuxProbeException("controller_negative_slice_not_fresh_and_guarded");
                    break;
                }
                if (deadline.Elapsed > TimeSpan.FromSeconds(8)) throw new LinuxProbeException("controller_negative_slice_start_deadline");
                await Task.Delay(25).ConfigureAwait(false);
            }
            try
            {
                unexpected = await StartCoreAsync(stage, ownerConfig, unit, limits, evidence, StartFault.MissingCpuController, slice).ConfigureAwait(false);
                throw new LinuxProbeException("controller_negative_owner_was_admitted");
            }
            catch (LinuxProbeException error) when (error.Code == "service_required_cpu_controller_absent")
            { evidence.Phase("resource_controller_absence", "actual_missing_cpu_refused_before_owner"); }
        }
        catch (Exception error) { evidence.Failure("resource_controller_absence", error); throw; }
        finally
        {
            if (unexpected is not null)
            {
                try { await unexpected.DisposeAsync().ConfigureAwait(false); }
                catch (Exception error)
                { evidence.Failure("resource_controller_child_cleanup", error, true); UnresolvedStartupScopes.Add(unexpected); }
            }
            try { await parent.CleanupFailedStartAsync().ConfigureAwait(false); }
            catch (Exception error)
            { evidence.Failure("resource_controller_slice_cleanup", error, true); UnresolvedStartupScopes.Add(parent); }
        }
    }

    internal async Task RequireNativeSettingRefusalAsync()
    {
        LinuxCgroup.VerifyTrustedProgram("/usr/bin/busctl");
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var before = await ObserveCoreAsync().ConfigureAwait(false);
            _evidence.Phase("resource_setting_refusal", "before_manager_write", IdentityFacts());
            // This typed zero value reaches the real manager, whose public
            // resource setter rejects it. It cannot remove/broaden a quota.
            var result = await CommandAsync("/usr/bin/busctl",
                ["--user", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
                    "SetUnitProperties", "sba(sv)", _unit, "true", "1", "CPUQuotaPerSecUSec", "t", "0"],
                "resource_setting_refusal", TimeSpan.FromSeconds(5), allowNonzero: true).ConfigureAwait(false);
            if (result.ExitCode == 0 || !result.Error.Contains("CPUQuotaPerSecUSec= value out of range", StringComparison.Ordinal))
                throw new LinuxProbeException("resource_expected_manager_setting_refusal_missing");
            var after = await ObserveCoreAsync().ConfigureAwait(false);
            if (after.Identity != before.Identity || after.Cgroup.Removed
                || after.Cgroup.CpuQuotaMicros != before.Cgroup.CpuQuotaMicros || after.Cgroup.CpuPeriodMicros != before.Cgroup.CpuPeriodMicros
                || after.Cgroup.MemoryMaxBytes != before.Cgroup.MemoryMaxBytes || after.Cgroup.PidsMax != before.Cgroup.PidsMax)
                throw new LinuxProbeException("resource_failed_setting_changed_actual_policy");
            _evidence.Phase("resource_setting_refusal", "native_manager_refusal_and_unchanged_readback", IdentityFacts());
        }
        catch (Exception error) { _evidence.Failure("resource_setting_refusal", error); throw; }
        finally { _gate.Release(); }
    }

    internal async Task<LinuxScopeObservation> ObserveAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try { return await ObserveCoreAsync().ConfigureAwait(false); }
        catch (Exception error) { _evidence.Failure("service_observe", error); throw; }
        finally { _gate.Release(); }
    }

    private async Task<LinuxScopeObservation> ObserveCoreAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var state = await ShowAsync().ConfigureAwait(false);
        RequireIdentity(state);
        var group = (_cgroup ?? throw new LinuxProbeException("service_cgroup_not_held")).Read();
        return _last = new(Identity, Get(state, "ActiveState"), Get(state, "SubState"), Get(state, "Result"),
            Integer(state, "ExecMainCode"), Integer(state, "ExecMainStatus"), group);
    }

    internal async Task<LinuxScopeObservation> UpdateLimitsAsync(LinuxScopeLimits limits)
    {
        ValidateLimits(limits);
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var before = await ObserveCoreAsync().ConfigureAwait(false);
            if (before.Cgroup.Removed) throw new LinuxProbeException("resource_update_scope_removed");
            if (limits.MemoryBytes < before.Cgroup.MemoryCurrentBytes || limits.ProcessLimit < before.Cgroup.PidsCurrent)
                throw new LinuxProbeException("resource_update_below_current_usage");
            var arguments = new List<string> { "--user", "--no-pager", "set-property", "--runtime", _unit };
            arguments.AddRange(LimitArguments(limits));
            await CommandAsync("/usr/bin/systemctl", arguments, "resource_update", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            var observed = await ObserveCoreAsync().ConfigureAwait(false);
            RequireLimits(observed.Cgroup, limits);
            _evidence.Phase("resource_update", "actual_readback_confirmed", IdentityFacts());
            return observed;
        }
        catch (Exception error) { _evidence.Failure("resource_update", error); throw; }
        finally { _gate.Release(); }
    }

    internal async Task<LinuxScopeObservation> StopAsync(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(2)) throw new LinuxProbeException("service_stop_timeout_invalid");
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var clock = Stopwatch.StartNew();
            var state = await ShowAsync().ConfigureAwait(false);
            var held = _cgroup ?? throw new LinuxProbeException("service_stop_cgroup_not_held");
            if (!held.EmptyProof())
            {
                RequireIdentity(state);
                await CommandAsync("/usr/bin/systemctl", ["--user", "--no-pager", "--no-block", "stop", _unit],
                    "service_stop", Remaining(clock, timeout, TimeSpan.FromSeconds(5))).ConfigureAwait(false);
            }
            while (!held.EmptyProof())
            {
                state = await ShowAsync().ConfigureAwait(false);
                RequireIdentity(state);
                if (clock.Elapsed >= timeout) throw new LinuxProbeException("service_stop_cleanup_deadline");
                await Task.Delay(25).ConfigureAwait(false);
            }
            var group = held.Read();
            if (group.Populated || group.ProcessIds.Length != 0) throw new LinuxProbeException("service_stop_scope_not_empty");
            // Empty original scope requires no mutation of a reused unit name.
            var stopped = new LinuxScopeObservation(Identity, Get(state, "ActiveState"), Get(state, "SubState"), Get(state, "Result"),
                Integer(state, "ExecMainCode"), Integer(state, "ExecMainStatus"), group);
            _last = stopped;
            var facts = IdentityFacts();
            facts["emptyProof"] = group.RemovalProof ?? "cgroup_events_and_subtree_processes_empty";
            facts["scopeRemoved"] = group.Removed ? "true" : "false";
            if (group.HeldLinkCount is { } links) facts["heldLinkCount"] = Text(links);
            _evidence.Phase("service_stop", "native_scope_empty", facts);
            return stopped;
        }
        catch (Exception error) { _evidence.Failure("service_stop", error, true); throw; }
        finally { _gate.Release(); }
    }

    // Owner-loss experiment only: request a signal for the manager's verified
    // main process, then let the independent driver prove native group drain.
    // This must never be replaced with a whole-unit/payload-tree kill.
    internal async Task KillMainAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var state = await ShowAsync().ConfigureAwait(false);
            RequireIdentity(state);
            var group = (_cgroup ?? throw new LinuxProbeException("owner_loss_cgroup_not_held")).Read();
            if (Integer(state, "MainPID") != Identity.MainPid || group.Removed
                || !group.ProcessIds.Contains(Identity.MainPid)
                || LinuxCgroup.ProcessStartTicks(Identity.MainPid) != Identity.MainStartTicks
                || LinuxCgroup.ProcessControlGroup(Identity.MainPid) != Identity.ControlGroup)
                throw new LinuxProbeException("owner_loss_live_main_identity_unproven");
            _evidence.Phase("owner_loss", "verified_main_before_signal", IdentityFacts());
            await CommandAsync("/usr/bin/systemctl", ["--user", "--no-pager", "kill", "--kill-whom=main", "--signal=KILL", _unit],
                "owner_loss", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            _evidence.Phase("owner_loss", "main_signal_requested", IdentityFacts());
        }
        catch (Exception error) { _evidence.Failure("owner_loss", error); throw; }
        finally { _gate.Release(); }
    }

    private async Task CleanupFailedStartAsync()
    {
        if (!_submitted) { _gate.Dispose(); _disposed = true; return; }
        if (_identity is not null && _cgroup is not null && _last is not null)
        {
            _ = await StopAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            await DisposeAsync().ConfigureAwait(false);
            return;
        }
        var state = await ShowAsync().ConfigureAwait(false);
        if (Get(state, "LoadState") == "not-found")
        { _evidence.Phase("service_start_cleanup", "manager_no_unit"); _gate.Dispose(); _disposed = true; return; }
        RequireTag(state);
        var invocation = Get(state, "InvocationID");
        if (_identity is not null && invocation.Length > 0 && invocation != _identity.InvocationId)
            throw new LinuxProbeException("startup_cleanup_generation_changed");
        var group = Get(state, "ControlGroup");
        if (group.Length > 0) _cgroup ??= LinuxCgroup.Open(group);
        await CommandAsync("/usr/bin/systemctl", ["--user", "--no-pager", "--no-block", "stop", _unit], "service_start_cleanup", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        var clock = Stopwatch.StartNew();
        while (clock.Elapsed < TimeSpan.FromSeconds(10))
        {
            state = await ShowAsync().ConfigureAwait(false);
            if (Get(state, "LoadState") != "not-found")
            {
                // Stopping a transient slice unloads it. show then synthesizes
                // a fresh loaded/inactive definition without our former tag.
                // Only the already-tagged generation's held native scope can
                // establish that its cleanup succeeded despite that new name.
                bool stoppedSyntheticSlice = _unit.EndsWith(".slice", StringComparison.Ordinal) && invocation.Length == 32
                    && LinuxCgroup.BootId() == _boot && _cgroup?.EmptyProof() == true
                    && Get(state, "Id") == _unit && Get(state, "LoadState") == "loaded"
                    && Get(state, "ActiveState") == "inactive" && Get(state, "SubState") == "dead"
                    && Get(state, "InvocationID").Length == 0 && Get(state, "ControlGroup").Length == 0
                    && Get(state, "FragmentPath").Length == 0 && Get(state, "SourcePath").Length == 0
                    && Get(state, "Job").Length == 0 && Get(state, "Transient") == "no";
                if (!stoppedSyntheticSlice)
                {
                    RequireTag(state);
                    if (invocation.Length > 0 && Get(state, "InvocationID").Length > 0 && Get(state, "InvocationID") != invocation)
                        throw new LinuxProbeException("startup_cleanup_generation_changed");
                }
            }
            var empty = _cgroup?.EmptyProof() ?? (Get(state, "LoadState") == "not-found"
                || Get(state, "ActiveState") is "inactive" or "failed" && Integer(state, "MainPID") == 0
                && Integer(state, "ControlPID") == 0 && Get(state, "ControlGroup").Length == 0);
            if (empty)
            {
                _evidence.Phase("service_start_cleanup", "confirmed_no_live_scope", new()
                {
                    ["unit"] = _unit,
                    ["invocationId"] = invocation,
                    ["cleanupAuthority"] = _cgroup is null ? "manager_no_live_native_scope" : "held_native_cgroup_empty_proof",
                    ["controlGroup"] = _cgroup?.ControlGroup ?? Get(state, "ControlGroup"),
                    ["heldInode"] = _cgroup is null ? "not_held" : Text(_cgroup.Inode),
                    ["heldMountId"] = _cgroup is null ? "not_held" : Text(_cgroup.MountId),
                    ["mainPid"] = Get(state, "MainPID"),
                    ["controlPid"] = Get(state, "ControlPID")
                });
                _cgroup?.Dispose(); _gate.Dispose(); _disposed = true;
                return;
            }
            await Task.Delay(25).ConfigureAwait(false);
        }
        throw new LinuxProbeException("service_start_cleanup_unresolved");
    }

    private void RequireTag(Dictionary<string, string> state)
    {
        if (Get(state, "Id") != _unit || Get(state, "Description") != _tag) throw new LinuxProbeException("service_owner_tag_mismatch");
    }

    private void RequireIdentity(Dictionary<string, string> state)
    {
        if (LinuxCgroup.BootId() != Identity.BootId) throw new LinuxProbeException("service_boot_changed");
        if (Get(state, "LoadState") == "not-found")
        {
            if (_cgroup?.EmptyProof() == true) return;
            throw new LinuxProbeException("service_missing_scope_unresolved");
        }
        RequireTag(state);
        if (Get(state, "InvocationID").Length == 0 && Get(state, "ActiveState") is "inactive" or "failed"
            && Integer(state, "MainPID") == 0 && Integer(state, "ControlPID") == 0 && _cgroup?.EmptyProof() == true) return;
        if (Get(state, "InvocationID") != Identity.InvocationId || Get(state, "ControlGroup") is { Length: > 0 } group && group != Identity.ControlGroup)
            throw new LinuxProbeException("service_generation_or_scope_changed");
        if (Get(state, "Delegate") != "yes" || Get(state, "KillMode") != "control-group" || Get(state, "Restart") != "no")
            throw new LinuxProbeException("service_lifecycle_policy_changed");
        var pid = Integer(state, "MainPID");
        if (pid > 0 && (pid != Identity.MainPid || LinuxCgroup.ProcessStartTicks(pid) != Identity.MainStartTicks
            || LinuxCgroup.ProcessControlGroup(pid) != Identity.ControlGroup)) throw new LinuxProbeException("service_main_process_identity_changed");
    }

    private async Task<Dictionary<string, string>> ShowAsync()
    {
        var result = await CommandAsync("/usr/bin/systemctl", ["--user", "--no-pager", "show", "--property=" + string.Join(',', Properties), _unit],
            "service_query", TimeSpan.FromSeconds(5), allowNonzero: true).ConfigureAwait(false);
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in result.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        { var equals = line.IndexOf('='); if (equals > 0 && !values.TryAdd(line[..equals], line[(equals + 1)..])) throw new LinuxProbeException("service_duplicate_property"); }
        if (result.ExitCode != 0 && Get(values, "LoadState") != "not-found")
        {
            if (result.Error.Trim() == "Unit " + _unit + " could not be found.") return new(StringComparer.Ordinal) { ["LoadState"] = "not-found", ["ActiveState"] = "inactive" };
            throw new LinuxProbeException("systemctl_show_failed");
        }
        if (Get(values, "LoadState").Length == 0) throw new LinuxProbeException("service_load_state_missing");
        return values;
    }

    private sealed record CommandResult(int ExitCode, string Output, string Error);
    private async Task<CommandResult> CommandAsync(string executable, IReadOnlyList<string> arguments, string phase, TimeSpan timeout, bool allowNonzero = false)
    {
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        foreach (var value in arguments) start.ArgumentList.Add(value);
        start.Environment.Clear(); start.Environment["PATH"] = ToolPath; start.Environment["LANG"] = "C"; start.Environment["LC_ALL"] = "C";
        start.Environment["XDG_RUNTIME_DIR"] = RuntimeDirectory(); start.Environment["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + RuntimeDirectory() + "/bus";
        using var deadline = new CancellationTokenSource(timeout);
        using var process = Process.Start(start) ?? throw new LinuxProbeException("systemd_command_not_started");
        var output = CaptureAsync(process.StandardOutput.BaseStream, deadline.Token);
        var error = CaptureAsync(process.StandardError.BaseStream, deadline.Token);
        try
        {
            await Task.WhenAll(output, error, process.WaitForExitAsync(deadline.Token)).ConfigureAwait(false);
            var stdout = await output.ConfigureAwait(false); var stderr = await error.ConfigureAwait(false);
            PreserveCommandDetails(phase, process.ExitCode, stdout, stderr);
            _evidence.Phase(phase, "command_result", new()
            {
                ["command"] = Path.GetFileName(executable),
                ["exitCode"] = Text(process.ExitCode),
                ["stdoutBytes"] = Text(stdout.Length),
                ["stderrBytes"] = Text(stderr.Length),
                ["stdoutSha256"] = Convert.ToHexStringLower(SHA256.HashData(stdout)),
                ["stderrSha256"] = Convert.ToHexStringLower(SHA256.HashData(stderr))
            });
            if (!allowNonzero && process.ExitCode != 0) throw new LinuxProbeException("systemd_command_exit_nonzero");
            return new(process.ExitCode, new UTF8Encoding(false, true).GetString(stdout).Trim(), new UTF8Encoding(false, true).GetString(stderr).Trim());
        }
        catch
        {
            try
            {
                if (!process.HasExited) process.Kill(); // Only this held control-tool process, never a workload PID/tree.
                await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            }
            catch (Exception cleanup) { _evidence.Failure(phase + "_command_cleanup", cleanup, true); }
            throw;
        }
    }

    private void PreserveCommandDetails(string phase, int exitCode, byte[] stdout, byte[] stderr)
    {
        try
        {
            // Only fixed manager commands and an explicit property list reach
            // this path. Raw output stays in bounded, owner-private evidence;
            // normal successful property snapshots need no duplicate file.
            if (stderr.Length > 0) _evidence.Detail(phase, "stderr", stderr);
            if (exitCode != 0 && stdout.Length > 0) _evidence.Detail(phase, "stdout", stdout);
        }
        catch (Exception detailFailure)
        {
            try { _evidence.Failure(phase + "_evidence", detailFailure); }
            catch (Exception evidenceFailure)
            {
                // An evidence failure cannot replace the original provider
                // exit/cleanup result. The fallback contains no arbitrary text.
                Console.Error.WriteLine("linux_scope_detail_evidence_failed:" + phase + ":"
                    + detailFailure.GetType().Name + ":" + evidenceFailure.GetType().Name);
            }
        }
    }

    private static async Task<byte[]> CaptureAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var capture = new MemoryStream(); var buffer = new byte[4096];
        while (true)
        {
            var count = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false); if (count == 0) return capture.ToArray();
            if (capture.Length + count > 65_536) throw new LinuxProbeException("systemd_command_output_bound"); await capture.WriteAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
        }
    }

    private static IEnumerable<string> LimitArguments(LinuxScopeLimits limits) => [
        "CPUQuota=" + (limits.CpuMillicores / 10m).ToString("0.###", CultureInfo.InvariantCulture) + "%",
        "MemoryMax=" + Text(limits.MemoryBytes), "TasksMax=" + Text(limits.ProcessLimit)];
    private static void RequireLimits(LinuxCgroupObservation actual, LinuxScopeLimits limits)
    {
        if (actual.Removed || actual.CpuPeriodMicros != 100_000 || actual.CpuQuotaMicros != limits.CpuMillicores * 100L
            || actual.MemoryMaxBytes != limits.MemoryBytes || actual.PidsMax != limits.ProcessLimit)
            throw new LinuxProbeException("resource_actual_readback_mismatch");
    }
    private static void ValidateLimits(LinuxScopeLimits limits)
    {
        if (limits.CpuMillicores is < 10 or > 64_000 || limits.MemoryBytes is < 16_777_216 or > 2_147_483_648
            || limits.ProcessLimit is < 4 or > 4096) throw new LinuxProbeException("resource_probe_limit_out_of_bounds");
    }
    private Dictionary<string, string> IdentityFacts() => new()
    {
        ["unit"] = Identity.Unit,
        ["invocationId"] = Identity.InvocationId,
        ["bootId"] = Identity.BootId,
        ["mainPid"] = Text(Identity.MainPid),
        ["mainStartTicks"] = Text(Identity.MainStartTicks),
        ["controlGroup"] = Identity.ControlGroup,
        ["cgroupInode"] = Text(Identity.CgroupInode),
        ["cgroupMountId"] = Text(Identity.CgroupMountId)
    };
    private static string RuntimeDirectory() => "/run/user/" + Text(LinuxCgroup.UserId);
    private static string Get(Dictionary<string, string> state, string key) => state.GetValueOrDefault(key, "");
    private static int Integer(Dictionary<string, string> state, string key) => Get(state, key) is { Length: > 0 } value ? int.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture) : 0;
    private static string Text<T>(T value) where T : IFormattable => value.ToString(null, CultureInfo.InvariantCulture);
    private static TimeSpan Remaining(Stopwatch clock, TimeSpan timeout, TimeSpan maximum) => timeout - clock.Elapsed is var left && left > TimeSpan.Zero
        ? left < maximum ? left : maximum : throw new LinuxProbeException("service_operation_deadline");

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _ = await StopAsync(TimeSpan.FromSeconds(20)).ConfigureAwait(false);
        if (_cgroup?.EmptyProof() != true) throw new LinuxProbeException("scope_dispose_cleanup_unresolved");
        _cgroup.Dispose(); _gate.Dispose(); _disposed = true;
    }
}
