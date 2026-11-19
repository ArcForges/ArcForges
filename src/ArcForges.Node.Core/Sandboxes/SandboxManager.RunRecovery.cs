// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using ArcForges.RunSupervisor.Protocol;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private static readonly Lazy<string?> s_linuxMachineIdentity = new(ReadLinuxMachineIdentity);

    private string RunRecoveryBootIdentity => OperatingSystem.IsLinux() && s_linuxMachineIdentity.Value is { } machine
        ? _store.Metadata.BootIdentity + ":" + machine : _store.Metadata.BootIdentity;

    internal async Task RecoverRunsAsync(RecoveryReport report, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(report);
        if (report.IntegrityCheck is { } integrity && integrity != "ok")
        {
            return;
        }

        var runs = _store.Read(reader => RunRecords.ListNonterminal(reader, OwnerId));
        if (runs.Count == 0)
        {
            return;
        }

        byte[] ownerEpoch;
        try
        {
            ownerEpoch = Receipts.OwnerEpoch.ToArray();
        }
        catch (Exception failure) when (IsStorageFailure(failure))
        {
            // Incomplete authority stays in maintenance. The original epoch is never replaced.
            return;
        }

        await Parallel.ForEachAsync(runs, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = cancellationToken },
            (run, token) => RecoverRunAsync(run, ownerEpoch, token)).ConfigureAwait(false);
    }

    private async ValueTask RecoverRunAsync(StoredRun run, byte[] ownerEpoch, CancellationToken cancellationToken)
    {
        IRunOwnerLease? lease = null;
        byte[]? key = null;
        LiveRun? live = null;
        try
        {
            var snapshot = ReadRunSnapshot(run);
            var stored = _store.Read(reader => (Recovery: RunRecoveryRecords.Read(reader, OwnerId, run),
                Owner: RunRecords.GetSupervisor(reader, OwnerId, run.RunId),
                Stop: RunRecoveryRecords.ReadStop(reader, OwnerId, ownerEpoch, run, snapshot.StartCommandId)));
            live = new LiveRun(run.RunId, run.Epoch, Convert.FromHexString(snapshot.StartCommandId), _runObserverStop.Token);
            if (stored.Stop is { } stop)
            {
                live.StopRequest.TrySetResult(stop);
            }

            if (stored.Recovery is { PrepareStarted: false } && stored.Owner is null
                && (run.State is StoredRunState.Starting or StoredRunState.RecoveryRequired || stored.Stop is not null))
            {
                ObserveRun(live, stored.Stop is null ? NoRunPayload("recovered_before_owner_prepare")
                    : NoRunPayload("stopped_before_prepare") with { State = RunOwnerState.Exited });
                return;
            }

            var currentBoot = RunRecoveryBootIdentity;
            bool reboot = stored.Recovery is { } durable && IsDifferentRunBoot(durable.BootId, currentBoot);
            if (reboot && stored.Owner is null)
            {
                ObserveRun(live, new RunOwnerObservation(RunOwnerState.Exited, RunPayloadStart.Unknown,
                    GroupEmptyVerified: true, ExitSource: RunExitSources.Unknown, TerminationReason: "host_reboot"));
                return;
            }

            if (stored.Recovery is not { PrepareStarted: true } recovery || stored.Owner is not { } owner
                || owner.ControlEpoch != run.Epoch || RunLauncher is not IRunRecoveryLauncher recoverer)
            {
                ObserveRun(live, UncertainRun("run_recovery_identity_unavailable"));
                return;
            }

            if (!SameRunBoot(recovery.BootId, owner.BootId) || !reboot && !SameRunBoot(recovery.BootId, currentBoot))
            {
                ObserveRun(live, UncertainRun("run_recovery_host_identity_unconfirmed"));
                return;
            }

            _roots.ValidateControlPaths();
            var control = Path.Combine(_dataRoot, "control", "run-" + run.RunId);
            var expected = new RunOwnerIdentity(owner.InstanceId, owner.BootId, owner.ProcessId, owner.CreationIdentity,
                owner.Endpoint, owner.BoundaryIdentity, owner.BackendId, owner.Cohort, owner.ControlEpoch);
            lock (OwnershipGate)
            {
                key = Receipts.DeriveRunControlKey(run.RunId, run.LaunchSha256);
                RequireChanged(_store.Write(transaction => RunRecoveryRecords.AdvanceGeneration(transaction, OwnerId,
                    run, owner, recovery.Generation), CommitDurability.Full));
            }

            long generation = checked(recovery.Generation + 1);
            var spec = new RunRecoverySpec(run.RunId, run.SandboxId, run.Epoch, run.LaunchSha256, control,
                recovery.SupervisorPath, recovery.SupervisorSha256, recovery.InstallationRoot, key, expected, generation);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromSeconds(10));
            var result = await recoverer.RecoverAsync(spec, deadline.Token).ConfigureAwait(false);
            lease = result.Lease;
            if (lease is null)
            {
                var observation = result.Observation;
                ObserveRun(live, observation is { IsTerminal: true, GroupEmptyVerified: true } or { State: RunOwnerState.Draining }
                    ? observation : UncertainRun(observation?.TerminationReason ?? "run_recovery_boundary_unconfirmed") with
                    { NativeError = observation?.NativeError });
                return;
            }

            if (lease.Identity != expected)
            {
                throw new InvalidDataException("run_recovery_owner_changed");
            }

            var first = result.Observation ?? await lease.ObserveAsync(deadline.Token).ConfigureAwait(false);
            lock (OwnershipGate)
            {
                var current = _store.Read(reader => (Run: RunRecords.Get(reader, OwnerId, run.RunId),
                    Owner: RunRecords.GetSupervisor(reader, OwnerId, run.RunId), Recovery: RunRecoveryRecords.Read(reader, OwnerId, run)));
                if (_runObservationStopped || current.Run != run || current.Owner != owner || current.Recovery?.Generation != generation)
                {
                    return;
                }

                if (first is { IsTerminal: true, GroupEmptyVerified: true })
                {
                    ObserveRun(live, first);
                    return;
                }

                live.RecoveryLimitRefusal = CheckRecoveredRunLimits(run, snapshot, lease);
                if (live.RecoveryLimitRefusal is { } refusal)
                {
                    ReportRun(run.RunId, "recover_owner_limits_refused", refusal);
                }

                ObserveRun(live, first);
                live.OwnerLease = lease;
                _liveRuns.Add(run.RunId, live);
                var recoveredLease = lease;
                var recoveredKey = key;
                _ = Task.Run(() => ObserveRecoveredRunAsync(live, recoveredLease, recoveredKey), CancellationToken.None);
                lease = null;
                key = null;
            }
        }
        catch (Exception failure) when (!cancellationToken.IsCancellationRequested
            && (IsRunOwnerFailure(failure) || IsStorageFailure(failure) || failure is System.ComponentModel.Win32Exception))
        {
            ReportRun(run.RunId, "recover_owner_failed", NativeFailure(failure));
            if (live is not null)
            {
                try
                {
                    ObserveRun(live, UncertainRun("run_recovery_boundary_unconfirmed"));
                }
                catch (Exception stateError) when (IsStorageFailure(stateError))
                {
                    ReportRun(run.RunId, "persist_recovery_failed", NativeFailure(stateError));
                }
            }
        }
        finally
        {
            if (lease is not null)
            {
                await DisposeRecoveredLeaseAsync(run.RunId, lease).ConfigureAwait(false);
            }

            if (key is not null)
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
    }

    private string? CheckRecoveredRunLimits(StoredRun run, RunSnapshot snapshot, IRunOwnerLease lease)
    {
        var required = new List<(string Dimension, string Unit)>
        {
            ("cpu", "millicores"),
            ("memory", OperatingSystem.IsWindows() ? "windows_commit_bytes" : "linux_cgroup_bytes"),
            ("pids", "count"),
        };
        if (OperatingSystem.IsLinux())
        {
            required.Add(("swap", "bytes"));
        }

        if (snapshot.CpuWeight.HasValue)
        {
            required.Add(("cpu_weight", "weight"));
        }

        var limits = _store.Read(reader => ResourceStateRecords.ReadLimits(reader, OwnerId, run.RunId));
        if (limits.Count != required.Count || limits.Any(limit => !required.Contains((limit.Dimension, limit.Unit))
            || limit.Status != StoredRunLimitStatus.Effective || limit.BoundaryIdentity != lease.Identity.BoundaryIdentity
            || limit.AppliedAt is null || limit.ReadbackAt is null || limit.AppliedValue != limit.ReadbackValue
            || !ulong.TryParse(limit.AppliedValue, NumberStyles.None, CultureInfo.InvariantCulture, out _)))
        {
            return "run_recovery_limit_records_unconfirmed";
        }

        RunResourceLimitReading? native;
        try
        {
            native = ReadOwnedLimits(lease);
        }
        catch (Exception failure) when (IsNativeResourceFailure(failure))
        {
            return "run_recovery_native_limits_unavailable";
        }

        if (native is null || limits.Any(limit => !native.Value(NativeLimitDimension(limit.Dimension)).HasValue))
        {
            return "run_recovery_native_limits_unavailable";
        }

        return limits.All(limit => native.Value(NativeLimitDimension(limit.Dimension)) is { } value
            && LimitText(value) == limit.ReadbackValue) ? null : "run_recovery_native_limits_mismatch";
    }

    private async Task ObserveRecoveredRunAsync(LiveRun live, IRunOwnerLease lease, byte[] key)
    {
        using var stopLifetime = CancellationTokenSource.CreateLinkedTokenSource(live.CancellationToken);
        var stop = ForwardRunStopAsync(live, lease, stopLifetime.Token);
        try
        {
            await ObserveOwnerAsync(live, lease).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (live.CancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception failure) when (IsRunOwnerFailure(failure) || IsStorageFailure(failure))
        {
            ReportRun(live.RunId, "recovered_observation_failed", NativeFailure(failure));
        }
        finally
        {
            lock (OwnershipGate)
            {
                live.OwnerLease = null;
                if (_liveRuns.TryGetValue(live.RunId, out var current) && ReferenceEquals(current, live))
                {
                    _liveRuns.Remove(live.RunId);
                }
            }

            await stopLifetime.CancelAsync().ConfigureAwait(false);
            await stop.ConfigureAwait(false);
            await DisposeRecoveredLeaseAsync(live.RunId, lease).ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private async ValueTask DisposeRecoveredLeaseAsync(string runId, IRunOwnerLease lease)
    {
        try
        {
            await lease.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception failure) when (IsRunOwnerFailure(failure) || failure is ObjectDisposedException)
        {
            ReportRun(runId, "recovered_owner_channel_close_failed", NativeFailure(failure));
        }
    }

    private static bool SameRunBoot(string retained, string current) => OperatingSystem.IsLinux()
        ? TryLinuxBoot(retained, out var initial, out _) && TryLinuxBoot(current, out var now, out _) && initial == now
        : string.Equals(retained, current, StringComparison.Ordinal);

    private static bool IsDifferentRunBoot(string retained, string current)
    {
        if (OperatingSystem.IsLinux())
        {
            return TryLinuxBoot(retained, out var previous, out var machine) && machine is not null
                && TryLinuxBoot(current, out var boot, out var currentMachine) && machine == currentMachine && previous != boot;
        }

        return OperatingSystem.IsWindows() && TryWindowsBoot(retained, out var previousMachine, out var previousBoot)
            && TryWindowsBoot(current, out var machineNow, out var bootNow) && previousMachine == machineNow && previousBoot != bootNow;
    }

    private static bool TryLinuxBoot(string value, out Guid boot, out string? machine)
    {
        var fields = value.Split(':');
        machine = fields is ["linux", _, { Length: 64 } hash] && hash.All(char.IsAsciiHexDigitLower) ? hash : null;
        var identity = fields is ["linux", _] or ["linux", _, _] ? fields[1] : value;
        return Guid.TryParseExact(identity, "D", out boot) && boot != Guid.Empty;
    }

    private static bool TryWindowsBoot(string value, out Guid machine, out long boot)
    {
        machine = default;
        boot = 0;
        var fields = value.Split(':');
        return fields is ["windows", var id, var seconds] && Guid.TryParse(id, out machine) && machine != Guid.Empty
            && long.TryParse(seconds, NumberStyles.None, CultureInfo.InvariantCulture, out boot) && boot > 0;
    }

    private static string? ReadLinuxMachineIdentity()
    {
        try
        {
            using var etc = WorkspacePath.OpenRoot("/etc");
            using var file = etc.OpenRead("machine-id");
            WorkspacePath.CheckMxcTrustedObject(file, systemOnly: true);
            using var stream = new FileStream(file, FileAccess.Read);
            if (stream.Length is not (32 or 33))
            {
                return null;
            }

            Span<byte> bytes = stackalloc byte[(int)stream.Length];
            stream.ReadExactly(bytes);
            var value = Encoding.ASCII.GetString(bytes).TrimEnd('\n');
            return Guid.TryParseExact(value, "N", out var id) && id != Guid.Empty
                ? Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(id.ToString("N")))) : null;
        }
        catch (Exception failure) when (IsRunOwnerFailure(failure) || IsStorageFailure(failure))
        {
            return null;
        }
    }
}
