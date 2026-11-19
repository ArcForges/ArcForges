// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Store;
using ArcForges.RunSupervisor.Protocol;
using Google.Protobuf;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private const string StartRunMethod = "RunService.Start";
    private const string StopRunMethod = "RunService.Stop";
    private const string RunAggregate = "run";
    private readonly Dictionary<string, LiveRun> _liveRuns = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _runObserverStop = new();
    private bool _runObservationStopped;

    internal IRunLauncher? RunLauncher { get; init; }
    internal Action<string, string, string?>? RunDiagnostic { get; init; }

    internal RunServiceStartResponse Start(RunServiceStartRequest request, CancellationToken cancellationToken)
    {
        lock (OwnershipGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var result = StartRunLocked(request);
                return result.Error is { } error
                    ? new() { Meta = Response(request.Meta), Error = error }
                    : new() { Meta = Response(request.Meta, result.Run!.Revision.Value), Value = new() { Run = result.Run, Operation = result.Operation } };
            }
            catch (SandboxPrivateRootException error)
            {
                return new() { Meta = Response(request.Meta), Error = ControlPathFailure(request.Meta, error) };
            }
            catch (Exception error) when (IsStorageFailure(error))
            {
                return new() { Meta = Response(request.Meta), Error = StorageFailure(request.Meta) };
            }
        }
    }

    private RunMutationResult StartRunLocked(RunServiceStartRequest request)
    {
        var meta = request.Meta;
        if (!ValidId(meta?.CommandId) || !ValidId(request.OwnerEpoch) || !ValidId(request.SandboxId) || meta?.ExpectedRev is not { Value: > 0 } expected)
        {
            return RunFailure(InvalidRun(meta));
        }

        if (!EpochMatches(request.OwnerEpoch))
        {
            return RunFailure(RetiredRunEpoch(meta));
        }

        var command = meta.CommandId.Value.ToByteArray();
        var epoch = request.OwnerEpoch.Value.ToByteArray();
        string sandboxId = ToHex(request.SandboxId);
        var previous = Receipts.Inspect(command);
        string runId = previous?.AggregateId ?? Guid.NewGuid().ToString("N");
        var body = request.Clone();
        body.Meta = null;
        body.OwnerEpoch = null;
        var canonical = body.ToByteArray();
        var intent = new DurableIntent(command, epoch, StartRunMethod, RunAggregate, runId, canonical, expected.Value,
            ExpectedSandboxId: sandboxId);

        // The original identity and keyed intent are resolved before checking today's Sandbox or host.
        if (previous is not null)
        {
            return ResolveRunMutation(Receipts.Admit(intent), meta, request.OwnerEpoch);
        }

        var row = _store.Read(reader => SandboxRecords.Get(reader, OwnerId, sandboxId));
        if (row is null)
        {
            return RunFailure(NotFound(meta));
        }

        if (row.Revision != expected.Value)
        {
            return RunFailure(RevisionError(meta, expected.Value, row.Revision));
        }

        if (row.State != StoredSandboxState.Ready || row.RootRelative != SandboxPrivateRoots.RelativePath(sandboxId))
        {
            return RunFailure(Error(meta, ErrorCategory.State, "busy", "sandbox_not_ready"));
        }

        var launcher = RunLauncher;
        if (launcher is null || _runObservationStopped)
        {
            return RunFailure(Error(meta, ErrorCategory.Execution, "unsupported_combination", "run_launcher_unavailable"));
        }

        var config = FromStored(row.Config);
        var maximumRuns = config.Resources.HasMaxConcurrentRuns ? config.Resources.MaxConcurrentRuns : 1;
        if (_store.Read(reader => RunRecords.CountNonterminal(reader, OwnerId, sandboxId)) >= maximumRuns)
        {
            return RunFailure(Error(meta, ErrorCategory.Resource, "budget_unavailable", "sandbox_concurrency_ceiling"));
        }

        SandboxPrivateRootLease? root = _roots.Inspect(sandboxId, row.RootIdentity);
        try
        {
            var controlKey = RandomNumberGenerator.GetBytes(RunWire.KeyLength);
            var launchDigest = Convert.ToHexStringLower(HMACSHA256.HashData(controlKey, canonical));
            var generation = Guid.NewGuid().ToString("N");
            var policy = PrepareRunPolicy(request, row, root, runId, generation, launchDigest, controlKey);
            if (policy.Spec is not { } spec)
            {
                CryptographicOperations.ZeroMemory(controlKey);
                return RunFailure(policy.Error ?? InvalidRun(meta));
            }

            var snapshot = RunSnapshotJson(spec, Convert.ToHexStringLower(command));
            var started = new StoredRun(runId, sandboxId, row.Revision, 1, StoredRunState.Starting, generation,
                launchDigest, snapshot, StoredPayloadStart.Unknown, _clock.GetUtcNow());
            var admitted = Receipts.Admit(intent,
                transaction => RequireChanged(RunRecords.InsertStarting(transaction, OwnerId, started)));
            if (admitted.Decision == DurableDecision.Execute)
            {
                var live = new LiveRun(spec, launcher, root, command, _runObserverStop.Token);
                _liveRuns.Add(runId, live);
                root = null;
                _ = Task.Run(() => OwnRunAsync(live), CancellationToken.None);
            }
            else
            {
                CryptographicOperations.ZeroMemory(controlKey);
            }

            return ResolveRunMutation(admitted, meta, request.OwnerEpoch);
        }
        finally
        {
            root?.Dispose();
        }
    }

    internal RunServiceStopResponse Stop(RunServiceStopRequest request, CancellationToken cancellationToken)
    {
        lock (OwnershipGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var result = StopRunLocked(request);
                return result.Error is { } error
                    ? new() { Meta = Response(request.Meta), Error = error }
                    : new() { Meta = Response(request.Meta, result.Run!.Revision.Value), Value = new() { Run = result.Run, Operation = result.Operation } };
            }
            catch (Exception error) when (IsStorageFailure(error))
            {
                return new() { Meta = Response(request.Meta), Error = StorageFailure(request.Meta) };
            }
        }
    }

    private RunMutationResult StopRunLocked(RunServiceStopRequest request)
    {
        var meta = request.Meta;
        if (!ValidId(meta?.CommandId) || !ValidId(request.OwnerEpoch) || !ValidId(request.RunId) || meta?.ExpectedRev is not { Value: > 0 } expected
            || request.HasGraceMs && request.GraceMs > 60000)
        {
            return RunFailure(InvalidRun(meta));
        }

        if (!EpochMatches(request.OwnerEpoch))
        {
            return RunFailure(RetiredRunEpoch(meta));
        }

        var command = meta.CommandId.Value.ToByteArray();
        string runId = ToHex(request.RunId);
        var existing = Receipts.Inspect(command);
        if (existing is not null && (existing.Method != StopRunMethod || existing.AggregateKind != RunAggregate || existing.AggregateId != runId))
        {
            return RunFailure(Error(meta, ErrorCategory.Conflict, "command_id_reused", "command_intent_changed"));
        }

        var run = _store.Read(reader => RunRecords.Get(reader, OwnerId, runId));
        if (run is null)
        {
            return RunFailure(NotFound(meta));
        }

        var body = request.Clone();
        body.Meta = new RequestMeta { ExpectedRev = expected.Clone() };
        body.OwnerEpoch = null;
        var canonical = body.ToByteArray();
        var parent = existing is null ? Convert.FromHexString(ReadRunSnapshot(run).StartCommandId)
            : existing.SafetyParentCommandId is { } linked ? Convert.FromHexString(linked) : null;
        var intent = new DurableIntent(command, request.OwnerEpoch.Value.ToByteArray(), StopRunMethod, RunAggregate, runId,
            canonical, SafetyParent: parent);
        if (existing is not null)
        {
            return ResolveRunMutation(Receipts.Admit(intent), meta, request.OwnerEpoch);
        }

        if (run.Revision != expected.Value)
        {
            var error = RevisionError(meta, expected.Value, run.Revision);
            error.Details.State.Reason = "run_revision_changed";
            return RunFailure(error);
        }

        if (run.State is StoredRunState.Exited or StoredRunState.Failed)
        {
            var settled = Receipts.AdmitObserved(intent with { SafetyParent = null }, "SUCCEEDED", (int)EffectCertainty.DidNotHappen,
                ResultBody(run.Revision, null));
            return ResolveRunMutation(settled, meta, request.OwnerEpoch);
        }

        if (!_liveRuns.TryGetValue(runId, out var live))
        {
            var recoveryRevision = run.State == StoredRunState.RecoveryRequired ? run.Revision : checked(run.Revision + 1);
            var unresolved = Receipts.AdmitObserved(intent, "UNKNOWN", (int)EffectCertainty.Unknown,
                ResultBody(recoveryRevision, null, ErrorCategory.Execution, "outcome_unknown", "run_owner_identity_requires_recovery"),
                transaction =>
                {
                    if (run.State != StoredRunState.RecoveryRequired)
                    {
                        RequireChanged(RunRecords.TryAdvance(transaction, OwnerId, runId, run.Epoch, run.Revision, run.State,
                            new StoredRunObservation(StoredRunState.RecoveryRequired, run.PayloadStarted, run.EffectCertainty)));
                    }
                });
            return ResolveRunMutation(unresolved, meta, request.OwnerEpoch);
        }

        var admission = Receipts.Admit(intent, transaction =>
        {
            if (run.State is not (StoredRunState.Stopping or StoredRunState.Draining or StoredRunState.RecoveryRequired))
            {
                RequireChanged(RunRecords.TryAdvance(transaction, OwnerId, runId, run.Epoch, run.Revision, run.State,
                    new StoredRunObservation(StoredRunState.Stopping, run.PayloadStarted, run.EffectCertainty)));
            }
        });
        if (admission.Decision == DurableDecision.Execute)
        {
            live.StopCommand = command;
            live.StopRequest.TrySetResult(TimeSpan.FromMilliseconds(request.HasGraceMs ? request.GraceMs : 5000));
        }

        return ResolveRunMutation(admission, meta, request.OwnerEpoch);
    }

    private RunMutationResult ResolveRunMutation(DurableAdmission admission, RequestMeta meta, Id epoch)
    {
        var receipt = admission.Receipt;
        switch (admission.Decision)
        {
            case DurableDecision.Compacted when receipt is not null:
                var compacted = Error(meta, ErrorCategory.State, "receipt_compacted", "original_response_compacted",
                    (EffectCertainty)receipt.Effect);
                compacted.Details.State.State = receipt.State;
                compacted.Details.State.Resource = AggregateIdentity(receipt);
                compacted.Retry.ReconciliationOperation = "NodeService.GetOperation";
                return RunFailure(compacted);
            case DurableDecision.Conflict:
                return RunFailure(Error(meta, ErrorCategory.Conflict, "command_id_reused", "command_intent_changed"));
            case DurableDecision.EpochRetired:
                return RunFailure(RetiredRunEpoch(meta));
            case DurableDecision.RevisionConflict:
                return RunFailure(Error(meta, ErrorCategory.Conflict, "revision_mismatch", "sandbox_revision_changed"));
            case DurableDecision.Capacity:
                return RunFailure(Error(meta, ErrorCategory.Resource, "budget_unavailable", "operation_capacity"));
            case DurableDecision.Maintenance:
                return RunFailure(StorageFailure(meta));
        }

        if (receipt is null || receipt.AggregateKind != RunAggregate || receipt.AggregateId is not { } id)
        {
            return RunFailure(StorageFailure(meta));
        }

        if (receipt.State is "FAILED" or "UNKNOWN")
        {
            var observed = ReadResult(receipt.ResponseJson);
            return RunFailure(receipt.State == "UNKNOWN"
                ? Error(meta, ErrorCategory.Execution, "outcome_unknown", observed.Reason, EffectCertainty.Unknown)
                : Error(meta, observed.Category, observed.Code, observed.Reason, (EffectCertainty)receipt.Effect));
        }

        var run = _store.Read(reader => RunRecords.Get(reader, OwnerId, id));
        if (run is null)
        {
            return RunFailure(StorageFailure(meta));
        }

        var updated = _store.Read(reader => reader.Scalar("""
            SELECT updated_utc FROM command_receipt WHERE owner_id=$o AND owner_epoch=$e AND command_id=$c;
            """, ("$o", OwnerId), ("$e", epoch.Value.ToByteArray()), ("$c", receipt.CommandId))) as string;
        var operation = new Operation
        {
            CommandId = FromHex(receipt.CommandId),
            OwnerEpoch = epoch.Clone(),
            AggregateId = FromHex(id),
            Method = receipt.Method,
            State = receipt.State == "SUCCEEDED" ? OperationState.Succeeded : OperationState.Accepted,
            Effect = (EffectCertainty)receipt.Effect,
            Revision = new Revision { Value = run.Revision },
            UpdatedAt = ProtoTime.ToInstant(updated is null ? run.CreatedAt
                : DateTimeOffset.Parse(updated, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind)),
        };
        return new(RunView(run), operation);
    }

    private static string RunSnapshotJson(RunLaunchSpec spec, string startCommand)
    {
        var name = spec.Argv[0].Split('/', '\\').Last();
        name = string.Concat(name.EnumerateRunes().Where(rune => !System.Text.Rune.IsControl(rune)).Take(96));
        var snapshot = new JsonObject
        {
            ["profileId"] = spec.ProfileId,
            ["profileVersion"] = spec.ProfileVersion,
            ["terminalMode"] = (int)spec.TerminalMode,
            ["safeCommandDisplay"] = $"{name} [{spec.Argv.Length - 1} arguments redacted]",
            ["cpuMillicores"] = spec.CpuMillicores,
            ["memoryMaxBytes"] = spec.MemoryMaxBytes,
            ["maxProcesses"] = spec.MaxProcesses,
            ["cpuWeight"] = spec.CpuWeight,
            ["startCommandId"] = startCommand,
        };
        return snapshot.ToJsonString();
    }

    private static ArcError InvalidRun(RequestMeta? meta) =>
        Error(meta, ErrorCategory.Validation, "invalid_argument", "run_request_invalid");

    private static ArcError RetiredRunEpoch(RequestMeta? meta) =>
        Error(meta, ErrorCategory.Conflict, "owner_epoch_retired", "original_owner_epoch_required");

    private static RunMutationResult RunFailure(ArcError error) => new(null, null, error);

    private sealed record RunMutationResult(Run? Run, Operation? Operation, ArcError? Error = null);

    private sealed class LiveRun(RunLaunchSpec spec, IRunLauncher launcher, SandboxPrivateRootLease root, byte[] startCommand,
        CancellationToken cancellationToken)
    {
        internal RunLaunchSpec Spec { get; } = spec;
        internal IRunLauncher Launcher { get; } = launcher;
        internal SandboxPrivateRootLease Root { get; } = root;
        internal byte[] StartCommand { get; } = startCommand;
        internal CancellationToken CancellationToken { get; } = cancellationToken;
        internal TaskCompletionSource<TimeSpan> StopRequest { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal byte[]? StopCommand { get; set; }
    }
}
