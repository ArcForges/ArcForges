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
        try
        {
            var result = StartWithResourceBudget(request, secrets: null, cancellationToken);

            if (result.SecretReferences is { } references)
            {
                // A platform credential store can wait for its desktop keyring. Keep unrelated
                // Stop/inspect operations free, then recheck command identity and Sandbox revision.
                var secrets = new Dictionary<string, string>(StringComparer.Ordinal);
                try
                {
                    foreach (var reference in references)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        if (_runSecrets.Resolve(reference) is not { } value)
                        {
                            break;
                        }

                        secrets.Add(reference, value);
                    }

                    result = StartWithResourceBudget(request, secrets, cancellationToken);
                }
                finally
                {
                    secrets.Clear();
                }
            }

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

    private RunMutationResult StartWithResourceBudget(RunServiceStartRequest request,
        IReadOnlyDictionary<string, string>? secrets, CancellationToken cancellationToken)
    {
        var monitor = _resourceMonitor;
        lock (OwnershipGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = StartRunLocked(request, secrets, allowBudgetWait: monitor is not null);
            if (!result.AwaitingResourceBudget)
            {
                return result;
            }
        }

        // The sampler also uses OwnershipGate to capture its Run inventory. A new
        // scope needs two CPU counter observations before a complete budget exists.
        monitor!.WaitForBudget(cancellationToken);
        lock (OwnershipGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return StartRunLocked(request, secrets, allowBudgetWait: false);
        }
    }

    private RunMutationResult StartRunLocked(RunServiceStartRequest request, IReadOnlyDictionary<string, string>? secrets,
        bool allowBudgetWait)
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
        try
        {
            return AdmitStartRunLocked(request, expected.Value, command, epoch, sandboxId, previous, runId, canonical,
                secrets, allowBudgetWait);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    private RunMutationResult AdmitStartRunLocked(RunServiceStartRequest request, long expected, byte[] command,
        byte[] epoch, string sandboxId, DurableReceipt? previous, string runId, byte[] canonical,
        IReadOnlyDictionary<string, string>? secrets, bool allowBudgetWait)
    {
        var meta = request.Meta;
        var intent = new DurableIntent(command, epoch, StartRunMethod, RunAggregate, runId, canonical, expected,
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

        if (row.Revision != expected)
        {
            return RunFailure(RevisionError(meta, expected, row.Revision));
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

        SandboxPrivateRootLease? root = _roots.Inspect(sandboxId, row.RootIdentity);
        RunLaunchSpec? unowned = null;
        var controlKey = RandomNumberGenerator.GetBytes(RunWire.KeyLength);
        try
        {
            var launchDigest = Convert.ToHexStringLower(HMACSHA256.HashData(controlKey, canonical));
            var generation = Guid.NewGuid().ToString("N");
            var policy = PrepareRunPolicy(request, row, root, runId, generation, launchDigest, controlKey, secrets, out var references);
            if (references is not null)
            {
                return new(null, null, SecretReferences: references);
            }

            unowned = policy.Spec;
            if (unowned is not { } spec)
            {
                return RejectStart(policy.Error);
            }

            var budgetFrame = _resourceMonitor?.Latest;
            if (allowBudgetWait && budgetFrame is not { HasFreshBudget: true })
            {
                return new(null, null, AwaitingResourceBudget: true);
            }

            var authorization = AuthorizeRunResourceGrant(request, row, spec, budgetFrame);
            if (authorization.Spec is not { } granted)
            {
                return RejectStart(authorization.Error);
            }

            unowned = granted;
            var snapshot = RunSnapshotJson(granted, Convert.ToHexStringLower(command));
            var started = new StoredRun(runId, sandboxId, row.Revision, 1, StoredRunState.Starting, generation,
                launchDigest, snapshot, StoredPayloadStart.Unknown, _clock.GetUtcNow());
            var admitted = Receipts.Admit(intent, transaction =>
            {
                RequireChanged(RunRecords.InsertStarting(transaction, OwnerId, started));
                RecordRunResourceGrant(transaction, started, granted);
            });
            if (admitted.Decision == DurableDecision.Execute)
            {
                var live = new LiveRun(granted, launcher, root, command, _runObserverStop.Token);
                _liveRuns.Add(runId, live);
                root = null;
                unowned = null;
                _ = Task.Run(() => OwnRunAsync(live), CancellationToken.None);
            }

            return ResolveRunMutation(admitted, meta, request.OwnerEpoch);
        }
        finally
        {
            if (root is not null)
            {
                unowned?.ClearInputs();
                CryptographicOperations.ZeroMemory(controlKey);
            }

            root?.Dispose();
        }

        RunMutationResult RejectStart(ArcError? error)
        {
            if (error is not { Category: ErrorCategory.Resource, Code: "budget_unavailable", Effect: EffectCertainty.DidNotHappen })
            {
                return RunFailure(error ?? InvalidRun(meta));
            }

            var refused = Receipts.AdmitObserved(intent, "FAILED", (int)error.Effect,
                ResultBody(null, null, error.Category, error.Code, error.Details?.State?.Reason));
            return ResolveRunMutation(refused, meta, request.OwnerEpoch);
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
            return RunFailure(RevisionError(meta, expected.Value, run.Revision));
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
        var name = spec.ExecutablePath.Split('/', '\\').Last();
        name = string.Concat(name.EnumerateRunes().Where(rune => !System.Text.Rune.IsControl(rune)).Take(96));
        var snapshot = new JsonObject
        {
            ["profileId"] = spec.ProfileId,
            ["profileVersion"] = spec.ProfileVersion,
            ["terminalMode"] = (int)spec.TerminalMode,
            ["safeCommandDisplay"] = $"{name} [{spec.Argv.Length - 1} arguments redacted]",
            ["redactedEnvironmentEntries"] = spec.Environment.Length,
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

    private sealed record RunMutationResult(Run? Run, Operation? Operation, ArcError? Error = null,
        string[]? SecretReferences = null, bool AwaitingResourceBudget = false);

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
        internal IRunOwnerLease? OwnerLease { get; set; }
    }
}
