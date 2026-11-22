// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Core.Sandboxes;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;
using V1 = ArcForges.Contracts.Node.V1;
using V2 = ArcForges.Contracts.Sandbox.V2;

namespace ArcForges.Node.Core.Updates;

/// <summary>Coordinates the local store, immutable installations, and normal native Node service owner.</summary>
internal static class NativeUpdateOperation
{
    private const string SupervisorProtocol = "arcforges-run-owner-rebind-v1";
    private const int ProtocolProbeLimit = 4096;
    private static readonly TimeSpan RpcDeadline = TimeSpan.FromSeconds(8);

    internal static async Task<NodeUpdateResponse> RunAsync(NodeUpdateRequest request, Func<string?> currentOwner, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Action == NodeUpdateAction.Compatibility)
            return new(new()
            {
                ["schemaReader"] = StoreMigrations.SupportedSchemaVersion,
                ["runtimeSchema"] = StoreMigrations.ContractedSchemaVersion,
                ["supervisorProtocol"] = SupervisorProtocol,
                ["nativeUpdateProtocol"] = 1,
            });

        string dataRoot = NodeLocations.ResolveDataRoot(request.TestMode);
        string appRoot = NodeLocations.UpdateApplicationRoot(request.TestMode);
        try
        {
            if (request.Action == NodeUpdateAction.Status)
                return new(Report(NativeUpdateGate.Read(dataRoot), NodeVersionSelection.Read(appRoot)));

            using var operation = NativeUpdateGate.EnterOperator(dataRoot);
            var state = NativeUpdateGate.Read(dataRoot);
            if (request.Action == NodeUpdateAction.Apply)
            {
                if (state?.IsFenced == true)
                    throw Refused("native_update_operation_exists_use_resume_or_rollback");
                var candidate = request.Candidate ?? throw Refused("native_update_candidate_required");
                var priorSelection = NodeVersionSelection.Read(appRoot);
                var previous = request.Previous ?? PreviouslySelected(state, priorSelection);
                VerifyCohort(appRoot, candidate, cancellationToken);
                VerifyCohort(appRoot, previous, cancellationToken);
                if ((priorSelection is not null && priorSelection != previous.ArchiveSha256) || previous.ArchiveSha256 == candidate.ArchiveSha256)
                    throw Refused("native_update_previous_selection_mismatch");

                var proposed = await ProbeCompatibilityAsync(candidate, request.TestMode, cancellationToken).ConfigureAwait(false)
                    ?? throw Refused("native_update_candidate_protocol_unconfirmed");
                var prior = await ProbeCompatibilityAsync(previous, request.TestMode, cancellationToken).ConfigureAwait(false);
                await using var session = await NodeClient.WaitForReadyAsync(new NodeConnectOptions
                    { TestMode = request.TestMode, AutoStart = false, ReadinessTimeout = RpcDeadline }, cancellationToken).ConfigureAwait(false);
                using var process = NodeUpdateLauncher.ReadBoundProcess(session, previous, expectedPid: null, allowVerifiedCopy: priorSelection is null);
                if (priorSelection is not null)
                    await NodeUpdateLauncher.RequireManagedProcessAsync(previous, process, started: null, request.TestMode, cancellationToken)
                        .ConfigureAwait(false);
                var owner = await ReadAuthorityAsync(session, cancellationToken).ConfigureAwait(false);
                var floor = NodeStore.InspectNativeUpdateFloor(dataRoot, onlineObservation: true);
                NativeUpdateGate.RequireCompatibleReader(floor.Schema, floor.MinimumReader, proposed.SchemaReader);
                if (proposed.RuntimeSchema != floor.Schema)
                    throw Refused("native_update_store_requires_prepared_offline_migration");

                var authority = new NativeUpdateAuthority(owner.NodeId, owner.OwnerEpoch, priorSelection, floor.Schema, floor.MinimumReader,
                    prior?.SupervisorProtocol);
                if (prior is null)
                {
                    var legacy = await FenceLegacyPredecessorAsync(session, process, state, authority, previous, candidate, dataRoot,
                        appRoot, request.TestMode, cancellationToken).ConfigureAwait(false);
                    if (legacy.Refusal is { } refusal)
                        return refusal;
                    state = legacy.State;
                }
                else
                {
                    await ConfirmRunDrainAsync(session, cancellationToken).ConfigureAwait(false);
                    state = NativeUpdateGate.Begin(dataRoot, Guid.NewGuid(), Cohort(previous), Cohort(candidate), authority);
                }
            }

            if (state?.Authority is not { } recorded)
                throw Refused("native_update_operation_missing_or_unverified");
            if (request.Action == NodeUpdateAction.Restore)
                return Restore(state, request, dataRoot, appRoot);

            if (state.Phase == NativeUpdatePhase.RestoringPredecessor ||
                request.Action == NodeUpdateAction.Rollback && CanRestoreLegacyPredecessor(state, recorded, appRoot))
            {
                var restored = await RestoreLegacyPredecessorAsync(state, recorded, Installation(state.Previous),
                    Installation(state.Candidate), dataRoot, appRoot, request.TestMode, cancellationToken).ConfigureAwait(false);
                return new(Report(restored, NodeVersionSelection.Read(appRoot)));
            }

            if (request.Action == NodeUpdateAction.Rollback && state.Phase != NativeUpdatePhase.RolledBack)
            {
                if (recorded.PreviousSupervisorProtocol is null && recorded.PreviousSelection != state.Previous.ArchiveSha256)
                    throw Refused("native_update_predecessor_managed_custody_unconfirmed_use_verified_restore");
                if (state.Phase == NativeUpdatePhase.Completed)
                {
                    if (NodeVersionSelection.Read(appRoot) != state.Candidate.ArchiveSha256)
                        throw Refused("native_update_selection_changed");
                    RequirePreviousFloor(dataRoot, recorded, online: true, verifyAuthority: true);
                    await ConfirmCurrentDrainBeforeRollbackAsync(Installation(state.Candidate), recorded, dataRoot, request.TestMode, cancellationToken)
                        .ConfigureAwait(false);
                }
                state = NativeUpdateGate.BeginRollback(dataRoot, state.OperationId);
            }

            if (state.IsFenced)
            {
                var previous = Installation(state.Previous);
                var candidate = Installation(state.Candidate);
                VerifyCohort(appRoot, previous, cancellationToken);
                VerifyCohort(appRoot, candidate, cancellationToken);
                if (state.Phase == NativeUpdatePhase.RollingBack)
                    state = recorded.PreviousSupervisorProtocol is null
                        ? await RestoreLegacyPredecessorAsync(state, recorded, previous, candidate, dataRoot, appRoot,
                            request.TestMode, cancellationToken).ConfigureAwait(false)
                        : await RollbackAsync(state, recorded, previous, candidate, dataRoot, appRoot, request.TestMode, cancellationToken)
                            .ConfigureAwait(false);
                else
                {
                    try
                    {
                        state = await ActivateAsync(state, recorded, previous, candidate, dataRoot, appRoot, request.TestMode, currentOwner, cancellationToken)
                            .ConfigureAwait(false);
                    }
                    catch (Exception activation) when (IsOperatorFailure(activation))
                    {
                        var current = NativeUpdateGate.Read(dataRoot);
                        if (current?.OperationId != state.OperationId || !current.IsFenced)
                            throw;
                        bool restoreLegacy = CanRestoreLegacyPredecessor(current, recorded, appRoot);
                        if (!restoreLegacy && (current.Checkpoint is null || recorded.PreviousSupervisorProtocol is null))
                            throw;

                        using var recover = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                        recover.CancelAfter(TimeSpan.FromSeconds(90));
                        try
                        {
                            var rollback = restoreLegacy
                                ? await RestoreLegacyPredecessorAsync(current, recorded, previous, candidate, dataRoot, appRoot,
                                    request.TestMode, recover.Token).ConfigureAwait(false)
                                : await RollbackAsync(NativeUpdateGate.BeginRollback(dataRoot, state.OperationId), recorded,
                                    previous, candidate, dataRoot, appRoot, request.TestMode, recover.Token).ConfigureAwait(false);
                            return new(Report(rollback, NodeVersionSelection.Read(appRoot)), Reason(activation));
                        }
                        catch (Exception failure) when (IsOperatorFailure(failure) ||
                            failure is OperationCanceledException && !cancellationToken.IsCancellationRequested)
                        {
                            throw Refused($"{Reason(activation)}; native_update_recovery_requires_resume: {Reason(failure)}");
                        }
                    }
                }
            }

            return new(Report(state, NodeVersionSelection.Read(appRoot)));
        }
        catch (Exception error) when (IsOperatorFailure(error))
        {
            return new(ObserveRefusal(dataRoot, appRoot), Reason(error));
        }
    }

    private static bool CanRestoreLegacyPredecessor(NativeUpdateState state, NativeUpdateAuthority authority, string appRoot)
    {
        if (authority.PreviousSupervisorProtocol is not null || authority.PreviousSelection != state.Previous.ArchiveSha256)
            return false;
        var selected = NodeVersionSelection.Read(appRoot);
        return state.Phase switch
        {
            NativeUpdatePhase.Fenced or NativeUpdatePhase.Prepared => selected == authority.PreviousSelection,
            NativeUpdatePhase.RollingBack => selected == state.Candidate.ArchiveSha256,
            NativeUpdatePhase.CandidateReady or NativeUpdatePhase.RestoringPredecessor =>
                selected == authority.PreviousSelection || selected == state.Candidate.ArchiveSha256,
            _ => false,
        };
    }

    private static async Task<NativeUpdateState> RestoreLegacyPredecessorAsync(NativeUpdateState state, NativeUpdateAuthority authority,
        NodeUpdateInstallation previous, NodeUpdateInstallation candidate, string dataRoot, string appRoot, bool testMode, CancellationToken ct)
    {
        if (!CanRestoreLegacyPredecessor(state, authority, appRoot))
            throw Refused("native_update_legacy_predecessor_unconfirmed");

        VerifyCohort(appRoot, previous, ct);
        var selected = NodeVersionSelection.Read(appRoot);
        if (selected == candidate.ArchiveSha256)
        {
            VerifyCohort(appRoot, candidate, ct);
            await StopAfterDrainAsync(previous, candidate, authority, testMode, permitCandidate: true,
                allowPreviousCopy: false, ct).ConfigureAwait(false);
        }
        if (selected == candidate.ArchiveSha256 || state.Phase != NativeUpdatePhase.RestoringPredecessor)
        {
            // The candidate is fenced. Prove the old reader and drain before restoring original selection.
            using var offline = AcquireOffline(testMode, dataRoot);
            if (NodeVersionSelection.Read(appRoot) != selected)
                throw Refused("native_update_selection_changed");
            RequirePreviousFloor(dataRoot, authority, online: false, requireDrain: true, verifyAuthority: true);
            state = NativeUpdateGate.BeginPreviousOwnerRestore(dataRoot, state.OperationId);
            if (selected == candidate.ArchiveSha256)
                NodeVersionSelection.Select(appRoot, selected, previous.ArchiveSha256);
        }
        else
        {
            // The prior owner may already be running after interruption. A stopped owner must still pass the offline check.
            await using var existing = await TryConnectAsync(testMode, ct).ConfigureAwait(false);
            if (existing is null)
            {
                using var offline = AcquireOffline(testMode, dataRoot);
                RequirePreviousFloor(dataRoot, authority, online: false, verifyAuthority: true);
            }
        }

        var proof = await StartAndCheckManagedAsync(previous, state, testMode, ct).ConfigureAwait(false);
        if (NodeVersionSelection.Read(appRoot) != previous.ArchiveSha256)
            throw Refused("native_update_selection_changed");
        RequirePreviousFloor(dataRoot, authority, online: true);
        NodeUpdateLauncher.RebindWindowsStartup(candidate, previous, testMode);
        return NativeUpdateGate.MarkRolledBack(dataRoot, state.OperationId, proof);
    }

    private static async Task<(NativeUpdateState? State, NodeUpdateResponse? Refusal)> FenceLegacyPredecessorAsync(
        NodeSession session, Process process, NativeUpdateState? before, NativeUpdateAuthority authority,
        NodeUpdateInstallation previous, NodeUpdateInstallation candidate, string dataRoot, string appRoot, bool testMode,
        CancellationToken ct)
    {
        try
        {
            // Ask the authenticated V2 control plane to prove native drain while the original owner can still stop Runs.
            await ConfirmRunDrainAsync(session, ct).ConfigureAwait(false);
        }
        catch (Exception failure) when (IsOperatorFailure(failure))
        {
            var refused = Report(before, authority.PreviousSelection);
            if (!process.HasExited)
                refused["predecessorProcessId"] = process.Id;
            return (null, new(refused, Reason(failure), EffectCertainty.DidNotHappen));
        }

        await NodeUpdateLauncher.StopBoundAsync(session, process, ct).ConfigureAwait(false);
        using (AcquireOffline(testMode, dataRoot))
        {
            RequireUnchangedPredecessor(dataRoot, appRoot, before, authority.PreviousSelection);
            if (LegacyPredecessorIsDrained(dataRoot, authority))
                return (NativeUpdateGate.Begin(dataRoot, Guid.NewGuid(), Cohort(previous), Cohort(candidate), authority), null);
        }

        // The old binary could admit a Start before it exited. Keep that Run drainable under the unchanged original owner.
        var report = Report(before, authority.PreviousSelection);
        if (authority.PreviousSelection != previous.ArchiveSha256)
        {
            report["predecessorRecovery"] = "start_original_custody_to_drain";
            return (null, new(report, "native_update_supervisor_drain_required"));
        }

        VerifyCohort(appRoot, previous, ct);
        RequireUnchangedPredecessor(dataRoot, appRoot, before, authority.PreviousSelection);
        await using var existing = await TryConnectAsync(testMode, ct).ConfigureAwait(false);
        var started = existing is null ? NodeUpdateLauncher.StartManagedService(testMode) : null;
        if (started is { Outcome: not AutoStartOutcome.Started })
            throw Refused("native_update_supervisor_drain_required; native_update_predecessor_restart_unconfirmed");

        await using var recovered = await NodeUpdateLauncher.WaitForBoundReadyAsync(previous, testMode, expectedPid: null, ct).ConfigureAwait(false);
        using var recoveredProcess = NodeUpdateLauncher.ReadBoundProcess(recovered, previous, expectedPid: null, allowVerifiedCopy: false);
        await NodeUpdateLauncher.RequireManagedProcessAsync(previous, recoveredProcess, started, testMode, ct).ConfigureAwait(false);
        var live = await ReadAuthorityAsync(recovered, ct).ConfigureAwait(false);
        if (live.NodeId != authority.NodeId || live.OwnerEpoch != authority.OwnerEpoch)
            throw Refused("native_update_predecessor_restart_owner_changed");
        RequireUnchangedPredecessor(dataRoot, appRoot, before, authority.PreviousSelection);
        report["predecessorRecovery"] = "verified_original_owner_ready_to_drain";
        report["predecessorProcessId"] = recoveredProcess.Id;
        return (null, new(report, "native_update_supervisor_drain_required"));
    }

    private static bool LegacyPredecessorIsDrained(string dataRoot, NativeUpdateAuthority authority)
    {
        try
        {
            RequirePreviousFloor(dataRoot, authority, online: false, requireDrain: true, verifyAuthority: true);
            return true;
        }
        catch (StoreIncompatibleException failure) when (failure.Message == "native_update_supervisor_drain_required")
        {
            // The drain predicate failed before the authority query. Verify identity without requiring a stopped Run.
            RequirePreviousFloor(dataRoot, authority, online: false, verifyAuthority: true);
            return false;
        }
    }

    private static void RequireUnchangedPredecessor(string dataRoot, string appRoot, NativeUpdateState? expected, string? expectedSelection)
    {
        if (!NativeUpdateGate.IsUnchangedUnfenced(dataRoot, expected) || NodeVersionSelection.Read(appRoot) != expectedSelection)
            throw Refused("native_update_predecessor_custody_changed");
    }

    private static NodeUpdateResponse Restore(NativeUpdateState state, NodeUpdateRequest request, string dataRoot, string appRoot)
    {
        var checkpoint = state.Checkpoint ?? throw Refused("native_update_verified_backup_required");
        string backup = checkpoint.BackupRoot ?? throw Refused("native_update_verified_backup_required");
        string destinationArgument = request.RestoreDestination ?? throw Refused("native_update_restore_destination_required");
        if (!Path.IsPathFullyQualified(destinationArgument))
            throw Refused("native_update_restore_destination_absolute_required");
        string destination = Path.TrimEndingDirectorySeparator(Path.GetFullPath(destinationArgument));
        string? selected = NodeVersionSelection.Read(appRoot);
        using var offline = AcquireOffline(request.TestMode, dataRoot);
        var floor = NodeStore.InspectNativeUpdateFloor(dataRoot, requireDrained: true);
        if (checkpoint.StoreSchema != floor.Schema || checkpoint.MinimumReader != floor.MinimumReader)
            throw Refused("native_update_restore_current_floor_incompatible");

        DurableCommandStore.VerifyNativeUpdateBackup(checkpoint, request.TestMode);
        DurableCommandStore.RestoreBackup(backup, NodeSecretStores.ForNode(backup, request.TestMode), dataRoot,
            NodeSecretStores.ForNode(dataRoot, request.TestMode), destination, NodeSecretStores.ForNode(destination, request.TestMode),
            verifyNativeOffline: true);
        if (NodeStore.InspectNativeUpdateFloor(destination) != floor)
            throw Refused("native_update_restored_store_floor_unconfirmed");

        var report = Report(state, selected);
        report["restoredDataRoot"] = destination;
        report["restoreStatus"] = "verified_detached_store";
        report["restoreIncludes"] = "store_database_owner_epoch_and_command_authority";
        report["activationRequires"] = "retire_original_runtime_custody_and_reconcile_private_workspace_data";
        return new(report);
    }

    private static JsonObject ObserveRefusal(string dataRoot, string appRoot)
    {
        try { return Report(NativeUpdateGate.Read(dataRoot), NodeVersionSelection.Read(appRoot)); }
        catch (Exception failure) when (IsOperatorFailure(failure)) { return new() { ["phase"] = "Unconfirmed" }; }
    }

    private static bool IsOperatorFailure(Exception error) => error is IOException or UnauthorizedAccessException or StoreIncompatibleException
        or DurableStoreMaintenanceException or SqliteException or NodeUnavailableException or Win32Exception or JsonException
        or CryptographicException or Grpc.Core.RpcException;

    private static string Reason(Exception error) => error is SqliteException or CryptographicException or DurableStoreMaintenanceException
        ? "native_update_store_or_owner_authority_unconfirmed" : error.Message;

    private static async Task<NativeUpdateState> ActivateAsync(NativeUpdateState state, NativeUpdateAuthority authority,
        NodeUpdateInstallation previous, NodeUpdateInstallation candidate, string dataRoot, string appRoot, bool testMode,
        Func<string?> currentOwner, CancellationToken ct)
    {
        if (state.Phase == NativeUpdatePhase.Fenced)
        {
            var proposed = await ProbeCompatibilityAsync(candidate, testMode, ct).ConfigureAwait(false)
                ?? throw Refused("native_update_candidate_protocol_unconfirmed");
            if (proposed.RuntimeSchema != authority.PreviousSchema)
                throw Refused("native_update_store_requires_prepared_offline_migration");

            await StopAfterDrainAsync(previous, candidate, authority, testMode, permitCandidate: false, authority.PreviousSelection is null, ct)
                .ConfigureAwait(false);
            using var offline = AcquireOffline(testMode, dataRoot);
            var owner = currentOwner() ?? throw Refused("native_update_local_owner_unconfirmed");
            var checkpoint = NodeStore.CaptureNativeUpdateBackup(dataRoot, owner, BootIdentity.Read(), authority, state.OperationId,
                proposed.SchemaReader, testMode, proposed.SupervisorProtocol);
            state = NativeUpdateGate.Prepare(dataRoot, state.OperationId, checkpoint);
        }

        DurableCommandStore.VerifyNativeUpdateBackup(state.Checkpoint!, testMode);
        string? selected = NodeVersionSelection.Read(appRoot);
        if (selected != authority.PreviousSelection && selected != candidate.ArchiveSha256)
            throw Refused("native_update_selection_changed");
        if (selected != candidate.ArchiveSha256)
        {
            await StopAfterDrainAsync(previous, candidate, authority, testMode, permitCandidate: true, authority.PreviousSelection is null, ct)
                .ConfigureAwait(false);
            using (AcquireOffline(testMode, dataRoot))
                RequirePreviousFloor(dataRoot, authority, online: false, requireDrain: true, verifyAuthority: true);

            using var probe = NodeUpdateLauncher.StartCandidate(candidate, testMode);
            try
            {
                await using var session = await NodeUpdateLauncher.WaitForBoundReadyAsync(candidate, testMode, probe.Id, ct).ConfigureAwait(false);
                var proof = await RequireReadyAsync(session, state, candidate, probe, ct).ConfigureAwait(false);
                RequireActivationFloor(dataRoot, state.Checkpoint!, authority);
                state = NativeUpdateGate.MarkReady(dataRoot, state.OperationId, proof);
                await NodeUpdateLauncher.StopBoundAsync(session, probe, ct).ConfigureAwait(false);
            }
            finally
            {
                await TerminateOwnedProbeAsync(probe).ConfigureAwait(false);
            }

            NodeVersionSelection.Select(appRoot, selected, candidate.ArchiveSha256);
        }
        else if (state.Phase != NativeUpdatePhase.CandidateReady)
        {
            throw Refused("native_update_selection_without_health_checkpoint");
        }

        var ready = await StartAndCheckManagedAsync(candidate, state, testMode, ct).ConfigureAwait(false);
        RequireActivationFloor(dataRoot, state.Checkpoint!, authority);
        NodeUpdateLauncher.RebindWindowsStartup(previous, candidate, testMode);
        return NativeUpdateGate.Complete(dataRoot, state.OperationId, ready);
    }

    private static async Task TerminateOwnedProbeAsync(Process probe)
    {
        if (probe.HasExited)
            return;

        try { probe.Kill(entireProcessTree: false); }
        catch (InvalidOperationException) when (probe.HasExited) { }
        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try { await probe.WaitForExitAsync(cleanup.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw Refused("native_update_probe_cleanup_unconfirmed"); }
    }

    private static async Task<NativeUpdateState> RollbackAsync(NativeUpdateState state, NativeUpdateAuthority authority,
        NodeUpdateInstallation previous, NodeUpdateInstallation candidate, string dataRoot, string appRoot, bool testMode, CancellationToken ct)
    {
        string? selected = NodeVersionSelection.Read(appRoot);
        if (selected != authority.PreviousSelection && selected != previous.ArchiveSha256 && selected != candidate.ArchiveSha256)
            throw Refused("native_update_selection_changed");

        if (selected == candidate.ArchiveSha256)
            RequirePreviousFloor(dataRoot, authority, online: true);

        await StopAfterDrainAsync(previous, candidate, authority, testMode, permitCandidate: true, authority.PreviousSelection is null, ct)
            .ConfigureAwait(false);
        using (AcquireOffline(testMode, dataRoot))
        {
            RequirePreviousFloor(dataRoot, authority, online: false, requireDrain: true, verifyAuthority: true);
            if (selected != previous.ArchiveSha256)
                NodeVersionSelection.Select(appRoot, selected, previous.ArchiveSha256);
        }

        var ready = await StartAndCheckManagedAsync(previous, state, testMode, ct).ConfigureAwait(false);
        RequirePreviousFloor(dataRoot, authority, online: true, requireDrain: true, verifyAuthority: true);
        NodeUpdateLauncher.RebindWindowsStartup(candidate, previous, testMode);
        return NativeUpdateGate.MarkRolledBack(dataRoot, state.OperationId, ready);
    }

    private static void RequireActivationFloor(string dataRoot, NativeUpdateCheckpoint checkpoint, NativeUpdateAuthority authority)
    {
        var floor = NodeStore.InspectNativeUpdateFloor(dataRoot, onlineObservation: true, requireDrained: true, previousAuthority: authority);
        if (floor.Schema != checkpoint.StoreSchema || floor.MinimumReader < checkpoint.MinimumReader)
            throw Refused("native_update_observed_store_floor_mismatch");
        NativeUpdateGate.RequireCompatibleReader(floor.Schema, floor.MinimumReader, checkpoint.CandidateReader);
    }

    private static void RequirePreviousFloor(string dataRoot, NativeUpdateAuthority authority, bool online, bool requireDrain = false,
        bool verifyAuthority = false)
    {
        // The authenticated predecessor served this exact floor. A changed floor needs the separate verified restore flow.
        var floor = NodeStore.InspectNativeUpdateFloor(dataRoot, onlineObservation: online, requireDrained: requireDrain,
            previousAuthority: verifyAuthority ? authority : null);
        if (floor.Schema != authority.PreviousSchema || floor.MinimumReader != authority.PreviousMinimumReader)
            throw Refused("native_update_rollback_store_incompatible_restore_requires_latest_owner_history");
    }

    private static async Task<NativeUpdateReadiness> StartAndCheckManagedAsync(NodeUpdateInstallation cohort, NativeUpdateState state, bool testMode, CancellationToken ct)
    {
        var existing = await TryConnectAsync(testMode, ct).ConfigureAwait(false);
        await using var disposeExisting = existing;
        var started = existing is null ? NodeUpdateLauncher.StartManagedService(testMode) : null;
        if (started is { Outcome: not AutoStartOutcome.Started })
            throw Refused("native_update_managed_service_start_failed: " + started.Detail);
        await using var session = await NodeUpdateLauncher.WaitForBoundReadyAsync(cohort, testMode, expectedPid: null, ct).ConfigureAwait(false);
        using var process = NodeUpdateLauncher.ReadBoundProcess(session, cohort, expectedPid: null, allowVerifiedCopy: false);
        await NodeUpdateLauncher.RequireManagedProcessAsync(cohort, process, started, testMode, ct).ConfigureAwait(false);
        return await RequireReadyAsync(session, state, cohort, process, ct).ConfigureAwait(false);
    }

    private static async Task ConfirmCurrentDrainBeforeRollbackAsync(NodeUpdateInstallation current, NativeUpdateAuthority authority,
        string dataRoot, bool testMode, CancellationToken ct)
    {
        await using var session = await TryConnectAsync(testMode, ct).ConfigureAwait(false);
        if (session is null)
        {
            using var offline = AcquireOffline(testMode, dataRoot);
            RequirePreviousFloor(dataRoot, authority, online: false, requireDrain: true, verifyAuthority: true);
            return;
        }

        using var process = NodeUpdateLauncher.ReadBoundProcess(session, current, expectedPid: null, allowVerifiedCopy: false);
        var live = await ReadAuthorityAsync(session, ct).ConfigureAwait(false);
        if (authority.NodeId != live.NodeId || authority.OwnerEpoch != live.OwnerEpoch)
            throw Refused("native_update_rollback_owner_changed");
        await ConfirmRunDrainAsync(session, ct).ConfigureAwait(false);
    }

    private static async Task ConfirmRunDrainAsync(NodeSession session, CancellationToken ct)
    {
        using var pin = NodeUpdateLauncher.PinBoundSession(session);
        var sandboxes = new V2.SandboxService.SandboxServiceClient(session.Channel.CallInvoker);
        var runs = new V2.RunService.RunServiceClient(session.Channel.CallInvoker);
        DateTime deadline = DateTime.UtcNow.AddSeconds(30);
        string cursor = "";
        do
        {
            using var call = sandboxes.ListAsync(new V2.SandboxServiceListRequest { Meta = Meta(), Limit = 200, Cursor = cursor },
                deadline: deadline, cancellationToken: ct);
            var view = (await call.ResponseAsync.ConfigureAwait(false)).Value
                ?? throw Refused("native_update_predecessor_drain_unconfirmed");
            foreach (var sandbox in view.Sandboxes)
            {
                if (sandbox.ActiveRunIds.Count != 0)
                    throw Refused("native_update_supervisor_drain_required");

                string runCursor = "";
                do
                {
                    using var check = runs.ListAsync(new V2.RunServiceListRequest { Meta = Meta(), SandboxId = sandbox.SandboxId,
                        Limit = 200, Cursor = runCursor }, deadline: deadline, cancellationToken: ct);
                    var page = (await check.ResponseAsync.ConfigureAwait(false)).Value
                        ?? throw Refused("native_update_predecessor_drain_unconfirmed");
                    if (page.Runs.Any(run => run is not { State: V2.RunState.Exited or V2.RunState.Failed, Exit.GroupEmptyVerified: true }))
                        throw Refused("native_update_supervisor_drain_required");

                    runCursor = page.Page?.NextCursor ?? throw Refused("native_update_predecessor_drain_unconfirmed");
                } while (runCursor.Length != 0);
            }

            cursor = view.Page?.NextCursor ?? throw Refused("native_update_predecessor_drain_unconfirmed");
        } while (cursor.Length != 0);
    }

    private static async Task StopAfterDrainAsync(NodeUpdateInstallation previous, NodeUpdateInstallation candidate,
        NativeUpdateAuthority authority, bool testMode, bool permitCandidate, bool allowPreviousCopy, CancellationToken ct)
    {
        await using var session = await TryConnectAsync(testMode, ct).ConfigureAwait(false);
        if (session is null)
            return;

        Process process;
        try
        {
            process = NodeUpdateLauncher.ReadBoundProcess(session, previous, expectedPid: null, allowVerifiedCopy: allowPreviousCopy);
        }
        catch (IOException failure) when (permitCandidate && failure.Message == "node_update_running_cohort_mismatch")
        {
            process = NodeUpdateLauncher.ReadBoundProcess(session, candidate, expectedPid: null, allowVerifiedCopy: false);
        }

        using (process)
        {
            var live = await ReadAuthorityAsync(session, ct).ConfigureAwait(false);
            if (live.NodeId != authority.NodeId || live.OwnerEpoch != authority.OwnerEpoch)
                throw Refused("native_update_shutdown_owner_changed");
            await ConfirmRunDrainAsync(session, ct).ConfigureAwait(false);
            await NodeUpdateLauncher.StopBoundAsync(session, process, ct).ConfigureAwait(false);
        }
    }

    private static async Task<NodeSession?> TryConnectAsync(bool testMode, CancellationToken ct)
    {
        try
        {
            return await NodeClient.ConnectAsync(new NodeConnectOptions { TestMode = testMode, AutoStart = false, ReadinessTimeout = RpcDeadline }, ct)
                .ConfigureAwait(false);
        }
        catch (NodeUnavailableException failure) when (failure.Reason == NodeUnavailableReason.NotRunning)
        {
            return null;
        }
    }

    private static async Task<(string NodeId, string OwnerEpoch, string NodeEpoch, bool DefaultProfileAdmitted)> ReadAuthorityAsync(NodeSession session, CancellationToken ct)
    {
        using var pin = NodeUpdateLauncher.PinBoundSession(session);
        var node = new V2.NodeService.NodeServiceClient(session.Channel.CallInvoker);
        using var call = node.HandshakeAsync(new V2.NodeServiceHandshakeRequest { Meta = Meta() },
            deadline: DateTime.UtcNow + RpcDeadline, cancellationToken: ct);
        var value = (await call.ResponseAsync.ConfigureAwait(false)).Value;
        if (value?.OwnerEpoch?.Value.Length != 16 || value.ContractVersion != "2.0" || string.IsNullOrEmpty(value.NodeEpoch)
            || session.Hello.Node.Node.NodeId.Value.Length != 16)
            throw Refused("native_update_v2_owner_or_protocol_unconfirmed");
        bool admitted = value.Capabilities.Any(capability => capability.Key == SandboxRunReadiness.ProfileKey &&
            capability.State == V2.CapabilityState.Available && !string.IsNullOrEmpty(capability.EvidenceId));
        return (Convert.ToHexStringLower(session.Hello.Node.Node.NodeId.Value.Span),
            Convert.ToHexStringLower(value.OwnerEpoch.Value.Span), value.NodeEpoch, admitted);
    }

    private static async Task<NativeUpdateReadiness> RequireReadyAsync(NodeSession session, NativeUpdateState state,
        NodeUpdateInstallation cohort, Process process, CancellationToken ct)
    {
        var owner = await ReadAuthorityAsync(session, ct).ConfigureAwait(false);
        if (owner.NodeId != state.Authority!.NodeId || owner.OwnerEpoch != state.Authority.OwnerEpoch)
            throw Refused("native_update_owner_epoch_changed");

        using var pin = NodeUpdateLauncher.PinBoundSession(session);
        using var healthCall = session.Channel.Node.GetHealthAsync(new V1.NodeServiceGetHealthRequest { Meta = Meta() },
            deadline: DateTime.UtcNow + RpcDeadline, cancellationToken: ct);
        var health = (await healthCall.ResponseAsync.ConfigureAwait(false)).Value;
        if (health is not { State: V1.NodeLifecycleState.Ready } ||
            !health.Checks.Any(check => check.CheckId == "node.store" && check.Status == V1.CheckStatus.Pass))
            throw Refused("native_update_node_store_health_unconfirmed");
        if (!owner.DefaultProfileAdmitted ||
            !health.Checks.Any(check => check.CheckId == "node.v2_run_profile" && check.Status == V1.CheckStatus.Pass))
            throw Refused("native_update_default_mxc_profile_unconfirmed");

        if (process.HasExited)
            throw Refused("native_update_ready_process_exited");
        return new(cohort.ArchiveSha256, owner.NodeEpoch, process.Id,
            new DateTimeOffset(process.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds());
    }

    private static SingleInstance AcquireOffline(bool testMode, string dataRoot)
    {
        var authority = OperatingSystem.IsLinux() ? LinuxSandboxDeletionAuthority.OpenIfProvisioned(dataRoot) : null;
        var instance = authority is not null && OperatingSystem.IsLinux()
            ? SingleInstance.TryAcquire(authority)
            : SingleInstance.TryAcquire(NodeLocations.InstanceKey(testMode), dataRoot);
        return instance ?? throw Refused("native_update_offline_node_owner_unconfirmed");
    }

    private static void VerifyCohort(string appRoot, NodeUpdateInstallation cohort, CancellationToken cancellationToken)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (!cohort.Root.Equals(NodeVersionSelection.InstallationDirectory(appRoot, cohort.ArchiveSha256), comparison))
            throw Refused("native_update_installation_identity_mismatch");
        ContractionPaths.RequireOwnedDirectory(cohort.Root);
        using var manifest = ContractionPaths.OpenRegularRead(Path.Combine(cohort.Root, VersionIntegrity.ManifestName));
        if (!Convert.ToHexStringLower(SHA256.HashData(manifest)).Equals(cohort.DigestManifestSha256, StringComparison.Ordinal)
            || VersionIntegrity.Check(cohort.Root, cancellationToken).Fact != VersionIntegrity.Verified)
            throw Refused("native_update_installation_integrity_unconfirmed");
    }

    private sealed record Compatibility(int SchemaReader, int RuntimeSchema, string SupervisorProtocol);

    private static async Task<Compatibility?> ProbeCompatibilityAsync(NodeUpdateInstallation cohort, bool testMode, CancellationToken ct)
    {
        var start = new ProcessStartInfo(NodeUpdateLauncher.Executable(cohort.Root))
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true,
            WorkingDirectory = cohort.Root,
        };
        foreach (string argument in new[] { "update", "compatibility", "--json" })
            start.ArgumentList.Add(argument);
        if (testMode)
            start.ArgumentList.Add(NodeLocations.TestModeOption);

        using var process = Process.Start(start) ?? throw Refused("native_update_compatibility_probe_unavailable");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(RpcDeadline);
        try
        {
            char[] buffer = new char[ProtocolProbeLimit + 1];
            int count = await process.StandardOutput.ReadBlockAsync(buffer, timeout.Token).ConfigureAwait(false);
            if (count > ProtocolProbeLimit)
                throw Refused("native_update_compatibility_probe_large");
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            if (process.ExitCode != 0)
                return null;

            using var document = JsonDocument.Parse(new string(buffer, 0, count));
            var value = document.RootElement;
            if (value.ValueKind != JsonValueKind.Object ||
                !TryInteger(value, "nativeUpdateProtocol", out int format) || format != 1 ||
                !value.TryGetProperty("supervisorProtocol", out var protocolValue) || protocolValue.ValueKind != JsonValueKind.String ||
                protocolValue.GetString() is not { Length: > 0 and <= 128 } protocol ||
                !TryInteger(value, "schemaReader", out int reader) || !TryInteger(value, "runtimeSchema", out int schema))
                throw Refused("native_update_compatibility_probe_invalid");
            return new(reader, schema, protocol);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw Refused("native_update_compatibility_probe_timeout");
        }
        finally
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: false);
        }
    }

    private static bool TryInteger(JsonElement value, string name, out int number)
    {
        number = 0;
        return value.TryGetProperty(name, out var field) && field.ValueKind == JsonValueKind.Number && field.TryGetInt32(out number);
    }

    private static NodeUpdateInstallation PreviouslySelected(NativeUpdateState? state, string? selected) =>
        selected is not null && state is not null && state.Candidate.ArchiveSha256 == selected ? Installation(state.Candidate)
        : selected is not null && state is not null && state.Previous.ArchiveSha256 == selected ? Installation(state.Previous)
        : throw Refused("native_update_verified_predecessor_required");

    private static NativeUpdateCohort Cohort(NodeUpdateInstallation value) =>
        new(value.Commit, value.Tree, value.ArchiveSha256, value.Root, value.DigestManifestSha256);

    private static NodeUpdateInstallation Installation(NativeUpdateCohort value) =>
        new(value.InstallationRoot, value.ArchiveSha256, value.Commit, value.Tree, value.DigestManifestSha256!);

    private static RequestMeta Meta() => new() { CorrelationId = CommandIds.New() };

    private static JsonObject Report(NativeUpdateState? state, string? selected) => new()
    {
        ["operationId"] = state?.OperationId.ToString("D"),
        ["phase"] = state?.Phase.ToString() ?? "Idle",
        ["admissionFenced"] = state?.IsFenced ?? false,
        ["restoringManagedPredecessor"] = state?.Phase == NativeUpdatePhase.RestoringPredecessor ? true : null,
        ["previousArchiveSha256"] = state?.Previous.ArchiveSha256,
        ["previousCommit"] = state?.Previous.Commit,
        ["previousTree"] = state?.Previous.Tree,
        ["candidateArchiveSha256"] = state?.Candidate.ArchiveSha256,
        ["candidateCommit"] = state?.Candidate.Commit,
        ["candidateTree"] = state?.Candidate.Tree,
        ["selectedArchiveSha256"] = selected,
        ["storeSchema"] = state?.Checkpoint?.StoreSchema ?? state?.Authority?.PreviousSchema,
        ["minimumReader"] = state?.Checkpoint?.MinimumReader ?? state?.Authority?.PreviousMinimumReader,
        ["backupRoot"] = state?.Checkpoint?.BackupRoot,
        ["backupManifestSha256"] = state?.Checkpoint?.BackupManifestSha256,
        ["drainConfirmed"] = state?.Checkpoint?.DrainConfirmed,
        ["supervisorProtocol"] = state?.Checkpoint?.CandidateSupervisorProtocol,
        ["candidateProbe"] = ReadinessReport(state?.CandidateProbe),
        ["activatedOwner"] = ReadinessReport(state?.ActivatedOwner),
        ["restoredOwner"] = ReadinessReport(state?.RestoredOwner),
        ["updatedAt"] = state?.UpdatedAt,
    };

    private static JsonObject? ReadinessReport(NativeUpdateReadiness? readiness) => readiness is null ? null : new()
    {
        ["archiveSha256"] = readiness.ArchiveSha256,
        ["nodeEpoch"] = readiness.NodeEpoch,
        ["processId"] = readiness.ProcessId,
        ["processStartUnixMs"] = readiness.ProcessStartUnixMs,
    };

    private static IOException Refused(string reason) => new(reason);
}
