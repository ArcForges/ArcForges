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
using ArcForges.Node.Store;
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;
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
                var owner = await ReadAuthorityAsync(session, cancellationToken).ConfigureAwait(false);
                var floor = NodeStore.InspectNativeUpdateFloor(dataRoot, onlineObservation: true);
                NativeUpdateGate.RequireCompatibleReader(floor.Schema, floor.MinimumReader, proposed.SchemaReader);
                if (proposed.RuntimeSchema != floor.Schema)
                    throw Refused("native_update_store_requires_prepared_offline_migration");

                // A prior binary without this gate can serve until its verified process has completely exited.
                // Take the offline Node lease before publishing that predecessor's fence.
                var authority = new NativeUpdateAuthority(owner.NodeId, owner.OwnerEpoch, priorSelection, floor.Schema, floor.MinimumReader,
                    prior?.SupervisorProtocol);
                if (prior is null)
                {
                    await NodeUpdateLauncher.StopBoundAsync(session, process, cancellationToken).ConfigureAwait(false);
                    using var offline = AcquireOffline(request.TestMode, dataRoot);
                    state = NativeUpdateGate.Begin(dataRoot, Guid.NewGuid(), Cohort(previous), Cohort(candidate), authority);
                }
                else
                {
                    state = NativeUpdateGate.Begin(dataRoot, Guid.NewGuid(), Cohort(previous), Cohort(candidate), authority);
                }
            }

            if (state?.Authority is not { } recorded)
                throw Refused("native_update_operation_missing_or_unverified");
            if (request.Action == NodeUpdateAction.Rollback && state.Phase != NativeUpdatePhase.RolledBack)
                state = NativeUpdateGate.BeginRollback(dataRoot, state.OperationId);

            if (state.IsFenced)
            {
                var previous = Installation(state.Previous);
                var candidate = Installation(state.Candidate);
                VerifyCohort(appRoot, previous, cancellationToken);
                VerifyCohort(appRoot, candidate, cancellationToken);
                if (state.Phase == NativeUpdatePhase.RollingBack)
                    state = await RollbackAsync(state, recorded, previous, candidate, dataRoot, appRoot, request.TestMode, cancellationToken)
                        .ConfigureAwait(false);
                else
                    state = await ActivateAsync(state, recorded, previous, candidate, dataRoot, appRoot, request.TestMode, currentOwner, cancellationToken)
                        .ConfigureAwait(false);
            }

            return new(Report(state, NodeVersionSelection.Read(appRoot)));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or StoreIncompatibleException or DurableStoreMaintenanceException
            or SqliteException or NodeUnavailableException or Win32Exception or JsonException or CryptographicException or Grpc.Core.RpcException)
        {
            return new(new(), error is SqliteException or CryptographicException or DurableStoreMaintenanceException
                ? "native_update_store_or_owner_authority_unconfirmed" : error.Message);
        }
    }

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

            await StopObservedAsync(previous, candidate, testMode, permitCandidate: false, authority.PreviousSelection is null, ct).ConfigureAwait(false);
            using var offline = AcquireOffline(testMode, dataRoot);
            var owner = currentOwner() ?? throw Refused("native_update_local_owner_unconfirmed");
            var checkpoint = NodeStore.CaptureNativeUpdateBackup(dataRoot, owner, BootIdentity.Read(), authority, state.OperationId,
                proposed.SchemaReader, authority.PreviousSupervisorProtocol == proposed.SupervisorProtocol, testMode);
            state = NativeUpdateGate.Prepare(dataRoot, state.OperationId, checkpoint);
        }

        NodeStore.VerifyNativeUpdateBackup(state.Checkpoint!);
        string? selected = NodeVersionSelection.Read(appRoot);
        if (selected != authority.PreviousSelection && selected != candidate.ArchiveSha256)
            throw Refused("native_update_selection_changed");
        if (selected != candidate.ArchiveSha256)
        {
            await StopObservedAsync(previous, candidate, testMode, permitCandidate: true, authority.PreviousSelection is null, ct).ConfigureAwait(false);
            using var probe = NodeUpdateLauncher.StartCandidate(candidate, testMode);
            try
            {
                await using var session = await NodeUpdateLauncher.WaitForBoundReadyAsync(candidate, testMode, probe.Id, ct).ConfigureAwait(false);
                await RequireReadyAsync(session, state, ct).ConfigureAwait(false);
                state = NativeUpdateGate.MarkReady(dataRoot, state.OperationId);
                await NodeUpdateLauncher.StopBoundAsync(session, probe, ct).ConfigureAwait(false);
            }
            finally
            {
                if (!probe.HasExited)
                {
                    probe.Kill(entireProcessTree: false);
                    using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                    await probe.WaitForExitAsync(cleanup.Token).ConfigureAwait(false);
                }
            }

            NodeVersionSelection.Select(appRoot, selected, candidate.ArchiveSha256);
        }
        else if (state.Phase != NativeUpdatePhase.CandidateReady)
        {
            throw Refused("native_update_selection_without_health_checkpoint");
        }

        await StartAndCheckManagedAsync(candidate, state, testMode, ct).ConfigureAwait(false);
        NodeUpdateLauncher.RebindWindowsStartup(previous, candidate, testMode);
        return NativeUpdateGate.Complete(dataRoot, state.OperationId);
    }

    private static async Task<NativeUpdateState> RollbackAsync(NativeUpdateState state, NativeUpdateAuthority authority,
        NodeUpdateInstallation previous, NodeUpdateInstallation candidate, string dataRoot, string appRoot, bool testMode, CancellationToken ct)
    {
        string? selected = NodeVersionSelection.Read(appRoot);
        if (selected != authority.PreviousSelection && selected != previous.ArchiveSha256 && selected != candidate.ArchiveSha256)
            throw Refused("native_update_selection_changed");

        await StopObservedAsync(previous, candidate, testMode, permitCandidate: true, authority.PreviousSelection is null, ct).ConfigureAwait(false);
        using (AcquireOffline(testMode, dataRoot))
        {
            var floor = NodeStore.InspectNativeUpdateFloor(dataRoot);
            // The predecessor served this exact activation floor. If it changed, use the authenticated offline restore path.
            if (floor.Schema != authority.PreviousSchema || floor.MinimumReader != authority.PreviousMinimumReader)
                throw Refused("native_update_rollback_store_incompatible_restore_requires_latest_owner_history");
            if (selected != previous.ArchiveSha256)
                NodeVersionSelection.Select(appRoot, selected, previous.ArchiveSha256);
        }

        await StartAndCheckManagedAsync(previous, state, testMode, ct).ConfigureAwait(false);
        NodeUpdateLauncher.RebindWindowsStartup(candidate, previous, testMode);
        return NativeUpdateGate.MarkRolledBack(dataRoot, state.OperationId);
    }

    private static async Task StartAndCheckManagedAsync(NodeUpdateInstallation cohort, NativeUpdateState state, bool testMode, CancellationToken ct)
    {
        var existing = await TryConnectAsync(testMode, ct).ConfigureAwait(false);
        await using var disposeExisting = existing;
        var started = existing is null ? NodeUpdateLauncher.StartManagedService(testMode) : null;
        if (started is { Outcome: not AutoStartOutcome.Started })
            throw Refused("native_update_managed_service_start_failed: " + started.Detail);
        await using var session = await NodeUpdateLauncher.WaitForBoundReadyAsync(cohort, testMode, expectedPid: null, ct).ConfigureAwait(false);
        using var process = NodeUpdateLauncher.ReadBoundProcess(session, cohort, expectedPid: null, allowVerifiedCopy: false);
        await NodeUpdateLauncher.RequireManagedProcessAsync(cohort, process, started, testMode, ct).ConfigureAwait(false);
        await RequireReadyAsync(session, state, ct).ConfigureAwait(false);
    }

    private static async Task StopObservedAsync(NodeUpdateInstallation previous, NodeUpdateInstallation candidate, bool testMode,
        bool permitCandidate, bool allowPreviousCopy, CancellationToken ct)
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
            await NodeUpdateLauncher.StopBoundAsync(session, process, ct).ConfigureAwait(false);
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

    private static async Task<(string NodeId, string OwnerEpoch)> ReadAuthorityAsync(NodeSession session, CancellationToken ct)
    {
        using var pin = NodeUpdateLauncher.PinBoundSession(session);
        var node = new V2.NodeService.NodeServiceClient(session.Channel.CallInvoker);
        using var call = node.HandshakeAsync(new V2.NodeServiceHandshakeRequest { Meta = Meta() },
            deadline: DateTime.UtcNow + RpcDeadline, cancellationToken: ct);
        var value = (await call.ResponseAsync.ConfigureAwait(false)).Value;
        if (value?.OwnerEpoch?.Value.Length != 16 || value.ContractVersion != "2.0" || string.IsNullOrEmpty(value.NodeEpoch)
            || session.Hello.Node.Node.NodeId.Value.Length != 16)
            throw Refused("native_update_v2_owner_or_protocol_unconfirmed");
        return (Convert.ToHexStringLower(session.Hello.Node.Node.NodeId.Value.Span), Convert.ToHexStringLower(value.OwnerEpoch.Value.Span));
    }

    private static async Task RequireReadyAsync(NodeSession session, NativeUpdateState state, CancellationToken ct)
    {
        var owner = await ReadAuthorityAsync(session, ct).ConfigureAwait(false);
        if (owner.NodeId != state.Authority!.NodeId || owner.OwnerEpoch != state.Authority.OwnerEpoch)
            throw Refused("native_update_owner_epoch_changed");

        using var pin = NodeUpdateLauncher.PinBoundSession(session);
        var runs = new V2.RunService.RunServiceClient(session.Channel.CallInvoker);
        foreach (string run in state.Checkpoint?.RetainedRuns ?? [])
        {
            var id = new Id { Value = Google.Protobuf.ByteString.CopyFrom(Convert.FromHexString(run)) };
            using var call = runs.InspectAsync(new V2.RunServiceInspectRequest { Meta = Meta(), RunId = id },
                deadline: DateTime.UtcNow + RpcDeadline, cancellationToken: ct);
            var observed = (await call.ResponseAsync.ConfigureAwait(false)).Value?.Run;
            if (observed is null || !id.Equals(observed.RunId) || observed.State == V2.RunState.RecoveryRequired)
                throw Refused("native_update_original_run_recovery_unconfirmed");
        }
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

            var value = JsonNode.Parse(new string(buffer, 0, count)) as JsonObject;
            if (value?["nativeUpdateProtocol"]?.GetValue<int>() != 1 ||
                value["supervisorProtocol"]?.GetValue<string>() is not { Length: > 0 and <=128 } protocol ||
                value["schemaReader"]?.GetValue<int>() is not int reader || value["runtimeSchema"]?.GetValue<int>() is not int schema)
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
        ["previousArchiveSha256"] = state?.Previous.ArchiveSha256,
        ["candidateArchiveSha256"] = state?.Candidate.ArchiveSha256,
        ["selectedArchiveSha256"] = selected,
        ["storeSchema"] = state?.Checkpoint?.StoreSchema ?? state?.Authority?.PreviousSchema,
        ["minimumReader"] = state?.Checkpoint?.MinimumReader ?? state?.Authority?.PreviousMinimumReader,
        ["backupRoot"] = state?.Checkpoint?.BackupRoot,
        ["backupManifestSha256"] = state?.Checkpoint?.BackupManifestSha256,
        ["retainedRuns"] = state?.Checkpoint?.RetainedRuns?.Length,
        ["updatedAt"] = state?.UpdatedAt,
    };

    private static IOException Refused(string reason) => new(reason);
}
