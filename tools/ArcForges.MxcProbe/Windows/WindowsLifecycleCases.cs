// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;

namespace ArcForges.MxcProbe;

internal sealed class WindowsLifecycleMember
{
    public uint ProcessId { get; set; }
    public string? CreatedUtc { get; set; }
    public string? ImageName { get; set; }
    public string? ImagePath { get; set; }
    public string? ImageSha256 { get; set; }
    public bool HeldOwner { get; set; }
    public bool MemberBeforeIdentityRead { get; set; }
    public bool MemberAfterIdentityRead { get; set; }
    public WindowsQualificationFailure? ObservationFailure { get; set; }
}

internal sealed class WindowsLifecycleEvidence
{
    public string Case { get; set; } = "";
    public string ClientRole { get; set; } = "independent probe Node-simulator; not product Node";
    public string GuardianRole { get; set; } = "surviving experiment guardian; not Node";
    public string? Boundary { get; set; }
    public int? ClientPid { get; set; }
    public string? ClientCreatedUtc { get; set; }
    public bool ClientKilled { get; set; }
    public int? ForeignPid { get; set; }
    public string? ForeignCreatedUtc { get; set; }
    public bool? ForeignUnaffected { get; set; }
    public uint? ChildPid { get; set; }
    public string? ChildCreatedUtc { get; set; }
    public bool ChildHeldIdentityExited { get; set; }
    public ProbeOwnerRecord? InitialOwner { get; set; }
    public ProbeOwnerRecord? FinalOwner { get; set; }
    public ConPtyJobObservation? BeforeHelperDrain { get; set; }
    public ConPtyJobObservation? AfterHelperDrain { get; set; }
    public List<WindowsLifecycleMember> BeforeHelperMembers { get; set; } = [];
    public List<WindowsLifecycleMember> AfterHelperMembers { get; set; } = [];
    public bool HelperMemberCaptureTruncated { get; set; }
    public WindowsQualificationFailure? HelperDrainObservationFailure { get; set; }
    public ConPtyJobObservation? FinalAggregate { get; set; }
    public ConPtyJobObservation? BeforeCenterLossAggregate { get; set; }
    public ConPtyJobObservation? AfterCenterLossAggregate { get; set; }
    public Dictionary<string, bool> Checks { get; set; } = new(StringComparer.Ordinal);
}

[SupportedOSPlatform("windows")]
internal static class WindowsLifecycleCases
{
    // Retain failed native owners until explicit coordinator reconciliation;
    // failed teardown must not become a garbage-collection release receipt.
    internal static List<WindowsOwnerHost> UnresolvedGuardians { get; } = [];

    internal static async Task<List<WindowsQualificationCase>> RunAsync(string stage, string work)
    {
        var cases = new List<WindowsQualificationCase>();
        var attached = await RunCaseAsync("owner-detach-auth-lease", stage, work, ["console", "raw", "60000"], ExerciseAttachmentAsync).ConfigureAwait(false);
        cases.Add(attached);
        if (!attached.Passed) return cases;

        cases.Add(await RunCaseAsync("owner-detached-bounded-replay", stage, work, ["flood", "1048576"], ExerciseReplayAsync).ConfigureAwait(false));
        cases.Add(await RunCaseAsync("center-observer-loss", stage, work, ["console", "raw", "60000"], ExerciseCenterLossAsync).ConfigureAwait(false));
        cases.Add(await RunCaseAsync("owner-loss-native-drain", stage, work, ["console", "raw", "60000"], ExerciseOwnerLossAsync).ConfigureAwait(false));
        cases.Add(await RunCaseAsync("root-exit-background-child", stage, work, ["root-exit-child", "60000", "2000"], ExerciseRootExitAsync).ConfigureAwait(false));
        cases.Add(await RunCaseAsync("cleanup-record-publication-failure", stage, work, ["console-info"], ExerciseCleanupFailureAsync, "cleaning").ConfigureAwait(false));
        foreach (var boundary in new[] { "prepared", "scope-created", "owner-ack", "executor-created", "active", "cleaning", "final" })
        {
            var exits = boundary is "cleaning" or "final";
            cases.Add(await RunCaseAsync("client-loss-at-" + boundary, stage, work,
                exits ? ["console-info"] : ["console", "raw", "60000"], fixture => ExerciseBoundaryAsync(fixture, boundary),
                boundary == "scope-created" ? null : boundary, killClientBeforeResume: boundary == "scope-created", createClientBeforeOwner: true).ConfigureAwait(false));
        }

        var persistentRoot = Path.Combine(work, "persistent-sandbox");
        var persistent = CreateOwned(persistentRoot);
        var data = Path.Combine(persistent.Data, "fixture-state.bin");
        cases.Add(await RunCaseAsync("persistent-data-first-run", stage, work, ["persistence", "write", data],
            fixture => ExercisePersistenceAsync(fixture, false), owned: persistent).ConfigureAwait(false));
        cases.Add(await RunCaseAsync("persistent-data-new-run", stage, work, ["persistence", "read", data],
            fixture => ExercisePersistenceAsync(fixture, true), owned: persistent).ConfigureAwait(false));
        return cases;
    }

    // Also used by the single-Run combined experiment. The caller supplies its
    // exact compiled policy; this helper does not broaden any grants or modes.
    internal static async Task<(ProbeOwnerConfig Config, WindowsOwnerHost Guardian, WindowsPolicyArtifact Policy)> StartOwnerAsync(
        string stage, string newControl, WindowsPolicyRequest request, string? pauseAtPhase = null, Action? beforeOwnerResume = null,
        Action<WindowsPolicyArtifact>? beforeLaunch = null)
    {
        var policy = WindowsPolicy.WritePrivate(newControl, request);
        beforeLaunch?.Invoke(policy);
        var probe = await WindowsPolicyProbe.RunAsync(stage, policy.Path, Path.Combine(newControl, "native-probe")).ConfigureAwait(false);
        Check(probe.ExitCode == 0 && probe.JsonParsed && probe.NativeBaseContainer && probe.NeedsDaclAugmentation == false
            && probe.DenyPaths && probe.UiRestrictionsComplete, "same_policy_native_probe_refused");
        var config = new ProbeOwnerConfig(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), 1, policy.Sha256,
            "arcforges-mxc-owner-" + Guid.NewGuid().ToString("N"), Key(), Key(),
            new(Path.Combine(stage, "wxc-exec.exe"), policy.Path, policy.ControlDirectory, 80, 24,
                new(5000, 1024UL * 1024 * 1024, 16)), pauseAtPhase);
        var configPath = Path.Combine(newControl, "owner-config.json");
        WritePrivate(configPath, config, OwnerJson.Default.ProbeOwnerConfig);
        var guardian = WindowsOwnerHost.Start(stage, configPath, new(5000, 1536UL * 1024 * 1024, 24), beforeOwnerResume);
        return (config, guardian, policy);
    }

    internal static async Task<ProbeOwnerResponse> AwaitStatusAsync(ProbeOwnerConfig config,
        Func<ProbeOwnerResponse, bool> accept, TimeSpan timeout)
    {
        var clock = Stopwatch.StartNew();
        while (clock.Elapsed < timeout)
        {
            try
            {
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                var status = await OwnerProtocol.SendAsync(config, new() { Operation = "status", Generation = config.Generation },
                    cancellationToken: deadline.Token).ConfigureAwait(false);
                if (status.Ok && accept(status)) return status;
                if (status.State == "FAILED") throw new WindowsQualificationCheckException("owner_launch_failed");
            }
            catch (Exception error) when (error is IOException or OperationCanceledException or TimeoutException) { }
            await Task.Delay(50).ConfigureAwait(false);
        }
        throw new WindowsQualificationCheckException("owner_status_timeout");
    }

    internal static async Task<WindowsPhaseObservation> KillAuthenticatedClientAsync(ProbeOwnerConfig config, string privateControlDirectory)
    {
        var name = "authenticated-client-" + Guid.NewGuid().ToString("N");
        using var client = await StartClientAsync(Path.GetDirectoryName(config.Launch.ExecutorPath)!, config,
            privateControlDirectory, name, true).ConfigureAwait(false);
        try
        {
            var observed = await ReadWhenReadyAsync(Path.Combine(privateControlDirectory, name, "client-ready.json"),
                PhaseJson.Default.WindowsPhaseObservation, TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            Check(observed.Phase == "client-attached" && observed.OwnerPid is > 0 && observed.ExecutorPid is > 0,
                "independent_client_did_not_authenticate");
            var busy = await OwnerProtocol.SendAsync(config, new() { Operation = "acquire", Generation = config.Generation }).ConfigureAwait(false);
            Check(!busy.Ok && busy.Error == "writer_busy", "authenticated_client_did_not_hold_writer_lease");
            KillClient(client, new WindowsLifecycleEvidence());
            return observed with { Phase = "authenticated-client-killed" };
        }
        finally { await EndClientAsync(client).ConfigureAwait(false); }
    }

    private static async Task<WindowsQualificationCase> RunCaseAsync(string name, string stage, string work, string[] workload,
        Func<Fixture, Task> exercise, string? pause = null, bool killClientBeforeResume = false,
        bool createClientBeforeOwner = false, WindowsOwnedPaths? owned = null)
    {
        var result = new WindowsQualificationCase { Name = name, Protocol = "MXC-WIN-05" };
        var evidence = new WindowsLifecycleEvidence { Case = name, Boundary = pause ?? (killClientBeforeResume ? "scope-created" : null) };
        var clock = Stopwatch.StartNew();
        var root = Path.Combine(work, name);
        Directory.CreateDirectory(root);
        var paths = owned ?? CreateOwned(Path.Combine(root, "sandbox"));
        var control = Path.Combine(root, "private-control");
        var request = WindowsPolicy.BuildRequest(Path.Combine(stage, "arcforges-mxc-probe.exe"), ["--windows-workload", .. workload],
            paths, [stage, Environment.SystemDirectory], [control], WindowsNetworkChoice.DenyAll);
        request.Process.Timeout = 120_000;
        var events = WindowsQualification.EnableFixtureEvents(request, paths.Work);
        Fixture? fixture = null;
        Process? earlyClient = null;
        try
        {
            // The pre-owner client is a real independent process. Its private
            // config is prepared before the guardian launches the owner.
            if (createClientBeforeOwner)
            {
                var policy = WindowsPolicy.WritePrivate(control, request);
                var probe = await WindowsPolicyProbe.RunAsync(stage, policy.Path, Path.Combine(control, "native-probe")).ConfigureAwait(false);
                Check(probe.ExitCode == 0 && probe.JsonParsed && probe.NativeBaseContainer && probe.NeedsDaclAugmentation == false
                    && probe.DenyPaths && probe.UiRestrictionsComplete, "same_policy_native_probe_refused");
                var config = NewConfig(stage, policy, pause);
                WritePrivate(Path.Combine(control, "owner-config.json"), config, OwnerJson.Default.ProbeOwnerConfig);
                earlyClient = await StartClientAsync(stage, config, root, "boundary-client", false).ConfigureAwait(false);
                var callbackRan = false;
                var guardian = WindowsOwnerHost.Start(stage, Path.Combine(control, "owner-config.json"), new(5000, 1536UL * 1024 * 1024, 24),
                    killClientBeforeResume ? () => { KillClient(earlyClient!, evidence); callbackRan = true; }
                : null);
                fixture = new(config, guardian, policy, result, evidence, root, events) { Client = earlyClient };
                if (killClientBeforeResume) Check(callbackRan, "scope_before_resume_callback_missing");
            }
            else
            {
                var started = await StartOwnerAsync(stage, control, request, pause).ConfigureAwait(false);
                fixture = new(started.Config, started.Guardian, started.Policy, result, evidence, root, events);
            }
            result.PolicySha256 = fixture.Policy.Sha256;
            result.SamePolicyProbePassed = true;
            await exercise(fixture).ConfigureAwait(false);
            result.Passed = true;
        }
        catch (Exception error)
        {
            result.Passed = false;
            result.PrimaryFailure = WindowsQualification.ObserveFailure(error);
            result.FailureCode = error is WindowsQualificationCheckException check ? check.Code : "native_operation_failed";
            result.FailureType = error.GetType().Name;
            result.FailureHResult = error.HResult;
            if (error is WindowsOwnerLaunchException launch) UnresolvedGuardians.Add(launch.CleanupOwner);
        }
        finally
        {
            if (fixture is not null) await fixture.DisposeAsync().ConfigureAwait(false);
            if (earlyClient is not null)
            {
                if (!earlyClient.HasExited) { earlyClient.Kill(); await earlyClient.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false); }
                earlyClient.Dispose();
            }
            result.ElapsedMs = clock.Elapsed.TotalMilliseconds;
            try
            {
                WritePrivate(Path.Combine(root, "lifecycle-evidence.json"), evidence, PhaseJson.Default.WindowsLifecycleEvidence, verifyPrivate: false);
            }
            catch (Exception error) { result.Passed = false; result.EvidenceFailure = WindowsQualification.ObserveFailure(error); }
        }
        return result;
    }

    private static ProbeOwnerConfig NewConfig(string stage, WindowsPolicyArtifact policy, string? pause) => new(
        Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), 1, policy.Sha256,
        "arcforges-mxc-owner-" + Guid.NewGuid().ToString("N"), Key(), Key(),
        new(Path.Combine(stage, "wxc-exec.exe"), policy.Path, policy.ControlDirectory, 80, 24, new(5000, 1024UL * 1024 * 1024, 16)), pause);

    private static async Task ExerciseAttachmentAsync(Fixture fixture)
    {
        var initial = await fixture.StartedAsync().ConfigureAwait(false);
        using var sentinel = await StartClientAsync(fixture.Stage, fixture.Config, fixture.Root, "foreign-sentinel", false).ConfigureAwait(false);
        fixture.Evidence.ForeignPid = sentinel.Id;
        fixture.Evidence.ForeignCreatedUtc = sentinel.StartTime.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
        try
        {
            var observer = await OwnerProtocol.SendAsync(fixture.Config, new() { Operation = "status", Generation = 1 }, true).ConfigureAwait(false);
            Check(observer.Ok, "observer_status_refused");
            observer = await OwnerProtocol.SendAsync(fixture.Config, new() { Operation = "write", Generation = 1, Sequence = 1, Input = "x"u8.ToArray() }, true).ConfigureAwait(false);
            Check(!observer.Ok && observer.Error == "observer_read_only", "observer_mutation_not_refused");
            await ExpectAuthenticationRefusalAsync(fixture.Config with { ControllerKey = Key() }).ConfigureAwait(false);
            await ExpectAuthenticationRefusalAsync(fixture.Config with { OwnerEpoch = Guid.NewGuid().ToString("N") }).ConfigureAwait(false);
            fixture.Evidence.Checks["observer_read_only_and_bad_capability_refused"] = true;

            var acquired = await fixture.SendAsync("acquire").ConfigureAwait(false);
            Check(acquired.Ok && acquired.LeaseId is not null, "writer_acquire_refused");
            var busy = await fixture.SendAsync("acquire").ConfigureAwait(false);
            Check(!busy.Ok && busy.Error == "writer_busy", "second_writer_not_refused");
            var input = new ProbeOwnerRequest { Operation = "write", Generation = 1, LeaseId = acquired.LeaseId, Sequence = 1, Input = "x"u8.ToArray() };
            var first = await OwnerProtocol.SendAsync(fixture.Config, input).ConfigureAwait(false);
            var duplicate = await OwnerProtocol.SendAsync(fixture.Config, input).ConfigureAwait(false);
            Check(first.Ok && duplicate == first, "transient_input_ack_replay_mismatch");
            var resized = await OwnerProtocol.SendAsync(fixture.Config, new()
            {
                Operation = "resize",
                Generation = 1,
                LeaseId = acquired.LeaseId,
                Sequence = 2,
                Columns = 100,
                Rows = 30
            }).ConfigureAwait(false);
            Check(resized.Ok, "writer_resize_refused");
            var conflict = await OwnerProtocol.SendAsync(fixture.Config, new()
            {
                Operation = "resize",
                Generation = 1,
                LeaseId = acquired.LeaseId,
                Sequence = 2,
                Columns = 110,
                Rows = 31
            }).ConfigureAwait(false);
            Check(!conflict.Ok && conflict.Error == "terminal_sequence_conflict", "terminal_sequence_reuse_not_refused");
            Check((await OwnerProtocol.SendAsync(fixture.Config, new() { Operation = "detach", Generation = 1, LeaseId = acquired.LeaseId }).ConfigureAwait(false)).Ok,
                "writer_detach_refused");
            var detached = await fixture.SendAsync("status").ConfigureAwait(false);
            SameOwner(initial, detached);

            using var client = await StartClientAsync(fixture.Stage, fixture.Config, fixture.Root, "attached-client", true).ConfigureAwait(false);
            KillClient(client, fixture.Evidence);
            SameOwner(initial, await fixture.SendAsync("status").ConfigureAwait(false));
            var rebound = await fixture.SendAsync("rebind").ConfigureAwait(false);
            Check(rebound.Ok && rebound.Generation == 2, "control_generation_not_rebound");
            await ExpectAuthenticationRefusalAsync(fixture.Config).ConfigureAwait(false); // Old generation is not accepted.
            fixture.Config = fixture.Config with { Generation = rebound.Generation };
            var fresh = await fixture.SendAsync("acquire").ConfigureAwait(false);
            Check(fresh.Ok && fresh.LeaseId is not null, "writer_not_reacquired_after_rebind");
            var staleLease = await OwnerProtocol.SendAsync(fixture.Config, new()
            {
                Operation = "write",
                Generation = 2,
                LeaseId = acquired.LeaseId,
                Sequence = 3,
                Input = "x"u8.ToArray()
            }).ConfigureAwait(false);
            Check(!staleLease.Ok && staleLease.Error == "writer_lease_unavailable", "old_writer_authority_survived_rebind");
            SameOwner(initial, await fixture.SendAsync("status").ConfigureAwait(false));
            fixture.Evidence.Checks["same_owner_executor_and_limits_after_client_kill_rebind"] = true;
            await fixture.FinishAsync().ConfigureAwait(false);
            fixture.Evidence.ForeignUnaffected = !sentinel.HasExited;
            Check(fixture.Evidence.ForeignUnaffected == true, "unrelated_sentinel_was_affected");
        }
        finally { await EndClientAsync(sentinel).ConfigureAwait(false); }
    }

    private static async Task ExerciseOwnerLossAsync(Fixture fixture)
    {
        _ = await fixture.StartedAsync().ConfigureAwait(false);
        using var sentinel = await StartClientAsync(fixture.Stage, fixture.Config, fixture.Root, "foreign-sentinel", false).ConfigureAwait(false);
        fixture.Evidence.ForeignPid = sentinel.Id;
        fixture.Evidence.ForeignCreatedUtc = sentinel.StartTime.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
        try
        {
            await fixture.Guardian.KillOwnerAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            fixture.Evidence.FinalAggregate = await fixture.Guardian.WaitEmptyAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            Check(fixture.Evidence.FinalAggregate.ActiveProcesses == 0 && fixture.Evidence.FinalAggregate.ProcessIds.Length == 0, "owner_loss_descendants_remain");
            fixture.Result.RawExecutorExit = null;
            fixture.Result.ExitSource = "unknown";
            fixture.Evidence.Checks["owner_loss_auto_cleanup_without_driver_payload_kill"] = true;
            fixture.Evidence.ForeignUnaffected = !sentinel.HasExited;
            Check(fixture.Evidence.ForeignUnaffected == true, "unrelated_sentinel_was_affected");
        }
        finally { await EndClientAsync(sentinel).ConfigureAwait(false); }
    }

    private static async Task ExerciseCenterLossAsync(Fixture fixture)
    {
        var initial = await fixture.StartedAsync().ConfigureAwait(false);
        fixture.Evidence.ClientRole = "independent read-only Center-availability observer; not a Center business service";
        using var observer = await StartClientAsync(fixture.Stage, fixture.Config, fixture.Root, "center-observer", attach: false, observer: true).ConfigureAwait(false);
        try
        {
            var observed = await ReadWhenReadyAsync(Path.Combine(fixture.Root, "center-observer", "client-ready.json"),
                PhaseJson.Default.WindowsPhaseObservation, TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            Check(observed.Phase == "center-observer-attached" && observed.OwnerPid == initial.OwnerPid
                && observed.ExecutorPid == initial.ExecutorPid, "center_observer_did_not_authenticate_same_owner");
            using var executor = Process.GetProcessById(checked((int)initial.ExecutorPid!.Value));
            Check(!executor.HasExited && executor.StartTime.ToUniversalTime() == initial.ExecutorCreatedUtc!.Value.UtcDateTime,
                "center_observer_executor_identity_not_live");
            var before = fixture.Guardian.ObserveAggregate();
            fixture.Evidence.BeforeCenterLossAggregate = before;
            Check(before.ProcessIds.Contains(fixture.Guardian.ProcessId) && before.ProcessIds.Contains(initial.ExecutorPid.Value),
                "center_observer_native_membership_missing_before_loss");
            KillClient(observer, fixture.Evidence);
            var afterStatus = await fixture.SendAsync("status").ConfigureAwait(false);
            SameOwner(initial, afterStatus);
            Check(afterStatus.State == "RUNNING" && !executor.HasExited && afterStatus.Job is { ActiveProcesses: > 0 }
                && afterStatus.Job.ProcessIds.Contains(initial.ExecutorPid.Value), "center_loss_stopped_locally_owned_run");
            var after = fixture.Guardian.ObserveAggregate();
            fixture.Evidence.AfterCenterLossAggregate = after;
            Check(after.Limits == before.Limits && after.ProcessIds.Contains(fixture.Guardian.ProcessId)
                && after.ProcessIds.Contains(initial.ExecutorPid.Value), "center_loss_changed_native_scope_or_limits");
            fixture.Evidence.Checks["center_observer_process_authenticated_read_only_then_actually_killed"] = true;
            fixture.Evidence.Checks["same_native_owner_executor_job_and_limits_after_center_loss"] = true;
            await fixture.FinishAsync().ConfigureAwait(false);
            fixture.Evidence.Checks["local_stop_and_empty_cleanup_after_center_loss"] = true;
        }
        finally { await EndClientAsync(observer).ConfigureAwait(false); }
    }

    private static async Task ExerciseReplayAsync(Fixture fixture)
    {
        _ = await fixture.StartedAsync(allowTerminal: true).ConfigureAwait(false);
        var ended = await AwaitStatusAsync(fixture.Config, x => x.State == "EXITED", TimeSpan.FromSeconds(25)).ConfigureAwait(false);
        Check(ended.RawExitCode == 0 && ended.CleanupConfirmed, "detached_flood_did_not_drain");
        // No terminal subscriber has read any output during the flood. The
        // owner's independent drain must have retained an honest bounded tail.
        var response = await OwnerProtocol.SendAsync(fixture.Config, new() { Operation = "read", Generation = 1, Cursor = 0 }, true).ConfigureAwait(false);
        var replay = response.Replay ?? throw new WindowsQualificationCheckException("bounded_replay_unavailable");
        Check(response.Ok && replay.AvailableUntil >= 1_048_576 && replay.AvailableFrom > 0
            && replay.GapFrom == 0 && replay.GapUntil == replay.AvailableFrom && replay.Data.Length > 0 && replay.DrainFailure is null,
            "detached_replay_gap_not_truthful");
        fixture.Result.ObservedTerminalBytes = replay.AvailableUntil;
        fixture.Result.ReplayGaps.Add(new(0, replay.AvailableFrom));
        var captured = replay.Data.Length;
        for (var read = 0; !replay.EndOfStream && read < 9; read++)
        {
            response = await OwnerProtocol.SendAsync(fixture.Config, new() { Operation = "read", Generation = 1, Cursor = replay.NextSequence }, true).ConfigureAwait(false);
            var next = response.Replay ?? throw new WindowsQualificationCheckException("bounded_replay_unavailable");
            Check(response.Ok && next.StartSequence == replay.NextSequence && next.GapFrom is null && next.DrainFailure is null,
                "retained_replay_cursor_discontinuity");
            captured += next.Data.Length;
            replay = next;
        }
        Check(replay.EndOfStream && captured <= fixture.Config.Launch.ReplayBytes, "bounded_replay_did_not_reach_real_eof");
        fixture.Result.CapturedBytes = captured;
        fixture.Result.CaptureTruncated = true;
        fixture.Evidence.Checks["drained_without_clients_bounded_gap_and_retained_eof"] = true;
        await fixture.FinishAsync().ConfigureAwait(false);
    }

    private static async Task ExerciseBoundaryAsync(Fixture fixture, string boundary)
    {
        if (boundary != "scope-created")
        {
            var observed = await AwaitPhaseAsync(fixture).ConfigureAwait(false);
            Check(observed.Phase == boundary && observed.ProcessId == fixture.Guardian.ProcessId
                && observed.CreatedUtc == fixture.Guardian.ProcessStartTimeUtc, "phase_owner_identity_mismatch");
            if (boundary == "executor-created")
            {
                using var input = new FileStream(Path.Combine(fixture.Config.Launch.ControlDirectory, "owner-record.json"),
                    FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                var prepared = JsonSerializer.Deserialize(input, OwnerJson.Default.ProbeOwnerRecord);
                Check(prepared is { State: "STARTING", ExecutorPid: > 0, Job.ActiveProcesses: 1 }
                    && observed.ExecutorPid is uint executorPid && prepared.ExecutorPid == executorPid && prepared.Job.ProcessIds.Length == 1
                    && prepared.Job.ProcessIds[0] == executorPid
                    && fixture.Guardian.ObserveAggregate().ProcessIds.Contains(executorPid),
                    "executor_pre_resume_scope_evidence_missing");
                fixture.Evidence.Checks["exact_executor_created_and_admitted_before_resume"] = true;
            }
            Check(fixture.Client is not null, "independent_phase_client_missing");
            KillClient(fixture.Client!, fixture.Evidence);
            ReleasePhase(fixture);
        }
        var state = await fixture.StartedAsync(allowTerminal: boundary is "cleaning" or "final").ConfigureAwait(false);
        Check(fixture.Evidence.ClientKilled && state.OwnerPid == fixture.Guardian.ProcessId
            && state.OwnerCreatedUtc == fixture.Guardian.ProcessStartTimeUtc, "phase_client_loss_changed_owner");
        var rebind = await fixture.SendAsync("rebind").ConfigureAwait(false);
        Check(rebind.Ok && rebind.Generation == 2, "phase_rebind_refused");
        fixture.Config = fixture.Config with { Generation = 2 };
        SameOwner(state, await fixture.SendAsync("status").ConfigureAwait(false));
        fixture.Evidence.Checks["real_client_killed_at_exact_owned_boundary"] = true;
        fixture.Evidence.Checks["same_owner_rebound_without_payload_restart"] = true;
        await fixture.FinishAsync().ConfigureAwait(false);
    }

    private static async Task ExerciseCleanupFailureAsync(Fixture fixture)
    {
        _ = await AwaitPhaseAsync(fixture).ConfigureAwait(false);
        // A real Windows sharing violation prevents final-record replacement.
        // This tests completion-proof persistence, not a fabricated OS kill or
        // a claim that kernel termination itself failed.
        using (var heldRecord = new FileStream(Path.Combine(fixture.Config.Launch.ControlDirectory, "owner-record.json"),
            FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            ReleasePhase(fixture);
            var unresolved = await AwaitStatusAsync(fixture.Config, x => x.State == "RECOVERY_REQUIRED", TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            Check(!unresolved.CleanupConfirmed && !unresolved.DataDeletionAllowed, "unresolved_completion_allowed_deletion");
            var refused = await fixture.SendAsync("shutdown").ConfigureAwait(false);
            Check(!refused.Ok && refused.Error == "cleanup_unresolved", "unresolved_owner_shutdown_succeeded");
            Check(fixture.Guardian.ObserveAggregate().ProcessIds.Contains(fixture.Guardian.ProcessId), "unresolved_owner_was_not_retained");
            fixture.Evidence.Checks["real_final_record_share_violation_retains_owner_and_denies_deletion"] = true;
        }
        await fixture.FinishAsync().ConfigureAwait(false);
        fixture.Evidence.Checks["same_owner_cleanup_retry_after_actual_fault_removed"] = true;
    }

    private static async Task ExerciseRootExitAsync(Fixture fixture)
    {
        _ = await fixture.StartedAsync().ConfigureAwait(false);
        var item = await AwaitFixtureEventAsync(fixture.Events, "root-exit-with-child", TimeSpan.FromSeconds(15)).ConfigureAwait(false);
        var pid = item.GetProperty("childPid").GetUInt32();
        using var child = Process.GetProcessById(checked((int)pid));
        _ = child.SafeHandle; // Retain a native identity before membership recheck.
        Check(fixture.Guardian.ObserveAggregate().ProcessIds.Contains(pid), "background_child_not_in_guardian");
        var created = child.StartTime.ToUniversalTime();
        Check(item.GetProperty("childCreatedUtc").GetDateTimeOffset() == created, "background_child_creation_identity_mismatch");
        fixture.Evidence.ChildPid = pid;
        fixture.Evidence.ChildCreatedUtc = created.ToString("O", CultureInfo.InvariantCulture);
        var ended = await AwaitStatusAsync(fixture.Config, x => x.State == "EXITED", TimeSpan.FromSeconds(20)).ConfigureAwait(false);
        Check(ended.RawExitCode == 0 && ended.CleanupConfirmed && ended.Job?.ActiveProcesses == 0, "root_exit_cleanup_not_confirmed");
        await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
        fixture.Evidence.ChildHeldIdentityExited = child.HasExited;
        Check(fixture.Evidence.ChildHeldIdentityExited, "background_child_survived_root");
        await fixture.FinishAsync().ConfigureAwait(false);
    }

    private static async Task ExercisePersistenceAsync(Fixture fixture, bool second)
    {
        var ended = await fixture.StartedAsync(allowTerminal: true).ConfigureAwait(false);
        if (ended.State != "EXITED") ended = await AwaitStatusAsync(fixture.Config, x => x.State == "EXITED", TimeSpan.FromSeconds(20)).ConfigureAwait(false);
        var item = await AwaitFixtureEventAsync(fixture.Events, "persistence", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        Check(item.GetProperty("succeeded").GetBoolean() && item.GetProperty("operation").GetString() == (second ? "read" : "write")
            && ended.RawExitCode == 0 && ended.CleanupConfirmed, "payload_persistence_not_proven");
        fixture.Evidence.Checks[second ? "new_run_reads_previous_payload_owned_data" : "first_run_payload_writes_owned_data"] = true;
        await fixture.FinishAsync().ConfigureAwait(false);
    }

    private static async Task ExpectAuthenticationRefusalAsync(ProbeOwnerConfig config)
    {
        try
        {
            var response = await OwnerProtocol.SendAsync(config, new() { Operation = "status", Generation = config.Generation }).ConfigureAwait(false);
            Check(!response.Ok, "invalid_authentication_accepted");
        }
        catch (Exception error) when (error is UnauthorizedAccessException or IOException) { return; }
    }

    private static void SameOwner(ProbeOwnerResponse before, ProbeOwnerResponse after) => Check(after.Ok
        && before.OwnerPid == after.OwnerPid && before.OwnerCreatedUtc == after.OwnerCreatedUtc
        && before.ExecutorPid == after.ExecutorPid && before.ExecutorCreatedUtc == after.ExecutorCreatedUtc
        && before.Job?.Limits == after.Job?.Limits, "owner_executor_or_limits_changed_on_reconnect");

    private static async Task<WindowsPhaseObservation> AwaitPhaseAsync(Fixture fixture)
    {
        var path = Path.Combine(fixture.Config.Launch.ControlDirectory, "owner-phase-ready.json");
        var observation = await ReadWhenReadyAsync(path, PhaseJson.Default.WindowsPhaseObservation, TimeSpan.FromSeconds(20)).ConfigureAwait(false);
        Check(observation.RunId == fixture.Config.RunId && observation.Succeeded, "foreign_or_failed_owner_phase");
        return observation;
    }

    private static void ReleasePhase(Fixture fixture) => WritePrivate(Path.Combine(fixture.Config.Launch.ControlDirectory, "owner-phase-release.json"),
        new WindowsPhaseRelease(fixture.Config.RunId, fixture.Config.PauseAtPhase!), PhaseJson.Default.WindowsPhaseRelease);

    private static async Task<Process> StartClientAsync(string stage, ProbeOwnerConfig config, string root, string name, bool attach, bool observer = false)
    {
        var control = Path.Combine(root, name);
        WindowsPolicy.CreatePrivateControl(control);
        var path = Path.Combine(control, "client-plan.json");
        var ready = Path.Combine(control, "client-ready.json");
        WritePrivate(path, new WindowsPhaseClientPlan(Path.Combine(config.Launch.ControlDirectory, "owner-config.json"), ready, attach,
            ExpectedGeneration: config.Generation, Observer: observer), PhaseJson.Default.WindowsPhaseClientPlan);
        var start = new ProcessStartInfo(Path.Combine(stage, "arcforges-mxc-probe.exe")) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = stage };
        start.ArgumentList.Add("--windows-phase-client"); start.ArgumentList.Add(path);
        start.Environment.Clear();
        start.Environment["SystemRoot"] = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        start.Environment["WINDIR"] = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        start.Environment["PATH"] = Environment.SystemDirectory;
        start.Environment["TEMP"] = control; start.Environment["TMP"] = control;
        var client = Process.Start(start) ?? throw new InvalidOperationException("The independent client process did not start.");
        try
        {
            _ = client.SafeHandle;
            var observed = await ReadWhenReadyAsync(ready, PhaseJson.Default.WindowsPhaseObservation, TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            Check(observed.Succeeded && observed.RunId == config.RunId && observed.ProcessId == client.Id
                && observed.CreatedUtc == client.StartTime.ToUniversalTime(), "independent_client_readiness_mismatch");
            return client;
        }
        catch { await EndClientAsync(client).ConfigureAwait(false); client.Dispose(); throw; }
    }

    private static void KillClient(Process client, WindowsLifecycleEvidence evidence)
    {
        Check(!client.HasExited, "client_exited_before_injected_loss");
        evidence.ClientPid = client.Id;
        evidence.ClientCreatedUtc = client.StartTime.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
        client.Kill(); // The held process only; never its guardian or descendants.
        Check(client.WaitForExit(5_000) && client.HasExited, "independent_client_kill_not_observed");
        evidence.ClientKilled = true;
    }

    private static async Task EndClientAsync(Process client)
    {
        if (!client.HasExited) client.Kill();
        await client.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
    }

    private static async Task<T> ReadWhenReadyAsync<T>(string path, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type, TimeSpan timeout)
    {
        var clock = Stopwatch.StartNew();
        while (clock.Elapsed < timeout)
        {
            if (File.Exists(path))
            {
                try
                {
                    WindowsPolicy.VerifyPrivateFile(path);
                    var bytes = await File.ReadAllBytesAsync(path).ConfigureAwait(false);
                    Check(bytes.Length <= 65_536, "private_marker_too_large");
                    return JsonSerializer.Deserialize(bytes, type) ?? throw new InvalidDataException("Empty private marker.");
                }
                catch (Exception error) when (error is IOException or JsonException) { }
            }
            await Task.Delay(25).ConfigureAwait(false);
        }
        throw new WindowsQualificationCheckException("owned_fixture_readiness_timeout");
    }

    private static Task<JsonElement> AwaitFixtureEventAsync(string directory, string name, TimeSpan timeout) =>
        WindowsTerminalCapture.WaitForFixtureEventAsync(directory, name, timeout);

    private static WindowsOwnedPaths CreateOwned(string root)
    {
        var paths = new WindowsOwnedPaths(Path.Combine(root, "home"), Path.Combine(root, "config"), Path.Combine(root, "cache"),
            Path.Combine(root, "temp"), Path.Combine(root, "work"), Path.Combine(root, "data"));
        foreach (var path in new[] { paths.Home, paths.Config, paths.Cache, paths.Temp, paths.Work, paths.Data }) Directory.CreateDirectory(path);
        return paths;
    }

    private static string Key() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    private static void Check([System.Diagnostics.CodeAnalysis.DoesNotReturnIf(false)] bool value, string code)
    { if (!value) throw new WindowsQualificationCheckException(code); }

    private static void WritePrivate<T>(string path, T value, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type, bool verifyPrivate = true)
    {
        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 4_096, FileOptions.WriteThrough))
        { JsonSerializer.Serialize(stream, value, type); stream.Flush(true); }
        if (verifyPrivate) WindowsPolicy.VerifyPrivateFile(path);
    }

    private static List<WindowsLifecycleMember> ObserveMembers(WindowsOwnerHost guardian, ConPtyJobObservation snapshot)
    {
        var observations = new List<WindowsLifecycleMember>();
        foreach (var pid in snapshot.ProcessIds.Take(16))
        {
            var item = new WindowsLifecycleMember { ProcessId = pid, HeldOwner = pid == guardian.ProcessId };
            observations.Add(item);
            try
            {
                using var process = Process.GetProcessById(checked((int)pid));
                _ = process.SafeHandle; // Hold the native process before rechecking exact Job membership.
                item.MemberBeforeIdentityRead = !process.HasExited && guardian.ObserveAggregate().ProcessIds.Contains(pid);
                if (!item.MemberBeforeIdentityRead) continue;
                item.CreatedUtc = process.StartTime.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
                var image = process.MainModule?.FileName ?? throw new InvalidOperationException("The held member image is unavailable.");
                item.ImagePath = image;
                item.ImageName = Path.GetFileName(image);
                using (var file = File.Open(image, FileMode.Open, FileAccess.Read, FileShare.Read))
                    item.ImageSha256 = Convert.ToHexStringLower(SHA256.HashData(file));
                item.MemberAfterIdentityRead = !process.HasExited && guardian.ObserveAggregate().ProcessIds.Contains(pid);
            }
            catch (Exception error) { item.ObservationFailure = WindowsQualification.ObserveFailure(error); }
        }
        return observations;
    }

    private sealed class Fixture(ProbeOwnerConfig config, WindowsOwnerHost guardian, WindowsPolicyArtifact policy,
        WindowsQualificationCase result, WindowsLifecycleEvidence evidence, string root, string events) : IAsyncDisposable
    {
        internal ProbeOwnerConfig Config { get; set; } = config;
        internal WindowsOwnerHost Guardian => guardian;
        internal WindowsPolicyArtifact Policy => policy;
        internal WindowsQualificationCase Result => result;
        internal WindowsLifecycleEvidence Evidence => evidence;
        internal string Root => root;
        internal string Events => events;
        internal string Stage => Path.GetDirectoryName(Config.Launch.ExecutorPath)!;
        internal Process? Client { get; init; }

        internal Task<ProbeOwnerResponse> SendAsync(string operation) => OwnerProtocol.SendAsync(Config, new() { Operation = operation, Generation = Config.Generation });

        internal async Task<ProbeOwnerResponse> StartedAsync(bool allowTerminal = false)
        {
            var observed = await AwaitStatusAsync(Config, x => x.State == "RUNNING" || allowTerminal && x.State == "EXITED", TimeSpan.FromSeconds(25)).ConfigureAwait(false);
            Check(observed.OwnerPid == guardian.ProcessId && observed.OwnerCreatedUtc == guardian.ProcessStartTimeUtc
                && observed.ExecutorPid is > 0 && observed.ExecutorCreatedUtc is not null, "background_native_identity_mismatch");
            result.ExecutorProcessId = observed.ExecutorPid.Value;
            result.ExecutorStartUtc = observed.ExecutorCreatedUtc.Value.ToString("O", CultureInfo.InvariantCulture);
            evidence.InitialOwner = ReadOwner();
            return observed;
        }

        internal async Task FinishAsync()
        {
            var stopped = await SendAsync("stop").ConfigureAwait(false);
            Check(stopped.Ok && stopped.CleanupConfirmed && stopped.DataDeletionAllowed, "stop_cleanup_unresolved");
            var status = await SendAsync("status").ConfigureAwait(false);
            Check(status.Job is { ActiveProcesses: 0 } && status.Job.ProcessIds.Length == 0, "inner_job_not_independently_empty");
            evidence.BeforeHelperDrain = guardian.ObserveAggregate();
            evidence.HelperMemberCaptureTruncated = evidence.BeforeHelperDrain.ProcessIds.Length > 16;
            evidence.BeforeHelperMembers = ObserveMembers(guardian, evidence.BeforeHelperDrain);
            ConPtyJobObservation aggregate;
            try { aggregate = await guardian.WaitOwnerOnlyAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false); }
            finally
            {
                try
                {
                    evidence.AfterHelperDrain = guardian.ObserveAggregate();
                    evidence.HelperMemberCaptureTruncated |= evidence.AfterHelperDrain.ProcessIds.Length > 16;
                    evidence.AfterHelperMembers = ObserveMembers(guardian, evidence.AfterHelperDrain);
                }
                catch (Exception error) { evidence.HelperDrainObservationFailure = WindowsQualification.ObserveFailure(error); }
            }
            Check(aggregate.ActiveProcesses == 1 && aggregate.ProcessIds.Length == 1 && aggregate.ProcessIds[0] == guardian.ProcessId,
                "unexpected_helpers_after_payload_drain");
            result.RawExecutorExit = status.RawExitCode;
            result.ExitSource = status.ExitSource;
            evidence.FinalOwner = ReadOwner();
            var shutdown = await SendAsync("shutdown").ConfigureAwait(false);
            Check(shutdown.Ok, "empty_owner_shutdown_refused");
            evidence.FinalAggregate = await guardian.WaitEmptyAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false);
        }

        private ProbeOwnerRecord ReadOwner()
        {
            // Ordinary inspection must allow atomic owner-record replacement;
            // only the explicit fault case takes a delete-denying share lock.
            using var input = new FileStream(Path.Combine(Config.Launch.ControlDirectory, "owner-record.json"),
                FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return JsonSerializer.Deserialize(input, OwnerJson.Default.ProbeOwnerRecord)
                ?? throw new InvalidDataException("Missing exact owner record.");
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                if (evidence.FinalAggregate is not { ActiveProcesses: 0, ProcessIds.Length: 0 })
                {
                    await guardian.KillOwnerAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
                    evidence.FinalAggregate = await guardian.WaitEmptyAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false);
                }
                result.JobEmpty = evidence.FinalAggregate.ActiveProcesses == 0 && evidence.FinalAggregate.ProcessIds.Length == 0;
                result.FinalJob = evidence.FinalAggregate;
                await guardian.DisposeAsync().ConfigureAwait(false);
                result.CleanupCompleted = true;
            }
            catch (Exception error)
            {
                result.Passed = false;
                result.CleanupFailure = WindowsQualification.ObserveFailure(error);
                UnresolvedGuardians.Add(guardian);
            }
        }
    }
}
