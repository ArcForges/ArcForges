// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArcForges.MxcProbe;

// A real, separately killable Node-simulator/client process. This fixture is
// deliberately not the product Node and never owns the guardian or PTY Job.
internal sealed record WindowsPhaseClientPlan(string OwnerConfigPath, string ReadyPath, bool AcquireWriter,
    int HoldMilliseconds = 180_000, long? ExpectedGeneration = null, bool Observer = false);
internal sealed record WindowsPhaseObservation(string RunId, string Phase, int ProcessId,
    DateTimeOffset CreatedUtc, bool Succeeded, int? OwnerPid = null, uint? ExecutorPid = null,
    string? FailureType = null, int? FailureHResult = null, string? FailureCode = null);
internal sealed record WindowsPhaseRelease(string RunId, string Phase);

[SupportedOSPlatform("windows")]
internal static class WindowsPhaseClient
{
    internal static async Task<int> RunAsync(string privatePlanPath)
    {
        WindowsPhaseClientPlan? plan = null;
        ProbeOwnerConfig? owner = null;
        try
        {
            WindowsPolicy.VerifyPrivateFile(privatePlanPath);
            plan = JsonSerializer.Deserialize(await File.ReadAllBytesAsync(privatePlanPath).ConfigureAwait(false),
                PhaseJson.Default.WindowsPhaseClientPlan) ?? throw new InvalidDataException("Missing private phase-client plan.");
            if (plan.HoldMilliseconds is < 1000 or > 180_000) throw new InvalidDataException("Invalid bounded client lifetime.");
            if (plan.Observer && plan.AcquireWriter) throw new InvalidDataException("An observer cannot acquire writer authority.");
            WindowsPolicy.VerifyPrivateFile(plan.OwnerConfigPath);
            WindowsPolicy.VerifyPrivateControl(Path.GetDirectoryName(plan.ReadyPath)!);
            if (File.Exists(plan.ReadyPath)) throw new InvalidDataException("Client readiness already exists.");
            owner = JsonSerializer.Deserialize(await File.ReadAllBytesAsync(plan.OwnerConfigPath).ConfigureAwait(false),
                OwnerJson.Default.ProbeOwnerConfig) ?? throw new InvalidDataException("Missing private owner configuration.");
            owner = owner with { Generation = plan.ExpectedGeneration ?? owner.Generation };
            ProbeOwnerResponse? attached = null;
            if (plan.AcquireWriter)
            {
                attached = await OwnerProtocol.SendAsync(owner, new() { Operation = "acquire", Generation = owner.Generation }).ConfigureAwait(false);
                if (!attached.Ok || attached.LeaseId is null) throw new InvalidOperationException("The independent client did not acquire its writer lease.");
            }
            else if (plan.Observer)
            {
                attached = await OwnerProtocol.SendAsync(owner, new() { Operation = "status", Generation = owner.Generation }, observer: true).ConfigureAwait(false);
                if (!attached.Ok || attached.State != "RUNNING" || attached.ExecutorPid is not > 0)
                    throw new WindowsQualificationCheckException("center_observer_status_not_live");
            }
            using var process = Process.GetCurrentProcess();
            WritePrivate(plan.ReadyPath, new(owner.RunId, plan.Observer ? "center-observer-attached" : plan.AcquireWriter ? "client-attached" : "client-holding",
                process.Id, process.StartTime.ToUniversalTime(), true, attached?.OwnerPid, attached?.ExecutorPid));
            if (plan.Observer)
            {
                // A real read-only process repeatedly observes the local owner.
                // Killing it models Center availability loss without an API
                // fixture or giving the observer the Run's native handles.
                var lifetime = Stopwatch.StartNew();
                while (lifetime.ElapsedMilliseconds < plan.HoldMilliseconds)
                {
                    await Task.Delay(250).ConfigureAwait(false);
                    var current = await OwnerProtocol.SendAsync(owner, new() { Operation = "status", Generation = owner.Generation }, observer: true).ConfigureAwait(false);
                    if (!current.Ok || current.State != "RUNNING" || current.OwnerPid != attached!.OwnerPid
                        || current.OwnerCreatedUtc != attached.OwnerCreatedUtc || current.ExecutorPid != attached.ExecutorPid
                        || current.ExecutorCreatedUtc != attached.ExecutorCreatedUtc)
                        throw new WindowsQualificationCheckException("center_observer_live_identity_changed");
                }
            }
            else await Task.Delay(plan.HoldMilliseconds).ConfigureAwait(false);
            // The driver must kill the exact held client process at a boundary;
            // a natural fixture timeout is never reported as a successful kill.
            return 2;
        }
        catch (Exception error)
        {
            if (plan is not null && owner is not null)
            {
                using var process = Process.GetCurrentProcess();
                // Readiness remains immutable; a later observer failure gets
                // its own bounded private record rather than losing the cause.
                string failurePath = File.Exists(plan.ReadyPath) ? plan.ReadyPath + ".failure.json" : plan.ReadyPath;
                WritePrivate(failurePath, new(owner.RunId, "client-failed", process.Id,
                    process.StartTime.ToUniversalTime(), false, FailureType: error.GetType().Name,
                    FailureHResult: error.HResult, FailureCode: error is WindowsQualificationCheckException check ? check.Code : "phase_client_native_operation_failed"));
            }
            // Do not print credentials, pipe transcripts, terminal bytes or
            // arbitrary exception messages from a client being killed.
            return 1;
        }
    }

    internal static async Task OwnerPhaseAsync(ProbeOwnerConfig config, string phase, uint? executorPid = null)
    {
        if (config.PauseAtPhase != phase) return;
        using var process = Process.GetCurrentProcess();
        var ready = Path.Combine(config.Launch.ControlDirectory, "owner-phase-ready.json");
        WritePrivate(ready, new(config.RunId, phase, process.Id, process.StartTime.ToUniversalTime(), true, ExecutorPid: executorPid));
        var releasePath = Path.Combine(config.Launch.ControlDirectory, "owner-phase-release.json");
        var clock = Stopwatch.StartNew();
        while (clock.Elapsed < TimeSpan.FromSeconds(30))
        {
            if (File.Exists(releasePath))
            {
                WindowsPolicy.VerifyPrivateFile(releasePath);
                var release = JsonSerializer.Deserialize(await File.ReadAllBytesAsync(releasePath).ConfigureAwait(false),
                    PhaseJson.Default.WindowsPhaseRelease);
                if (release?.RunId != config.RunId || release.Phase != phase)
                    throw new InvalidDataException("The owned phase release does not match this Run and boundary.");
                return;
            }
            await Task.Delay(25).ConfigureAwait(false);
        }
        throw new TimeoutException("The bounded experiment phase was not released.");
    }

    private static void WritePrivate(string path, WindowsPhaseObservation observation)
    {
        using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 4_096, FileOptions.WriteThrough))
        {
            JsonSerializer.Serialize(output, observation, PhaseJson.Default.WindowsPhaseObservation);
            output.Flush(true);
        }
        WindowsPolicy.VerifyPrivateFile(path);
    }
}

[JsonSourceGenerationOptions(WriteIndented = true, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(WindowsPhaseClientPlan))]
[JsonSerializable(typeof(WindowsPhaseObservation))]
[JsonSerializable(typeof(WindowsPhaseRelease))]
[JsonSerializable(typeof(WindowsLifecycleEvidence))]
internal sealed partial class PhaseJson : JsonSerializerContext;
