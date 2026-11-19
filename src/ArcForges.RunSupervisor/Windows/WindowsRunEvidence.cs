// SPDX-License-Identifier: AGPL-3.0-only

using System.Runtime.Versioning;
using System.Text.Json;
using ArcForges.Node.Platform.Windows.Mxc;
using ArcForges.RunSupervisor.Protocol;

namespace ArcForges.RunSupervisor;

[SupportedOSPlatform("windows")]
internal sealed class WindowsRunEvidence(RunLaunchSpec spec, string policySha256, int executorPid, long executorBirth)
{
    internal void WritePrepared(WindowsMxcJobLimits applied, WindowsMxcJobObservation aggregate, WindowsMxcJobObservation payload)
    {
        Write("windows-prepared.json", json =>
        {
            json.WriteNumber("cpuRate", applied.CpuRate);
            json.WriteNumber("commitLimitBytes", applied.CommitBytes);
            json.WriteNumber("maxProcesses", applied.MaxProcesses);
            WriteJob(json, "aggregate", aggregate);
            WriteJob(json, "payload", payload);
        });
    }

    internal void WriteDrained(int rawExit, string reason, WindowsMxcJobObservation aggregate, WindowsMxcJobObservation payload)
    {
        Write("windows-drained.json", json =>
        {
            json.WriteNumber("rawExitCode", rawExit);
            json.WriteString("exitSource", RunExitSources.OfficialExecutor);
            json.WriteString("terminationReason", reason);
            json.WriteBoolean("outputDrainCompleted", true);
            WriteJob(json, "aggregate", aggregate);
            WriteJob(json, "payload", payload);
        });
    }

    private void Write(string fileName, Action<Utf8JsonWriter> payload)
    {
        using var file = new FileStream(Path.Combine(spec.ControlDirectory, fileName), FileMode.CreateNew,
            FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        using var json = new Utf8JsonWriter(file);
        json.WriteStartObject();
        json.WriteString("runId", spec.RunId);
        json.WriteString("ownerInstance", spec.OwnerId);
        json.WriteString("launchSha256", spec.LaunchSha256);
        json.WriteString("policySha256", policySha256);
        json.WriteString("profileVersion", spec.ProfileVersion);
        json.WriteNumber("ownerPid", Environment.ProcessId);
        json.WriteNumber("ownerCreationFileTime", WindowsMxcProcess.CurrentCreationFileTime());
        json.WriteNumber("executorPid", executorPid);
        json.WriteNumber("executorCreationFileTime", executorBirth);
        json.WriteString("terminalMode", spec.TerminalMode.ToString());
        json.WriteString("observedUtc", DateTimeOffset.UtcNow);
        payload(json);
        json.WriteEndObject();
        json.Flush();
        file.Flush(flushToDisk: true);
    }

    private static void WriteJob(Utf8JsonWriter json, string name, WindowsMxcJobObservation observation)
    {
        json.WriteStartObject(name);
        json.WriteNumber("activeProcesses", observation.ActiveProcesses);
        json.WriteStartArray("processIds");
        foreach (var pid in observation.ProcessIds) json.WriteNumberValue(pid);
        json.WriteEndArray();
        json.WriteNumber("userTimeTicks", observation.Accounting.UserTime.Ticks);
        json.WriteNumber("kernelTimeTicks", observation.Accounting.KernelTime.Ticks);
        json.WriteNumber("peakCommitBytes", observation.Accounting.PeakJobMemory);
        json.WriteEndObject();
    }
}
