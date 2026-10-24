// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;

namespace ArcForges.Node.Platform.Windows;

/// <summary>
/// An adoption container on Windows (04 section 10): the job <c>Local\ArcForges.&lt;node&gt;.&lt;attempt&gt;</c>, nested under the root job, that
/// holds the adopted process and every process it starts afterwards. No holder keeps it open, so after a node restart it is re-opened by name
/// only if Windows still has it; otherwise the adopted task is recorded LOST, and its processes stay in the root job, whose limits still apply.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsAdoptedJob(JobObject job) : IAdoptedContainer
{
    /// <inheritdoc />
    public string ContainerName => job.Name ?? string.Empty;

    /// <inheritdoc />
    public IReadOnlyList<int> Processes() => job.Accounting().ActiveProcesses == 0 ? [] : job.ProcessIds();

    /// <inheritdoc />
    public void Terminate() => job.Terminate(WindowsExecutionPlatform.TerminatedExitCode);

    /// <inheritdoc />
    public string Abandon()
    {
        // Windows cannot take a process out of a job: the processes stay in this node's root job and in the adoption job (which ends with its
        // last process once this handle closes), under their limits, without being adopted.
        var name = ContainerName;
        job.Dispose();
        return $"the processes stay in this node's root job and the adoption job {name}, which they cannot leave; they keep running, not adopted";
    }

    /// <inheritdoc />
    public void Dispose() => job.Dispose();
}
