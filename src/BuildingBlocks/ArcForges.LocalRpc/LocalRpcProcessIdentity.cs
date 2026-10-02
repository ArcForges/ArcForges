// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;

namespace ArcForges.LocalRpc;

/// <summary>The closed set of children a parent launches. There is no other kind and no discovery of children.</summary>
public enum LocalRpcChildKind
{
    /// <summary>No child; never a valid launch.</summary>
    None = 0,

    /// <summary>The first-party restricted content parser helper.</summary>
    ContentSandbox = 1,

    /// <summary>An admitted executable extension.</summary>
    ExecutableExtension = 2,

    /// <summary>An owned connector adapter child.</summary>
    Connector = 3,
}

/// <summary>
/// An OS process named by its id and its start time. An id alone is reused by the OS, so a stale record that names a
/// recycled id does not match the new process.
/// </summary>
/// <param name="ProcessId">The OS process id.</param>
/// <param name="StartTimeUtcTicks">The UTC start time of the process in <see cref="DateTime.Ticks"/>.</param>
public readonly record struct LocalRpcProcessIdentity(int ProcessId, long StartTimeUtcTicks)
{
    /// <summary>
    /// Two reads of one process start time can differ by the OS clock resolution (Linux derives it from boot time and
    /// clock ticks), so a start time within this distance names the same process.
    /// </summary>
    internal static readonly TimeSpan StartTimeTolerance = TimeSpan.FromSeconds(2);

    private static readonly Lazy<LocalRpcProcessIdentity> CurrentProcess = new(() => FromProcess(Process.GetCurrentProcess()));

    /// <summary>The identity of the running process.</summary>
    public static LocalRpcProcessIdentity Current => CurrentProcess.Value;

    /// <summary>Names a live process by id and start time. The process must not have exited.</summary>
    public static LocalRpcProcessIdentity FromProcess(Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        return new LocalRpcProcessIdentity(process.Id, process.StartTime.ToUniversalTime().Ticks);
    }

    internal bool Names(LocalRpcProcessIdentity other) =>
        ProcessId == other.ProcessId
        && ProcessId > 0
        && Math.Abs(StartTimeUtcTicks - other.StartTimeUtcTicks) <= StartTimeTolerance.Ticks;
}

/// <summary>What the OS reports about a named process.</summary>
internal enum ProcessLiveness
{
    /// <summary>No process with this id and start time exists.</summary>
    Dead = 0,

    /// <summary>The named process is running.</summary>
    Live = 1,

    /// <summary>The OS would not say (for example access denied); callers that authorize treat this as not live and callers that delete treat it as live.</summary>
    Unknown = 2,
}

internal static class ProcessProbe
{
    internal static ProcessLiveness Probe(LocalRpcProcessIdentity identity)
    {
        if (identity.ProcessId <= 0)
        {
            return ProcessLiveness.Dead;
        }

        try
        {
            using var process = Process.GetProcessById(identity.ProcessId);
            if (process.HasExited)
            {
                return ProcessLiveness.Dead;
            }

            var observed = new LocalRpcProcessIdentity(identity.ProcessId, process.StartTime.ToUniversalTime().Ticks);
            return observed.Names(identity) ? ProcessLiveness.Live : ProcessLiveness.Dead;
        }
        catch (ArgumentException)
        {
            return ProcessLiveness.Dead;
        }
        catch (InvalidOperationException)
        {
            return ProcessLiveness.Dead;
        }
        catch (Win32Exception)
        {
            return ProcessLiveness.Unknown;
        }
        catch (NotSupportedException)
        {
            return ProcessLiveness.Unknown;
        }
    }
}
