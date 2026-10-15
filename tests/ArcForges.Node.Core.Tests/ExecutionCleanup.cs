// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using ArcForges.Client;
using ArcForges.Node.Platform.Windows;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Ends what a test node's attempts left behind (16 section 4): attempts outlive a stopped node under their holders by design, so the
/// fixture terminates every attempt job of the store by name, sets each ack event so the holders exit, and reports any holder or attempt
/// process that is still running afterwards. Holders are the node's (this test process's) child <c>arcforges</c> processes.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class ExecutionCleanup
{
    /// <summary>Terminates and releases every attempt of <paramref name="store"/>; returns what was still running afterwards.</summary>
    public static List<string> Run(NodeStore store, IReadOnlySet<int> childrenBefore)
    {
        var node = IdText.Format(store.Metadata.NodeId.Span);
        var attempts = store.Read(reader =>
        {
            var names = new List<string>();
            using var command = reader.CreateCommand("SELECT attempt_id FROM attempt;");
            using var rows = command.ExecuteReader();
            while (rows.Read())
            {
                names.Add(IdText.Format((byte[])rows.GetValue(0)));
            }

            return names;
        });
        foreach (var attempt in attempts)
        {
            using var job = JobObject.Open(WindowsExecutionPlatform.JobName(node, attempt));
            job?.Terminate(AttemptRunner.TerminatedExitCode);
        }

        var watch = Stopwatch.StartNew();
        List<int> holders;
        do
        {
            // A holder writes its exit record after the root exited, then waits for its ack.
            foreach (var attempt in attempts)
            {
                if (EventWaitHandle.TryOpenExisting(WindowsExecutionPlatform.AckName(node, attempt), out var ack))
                {
                    using (ack)
                    {
                        ack.Set();
                    }
                }
            }

            holders = [.. Children().Where(pid => !childrenBefore.Contains(pid))];
            if (holders.Count == 0)
            {
                break;
            }

            Thread.Sleep(100);
        }
        while (watch.Elapsed < TimeSpan.FromSeconds(20));

        var leftovers = new List<string>();
        foreach (var pid in holders)
        {
            leftovers.Add($"arcforges holder {pid}");
            try
            {
                using var process = Process.GetProcessById(pid);
                process.Kill(entireProcessTree: true);
            }
            catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
            }
        }

        foreach (var attempt in attempts)
        {
            using var job = JobObject.Open(WindowsExecutionPlatform.JobName(node, attempt));
            if (job is not null && job.Accounting().ActiveProcesses > 0)
            {
                leftovers.Add($"processes in job {attempt}");
                job.Terminate(AttemptRunner.TerminatedExitCode);
            }
        }

        return leftovers;
    }

    /// <summary>This process's child <c>arcforges</c> processes (the holders of in-process test nodes).</summary>
    public static HashSet<int> Children() =>
        [.. ProcessInfo.Snapshot().Where(entry => entry.ParentPid == Environment.ProcessId && entry.Image.Equals("arcforges.exe", StringComparison.OrdinalIgnoreCase))
            .Select(entry => entry.Pid)];
}
