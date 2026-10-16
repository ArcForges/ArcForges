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
/// process that is still running afterwards. Holders are the node's (this test process's) child <c>arcforges</c> processes; tests run in
/// parallel, so a node's holders are the ones whose command line names one of its attempts (<c>node exec-wrap --attempt &lt;name&gt;</c>).
/// </summary>
[SupportedOSPlatform("windows")]
internal static class ExecutionCleanup
{
    /// <summary>Terminates and releases every attempt of <paramref name="store"/>; returns what was still running afterwards.</summary>
    public static List<string> Run(NodeStore store)
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

            holders = [.. Holders(attempts)];
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

            // Killed only while it is still this node's holder (an ID reused meanwhile belongs to another process).
            if (ArcForges.Tests.ProcessIdentity.Capture(pid) is { } holder && Holders(attempts).Contains(pid))
            {
                holder.Kill();
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

    /// <summary>The running holders of <paramref name="attempts"/>: this process's child <c>arcforges</c> processes started for one of them.</summary>
    public static HashSet<int> Holders(IReadOnlyCollection<string> attempts) =>
        [.. Children().Where(pid => ArcForges.Tests.ProcessInspection.CommandLine(pid) is { } line && AttemptOf(line) is { } attempt && attempts.Contains(attempt))];

    private static string? AttemptOf(string commandLine)
    {
        var arguments = WindowsCommandLine.Parse(commandLine);
        var index = arguments.IndexOf("--attempt");
        return index >= 0 && index + 1 < arguments.Count ? arguments[index + 1] : null;
    }

    /// <summary>This process's child <c>arcforges</c> processes (the holders of every in-process test node).</summary>
    /// <remarks>An orphan of an earlier process that had this process's ID names it as parent too; it is older than this process and left out.</remarks>
    public static HashSet<int> Children()
    {
        var self = ArcForges.Tests.ProcessIdentity.Capture(Environment.ProcessId)!.Value.StartKey;
        return [.. ProcessInfo.Snapshot().Where(entry => entry.ParentPid == Environment.ProcessId && entry.Image.Equals("arcforges.exe", StringComparison.OrdinalIgnoreCase))
            .Select(entry => entry.Pid).Where(pid => ArcForges.Tests.ProcessIdentity.StartKeyOf(pid) is { } start && start >= self)];
    }
}
