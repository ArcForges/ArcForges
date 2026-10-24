// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using ArcForges.Tests;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// The stop sequence's escaped-process step (04 section 6 step 4: <c>terminate_escaped</c>, true for cancellation) with a real node, real
/// containers and real processes, on each OS (env=windows-real, env=linux-real; repair MR-01). The attempt's root traps the graceful signal
/// and exits at once, so the stop never reaches its forced phase. The processes the node recorded as the attempt's ESCAPED processes are
/// terminated when the stop sequence ends, after a node restart too (the process records are then all the node has), each by its process ID
/// and start time: a record whose ID now names a later process (a reused ID) is never terminated. An attempt that ends on its own keeps
/// its escaped processes (step 4 belongs to the stop sequence).
/// <para>
/// The escaped processes are recorded by the test, as the ancestry scan records one (process_record, label ESCAPED): a node attempt cannot
/// escape its job on Windows (no breakaway, and every process of the workstation is already in a job, L-30), and after its root exits an
/// escaped process on Linux no longer descends from the attempt, so the records are what the step must use. The closed-loop test
/// <c>AnEscapedProcessOfAnAttemptCancelledGracefullyIsTerminatedOnLinux</c> makes a real escape on Linux.
/// </para>
/// </summary>
public sealed class EscapedTerminationTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 180_000)]
    [Trait("env", "windows-real")]
    public async Task RecordedEscapedProcessesAreTerminatedWhenTheRootEndsOnTheGracefulSignalOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await RecordedEscapedProcessesAsync(
            (root, ready) => Tasks.Argv(root, Tasks.TestLoad, "signal", "--hold-ms", "120000", "--marker", ready),
            ready => Tasks.Marker(ready).Any(line => line.Event == "ready"),
            (root, go) => Tasks.Argv(root, Tasks.WaitForFile(go)),
            "CTRL_BREAK_EVENT delivered");
    }

    [Fact(Timeout = 180_000)]
    [Trait("env", "linux-real")]
    public async Task RecordedEscapedProcessesAreTerminatedWhenTheRootEndsOnTheGracefulSignalOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        await RecordedEscapedProcessesAsync(
            (root, ready) => Tasks.Argv(root, "/bin/sh", "-c", "trap 'exit 0' TERM; echo ready > \"$1\"; sleep 120 & wait", "sh", ready),
            File.Exists,
            (root, go) => Tasks.Argv(root, "/bin/sh", "-c", "while [ ! -e \"$1\" ]; do sleep 0.05; done", "sh", go),
            "SIGTERM sent to every process");
    }

    private static async Task RecordedEscapedProcessesAsync(Func<string, string, TaskSpec> trapping, Func<string, bool> trapped,
        Func<string, string, TaskSpec> untilFile, string graceful)
    {
        var image = Path.GetFileName(Tasks.TestLoad);
        using var escaped = StartOutside();
        using var reused = StartOutside();
        using var ownEnd = StartOutside();
        try
        {
            await using var node = await InProcessNode.Create().StartAsync();
            var ready = Path.Combine(node.Root, "ready.txt");
            var go = Path.Combine(node.Root, "go");
            Id stopped, ended;
            Attempt stoppedAttempt, endedAttempt;
            await using (var channel = await node.ChannelAsync())
            {
                stopped = await Tasks.SubmitAsync(channel, trapping(node.Root, ready));
                ended = await Tasks.SubmitAsync(channel, untilFile(node.Root, go));
                stoppedAttempt = await Tasks.RunningAsync(channel, stopped);
                endedAttempt = await Tasks.RunningAsync(channel, ended);
                await Tasks.WaitForAsync(() => trapped(ready), Tasks.Bound, "the root to handle the graceful signal");
            }

            // The stopped attempt's escaped process; a record of it whose ID now names a later process (the record's process exited and
            // its ID was reused); and an escaped process of the attempt that will end on its own.
            RecordEscaped(node, stoppedAttempt.AttemptId, escaped.Id, StartOf(escaped.Id), image);
            RecordEscaped(node, stoppedAttempt.AttemptId, reused.Id, StartOf(reused.Id).AddSeconds(-30), image);
            RecordEscaped(node, endedAttempt.AttemptId, ownEnd.Id, StartOf(ownEnd.Id), image);

            // After a node restart the records are all the node knows of them.
            await node.StopAsync();
            await node.StartAsync();
            await using var after = await node.ChannelAsync();
            await File.WriteAllTextAsync(go, "go", Ct);
            Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(after, ended)).State);

            await after.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = stopped, Reason = "test" }, cancellationToken: Ct);
            var task = await Tasks.WaitAsync(after, stopped);
            Assert.Equal(TaskState.Cancelled, task.State);
            Assert.Equal(TerminationReason.Cancelled, task.CurrentAttempt.Result.TerminationReason);
            var detail = task.CurrentAttempt.Result.Detail;
            Assert.Contains(graceful, detail, StringComparison.Ordinal);
            Assert.Contains(string.Create(CultureInfo.InvariantCulture, $"escaped processes terminated: {image} ({escaped.Id})"), detail, StringComparison.Ordinal);
            Assert.True(escaped.WaitForExit(TimeSpan.FromSeconds(10)), "The stopped attempt's escaped process was terminated.");

            // Never a process whose ID matches but whose start does not, and never an escaped process of an attempt that ended on its own.
            Assert.DoesNotContain(string.Create(CultureInfo.InvariantCulture, $"({reused.Id})"), detail, StringComparison.Ordinal);
            Assert.False(reused.HasExited, "A process that reused a recorded ID was terminated.");
            Assert.False(ownEnd.HasExited, "An escaped process of an attempt that ended on its own was terminated.");
        }
        finally
        {
            foreach (var process in (Process[])[escaped, reused, ownEnd])
            {
                if (!process.HasExited)
                {
                    process.Kill();
                    process.WaitForExit(TimeSpan.FromSeconds(10));
                }
            }
        }
    }

    /// <summary>A process of the test's user outside every attempt container (<c>arcforges-testload hold</c>).</summary>
    private static Process StartOutside()
    {
        var start = new ProcessStartInfo(Tasks.TestLoad)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in (string[])["hold", "--hold-ms", "150000"])
        {
            start.ArgumentList.Add(argument);
        }

        return Process.Start(start) ?? throw new InvalidOperationException("arcforges-testload did not start");
    }

    /// <summary>The process's start time as the node's platform reads it (Windows: its creation FILETIME; Linux: <c>/proc</c>).</summary>
    private static DateTimeOffset StartOf(int pid)
    {
        if (OperatingSystem.IsWindows())
        {
            using var handle = ArcForges.Node.Platform.Windows.ProcessInfo.Open(pid) ?? throw new InvalidOperationException($"process {pid} is gone");
            return ArcForges.Node.Platform.Windows.ProcessInfo.FromFileTime(ArcForges.Node.Platform.Windows.ProcessInfo.CreationFileTime(handle));
        }

        if (OperatingSystem.IsLinux())
        {
            return ArcForges.Node.Platform.Linux.ProcFs.StartOf(pid)?.Start ?? throw new InvalidOperationException($"process {pid} is gone");
        }

        throw new PlatformNotSupportedException();
    }

    /// <summary>Records <paramref name="pid"/> as an ESCAPED process of the attempt, as the ancestry scan records one (04 section 3).</summary>
    private static void RecordEscaped(InProcessNode node, Id attemptId, int pid, DateTimeOffset start, string image) =>
        node.Runtime.Store.Write(transaction => transaction.Execute(
            """
            INSERT INTO process_record (attempt_id, pid, start_at, parent_pid, executable, arguments_redacted, first_seen, last_seen, mem_peak_bytes, label)
            VALUES ($attempt, $pid, $start, 0, $image, NULL, $now, $now, 0, $label);
            """,
            ("$attempt", attemptId.Value.ToByteArray()), ("$pid", pid), ("$start", StoreTime.ToMicroseconds(start)), ("$image", image),
            ("$now", transaction.NowMicroseconds), ("$label", (int)ProcessLabel.Escaped)));
}
