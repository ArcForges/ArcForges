// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Policy;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Helpers of the TaskService tests: specs, submissions, waits and output reads through the real client.</summary>
internal static class Tasks
{
    public static readonly TimeSpan Bound = TimeSpan.FromSeconds(60);

    /// <summary><c>arcforges-testload</c> next to the tests, or <c>ARCFORGES_TESTLOAD_PATH</c>.</summary>
    public static string TestLoad => Environment.GetEnvironmentVariable("ARCFORGES_TESTLOAD_PATH") is { Length: > 0 } configured
        ? configured
        : Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? "arcforges-testload.exe" : "arcforges-testload");

    public static string Cmd => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>An argv spec in <paramref name="directory"/> inheriting the node's environment.</summary>
    public static TaskSpec Argv(string directory, params string[] argv)
    {
        var command = new ArgvCommand();
        command.Argv.Add(argv);
        return new TaskSpec
        {
            Command = new CommandSpec { Argv = command },
            WorkingDirectory = directory,
            Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Node },
        };
    }

    public static RequestMeta Meta() => new() { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };

    /// <summary>Submits; fails the test on an error.</summary>
    public static async Task<Id> SubmitAsync(NodeChannel channel, TaskSpec spec, bool cancelWhenCallerGone = false)
    {
        var response = await SubmitRawAsync(channel, spec, cancelWhenCallerGone);
        Assert.True(response.Error is null, $"SubmitTask failed: {response.Error?.Category}/{response.Error?.Code} {response.Error?.Details}");
        return response.Value.TaskId;
    }

    public static async Task<TaskServiceSubmitTaskResponse> SubmitRawAsync(NodeChannel channel, TaskSpec spec, bool cancelWhenCallerGone = false) =>
        await channel.Tasks.SubmitTaskAsync(new TaskServiceSubmitTaskRequest { Meta = Meta(), Spec = spec, CancelWhenCallerGone = cancelWhenCallerGone },
            deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: Ct);

    public static async Task<ManagedTask> GetAsync(NodeChannel channel, Id taskId, bool full = false)
    {
        var response = await channel.Tasks.GetTaskAsync(new TaskServiceGetTaskRequest { Meta = Meta(), TaskId = taskId, Detail = full ? TaskDetail.Full : TaskDetail.Summary },
            deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct);
        Assert.Null(response.Error);
        return response.Value.Task;
    }

    /// <summary>Waits (bounded) for the task to reach <paramref name="target"/>; returns it.</summary>
    public static async Task<ManagedTask> WaitAsync(NodeChannel channel, Id taskId, WaitTarget target = WaitTarget.Terminal, TimeSpan? bound = null)
    {
        var watch = Stopwatch.StartNew();
        var limit = bound ?? Bound;
        while (true)
        {
            var response = await channel.Tasks.WaitTaskAsync(new TaskServiceWaitTaskRequest { Meta = Meta(), TaskId = taskId, Target = target, WaitMs = 5_000 },
                deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: Ct);
            Assert.Null(response.Error);
            if (response.Value.Reached)
            {
                return response.Value.Task;
            }

            Assert.True(watch.Elapsed < limit, $"Task {IdText.Format(taskId)} did not reach {target} within {limit.TotalSeconds:0} s (state {response.Value.Task.State}).");
        }
    }

    /// <summary>Waits for an attempt's root process to be recorded (the attempt is RUNNING).</summary>
    public static async Task<Attempt> RunningAsync(NodeChannel channel, Id taskId)
    {
        var watch = Stopwatch.StartNew();
        while (true)
        {
            var task = await GetAsync(channel, taskId);
            if (task.CurrentAttempt is { State: AttemptState.Running } attempt)
            {
                return attempt;
            }

            Assert.True(watch.Elapsed < Bound, $"The attempt did not run (state {task.State}).");
            await Task.Delay(50, Ct);
        }
    }

    /// <summary>Reads one stream (or the merged view) of an attempt completely.</summary>
    public static async Task<byte[]> ReadAllAsync(NodeChannel channel, Id attemptId, OutputStream stream)
    {
        using var buffer = new MemoryStream();
        ulong offset = 0;
        while (true)
        {
            var response = await channel.Tasks.ReadTaskOutputAsync(new TaskServiceReadTaskOutputRequest
            {
                Meta = Meta(),
                AttemptId = attemptId,
                Stream = stream,
                FromOffset = offset,
                MaxBytes = 4 * 1024 * 1024,
            }, deadline: DateTime.UtcNow.AddSeconds(30), cancellationToken: Ct);
            Assert.Null(response.Error);
            buffer.Write(response.Value.Data.Span);
            if (response.Value.Data.Length == 0)
            {
                return buffer.ToArray();
            }

            offset = response.Value.NextOffset;
        }
    }

    /// <summary>Runs <paramref name="argv"/> directly (no node) and returns its exit code and the bytes of its streams.</summary>
    public static (int ExitCode, byte[] Stdout, byte[] Stderr) Direct(string directory, params string[] argv)
    {
        var start = new ProcessStartInfo(argv[0])
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            CreateNoWindow = true,
            WorkingDirectory = directory,
        };
        foreach (var argument in argv.Skip(1))
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        process.StandardInput.Close();
        using var stdout = new MemoryStream();
        using var stderr = new MemoryStream();
        var copyOut = process.StandardOutput.BaseStream.CopyToAsync(stdout, Ct);
        var copyErr = process.StandardError.BaseStream.CopyToAsync(stderr, Ct);
        Assert.True(process.WaitForExit(TimeSpan.FromSeconds(60)));
        Task.WaitAll([copyOut, copyErr], Ct);
        return (process.ExitCode, stdout.ToArray(), stderr.ToArray());
    }

    /// <summary>Writes policy revision 2 with <paramref name="change"/> applied to the default document (tests seed policy; PolicyService is AF-SCHED-01's).</summary>
    public static void SeedPolicy(StoreTransaction transaction, Action<PolicyDocument> change)
    {
        var document = PolicyDocuments.Current(transaction).Document.Clone();
        change(document);
        transaction.Execute("UPDATE policy_document SET is_current = 0 WHERE is_current = 1;");
        transaction.Execute(
            """
            INSERT INTO policy_document (revision, document, digest, created_at, actor, comment, approval_id, is_current)
            VALUES (2, $document, $digest, $now, $actor, 'test policy', NULL, 1);
            """,
            ("$document", document.ToByteArray()),
            ("$digest", PolicyDocuments.Digest(document)),
            ("$now", transaction.NowMicroseconds),
            ("$actor", new ActorRef { Origin = Origin.Human }.ToByteArray()));
    }

    /// <summary>The attempt's files under the node's data root.</summary>
    public static AttemptFiles Files(InProcessNode node, Id attemptId) => new(node.DataRoot, IdText.Format(attemptId));

    /// <summary>A launch step provider returning fixed synthetic steps.</summary>
    public sealed class FixedSteps(Func<AttemptFiles, IReadOnlyList<StepSpec>> launch, Func<AttemptFiles, IReadOnlyList<StepSpec>> end) : ArcForges.Node.Core.Execution.ILaunchStepProvider
    {
        public (IReadOnlyList<StepSpec> Launch, IReadOnlyList<StepSpec> End) StepsFor(TaskSpec spec, AttemptFiles files) => (launch(files), end(files));
    }

    /// <summary>The lines of an <c>arcforges-testload signal</c> marker: (event, pid, unix ms).</summary>
    public static List<(string Event, int Pid, long At)> Marker(string path)
    {
        if (!File.Exists(path))
        {
            return [];
        }

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        return [.. reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => line.Split(' ')).Where(parts => parts.Length == 3)
            .Select(parts => (parts[0], int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture), long.Parse(parts[2], System.Globalization.CultureInfo.InvariantCulture)))];
    }

    /// <summary>
    /// The processes of a marker file, each identified by its ID and the first moment it wrote a line (so a process that later reused the
    /// ID is never mistaken for it).
    /// </summary>
    public static List<ArcForges.Tests.ProcessIdentity> Processes(string marker) =>
        [.. Marker(marker).GroupBy(line => line.Pid).Select(group => ArcForges.Tests.ProcessIdentity.CreatedNoLaterThan(group.Key, group.Min(line => line.At)))];

    public static async Task WaitForAsync(Func<bool> condition, TimeSpan timeout, string what)
    {
        var watch = Stopwatch.StartNew();
        while (!condition())
        {
            Assert.True(watch.Elapsed < timeout, $"Timed out after {timeout.TotalSeconds:0.#} s waiting for {what}.");
            await Task.Delay(25, Ct);
        }
    }

    public static ByteString Bytes(string text) => ByteString.CopyFromUtf8(text);
}
