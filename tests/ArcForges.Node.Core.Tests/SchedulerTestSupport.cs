// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Helpers of the scheduler tests: <c>arcforges-testload hold</c> specs with start/end markers, queue and policy calls, seeds.</summary>
internal static class Sched
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>On Linux the tests need the user manager's transient units; on Windows the job platform is always there.</summary>
    public static void RequirePlatform()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.SkipWhen(ArcForges.Tests.SystemdTestEnvironment.SkipReason is not null, ArcForges.Tests.SystemdTestEnvironment.SkipReason ?? string.Empty);
        }
    }

    /// <summary>A <c>hold</c> task recording its start and end in <paramref name="marker"/>.</summary>
    public static TaskSpec Hold(InProcessNode node, string marker, int holdMs, params string[] extra) =>
        Hold(node.Root, marker, holdMs, extra);

    /// <summary>
    /// A <c>hold</c> task in <paramref name="directory"/> with a small hint (100 millicores, 64 MiB), so the tests that run several at once
    /// fit even when parallel tests shrink the measured budget to its minimum.
    /// </summary>
    public static TaskSpec Hold(string directory, string marker, int holdMs, params string[] extra)
    {
        var spec = Tasks.Argv(directory, [Tasks.TestLoad, "hold", "--hold-ms", holdMs.ToString(CultureInfo.InvariantCulture), "--marker", marker, .. extra]);
        spec.Resources = new ResourceSpec { Hint = new ResourceDemand { CpuMillicores = 100, MemExpectedBytes = 64UL << 20 } };
        return spec;
    }

    /// <summary>When a <c>hold</c> process recorded its readiness (unix ms); -1 when absent.</summary>
    public static long ReadyAt(string marker) =>
        Tasks.ReadShared(marker).Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => line.Split(' '))
            .LastOrDefault(parts => parts.Length == 3 && parts[0] == "ready") is { } ready ? long.Parse(ready[2], CultureInfo.InvariantCulture) : -1;

    /// <summary>An instant in unix milliseconds.</summary>
    public static long Ms(Instant instant) => (instant.UnixSeconds * 1000) + (instant.Nanos / 1_000_000);

    /// <summary>Polls ExplainTask until its blocking reason is <paramref name="reason"/> (the next admission pass records it).</summary>
    public static async Task<AdmissionExplanation> ExplainedAsync(NodeChannel channel, Id taskId, string reason, TimeSpan? bound = null, string what = "")
    {
        var limit = bound ?? Tasks.Bound;
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var seen = new List<string>();
        while (true)
        {
            var explanation = await ExplainAsync(channel, taskId);
            if (explanation.BlockingReason == reason)
            {
                return explanation;
            }

            var observed = $"{explanation.State} {explanation.BlockingReason} ({explanation.Text})";
            if (seen.Count == 0 || seen[^1] != observed)
            {
                seen.Add(observed);
            }

            Assert.True(watch.Elapsed < limit, $"{what} task {IdText.Format(taskId)}: blocking reason {reason} not reached within {limit.TotalSeconds:0} s; seen: {string.Join("; ", seen)}.");
            await Task.Delay(100, Ct);
        }
    }

    /// <summary>
    /// Lifts the default pool's AUTO limit (<c>floor(B_cpu / 1000)</c>, as low as 1 while parallel tests load the machine) for tests whose
    /// tasks must be able to run side by side.
    /// </summary>
    public static Task<Revision> WidenAsync(NodeChannel channel) => SetParallelismAsync(channel, ParallelismScope.Pool, "default", ParallelismMode.Fixed, 64);

    /// <summary>Adds an exclusive key.</summary>
    public static TaskSpec Exclusive(TaskSpec spec, string key)
    {
        spec.Concurrency ??= new ConcurrencySpec();
        spec.Concurrency.ExclusiveKeys.Add(key);
        return spec;
    }

    /// <summary>Adds a shared key.</summary>
    public static TaskSpec Shared(TaskSpec spec, string key)
    {
        spec.Concurrency ??= new ConcurrencySpec();
        spec.Concurrency.SharedKeys.Add(key);
        return spec;
    }

    /// <summary>Adds a dependency.</summary>
    public static TaskSpec DependsOn(TaskSpec spec, Id taskId, DependencyCondition condition = DependencyCondition.Succeeded)
    {
        spec.DependsOn.Add(new Dependency { TaskId = taskId, Condition = condition });
        return spec;
    }

    /// <summary>Cancels a task and waits for it to end.</summary>
    public static async Task CancelAsync(NodeChannel channel, Id taskId)
    {
        await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = taskId, Reason = "test" }, cancellationToken: Ct);
        await Tasks.WaitAsync(channel, taskId);
    }

    /// <summary>A long field of a log event.</summary>
    public static long Field(JsonElement logEvent, string name) => logEvent.GetProperty("fields").GetProperty(name).GetInt64();

    /// <summary>A string field of a log event.</summary>
    public static string Text(JsonElement logEvent, string name) => logEvent.GetProperty("fields").GetProperty(name).GetString() ?? string.Empty;

    /// <summary>The start and end (unix ms) a <c>hold</c> process recorded; -1 when absent.</summary>
    public static (long Start, long End) Window(string marker)
    {
        var lines = Tasks.ReadShared(marker).Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => line.Split(' ')).Where(parts => parts.Length == 3).ToList();
        long At(string what) => lines.LastOrDefault(parts => parts[0] == what) is { } parts ? long.Parse(parts[2], CultureInfo.InvariantCulture) : -1;
        return (At("start"), At("end"));
    }

    /// <summary>True when two recorded windows overlap in time.</summary>
    public static bool Overlap((long Start, long End) first, (long Start, long End) second) => first.Start < second.End && second.Start < first.End;

    /// <summary>A free loopback TCP port.</summary>
    public static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    public static async Task<AdmissionExplanation> ExplainAsync(NodeChannel channel, Id taskId)
    {
        var response = await channel.Queue.ExplainTaskAsync(new QueueServiceExplainTaskRequest { Meta = Tasks.Meta(), TaskId = taskId }, cancellationToken: Ct);
        Assert.True(response.Error is null, $"ExplainTask failed: {response.Error?.Code}");
        return response.Value.Explanation;
    }

    public static async Task<QueueServiceGetQueueValue> QueueAsync(NodeChannel channel)
    {
        var response = await channel.Queue.GetQueueAsync(new QueueServiceGetQueueRequest { Meta = Tasks.Meta() }, cancellationToken: Ct);
        Assert.True(response.Error is null, $"GetQueue failed: {response.Error?.Code}");
        return response.Value;
    }

    public static async Task<ResourceSnapshot> SnapshotAsync(NodeChannel channel)
    {
        while (true)
        {
            var response = await channel.Resources.GetResourceSnapshotAsync(new ResourceServiceGetResourceSnapshotRequest { Meta = Tasks.Meta() }, cancellationToken: Ct);
            Assert.Null(response.Error);
            if (response.Value.Snapshot.HasBudgetMemBytes)
            {
                return response.Value.Snapshot;
            }

            await Task.Delay(200, Ct);
        }
    }

    /// <summary>Waits until <paramref name="condition"/> holds on the task (bounded).</summary>
    public static async Task<ManagedTask> UntilAsync(NodeChannel channel, Id taskId, Func<ManagedTask, bool> condition, string what, TimeSpan? bound = null)
    {
        var limit = bound ?? Tasks.Bound;
        var watch = System.Diagnostics.Stopwatch.StartNew();
        while (true)
        {
            var task = await Tasks.GetAsync(channel, taskId);
            if (condition(task))
            {
                return task;
            }

            Assert.True(watch.Elapsed < limit, $"Task {IdText.Format(taskId)}: {what} not reached within {limit.TotalSeconds:0} s (state {task.State}, reason {task.StateReason}).");
            await Task.Delay(100, Ct);
        }
    }

    public static async Task<Revision> SetParallelismAsync(NodeChannel channel, ParallelismScope scope, string target, ParallelismMode mode, uint? limit = null)
    {
        var request = new QueueServiceSetParallelismRequest { Meta = Tasks.Meta(), Scope = scope, Mode = mode };
        if (target.Length > 0)
        {
            request.Target = target;
        }

        if (limit is { } value)
        {
            request.Fixed = value;
        }

        var response = await channel.Queue.SetParallelismAsync(request, cancellationToken: Ct);
        Assert.True(response.Error is null, $"SetParallelism failed: {response.Error?.Code} {response.Error?.Details}");
        return response.Value.PolicyRevision;
    }

    /// <summary>Applies <paramref name="change"/> to the current policy through UpdatePolicy (as the channel's origin).</summary>
    public static async Task<PolicyServiceUpdatePolicyResponse> ChangePolicyAsync(NodeChannel channel, Action<PolicyDocument> change)
    {
        var current = await channel.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = Tasks.Meta() }, cancellationToken: Ct);
        Assert.Null(current.Error);
        var document = current.Value.Document.Clone();
        change(document);
        var meta = Tasks.Meta();
        meta.ExpectedRev = current.Value.Revision.Revision;
        return await channel.Policy.UpdatePolicyAsync(new PolicyServiceUpdatePolicyRequest { Meta = meta, Document = document, Comment = "test" }, cancellationToken: Ct);
    }

    /// <summary>Inserts a registered workspace (workspaces are AF-WS-01's; the scheduler reads their root and concurrency mode).</summary>
    public static byte[] SeedWorkspace(StoreTransaction transaction, string root, WorkspaceConcurrency mode)
    {
        var id = StoreIds.NewUuid7(transaction.Clock);
        transaction.Execute(
            """
            INSERT INTO workspace (workspace_id, kind, state, name, root_path, concurrency_mode, created_at, last_used_at, rev)
            VALUES ($id, 1, 2, $name, $root, $mode, $now, $now, 0);
            """,
            ("$id", id), ("$name", Path.GetFileName(root)), ("$root", root), ("$mode", (int)mode), ("$now", transaction.NowMicroseconds));
        return id;
    }

    /// <summary>Inserts an AI client session (sessions arrive with AF-AI-01; the scheduler shares fairly across their owners).</summary>
    public static byte[] SeedSession(StoreTransaction transaction)
    {
        var id = StoreIds.NewUuid7(transaction.Clock);
        transaction.Execute(
            "INSERT INTO session (session_id, client, source, state, started_at, last_activity_at, rev) VALUES ($id, 1, 1, 1, $now, $now, 0);",
            ("$id", id), ("$now", transaction.NowMicroseconds));
        return id;
    }

    /// <summary>
    /// Submits through the supervisor as a session's task (the node sets the owner from the connection, and sessions arrive with
    /// AF-AI-01: this test seam submits with the owner a session's connection will carry; admission, launch and records are the node's own).
    /// </summary>
    public static async Task<Id> SubmitAsSessionAsync(InProcessNode node, TaskSpec spec, byte[] session, string pool = "default")
    {
        var execution = node.Runtime.Execution!;
        var settings = execution.Settings;
        var plan = new SubmitPlan
        {
            Parts = SubmittedEnvironment.Split(spec, settings.SecretNames),
            Owner = new ActorRef { Origin = Origin.Agent, ClientKind = ClientKind.McpAdapter, SessionId = new Id { Value = ByteString.CopyFrom(session) } },
            Title = "fair share",
            Summary = CommandText.Summary(spec.Command, settings.SecretNames),
            Fingerprint = CommandText.Fingerprint(spec.Command),
            CommandDigest = SHA256.HashData(spec.ToByteArray()),
            Pool = pool,
            SessionId = session,
            CommandId = CommandIds.New(),
        };
        var value = await node.Runtime.Processor.ExecuteAsync(context => execution.Submit(context, plan));
        execution.Submitted(value.TaskId.Value.Span, null);
        return value.TaskId;
    }

    /// <summary>The node log's events named <paramref name="name"/>.</summary>
    public static List<JsonElement> LogEvents(InProcessNode node, string name)
    {
        var log = Path.Combine(node.DataRoot, "logs", "node", "node.log");
        return [.. Tasks.ReadShared(log).Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line =>
        {
            try
            {
                return JsonDocument.Parse(line).RootElement.Clone();
            }
            catch (JsonException)
            {
                return default;
            }
        }).Where(element => element.ValueKind == JsonValueKind.Object && element.TryGetProperty("event", out var value) && value.GetString() == name)];
    }

    /// <summary>A synthetic adapter for <c>arcforges-testload cpu</c>: it sets <c>--threads</c> from the CPU grant (03 section 5.3), keeping the caller's.</summary>
    public sealed class TestLoadCpuAdapter : IToolConcurrency
    {
        public ToolInvocation? Apply(TaskSpec spec, long cpuGrantMillicores)
        {
            var argv = spec.Command.Argv.Argv;
            if (argv.Count < 2 || !Path.GetFileNameWithoutExtension(argv[0]).Equals("arcforges-testload", StringComparison.OrdinalIgnoreCase) || argv[1] != "cpu")
            {
                return null;
            }

            var given = argv.IndexOf("--threads");
            if (given > 0)
            {
                return new ToolInvocation("testload", "testload.cpu", [.. argv], int.Parse(argv[given + 1], CultureInfo.InvariantCulture), CallerFlag: true);
            }

            var parallelism = ToolParallelism.For(cpuGrantMillicores, 64);
            return new ToolInvocation("testload", "testload.cpu", [.. argv, "--threads", parallelism.ToString(CultureInfo.InvariantCulture)], parallelism, CallerFlag: false);
        }
    }
}
