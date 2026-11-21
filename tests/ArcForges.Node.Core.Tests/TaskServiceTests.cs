// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Proto;
using Google.Protobuf;
using OutputIndexRecord = ArcForges.Node.Platform.OutputIndexRecord;

namespace ArcForges.Node.Core.Tests;

/// <summary>Exercises retained V1 Task records through the real local RPC handlers and SQLite.</summary>
/// <remarks>
/// The Windows Task admission fixtures can be run from eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
/// The current installed Run exercises argv and working directory in
/// CliMxcRunServiceTests.InstalledCliManagesOfflineSandboxRunAndResourcesWithExactArgumentsAndReceipts.
/// TerminalCliMxcRunServiceTests.InstalledCliPreservesBinaryPipesEofAndApplicationExit exercises live binary pipes,
/// EOF and process exit. SecurityMxcRunServiceTests.InstalledOfflineOwnerRunsExactInputsWithProtectedIpcAndRedactedAuthority
/// covers V2 secret handling. Legacy CMD batch admission, fresh Task stdin modes and retry admission belong to the historical executor.
/// </remarks>
public sealed class TaskServiceTests
{
    private const string TaskService = "arcforges.node.v1.TaskService/";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory(Timeout = 60_000)]
    [InlineData(0, false, false)]
    [InlineData(7, false, false)]
    [InlineData(unchecked((int)0xc0000005), true, false)]
    [InlineData(1, false, true)]
    public async Task RetainedTaskReturnsExactArgumentsDirectoryAndTerminalResult(int code, bool hasWindowsStatus, bool cancelled)
    {
        await using var files = InProcessNode.Create();
        var (taskId, attemptId) = LegacyTaskHistoryFixture.Seed(files, AttemptState.Finished);
        var directory = Path.Combine(files.Root, "retained work dir ä");
        string[] arguments = ["historic.exe", "", "two words", "quote\"inside", "trailing\\", "unicode äöü 中文 🚀", "literal%name"];
        var spec = Tasks.Argv(directory, arguments);
        var state = cancelled ? TaskState.Cancelled : code == 0 ? TaskState.Succeeded : TaskState.Failed;
        var reason = cancelled ? TerminationReason.Cancelled : TerminationReason.Exited;
        await WithOfflineNodeAsync(files, async (store, channel) =>
        {
            store.Write(transaction =>
            {
                StoreSpec(transaction, taskId, spec);
                transaction.Execute("UPDATE task SET state = $state WHERE task_id = $id;",
                    ("$state", (int)state), ("$id", taskId.Value.ToByteArray()));
                transaction.Execute("UPDATE attempt SET exit_code = $exit, windows_status = $status, termination_reason = $reason WHERE attempt_id = $id;",
                    ("$exit", code), ("$status", hasWindowsStatus ? (long)unchecked((uint)code) : (long?)null),
                    ("$reason", (int)reason), ("$id", attemptId.Value.ToByteArray()));
            }, CommitDurability.Full);

            var full = await Tasks.GetAsync(channel, taskId, full: true);
            Assert.Equal(directory, full.Spec.WorkingDirectory);
            Assert.Equal(arguments, full.Spec.Command.Argv.Argv.ToArray());
            var waited = await channel.Tasks.WaitTaskAsync(new TaskServiceWaitTaskRequest { Meta = Tasks.Meta(), TaskId = taskId }, cancellationToken: Ct);
            Assert.Null(waited.Error);
            Assert.True(waited.Value.Reached);
            Assert.Equal(state, waited.Value.Task.State);
            var attempt = waited.Value.Task.CurrentAttempt;
            Assert.Equal(attemptId, attempt.AttemptId);
            Assert.Equal(AttemptState.Finished, attempt.State);
            Assert.Equal(reason, attempt.Result.TerminationReason);
            Assert.True(attempt.Result.HasExitCode);
            Assert.Equal(code, attempt.Result.ExitCode);
            Assert.Equal(EffectCertainty.Happened, attempt.Result.Effect);
            Assert.Equal(hasWindowsStatus, attempt.Result.HasWindowsStatus);
            if (hasWindowsStatus)
            {
                Assert.Equal(unchecked((uint)code), attempt.Result.WindowsStatus);
            }
        });
    }

    [Fact(Timeout = 60_000)]
    public async Task RetainedOutputKeepsExactBytesOffsetsTerminalFramesAndTail()
    {
        await using var files = InProcessNode.Create();
        var (taskId, attemptId) = LegacyTaskHistoryFixture.Seed(files, AttemptState.Finished);
        var stdout = Enumerable.Range(0, 150_000).Select(index => (byte)(index % 251)).ToArray();
        var stderr = Enumerable.Range(0, 150_000).Select(index => (byte)(255 - index % 251)).ToArray();
        var merged = SeedOutput(files, attemptId, stdout, stderr);

        await WithOfflineNodeAsync(files, async (_, channel) =>
        {
            Assert.Equal(stdout, await Tasks.ReadAllAsync(channel, attemptId, OutputStream.Stdout));
            Assert.Equal(stderr, await Tasks.ReadAllAsync(channel, attemptId, OutputStream.Stderr));
            Assert.Equal(merged, await Tasks.ReadAllAsync(channel, attemptId, OutputStream.Merged));

            using var attach = channel.Tasks.AttachTask(new TaskServiceAttachTaskRequest { Meta = Tasks.Meta(), TaskId = taskId },
                cancellationToken: Ct);
            var frames = new List<TaskServiceAttachTaskFrame>();
            while (await attach.ResponseStream.MoveNext(Ct))
            {
                frames.Add(attach.ResponseStream.Current);
            }

            Assert.Equal(TaskServiceAttachTaskFrame.FrameOneofCase.Started, frames[0].FrameCase);
            Assert.False(frames[0].Started.StdinGranted);
            Assert.Equal(TaskServiceAttachTaskFrame.FrameOneofCase.Result, frames[^1].FrameCase);
            Assert.Equal((TerminationReason.Exited, 0, EffectCertainty.Happened),
                (frames[^1].Result.TerminationReason, frames[^1].Result.ExitCode, frames[^1].Result.Effect));
            var chunks = frames.Where(frame => frame.FrameCase == TaskServiceAttachTaskFrame.FrameOneofCase.Output)
                .Select(frame => frame.Output).ToArray();
            Assert.True(chunks.Length > 4);
            Assert.All(chunks, chunk => Assert.InRange(chunk.Data.Length, 1, 64 * 1024));
            Assert.Equal(merged, chunks.SelectMany(chunk => chunk.Data).ToArray());

            using var watch = channel.Tasks.WatchTaskOutput(new TaskServiceWatchTaskOutputRequest
            {
                Meta = Tasks.Meta(),
                AttemptId = attemptId,
                Stream = OutputStream.Stdout,
                FromOffset = 1_000,
            }, cancellationToken: Ct);
            var observed = new List<TaskServiceWatchTaskOutputFrame>();
            while (await watch.ResponseStream.MoveNext(Ct))
            {
                observed.Add(watch.ResponseStream.Current);
            }

            Assert.Equal(TaskServiceWatchTaskOutputFrame.FrameOneofCase.Result, observed[^1].FrameCase);
            Assert.Equal(frames[^1].Result, observed[^1].Result);
            var watched = observed.Where(frame => frame.FrameCase == TaskServiceWatchTaskOutputFrame.FrameOneofCase.Output)
                .Select(frame => frame.Output).ToArray();
            ulong offset = 1_000;
            foreach (var chunk in watched)
            {
                Assert.Equal(attemptId, chunk.AttemptId);
                Assert.Equal(OutputStream.Stdout, chunk.Stream);
                Assert.Equal(offset, chunk.Offset);
                offset += (ulong)chunk.Data.Length;
            }
            Assert.Equal((ulong)stdout.Length, offset);
            Assert.Equal(stdout[1_000..], watched.SelectMany(chunk => chunk.Data).ToArray());

            var wait = await channel.Tasks.WaitTaskAsync(new TaskServiceWaitTaskRequest
            {
                Meta = Tasks.Meta(),
                TaskId = taskId,
                WaitMs = 100,
                TailBytes = 4_096,
            }, cancellationToken: Ct);
            Assert.Null(wait.Error);
            Assert.True(wait.Value.Reached);
            Assert.Equal(merged[^4_096..], wait.Value.Tail.ToByteArray());
            Assert.True(wait.Value.TailTruncated);

            var staleAttach = await channel.Tasks.WriteTaskInputAsync(new TaskServiceWriteTaskInputRequest
            {
                Meta = Tasks.Meta(),
                TaskId = taskId,
                AttachId = frames[0].Started.AttachId,
                Data = ByteString.CopyFrom(new byte[] { 0, 0xff }),
            }, cancellationToken: Ct);
            Assert.Equal("invalid_state", staleAttach.Error.Code);
            Assert.Equal("NOT_RUNNING", staleAttach.Error.Details.State.State);
            Assert.Null(staleAttach.Value);
        });
    }

    [Fact(Timeout = 60_000)]
    public async Task RetainedTaskShowsSealedSecretNamesWithoutExposingValues()
    {
        const string secret = "historical-test-only-secret-value";
        var secrets = new SecretEnvironment
        {
            Caller = { new EnvEntry { Name = "GITHUB_TOKEN", Value = "historical-caller-value" } },
            Set = { new EnvEntry { Name = "API_TOKEN", Value = secret } },
        };
        await using var files = InProcessNode.Create();
        var (taskId, _) = LegacyTaskHistoryFixture.Seed(files, AttemptState.Finished, secrets);
        var spec = Tasks.Argv(files.Root, "historic.exe");
        spec.Environment = new EnvironmentSpec { Set = { ["PLAIN_VALUE"] = "visible" } };

        await WithOfflineNodeAsync(files, async (store, channel) =>
        {
            store.Write(transaction => StoreSpec(transaction, taskId, spec), CommitDurability.Full);
            var full = await Tasks.GetAsync(channel, taskId, full: true);
            Assert.Equal("visible", full.Spec.Environment.Set["PLAIN_VALUE"]);
            Assert.False(full.Spec.Environment.Set.ContainsKey("API_TOKEN"));
            Assert.Empty(full.Spec.Environment.CallerEnvironment);
            using var keys = new NodeDataKeyRing(store, files.Secrets.Selection);
            var original = new TaskSecrets(store, keys).Unseal(taskId.Value.Span);
            Assert.Equal(UnsealStatus.Available, original.Status);
            Assert.Equal(secrets, original.Values);
            var stored = store.Read(reader => (reader.Scalar("SELECT names_json FROM task_secret WHERE task_id = $id;", ("$id", taskId.Value.ToByteArray())),
                reader.Scalar("SELECT count(*) FROM task WHERE instr(spec, $value) > 0;", ("$value", Encoding.UTF8.GetBytes(secret)))));
            Assert.Equal("[\"API_TOKEN\",\"GITHUB_TOKEN\"]", stored.Item1);
            Assert.Equal(0L, stored.Item2);
        });
    }

    [Fact(Timeout = 60_000)]
    public async Task RetainedSubmitReplaysAndListsHistoricalTasksNewestFirst()
    {
        await using var files = InProcessNode.Create();
        var (older, _) = LegacyTaskHistoryFixture.Seed(files, AttemptState.Finished);
        var (newer, _) = LegacyTaskHistoryFixture.Seed(files, AttemptState.Finished);
        var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Tasks.Argv(files.Root, "historic.exe") };
        var original = new TaskServiceSubmitTaskResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
            Value = new()
            {
                TaskId = older,
                State = TaskState.Queued,
                Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened },
            },
        };

        await WithOfflineNodeAsync(files, async (store, channel) =>
        {
            store.Write(transaction =>
            {
                StoreSpec(transaction, older, request.Spec);
                transaction.Execute("UPDATE task SET created_at = $at WHERE task_id = $id;",
                    ("$at", transaction.NowMicroseconds - 1_000_000), ("$id", older.Value.ToByteArray()));
                RecordPrior(transaction, "SubmitTask", request.Meta, request, original);
            }, CommitDurability.Full);
            Assert.Equal(original, await channel.Tasks.SubmitTaskAsync(request, cancellationToken: Ct));
            var changed = request.Clone();
            changed.Spec.Title = "different recorded request";
            Assert.Equal("command_id_reused", (await channel.Tasks.SubmitTaskAsync(changed, cancellationToken: Ct)).Error.Code);
            var fresh = request.Clone();
            fresh.Meta = Tasks.Meta();
            AssertLegacyUnavailable((await channel.Tasks.SubmitTaskAsync(fresh, cancellationToken: Ct)).Error);

            var current = await channel.Tasks.ListTasksAsync(new TaskServiceListTasksRequest { Meta = Tasks.Meta() }, cancellationToken: Ct);
            Assert.Null(current.Error);
            Assert.Equal([newer, older], current.Value.Tasks.Select(task => task.TaskId));
            var page = await channel.Tasks.ListTasksAsync(new TaskServiceListTasksRequest
            {
                Meta = Tasks.Meta(),
                Filter = new TaskFilter { States = { TaskState.Succeeded } },
                Page = new PageRequest { Limit = 1 },
            }, cancellationToken: Ct);
            Assert.Null(page.Error);
            Assert.Equal(newer, Assert.Single(page.Value.Tasks).TaskId);
            Assert.True(page.Value.Page.HasMore);
            Assert.Equal(2L, store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
            Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup;")));
        });
    }

    [Fact(Timeout = 60_000)]
    public async Task RetainedRetryDoesNotCreateAnAttemptAndExistingRecordsCanBePinnedAndPurged()
    {
        await using var files = InProcessNode.Create();
        var (taskId, attemptId) = LegacyTaskHistoryFixture.Seed(files, AttemptState.Finished);
        var directory = Tasks.Files(files, attemptId).Directory;
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Tasks.Files(files, attemptId).StdoutPath, [0, 1, 0xff]);
        var request = new TaskServiceRetryTaskRequest { Meta = Tasks.Meta(), TaskId = taskId };
        var original = new TaskServiceRetryTaskResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
            Value = new()
            {
                State = TaskState.Queued,
                Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened },
                Warnings = { "unknown prior side effect" },
            },
        };

        await WithOfflineNodeAsync(files, async (store, channel) =>
        {
            store.Write(transaction =>
            {
                var next = CommandIds.New();
                var source = attemptId.Value.ToByteArray();
                transaction.Execute("""
                    INSERT INTO attempt (attempt_id, task_id, number, kind, state, executor_node_id, boot_identity,
                        request_cpu_millicores, request_mem_expected_bytes, request_mem_ceiling_bytes, request_source,
                        accounted_mem_bytes, created_at, started_at, finished_at, exit_code, termination_reason, effect, rev)
                    SELECT $next, task_id, 2, kind, state, executor_node_id, boot_identity,
                        request_cpu_millicores, request_mem_expected_bytes, request_mem_ceiling_bytes, request_source,
                        accounted_mem_bytes, created_at, started_at, finished_at, 3, termination_reason, effect, 0
                    FROM attempt WHERE attempt_id = $first;
                    """, ("$next", next.Value.ToByteArray()), ("$first", source));
                transaction.Execute("UPDATE attempt SET exit_code = 3 WHERE attempt_id = $first;", ("$first", source));
                transaction.Execute("UPDATE task SET state = $state, current_attempt_id = $next, attempt_count = 2 WHERE task_id = $task;",
                    ("$state", (int)TaskState.Failed), ("$next", next.Value.ToByteArray()), ("$task", taskId.Value.ToByteArray()));
                RecordPrior(transaction, "RetryTask", request.Meta, request, original);
            }, CommitDurability.Full);

            Assert.Equal(original, await channel.Tasks.RetryTaskAsync(request, cancellationToken: Ct));
            var current = await Tasks.GetAsync(channel, taskId);
            Assert.Equal(TaskState.Failed, current.State);
            Assert.Equal(2u, current.AttemptCount);
            var attempts = await channel.Tasks.ListAttemptsAsync(new TaskServiceListAttemptsRequest { Meta = Tasks.Meta(), TaskId = taskId },
                cancellationToken: Ct);
            Assert.Null(attempts.Error);
            Assert.Equal([1u, 2u], attempts.Value.Attempts.Select(attempt => attempt.Number));
            AssertLegacyUnavailable((await channel.Tasks.RetryTaskAsync(new TaskServiceRetryTaskRequest
            {
                Meta = Tasks.Meta(),
                TaskId = taskId,
            }, cancellationToken: Ct)).Error);

            var pin = await channel.Tasks.PinTaskAsync(new TaskServicePinTaskRequest { Meta = Tasks.Meta(), TaskId = taskId, Pinned = true },
                cancellationToken: Ct);
            Assert.Null(pin.Error);
            Assert.True((await Tasks.GetAsync(channel, taskId)).Pinned);
            await using var script = await files.ChannelAsync(helloAsHuman: false);
            var denied = await script.Tasks.PurgeTaskRecordAsync(new TaskServicePurgeTaskRecordRequest { Meta = Tasks.Meta(), TaskId = taskId },
                cancellationToken: Ct);
            Assert.Equal("permission_denied", denied.Error.Code);
            Assert.True(Directory.Exists(directory));

            var purgeRequest = new TaskServicePurgeTaskRecordRequest { Meta = Tasks.Meta(), TaskId = taskId };
            var purge = await channel.Tasks.PurgeTaskRecordAsync(purgeRequest, cancellationToken: Ct);
            Assert.Null(purge.Error);
            Assert.Equal(purgeRequest.Meta.CommandId, purge.Value.Receipt.CommandId);
            Assert.Equal(EffectCertainty.Happened, purge.Value.Receipt.Effect);
            Assert.False(Directory.Exists(directory));
            Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE purged_at IS NOT NULL;")));
            Assert.Equal(2L, store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt WHERE output_purged = 1;")));
            Assert.Equal(original, await channel.Tasks.RetryTaskAsync(request, cancellationToken: Ct));
        });
    }

    private static async Task WithOfflineNodeAsync(InProcessNode files, Func<NodeStore, NodeChannel, Task> verify)
    {
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = files.DataRoot, BootIdentity = BootIdentity.Read(), Clock = files.Clock });
        using var log = new NodeLog(Path.Combine(files.DataRoot, "logs", "node"), LogLevel.Info, files.Clock);
        using var heartbeat = new NodeHeartbeatWriter(files.DataRoot, log, files.Clock);
        using var keys = new NodeDataKeyRing(store, files.Secrets.Selection);
        var journal = EventJournal.Open(store);
        var hub = new StreamHub();
        await using var processor = new CommandProcessor(store, journal, hub);
        await using var execution = new ExecutionSupervisor(new ExecutionOptions
        {
            Store = store,
            Processor = processor,
            Log = log,
            Clock = files.Clock,
            DataRoot = files.DataRoot,
            Secrets = new TaskSecrets(store, keys),
            Heartbeat = heartbeat,
        });
        using var runtime = new NodeRuntime(store, journal, hub, processor, log,
            new NodeSettingsManager(files.ConfigPath, files.DataRoot, log), files.DataRoot, "offline-fixture", files.Clock,
            new RecoveryReport(false, false, null, store.Opening), new CapabilityReport()) { Execution = execution };
        if (!OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(Path.GetDirectoryName(files.Endpoint.Address)!,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        await using var server = NodeApiServer.Build(files.Endpoint, runtime, new ClientSessions());
        await server.StartAsync(Ct);
        await using var channel = await files.ChannelAsync(helloAsHuman: true);
        await verify(store, channel);
        Assert.Null(execution.Platform);
        Assert.Empty(execution.RunningAttempts);
    }

    private static void StoreSpec(StoreTransaction transaction, Id task, TaskSpec spec)
    {
        var bytes = spec.ToByteArray();
        transaction.Execute("UPDATE task SET spec = $spec, spec_digest = $digest WHERE task_id = $task;",
            ("$spec", bytes), ("$digest", SHA256.HashData(bytes)), ("$task", task.Value.ToByteArray()));
    }

    private static void RecordPrior(StoreTransaction transaction, string method, RequestMeta meta, IMessage request, IMessage response)
    {
        Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, meta.CommandId.Value.Span,
            TaskService + method, PayloadDigest.Compute(request), Origin.Human).Status);
        CommandDeduplication.Complete(transaction, meta.CommandId.Value.Span, response.ToByteArray());
    }

    private static byte[] SeedOutput(InProcessNode node, Id attempt, byte[] stdout, byte[] stderr)
    {
        var files = Tasks.Files(node, attempt);
        Directory.CreateDirectory(files.Directory);
        File.WriteAllBytes(files.StdoutPath, stdout);
        using var errorFile = File.Create(files.OutputPath(OutputStreamKind.Stderr));
        errorFile.Write(stderr);
        using var index = File.Create(files.IndexPath);
        using var merged = new MemoryStream();
        const int recordSize = 75_000;
        var buffer = new byte[OutputIndexRecord.Size];
        for (var offset = 0; offset < stdout.Length; offset += recordSize)
        {
            new OutputIndexRecord(OutputStreamKind.Stdout, offset, recordSize, offset + 1, OutputChunkMarks.None).Write(buffer);
            index.Write(buffer);
            merged.Write(stdout.AsSpan(offset, recordSize));
            new OutputIndexRecord(OutputStreamKind.Stderr, offset, recordSize, offset + 2, OutputChunkMarks.None).Write(buffer);
            index.Write(buffer);
            merged.Write(stderr.AsSpan(offset, recordSize));
        }

        return merged.ToArray();
    }

    private static void AssertLegacyUnavailable(ArcError error)
    {
        Assert.Equal(("operation_failed", EffectCertainty.Unknown, RetryMode.Never), (error.Code, error.Effect, error.Retry.Mode));
        Assert.Equal("legacy_task_outcome_unavailable", error.Details.State.Reason);
    }
}
