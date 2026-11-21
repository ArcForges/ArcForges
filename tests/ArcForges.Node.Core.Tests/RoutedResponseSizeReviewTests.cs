// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using OutputIndexRecord = ArcForges.Node.Platform.OutputIndexRecord;

namespace ArcForges.Node.Core.Tests;

/// <summary>Independent review: bound complete routed responses while preserving pages and output offsets.</summary>
public sealed class RoutedResponseSizeReviewTests
{
    private const string HistoricalProgram = "response-size-fixture-never-starts";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 180_000)]
    public async Task LargeRoutedListPaginatesWithoutSkippingAnyTask()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = InProcessNode.Create();
        var spec = Tasks.Argv(node.Root, HistoricalProgram);
        for (var i = 0; i < 32; i++)
        {
            spec.Labels[("label" + i.ToString(System.Globalization.CultureInfo.InvariantCulture)).PadRight(64, 'k')] = new string('v', 256);
        }

        var expected = SeedQueuedTasks(node, spec, count: 130).Select(id => Convert.ToHexString(id.Value.Span)).ToHashSet(StringComparer.Ordinal);
        await node.StartAsync();
        var routed = new RoutedCalls(node);
        var caller = RoutedCalls.Session();
        string? cursor = null;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var pages = 0;
        do
        {
            var page = new PageRequest { Limit = 500 };
            if (cursor is not null)
            {
                page.Cursor = cursor;
            }

            var request = new TaskServiceListTasksRequest { Meta = ReadMeta(), Page = page };
            var (answer, response) = await routed.ReadAsync(caller, RoutedMethod.ListNodeTasks, request, TaskServiceListTasksResponse.Parser);
            Assert.Equal(RoutedOutcome.Executed, answer!.Outcome);
            Assert.Null(response!.Error);
            Assert.True(response.CalculateSize() <= ResultSigner.MaxPayloadBytes, "the complete list response must fit the routed payload");
            Assert.Equal(response.CalculateSize(), answer.Response!.Length);
            Assert.NotEmpty(response.Value.Tasks);
            foreach (var task in response.Value.Tasks)
            {
                Assert.True(seen.Add(Convert.ToHexString(task.TaskId.Value.Span)), "a task must not repeat across pages");
                Assert.Equal(spec.Labels, task.Labels);
            }

            pages++;
            cursor = response.Value.Page.HasMore ? response.Value.Page.NextCursor : null;
            Assert.False(response.Value.Page.HasMore && string.IsNullOrEmpty(cursor), "a partial page must have a continuation cursor");
            Assert.True(pages < 10, "pagination must advance");
        }
        while (cursor is not null);

        Assert.True(pages > 1);
        Assert.True(expected.SetEquals(seen), "pagination must not skip or repeat any task");
    }

    [Fact(Timeout = 180_000)]
    public async Task OversizedFullGetReturnsABoundedInternalFailureWithoutTruncatingTheTask()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = InProcessNode.Create();
        var longArgument = "--" + new string('x', (1024 * 1024) - System.Text.Encoding.UTF8.GetByteCount(HistoricalProgram) - 2);
        var spec = Tasks.Argv(node.Root, HistoricalProgram, longArgument);
        var taskId = Assert.Single(SeedQueuedTasks(node, spec, count: 1));
        await node.StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var execution = Assert.IsType<ExecutionSupervisor>(node.Runtime.Execution);
        var valid = TaskValidation.Submit(new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec }, Origin.Human,
            execution.Settings, node.Runtime.NodeId.Span, node.Runtime.Capabilities);
        Assert.Null(valid);
        Assert.Null((await Sched.ChangePolicyAsync(human, policy => (policy.Privacy ??= new PrivacyPolicy()).RemoteCommandLines = true)).Error);
        var request = new TaskServiceGetTaskRequest { Meta = ReadMeta(), TaskId = taskId, Detail = TaskDetail.Full };
        var routed = new RoutedCalls(node);
        var (answer, response) = await routed.ReadAsync(RoutedCalls.Session(), RoutedMethod.GetNodeTask, request, TaskServiceGetTaskResponse.Parser);
        Assert.Equal(RoutedOutcome.Executed, answer!.Outcome);
        Assert.True(response!.CalculateSize() <= ResultSigner.MaxPayloadBytes);
        Assert.Equal(response.CalculateSize(), answer.Response!.Length);
        Assert.Equal(("internal", ErrorCategory.Internal, EffectCertainty.Unknown, RetryMode.Never),
            (response.Error?.Code, response.Error?.Category, response.Error?.Effect, response.Error?.Retry.Mode));
        Assert.Null(response.Value);
        var local = await human.Tasks.GetTaskAsync(request, cancellationToken: Ct);
        Assert.Null(local.Error);
        Assert.Equal(taskId, local.Value.Task.TaskId);
        Assert.Equal(spec, local.Value.Task.Spec);
    }

    [Theory(Timeout = 180_000)]
    [InlineData(OutputStream.Merged)]
    [InlineData(OutputStream.Stdout)]
    [InlineData(OutputStream.Stderr)]
    public async Task AShortRecordHeavyOutputRemainsBoundedAndResumable(OutputStream stream)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = InProcessNode.Create();
        var (taskId, attemptId) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished);
        var files = Tasks.Files(node, attemptId);
        const int count = 65_536;
        Directory.CreateDirectory(files.Directory);
        File.WriteAllBytes(files.StdoutPath, Enumerable.Repeat((byte)'x', count).ToArray());
        File.WriteAllBytes(files.StderrPath, Enumerable.Repeat((byte)'y', count).ToArray());
        using (var index = new FileStream(files.IndexPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
        {
            var buffer = new byte[OutputIndexRecord.Size];
            for (var n = 0; n < count; n++)
            {
                new OutputIndexRecord(OutputStreamKind.Stdout, n, 1, 1_700_000_000_000_000_000, OutputChunkMarks.None).Write(buffer);
                index.Write(buffer);
                new OutputIndexRecord(OutputStreamKind.Stderr, n, 1, 1_700_000_000_000_000_001, OutputChunkMarks.None).Write(buffer);
                index.Write(buffer);
            }
        }

        using (var history = OpenHistory(node))
        {
            history.Write(transaction => Assert.Equal(1, transaction.Execute("""
                UPDATE attempt SET stdout_bytes = $size, stderr_bytes = $size, stdout_offset = $size, stderr_offset = $size, index_offset = $records
                WHERE attempt_id = $id;
                """, ("$size", count), ("$records", 2 * count), ("$id", attemptId.Value.ToByteArray()))), CommitDurability.Full);
        }

        await node.StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var task = await Tasks.GetAsync(human, taskId);
        Assert.Equal(TaskState.Succeeded, task.State);
        Assert.Equal(attemptId, task.CurrentAttempt.AttemptId);
        Assert.Equal(AttemptState.Finished, task.CurrentAttempt.State);
        Assert.Null((await Sched.ChangePolicyAsync(human, policy => (policy.Privacy ??= new PrivacyPolicy()).RemoteOutputTail = true)).Error);
        var routed = new RoutedCalls(node);
        var caller = RoutedCalls.Session();
        ulong offset = 0;
        var chunks = 0;
        var bytes = new List<byte>();
        bool eof;
        do
        {
            var request = new TaskServiceReadTaskOutputRequest { Meta = ReadMeta(), AttemptId = attemptId, FromOffset = offset, MaxBytes = count, Stream = stream };
            var (answer, response) = await routed.ReadAsync(caller, RoutedMethod.ReadNodeTaskOutput, request, TaskServiceReadTaskOutputResponse.Parser);
            Assert.Equal(RoutedOutcome.Executed, answer!.Outcome);
            Assert.Null(response!.Error);
            Assert.True(response.CalculateSize() <= ResultSigner.MaxPayloadBytes, "the complete data plus index must fit the routed payload");
            Assert.Equal(response.CalculateSize(), answer.Response!.Length);
            Assert.Equal(offset + (ulong)response.Value.Data.Length, response.Value.NextOffset);
            Assert.True(response.Value.Data.Length > 0 || response.Value.Eof);
            Assert.Equal(response.Value.Data.Length, response.Value.Index.Count);
            for (var i = 0; i < response.Value.Index.Count; i++)
            {
                var global = offset + (ulong)i;
                var stdout = stream == OutputStream.Stdout || (stream == OutputStream.Merged && global % 2 == 0);
                var entry = response.Value.Index[i];
                Assert.Equal(stdout ? OutputStream.Stdout : OutputStream.Stderr, entry.Stream);
                Assert.Equal(stream == OutputStream.Merged ? global / 2 : global, entry.Offset);
                Assert.Equal(1u, entry.Length);
                Assert.Equal(stdout ? (byte)'x' : (byte)'y', response.Value.Data[i]);
            }

            bytes.AddRange(response.Value.Data);
            offset = response.Value.NextOffset;
            eof = response.Value.Eof;
            Assert.True(++chunks < 10, "output continuation must advance");
        }
        while (!eof);

        Assert.Equal(stream == OutputStream.Merged ? 2 * count : count, bytes.Count);
        Assert.True(chunks > 1, "record-heavy output is resumed across more than one bounded response");
    }

    private static RequestMeta ReadMeta() => new() { CorrelationId = CommandIds.New() };

    private static NodeStore OpenHistory(InProcessNode node) => NodeStore.Open(
        new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = BootIdentity.Read(), Clock = node.Clock });

    private static List<Id> SeedQueuedTasks(InProcessNode node, TaskSpec spec, int count)
    {
        // Materialize the same bounded spec/labels that were stored by historical admission.
        spec.Kind = TaskKind.Command;
        var storage = PreparedSubmitStorage.Create(SubmittedEnvironment.Split(spec, SecretNameMatcher.Default));
        var summary = CommandText.Summary(spec.Command, SecretNameMatcher.Default);
        var fingerprint = CommandText.Fingerprint(spec.Command);
        var commandDigest = CommandText.Digest(spec, []);
        using var history = OpenHistory(node);
        return history.Write(transaction =>
        {
            var tasks = new List<Id>(count);
            for (var i = 0; i < count; i++)
            {
                var task = LegacyTaskHistoryFixture.SeedQueued(transaction, new ActorRef { Origin = Origin.Human });
                Assert.Equal(1, transaction.Execute("""
                    UPDATE task SET spec = $spec, spec_digest = $digest, labels_json = $labels, title = $summary, command_summary = $summary,
                                    command_fingerprint = $fingerprint, command_digest = $commandDigest
                    WHERE task_id = $id;
                    """, ("$spec", storage.Spec), ("$digest", storage.Digest), ("$labels", storage.Labels), ("$summary", summary),
                    ("$fingerprint", fingerprint), ("$commandDigest", commandDigest), ("$id", task.Value.ToByteArray())));
                tasks.Add(task);
            }

            return tasks;
        }, CommitDurability.Full);
    }
}
