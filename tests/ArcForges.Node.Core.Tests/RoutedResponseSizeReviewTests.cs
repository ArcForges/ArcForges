// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Platform;
using Google.Protobuf;
using OutputIndexRecord = ArcForges.Node.Platform.OutputIndexRecord;

namespace ArcForges.Node.Core.Tests;

/// <summary>Independent review: bound complete routed responses while preserving pages and output offsets.</summary>
public sealed class RoutedResponseSizeReviewTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 180_000)]
    public async Task LargeRoutedListPaginatesWithoutSkippingAnyTask()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var expected = new HashSet<string>(StringComparer.Ordinal);
        for (var n = 0; n < 130; n++)
        {
            var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100");
            for (var i = 0; i < 32; i++)
            {
                spec.Labels[("label" + i.ToString(System.Globalization.CultureInfo.InvariantCulture)).PadRight(64, 'k')] = new string('v', 256);
            }

            expected.Add(Convert.ToHexString((await Tasks.SubmitAsync(human, spec)).Value.Span));
        }

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

            var request = new TaskServiceListTasksRequest { Meta = Tasks.Meta(), Page = page };
            var (answer, response) = await routed.ReadAsync(caller, RoutedMethod.ListNodeTasks, request, TaskServiceListTasksResponse.Parser);
            Assert.Equal(RoutedOutcome.Executed, answer!.Outcome);
            Assert.Null(response!.Error);
            Assert.True(response.CalculateSize() <= ResultSigner.MaxPayloadBytes, "the complete list response must fit the routed payload");
            foreach (var task in response.Value.Tasks)
            {
                Assert.True(seen.Add(Convert.ToHexString(task.TaskId.Value.Span)), "a task must not repeat across pages");
            }

            pages++;
            cursor = response.Value.Page.HasMore ? response.Value.Page.NextCursor : null;
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
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100");
        var taskId = await Tasks.SubmitAsync(human, spec);
        spec.Command.Argv.Argv.Clear();
        spec.Command.Argv.Argv.Add(Tasks.TestLoad);
        spec.Command.Argv.Argv.Add(new string('x', (1024 * 1024) - System.Text.Encoding.UTF8.GetByteCount(Tasks.TestLoad)));
        var valid = TaskValidation.Submit(new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec }, Origin.Human,
            node.Runtime.Execution!.Settings, node.Runtime.NodeId.Span, node.Runtime.Capabilities);
        Assert.Null(valid);
        await node.Runtime.Processor.ExecuteAsync(context => context.Transaction.Execute("UPDATE task SET spec = $spec WHERE task_id = $id;",
            ("$spec", spec.ToByteArray()), ("$id", taskId.Value.ToByteArray())));
        Assert.Null((await Sched.ChangePolicyAsync(human, policy => (policy.Privacy ??= new PrivacyPolicy()).RemoteCommandLines = true)).Error);
        var request = new TaskServiceGetTaskRequest { Meta = Tasks.Meta(), TaskId = taskId, Detail = TaskDetail.Full };
        var routed = new RoutedCalls(node);
        var (answer, response) = await routed.ReadAsync(RoutedCalls.Session(), RoutedMethod.GetNodeTask, request, TaskServiceGetTaskResponse.Parser);
        Assert.Equal(RoutedOutcome.Executed, answer!.Outcome);
        Assert.True(response!.CalculateSize() <= ResultSigner.MaxPayloadBytes);
        Assert.Equal(("internal", ErrorCategory.Internal, EffectCertainty.Unknown, RetryMode.Never),
            (response.Error?.Code, response.Error?.Category, response.Error?.Effect, response.Error?.Retry.Mode));
        Assert.Null(response.Value);
        var local = await human.Tasks.GetTaskAsync(request, cancellationToken: Ct);
        Assert.Null(local.Error);
        Assert.Equal(spec.Command.Argv.Argv[1], local.Value.Task.Spec.Command.Argv.Argv[1]);
    }

    [Theory(Timeout = 180_000)]
    [InlineData(OutputStream.Merged)]
    [InlineData(OutputStream.Stdout)]
    [InlineData(OutputStream.Stderr)]
    public async Task AShortRecordHeavyOutputRemainsBoundedAndResumable(OutputStream stream)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var taskId = await Tasks.SubmitAsync(human, Tasks.Argv(node.Root, Tasks.TestLoad, "output", "--bytes", "1"));
        var task = await Tasks.WaitAsync(human, taskId);
        Assert.Equal(TaskState.Succeeded, task.State);
        var files = Tasks.Files(node, task.CurrentAttempt.AttemptId);
        const int count = 65_536;
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

        Assert.Null((await Sched.ChangePolicyAsync(human, policy => (policy.Privacy ??= new PrivacyPolicy()).RemoteOutputTail = true)).Error);
        var routed = new RoutedCalls(node);
        var caller = RoutedCalls.Session();
        ulong offset = 0;
        var chunks = 0;
        var bytes = new List<byte>();
        bool eof;
        do
        {
            var request = new TaskServiceReadTaskOutputRequest { Meta = Tasks.Meta(), AttemptId = task.CurrentAttempt.AttemptId, FromOffset = offset, MaxBytes = count, Stream = stream };
            var (answer, response) = await routed.ReadAsync(caller, RoutedMethod.ReadNodeTaskOutput, request, TaskServiceReadTaskOutputResponse.Parser);
            Assert.Equal(RoutedOutcome.Executed, answer!.Outcome);
            Assert.Null(response!.Error);
            Assert.True(response.CalculateSize() <= ResultSigner.MaxPayloadBytes, "the complete data plus index must fit the routed payload");
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
}
