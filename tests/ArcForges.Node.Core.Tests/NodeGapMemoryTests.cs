// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>Recovery classifies a retained Attempt from its durable exit record and recorded memory evidence.</summary>
public sealed class NodeGapMemoryTests
{
    [Theory(Timeout = 120_000)]
    [InlineData(272, 17, true, TaskState.Failed, TerminationReason.MemoryLimit)]
    [InlineData(272, 0, true, TaskState.Succeeded, TerminationReason.Exited)]
    [InlineData(16, 17, false, TaskState.Failed, TerminationReason.Exited)]
    [InlineData(272, 17, false, TaskState.Failed, TerminationReason.Exited)]
    [InlineData(192, 17, true, TaskState.Failed, TerminationReason.MemoryLimit)]
    public async Task RecoveryKeepsTheRecordedExitConditionAndMemoryEvidence(
        int peakMiB, int exitCode, bool recordedNotification, TaskState expectedState, TerminationReason expectedReason)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = InProcessNode.Create();
        var (taskId, attemptId) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Running);
        var files = Tasks.Files(node, attemptId);
        Directory.CreateDirectory(files.Directory);
        var peakBytes = (long)peakMiB << 20;
        HelperFiles.WriteAtomically(files.ExitPath, new ExitRecord
        {
            AttemptId = IdText.Format(attemptId),
            RecordedAt = node.Clock.GetUtcNow().ToString("O", CultureInfo.InvariantCulture),
            ExitStatus = exitCode,
            ServiceResult = exitCode == 0 ? "success" : "exit-code",
            MemPeakBytes = peakBytes,
            LimitViolations = recordedNotification ? ["job_memory"] : [],
            RecordedBy = "holder",
        }.ToJson());

        await node.StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        var task = await Tasks.WaitAsync(channel, taskId);
        Assert.Equal(expectedState, task.State);
        Assert.Equal(1u, task.AttemptCount);
        var attempt = task.CurrentAttempt;
        Assert.Equal(attemptId, attempt.AttemptId);
        Assert.True(attempt.NodeGap);
        Assert.Equal((ulong)peakBytes, attempt.Usage.MemPeakBytes);
        Assert.True(attempt.Result.HasExitCode);
        Assert.Equal(exitCode, attempt.Result.ExitCode);
        Assert.Equal(EffectCertainty.Happened, attempt.Result.Effect);
        Assert.Equal(expectedReason, attempt.Result.TerminationReason);
        if (expectedReason == TerminationReason.MemoryLimit)
        {
            Assert.Contains("own job", attempt.Result.Detail, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("not proven", attempt.Result.Detail, StringComparison.OrdinalIgnoreCase);
        }
    }
}
