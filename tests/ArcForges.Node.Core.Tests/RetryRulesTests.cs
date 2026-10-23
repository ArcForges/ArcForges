// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Scheduling;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// The automatic retry rules of AD-0006 section 4 and 04 section 8 (R-EXE-010) per class, source and termination reason, the attempt
/// count, the backoff and the larger memory grant after an OOM kill (pure rules; the node-level behaviour is in SchedulerTests).
/// </summary>
public sealed class RetryRulesTests
{
    private const long GiB = 1024L * 1024 * 1024;

    private static readonly TerminationReason[] AfterStart =
        [TerminationReason.Exited, TerminationReason.TimedOut, TerminationReason.CpuTimeExceeded, TerminationReason.Preempted, TerminationReason.Lost];

    private static TaskSpec Spec(uint? maxAttempts = null)
    {
        var spec = new TaskSpec();
        if (maxAttempts is { } attempts)
        {
            spec.Retry = new RetrySpec { MaxAttempts = attempts };
        }

        return spec;
    }

    [Theory]
    [InlineData(SideEffectClass.Pure, SideEffectSource.Caller, true)]
    [InlineData(SideEffectClass.Idempotent, SideEffectSource.Caller, true)]
    [InlineData(SideEffectClass.Idempotent, SideEffectSource.Policy, true)]
    [InlineData(SideEffectClass.Pure, SideEffectSource.Adapter, true)]
    [InlineData(SideEffectClass.Pure, SideEffectSource.Default, false)]
    [InlineData(SideEffectClass.Idempotent, SideEffectSource.Unspecified, false)]
    [InlineData(SideEffectClass.SideEffecting, SideEffectSource.Caller, false)]
    [InlineData(SideEffectClass.Unknown, SideEffectSource.Caller, false)]
    [InlineData(SideEffectClass.Unknown, SideEffectSource.Default, false)]
    public void OnlyAnAssertedPureOrIdempotentClassIsRetriedAfterTheProcessStarted(SideEffectClass sideEffect, SideEffectSource source, bool retried)
    {
        Assert.Equal(retried, RetryRules.Asserted(sideEffect, source));
        foreach (var reason in AfterStart)
        {
            var decision = RetryRules.Decide(Spec(5), sideEffect, source, reason, succeeded: false, attemptNumber: 1, canGrowMemory: true);
            Assert.True(retried == decision is not null, $"{sideEffect}/{source}/{reason}");
            Assert.False(decision?.LargerMemory ?? false);
        }

        // A success is never retried.
        Assert.Null(RetryRules.Decide(Spec(5), sideEffect, source, TerminationReason.Exited, succeeded: true, attemptNumber: 1, canGrowMemory: true));

        // A cancel, a policy denial, the output and disk limits and a node shutdown are never automatic retries.
        foreach (var reason in new[] { TerminationReason.Cancelled, TerminationReason.PolicyDenied, TerminationReason.OutputLimit, TerminationReason.DiskLimit, TerminationReason.NodeShutdown })
        {
            Assert.Null(RetryRules.Decide(Spec(5), sideEffect, source, reason, succeeded: false, attemptNumber: 1, canGrowMemory: true));
        }
    }

    [Fact]
    public void AnAssertedClassMakesThreeAttemptsByDefaultAndRetryMaxAttemptsOtherwise()
    {
        Assert.Equal(3, RetryRules.MaxAttempts(null, SideEffectClass.Idempotent, SideEffectSource.Caller));
        Assert.Equal(1, RetryRules.MaxAttempts(null, SideEffectClass.Unknown, SideEffectSource.Default));
        Assert.Equal(2, RetryRules.MaxAttempts(new RetrySpec { MaxAttempts = 2 }, SideEffectClass.Pure, SideEffectSource.Caller));
        Assert.Equal(5, RetryRules.MaxAttempts(new RetrySpec { MaxAttempts = 9 }, SideEffectClass.Pure, SideEffectSource.Caller));
        Assert.NotNull(RetryRules.Decide(Spec(), SideEffectClass.Pure, SideEffectSource.Caller, TerminationReason.Exited, false, 2, true));
        Assert.Null(RetryRules.Decide(Spec(), SideEffectClass.Pure, SideEffectSource.Caller, TerminationReason.Exited, false, 3, true));
        Assert.Null(RetryRules.Decide(Spec(2), SideEffectClass.Pure, SideEffectSource.Caller, TerminationReason.Exited, false, 2, true));
    }

    [Fact]
    public void ASpawnFailureIsRetriedForAnAssertedClassOrWhenTheTaskAskedForRetries()
    {
        // Before the process started (AD-0006 section 4): every class may be retried, but an unasserted one only with retry.max_attempts.
        Assert.NotNull(RetryRules.Decide(Spec(), SideEffectClass.Idempotent, SideEffectSource.Caller, TerminationReason.SpawnFailed, false, 1, true));
        Assert.NotNull(RetryRules.Decide(Spec(2), SideEffectClass.SideEffecting, SideEffectSource.Caller, TerminationReason.SpawnFailed, false, 1, true));
        Assert.NotNull(RetryRules.Decide(Spec(2), SideEffectClass.Unknown, SideEffectSource.Default, TerminationReason.SpawnFailed, false, 1, true));
        Assert.Null(RetryRules.Decide(Spec(), SideEffectClass.Unknown, SideEffectSource.Default, TerminationReason.SpawnFailed, false, 1, true));
    }

    [Fact]
    public void AnOomKillOfAnAssertedTaskIsRetriedWithALargerGrantWhileItCanGrow()
    {
        foreach (var reason in new[] { TerminationReason.OomKilled, TerminationReason.MemoryLimit })
        {
            var decision = RetryRules.Decide(Spec(), SideEffectClass.Pure, SideEffectSource.Caller, reason, false, 1, canGrowMemory: true);
            Assert.True(decision?.LargerMemory);
            Assert.Null(RetryRules.Decide(Spec(), SideEffectClass.Pure, SideEffectSource.Caller, reason, false, 1, canGrowMemory: false));
            Assert.Null(RetryRules.Decide(Spec(5), SideEffectClass.Unknown, SideEffectSource.Default, reason, false, 1, canGrowMemory: true));
        }

        // The ceiling doubles (at least +1 GiB), the expectation becomes the observed peak, both within max_task_memory.
        Assert.Equal((3 * GiB, 4 * GiB), RetryRules.LargerGrant(1 * GiB, 2 * GiB, 3 * GiB, 16 * GiB));
        Assert.Equal((GiB / 2, (GiB / 2) + GiB), RetryRules.LargerGrant(GiB / 4, GiB / 2, GiB / 2, 16 * GiB));
        Assert.Equal((5 * GiB, 5 * GiB), RetryRules.LargerGrant(4 * GiB, 4 * GiB, 6 * GiB, 5 * GiB));
    }

    [Fact]
    public void TheBackoffDoublesFromItsInitialValueUpToItsCap()
    {
        Assert.Equal(TimeSpan.FromSeconds(5), RetryRules.Backoff(null, 1));
        Assert.Equal(TimeSpan.FromSeconds(10), RetryRules.Backoff(null, 2));
        Assert.Equal(TimeSpan.FromSeconds(40), RetryRules.Backoff(null, 4));
        Assert.Equal(TimeSpan.FromSeconds(60), RetryRules.Backoff(null, 5));
        var fast = new RetrySpec { InitialBackoffMs = 200, MaxBackoffMs = 500 };
        Assert.Equal(TimeSpan.FromMilliseconds(200), RetryRules.Backoff(fast, 1));
        Assert.Equal(TimeSpan.FromMilliseconds(400), RetryRules.Backoff(fast, 2));
        Assert.Equal(TimeSpan.FromMilliseconds(500), RetryRules.Backoff(fast, 3));
        var spec = Spec(3);
        spec.Retry.InitialBackoffMs = 200;
        Assert.Equal(TimeSpan.FromMilliseconds(400), RetryRules.Decide(spec, SideEffectClass.Pure, SideEffectSource.Caller, TerminationReason.Exited, false, 2, true)?.Delay);
    }
}
