// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Scheduling;

/// <summary>An automatic retry admission decided for a finished attempt.</summary>
/// <param name="Delay">The backoff before the task is queued again.</param>
/// <param name="LargerMemory">The attempt was killed at its memory limit: the next attempt gets a larger memory grant.</param>
/// <param name="Reason">Why it is retried (for <c>state_reason</c>).</param>
public sealed record RetryDecision(TimeSpan Delay, bool LargerMemory, string Reason);

/// <summary>
/// The automatic retry rules of AD-0006 section 4 and 04 section 8 (R-EXE-010): a task is retried automatically only when its class is
/// <c>PURE</c> or <c>IDEMPOTENT</c> and that class was asserted (by the caller, a <c>retry_safety</c> rule or a verifying adapter; an
/// agent's assertion counts only with <c>accept_agent_assertions</c>, which submission already applied), or for an infrastructure failure
/// before the process started. A suggested class never retries; <c>SIDE_EFFECTING</c> and <c>UNKNOWN</c> tasks are never retried after the
/// process started (a LOST attempt included). The backoff is <c>initial x 2^(n-1)</c>, capped (defaults 5 s and 60 s).
/// </summary>
public static class RetryRules
{
    /// <summary>The automatic retries of an asserted class without a <c>retry</c> spec (AD-0006 section 4: default 2).</summary>
    public const int DefaultRetries = 2;

    /// <summary>The default initial backoff (tasks.proto <c>RetrySpec.initial_backoff_ms</c>).</summary>
    public static readonly TimeSpan DefaultInitialBackoff = TimeSpan.FromSeconds(5);

    /// <summary>The default backoff cap (tasks.proto <c>RetrySpec.max_backoff_ms</c>).</summary>
    public static readonly TimeSpan DefaultMaxBackoff = TimeSpan.FromSeconds(60);

    /// <summary>True when the class was asserted by a source that may make it retryable (AD-0006 section 4).</summary>
    public static bool Asserted(SideEffectClass sideEffect, SideEffectSource source) =>
        sideEffect is SideEffectClass.Pure or SideEffectClass.Idempotent
        && source is SideEffectSource.Caller or SideEffectSource.Policy or SideEffectSource.Adapter;

    /// <summary>The most attempts a task may make: <c>retry.max_attempts</c>, else 1 + <see cref="DefaultRetries"/> for an asserted class, else 1.</summary>
    public static int MaxAttempts(RetrySpec? retry, SideEffectClass sideEffect, SideEffectSource source) =>
        retry is { HasMaxAttempts: true } ? (int)Math.Clamp(retry.MaxAttempts, 1u, 5u) : Asserted(sideEffect, source) ? 1 + DefaultRetries : 1;

    /// <summary>The backoff before attempt <paramref name="failedAttempt"/> + 1: <c>initial x 2^(failedAttempt-1)</c>, capped.</summary>
    public static TimeSpan Backoff(RetrySpec? retry, int failedAttempt)
    {
        var initial = retry is { HasInitialBackoffMs: true } ? TimeSpan.FromMilliseconds(retry.InitialBackoffMs) : DefaultInitialBackoff;
        var cap = retry is { HasMaxBackoffMs: true } ? TimeSpan.FromMilliseconds(retry.MaxBackoffMs) : DefaultMaxBackoff;
        var factor = Math.Pow(2, Math.Clamp(failedAttempt - 1, 0, 20));
        var delay = TimeSpan.FromMilliseconds(Math.Min(initial.TotalMilliseconds * factor, cap.TotalMilliseconds));
        return delay < TimeSpan.Zero ? TimeSpan.Zero : delay;
    }

    /// <summary>
    /// The retry of a finished attempt, or <see langword="null"/>: <paramref name="reason"/> is how attempt <paramref name="attemptNumber"/>
    /// ended (a non-zero exit is <c>EXITED</c> with <paramref name="succeeded"/> false). <paramref name="canGrowMemory"/> is false when the
    /// memory grant is already at <c>max_task_memory</c>, so an OOM retry would fail the same way.
    /// </summary>
    public static RetryDecision? Decide(TaskSpec spec, SideEffectClass sideEffect, SideEffectSource source, TerminationReason reason, bool succeeded, int attemptNumber,
        bool canGrowMemory)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (succeeded)
        {
            return null;
        }

        var maxAttempts = MaxAttempts(spec.Retry, sideEffect, source);
        if (attemptNumber >= maxAttempts)
        {
            return null;
        }

        var asserted = Asserted(sideEffect, source);
        var delay = Backoff(spec.Retry, attemptNumber);
        string Text(string what) => string.Create(CultureInfo.InvariantCulture,
            $"{what}; automatic retry {attemptNumber} of {maxAttempts - 1} in {delay.TotalSeconds:0.#} s");
        return reason switch
        {
            // An infrastructure failure before the process started may be retried for every class (AD-0006 section 4); without an
            // asserted class only when the task asked for retries, since most spawn failures (a missing program) fail the same way again.
            TerminationReason.SpawnFailed when asserted || spec.Retry is { HasMaxAttempts: true, MaxAttempts: > 1 } => new RetryDecision(delay, false, Text("SPAWN_FAILED")),
            TerminationReason.Exited or TerminationReason.TimedOut or TerminationReason.CpuTimeExceeded or TerminationReason.Preempted or TerminationReason.Lost
                when asserted => new RetryDecision(delay, false, Text(reason.ToString().ToUpperInvariant())),
            TerminationReason.OomKilled or TerminationReason.MemoryLimit when asserted && canGrowMemory =>
                new RetryDecision(delay, true, Text(reason.ToString().ToUpperInvariant() + " (with a larger memory grant)")),
            _ => null,
        };
    }

    /// <summary>
    /// The larger memory grant of a retry after an OOM kill (AD-0006 section 4): <c>mem_expected</c> becomes the larger of the previous
    /// expectation and the observed peak, and the ceiling doubles, both within <c>max_task_memory</c>.
    /// </summary>
    public static (long Expected, long Ceiling) LargerGrant(long expected, long ceiling, long peak, long maxTaskMemory)
    {
        var grownCeiling = Math.Min(maxTaskMemory, Math.Max(ceiling * 2, ceiling + (1024L * 1024 * 1024)));
        var grownExpected = Math.Min(grownCeiling, Math.Max(expected, peak));
        return (grownExpected, grownCeiling);
    }
}
