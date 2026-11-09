// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store;

namespace ArcForges.Node.CloudLink;

/// <summary>Runs one write of the routed call log in the node's single writer (the host passes its command processor).</summary>
internal interface IRoutedCallStore
{
    /// <summary>Runs <paramref name="write"/> in one store transaction of the single writer and returns its result after the commit.</summary>
    Task<long> WriteAsync(Func<StoreTransaction, long> write);
}

/// <summary>The final decision of a verified call (node-store.md section 2a, <c>routed_call_log.decision</c>).</summary>
internal enum RoutedCallDecision
{
    /// <summary>1: the TaskService handler ran (its answer, a value or its own refusal, is the signed result).</summary>
    Executed = 1,

    /// <summary>2: refused by the center-routed policy or the permission matrix.</summary>
    RefusedByPolicy = 2,

    /// <summary>3: refused at verification (Design 11 T-11; a replayed call ID included).</summary>
    RefusedVerification = 3,

    /// <summary>4: verified, but expired at the re-check immediately before the effect.</summary>
    Expired = 4,

    /// <summary>5: verified, outcome pending (written at verification, before any effect).</summary>
    Pending = 5,
}

/// <summary>What a verified call records before any effect (the fields the call header signed; never a payload).</summary>
internal sealed record VerifiedCallRow
{
    /// <summary>SHA-256 of the received RelayFrame bytes.</summary>
    public required byte[] FrameSha256 { get; init; }

    /// <summary>The verified call ID (16 bytes).</summary>
    public required byte[] CallId { get; init; }

    /// <summary>The command key that signed the call.</summary>
    public required string Kid { get; init; }

    /// <summary>The routed method, 1..6.</summary>
    public required int Method { get; init; }

    /// <summary>The node.v1 CenterCaller bytes as the call header signed them.</summary>
    public required byte[] Caller { get; init; }

    /// <summary>The command ID of a submit or cancel (16 bytes), else <see langword="null"/>.</summary>
    public byte[]? CommandId { get; init; }

    /// <summary>SHA-256 of the payload.</summary>
    public required byte[] RequestSha256 { get; init; }

    /// <summary>The payload's length.</summary>
    public required long RequestSize { get; init; }
}

/// <summary>
/// The node store's <c>routed_call_log</c> (schema step 2, ArcForges-Design <c>docs/data/node-store.sql</c> at 611dda6 verbatim; node-store.md
/// section 2a; Plan PN-7, the D0 review's N-5 and C-N3): one row per received call frame. A refused frame is named by its frame digest and
/// failed step only and never names or occupies an ID; a verified call's row is written at verification, before any effect, with decision
/// 5 (pending), and is completed afterwards. A call ID already logged is a replay (<c>call_replayed</c>), also after a restart: the logged row
/// outlives the call's validity (at most 300 s plus the 120 s skew). Never a payload, argv, working directory, environment, output, message
/// or details: only <c>CATEGORY/code</c>, digests and sizes.
/// </summary>
internal sealed class RoutedCallLog(IRoutedCallStore store, TimeProvider clock)
{
    /// <summary>The newest verification refusals kept (node-store.md: 1 year or the newest 10,000, whichever is fewer).</summary>
    public const int RefusalsKept = 10_000;

    /// <summary>How long a row is kept (submit, cancel, every refusal).</summary>
    public static readonly TimeSpan Retention = TimeSpan.FromDays(365);

    /// <summary>How long an executed read is kept.</summary>
    public static readonly TimeSpan ReadRetention = TimeSpan.FromDays(7);

    /// <summary>The refusal step of a replayed call (C-N3).</summary>
    public const string Replayed = "call_replayed";

    /// <summary>
    /// Records a verified call as pending; <see langword="null"/> when its call ID is already logged: the replay is then recorded as a
    /// verification refusal (<c>call_replayed</c>) in the same transaction of the single writer, so of two copies of one call only the first
    /// passes.
    /// </summary>
    public async Task<long?> RecordVerifiedAsync(VerifiedCallRow row)
    {
        ArgumentNullException.ThrowIfNull(row);
        var now = StoreTime.NowMicroseconds(clock);
        var id = await store.WriteAsync(transaction =>
        {
            if (transaction.Scalar("SELECT 1 FROM routed_verified_call_id WHERE call_id = $call;", ("$call", row.CallId)) is not null)
            {
                InsertRefusal(transaction, now, row.FrameSha256, Replayed, "AUTHENTICATION/signature_invalid");
                return 0;
            }

            return (long)transaction.Scalar("""
                INSERT INTO routed_call_log (received_at, frame_sha256, decision, call_id, signature_kid, method, caller, command_id,
                  request_sha256, request_size)
                VALUES ($at, $frame, 5, $call, $kid, $method, $caller, $command, $request, $size)
                RETURNING log_id;
                """, ("$at", now), ("$frame", row.FrameSha256), ("$call", row.CallId), ("$kid", row.Kid), ("$method", row.Method),
                ("$caller", row.Caller), ("$command", (object?)row.CommandId ?? DBNull.Value), ("$request", row.RequestSha256), ("$size", row.RequestSize))!;
        }).ConfigureAwait(false);
        return id == 0 ? null : id;
    }

    /// <summary>Records a frame refused at verification: its digest, the failed step and <c>CATEGORY/code</c>; nothing it names.</summary>
    public Task RecordRefusalAsync(byte[] frameSha256, string step, string code)
    {
        ArgumentNullException.ThrowIfNull(frameSha256);
        var now = StoreTime.NowMicroseconds(clock);
        return store.WriteAsync(transaction =>
        {
            InsertRefusal(transaction, now, frameSha256, step, code);
            return 0;
        });
    }

    /// <summary>Completes a pending row with its final decision (1, 2 or 4) and what the answer named.</summary>
    public Task CompleteAsync(long logId, RoutedCallDecision decision, string? refusalCode, byte[]? taskId = null, int? risk = null,
        byte[]? responseSha256 = null, long? responseSize = null)
    {
        if (decision is not (RoutedCallDecision.Executed or RoutedCallDecision.RefusedByPolicy or RoutedCallDecision.Expired))
        {
            throw new ArgumentOutOfRangeException(nameof(decision), "A verified call ends executed, refused by policy or expired.");
        }

        return store.WriteAsync(transaction => transaction.Execute("""
            UPDATE routed_call_log SET decision = $decision, refusal_code = $code, task_id = $task, risk = $risk,
              response_sha256 = $response, response_size = $size
            WHERE log_id = $id AND decision = 5;
            """, ("$decision", (int)decision), ("$code", (object?)refusalCode ?? DBNull.Value), ("$task", (object?)taskId ?? DBNull.Value),
            ("$risk", (object?)risk ?? DBNull.Value), ("$response", (object?)responseSha256 ?? DBNull.Value), ("$size", (object?)responseSize ?? DBNull.Value),
            ("$id", logId)));
    }

    /// <summary>
    /// Applies the retention of node-store.md section 2a in <paramref name="transaction"/> (the housekeeping turn): executed reads after 7
    /// days, every row after 1 year, and verification refusals beyond the newest 10,000. Returns the rows removed.
    /// </summary>
    public static int Prune(StoreTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        var now = transaction.NowMicroseconds;
        var removed = transaction.Execute("DELETE FROM routed_call_log WHERE received_at < $cutoff;", ("$cutoff", now - Micros(Retention)));
        removed += transaction.Execute("DELETE FROM routed_call_log WHERE decision = 1 AND method BETWEEN 2 AND 5 AND received_at < $cutoff;",
            ("$cutoff", now - Micros(ReadRetention)));
        removed += transaction.Execute("""
            DELETE FROM routed_call_log WHERE decision = 3 AND log_id NOT IN
              (SELECT log_id FROM routed_call_log WHERE decision = 3 ORDER BY log_id DESC LIMIT $kept);
            """, ("$kept", RefusalsKept));
        return removed;
    }

    private static long Micros(TimeSpan span) => span.Ticks / 10;

    private static void InsertRefusal(StoreTransaction transaction, long now, byte[] frameSha256, string step, string code) =>
        transaction.Execute("""
            INSERT INTO routed_call_log (received_at, frame_sha256, decision, refusal_step, refusal_code)
            VALUES ($at, $frame, 3, $step, $code);
            """, ("$at", now), ("$frame", frameSha256), ("$step", step), ("$code", code));
}

/// <summary>The host's store: one write through the node's command processor.</summary>
internal sealed class ProcessorRoutedCallStore(ArcForges.Node.Core.CommandProcessor processor) : IRoutedCallStore
{
    /// <inheritdoc />
    public Task<long> WriteAsync(Func<StoreTransaction, long> write)
    {
        ArgumentNullException.ThrowIfNull(write);
        return processor.ExecuteAsync(context => write(context.Transaction));
    }
}
