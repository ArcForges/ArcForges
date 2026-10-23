// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Core.Security;

/// <summary>What an approval request captures (approvals.proto <c>Approval</c>; node-store.md <c>approval</c>).</summary>
public sealed class ApprovalCapture
{
    /// <summary>The method, as <c>&lt;Service&gt;.&lt;Method&gt;</c> (approvals.proto: for example <c>TaskService.CancelTask</c>).</summary>
    public required string Operation { get; init; }

    /// <summary>The matrix operation that required the approval (<see cref="PermissionMatrix"/>).</summary>
    public required string MatrixOperation { get; init; }

    /// <summary>A one-line summary for the approver.</summary>
    public required string Summary { get; init; }

    /// <summary>Details for the approver.</summary>
    public IReadOnlyList<KeyValue> Details { get; init; } = [];

    /// <summary>The risk class.</summary>
    public required RiskClass Risk { get; init; }

    /// <summary>The caller that asked.</summary>
    public required ActorRef Requester { get; init; }

    /// <summary>The original request's <c>meta.command_id</c>, under which the request executes once approved.</summary>
    public required byte[] CommandId { get; init; }

    /// <summary>The serialized original request (meta included: <c>expected_rev</c> is checked when it executes).</summary>
    public required byte[] Request { get; init; }

    /// <summary>The request's payload digest (<see cref="PayloadDigest"/>).</summary>
    public required byte[] RequestDigest { get; init; }

    /// <summary>The object the request acts on (audit), if any.</summary>
    public string? TargetKind { get; init; }

    /// <summary>The object's ID (audit), if any.</summary>
    public byte[]? TargetId { get; init; }
}

/// <summary>A stored approval with what the approval service needs beyond the API view.</summary>
/// <param name="View">The API view.</param>
/// <param name="Request">The captured request.</param>
/// <param name="RequestDigest">Its payload digest.</param>
/// <param name="Outcome">The serialized response of the executed request, once EXECUTED or FAILED.</param>
public sealed record StoredApproval(Approval View, byte[] Request, byte[] RequestDigest, byte[]? Outcome)
{
    /// <summary>The approval ID.</summary>
    public byte[] Id => View.ApprovalId.Value.ToByteArray();

    /// <summary>The state.</summary>
    public ApprovalState State => View.State;
}

/// <summary>
/// The approval records (SM-APPROVAL; node-store.md <c>approval</c>): a request the permission matrix marks APPROVAL is captured with its
/// original <c>command_id</c> as a PENDING approval; one command ID has at most one approval (unique index), so a caller that retries the same
/// request finds the same approval. PENDING becomes APPROVED or DENIED by a HUMAN decision, CANCELLED when withdrawn, EXPIRED after its TTL
/// (policy <c>approvals.default_ttl_ms</c>, default 24 h); APPROVED becomes EXECUTED or FAILED once the captured request ran under its original
/// command ID, with the response stored as the outcome. Every change is journaled on topic APPROVALS and written to the audit log in the same
/// transaction. Decided approvals are kept for 90 days.
/// </summary>
public static class Approvals
{
    /// <summary>The default TTL of a pending approval (policy.proto <c>ApprovalPolicy.default_ttl_ms</c>).</summary>
    public static readonly TimeSpan DefaultTtl = TimeSpan.FromHours(24);

    private const long RetentionMicroseconds = 90L * 24 * 60 * 60 * 1_000_000;

    private const string Columns =
        "approval_id, state, operation, summary, details_json, risk, requester, command_id, request, request_digest, finding_id, created_at, expires_at, " +
        "decided_by, decided_at, comment, outcome";

    /// <summary>
    /// Raises the approval of <paramref name="capture"/>, or finds the one already raised for its command ID. A command ID raised before for
    /// another operation or payload is <c>CONFLICT/command_id_reused</c>. Returns the approval and whether it was created now.
    /// </summary>
    public static (StoredApproval? Approval, bool Created, ArcError? Error) Raise(CommandContext context, ApprovalCapture capture, TimeSpan ttl)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(capture);
        var transaction = context.Transaction;
        if (ByCommand(transaction, capture.CommandId) is { } existing)
        {
            return existing.View.Operation == capture.Operation && existing.RequestDigest.AsSpan().SequenceEqual(capture.RequestDigest)
                ? (existing, false, null)
                : (null, false, StoreErrors.CommandIdReused());
        }

        var id = StoreIds.NewUuid7(transaction.Clock);
        var now = transaction.NowMicroseconds;
        transaction.Execute(
            $"""
            INSERT INTO approval ({Columns}, rev)
            VALUES ($id, $state, $operation, $summary, $details, $risk, $requester, $command, $request, $digest, NULL, $now, $expires, NULL, NULL, NULL, NULL, 0);
            """,
            ("$id", id), ("$state", (int)ApprovalState.Pending), ("$operation", capture.Operation), ("$summary", Truncate(capture.Summary, 500)),
            ("$details", DetailsJson(capture.Details)), ("$risk", (int)(capture.Risk == RiskClass.Unspecified ? RiskClass.Medium : capture.Risk)),
            ("$requester", capture.Requester.ToByteArray()), ("$command", capture.CommandId), ("$request", capture.Request), ("$digest", capture.RequestDigest),
            ("$now", now), ("$expires", now + (long)ttl.TotalMicroseconds));
        var created = Get(transaction, id)!;
        AuditLog.Append(transaction, capture.Requester, capture.MatrixOperation + " " + capture.Operation, capture.TargetKind, capture.TargetId ?? [],
            PermissionDecision.Approval, id, "approval requested: " + created.View.Summary);
        context.Emit(EventTopic.Approvals, new NodeEvent { Approval = created.View });
        return (created, true, null);
    }

    /// <summary>The approval <paramref name="id"/>, or <see langword="null"/>.</summary>
    public static StoredApproval? Get(StoreReader reader, ReadOnlySpan<byte> id)
    {
        ArgumentNullException.ThrowIfNull(reader);
        using var command = reader.CreateCommand($"SELECT {Columns} FROM approval WHERE approval_id = $id;");
        command.Parameters.AddWithValue("$id", id.ToArray());
        using var rows = command.ExecuteReader();
        return rows.Read() ? Read(rows) : null;
    }

    /// <summary>The approval raised for <paramref name="commandId"/>, or <see langword="null"/>.</summary>
    public static StoredApproval? ByCommand(StoreReader reader, ReadOnlySpan<byte> commandId)
    {
        ArgumentNullException.ThrowIfNull(reader);
        using var command = reader.CreateCommand($"SELECT {Columns} FROM approval WHERE command_id = $command;");
        command.Parameters.AddWithValue("$command", commandId.ToArray());
        using var rows = command.ExecuteReader();
        return rows.Read() ? Read(rows) : null;
    }

    /// <summary>
    /// A page of approvals, pending first, then newest first (approvals.proto <c>ListApprovals</c>), optionally only <paramref name="states"/>
    /// and only those <paramref name="visible"/> accepts.
    /// </summary>
    public static (List<Approval> Items, string? Next) List(StoreReader reader, IReadOnlyCollection<ApprovalState> states, Func<Approval, bool> visible, int offset, int limit)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(states);
        ArgumentNullException.ThrowIfNull(visible);
        var items = new List<Approval>();
        using (var command = reader.CreateCommand(
            $"SELECT {Columns} FROM approval ORDER BY CASE state WHEN {(int)ApprovalState.Pending} THEN 0 ELSE 1 END, created_at DESC, approval_id DESC;"))
        {
            using var rows = command.ExecuteReader();
            var skipped = 0;
            while (rows.Read())
            {
                var approval = Read(rows).View;
                if ((states.Count > 0 && !states.Contains(approval.State)) || !visible(approval))
                {
                    continue;
                }

                if (skipped++ < offset)
                {
                    continue;
                }

                items.Add(approval);
                if (items.Count > limit)
                {
                    break;
                }
            }
        }

        if (items.Count <= limit)
        {
            return (items, null);
        }

        items.RemoveAt(items.Count - 1);
        return (items, (offset + limit).ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    /// <summary>Moves every PENDING approval past its TTL to EXPIRED (journaled and audited). Returns the number expired.</summary>
    public static int Expire(CommandContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var transaction = context.Transaction;
        var due = new List<byte[]>();
        using (var command = transaction.CreateCommand("SELECT approval_id FROM approval WHERE state = $pending AND expires_at <= $now;"))
        {
            command.Parameters.AddWithValue("$pending", (int)ApprovalState.Pending);
            command.Parameters.AddWithValue("$now", transaction.NowMicroseconds);
            using var rows = command.ExecuteReader();
            while (rows.Read())
            {
                due.Add((byte[])rows.GetValue(0));
            }
        }

        foreach (var id in due)
        {
            var approval = Transition(context, id, ApprovalState.Expired, null, null);
            AuditLog.Append(transaction, new ActorRef { Origin = Origin.Node }, "approval.expire ApprovalService", "approval", id, PermissionDecision.Deny, id,
                "approval expired unanswered: " + approval.View.Summary);
        }

        return due.Count;
    }

    /// <summary>Records a HUMAN decision of a PENDING approval (the caller checked the state): APPROVED or DENIED.</summary>
    public static StoredApproval Decide(CommandContext context, ReadOnlySpan<byte> id, bool approve, ActorRef decider, string? comment)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(decider);
        var approval = Transition(context, id, approve ? ApprovalState.Approved : ApprovalState.Denied, decider, comment);
        AuditLog.Append(context.Transaction, decider, PermissionMatrix.ApprovalDecide + " ApprovalService.DecideApproval", "approval", id, PermissionDecision.Allow, id,
            (approve ? "approved: " : "denied: ") + approval.View.Summary);
        return approval;
    }

    /// <summary>Withdraws a PENDING approval (the caller checked the state and the caller).</summary>
    public static StoredApproval Cancel(CommandContext context, ReadOnlySpan<byte> id, ActorRef actor)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(actor);
        var approval = Transition(context, id, ApprovalState.Cancelled, null, null);
        AuditLog.Append(context.Transaction, actor, "approval.cancel ApprovalService.CancelApproval", "approval", id, PermissionDecision.Allow, id,
            "approval withdrawn: " + approval.View.Summary);
        return approval;
    }

    /// <summary>
    /// Records the execution of an APPROVED approval: EXECUTED with the response, or FAILED when the response carries an error. An approval
    /// that is no longer APPROVED (another execution recorded it first) is left as it is.
    /// </summary>
    public static StoredApproval? Executed(CommandContext context, ReadOnlySpan<byte> id, byte[] response, ArcError? error, string matrixOperation)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(response);
        var transaction = context.Transaction;
        if (Get(transaction, id) is not { State: ApprovalState.Approved } current)
        {
            return Get(transaction, id);
        }

        transaction.Execute("UPDATE approval SET outcome = $outcome WHERE approval_id = $id;", ("$outcome", response), ("$id", id.ToArray()));
        var executed = Transition(context, id, error is null ? ApprovalState.Executed : ApprovalState.Failed, null, null);
        AuditLog.Append(transaction, current.View.Requester, matrixOperation + " " + current.View.Operation, "approval", id, PermissionDecision.Allow, id,
            error is null ? "executed after approval" : $"failed after approval: {error.Category}/{error.Code}");
        return executed;
    }

    /// <summary>Approvals that were APPROVED but never recorded as executed (the node stopped in between): executed again at startup.</summary>
    public static List<StoredApproval> Unexecuted(StoreReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        var found = new List<StoredApproval>();
        using var command = reader.CreateCommand($"SELECT {Columns} FROM approval WHERE state = $approved ORDER BY created_at;");
        command.Parameters.AddWithValue("$approved", (int)ApprovalState.Approved);
        using var rows = command.ExecuteReader();
        while (rows.Read())
        {
            found.Add(Read(rows));
        }

        return found;
    }

    /// <summary>Retention (housekeeping): approvals decided (or otherwise ended) more than 90 days ago are deleted.</summary>
    public static int Prune(StoreTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        return transaction.Execute(
            "DELETE FROM approval WHERE state NOT IN ($pending, $approved) AND coalesce(decided_at, expires_at) < $cutoff;",
            ("$pending", (int)ApprovalState.Pending), ("$approved", (int)ApprovalState.Approved), ("$cutoff", transaction.NowMicroseconds - RetentionMicroseconds));
    }

    /// <summary>The <c>AUTHORIZATION/approval_required</c> error of a pending approval (errors.md: <c>state.resource = {kind: "approval", id}</c>).</summary>
    public static ArcError Required(Approval approval)
    {
        ArgumentNullException.ThrowIfNull(approval);
        return new ArcError
        {
            Code = "approval_required",
            Category = ErrorCategory.Authorization,
            MessageKey = "error.authorization.approval_required",
            Retry = new RetryAdvice { Mode = RetryMode.Reconcile },
            Effect = EffectCertainty.DidNotHappen,
            Details = new ErrorDetails
            {
                State = new StateFailure
                {
                    State = approval.State.ToString().ToUpperInvariant(),
                    Reason = approval.Operation + ": an approval is required; approve it in ArcForges Desktop or with 'arcforges approvals approve "
                        + IdText.Format(approval.ApprovalId) + "'",
                    Resource = new AggregateRef { Kind = "approval", Id = approval.ApprovalId },
                },
            },
        };
    }

    private static StoredApproval Transition(CommandContext context, ReadOnlySpan<byte> id, ApprovalState to, ActorRef? decider, string? comment)
    {
        var transaction = context.Transaction;
        var key = id.ToArray();
        if (decider is not null)
        {
            transaction.Execute("UPDATE approval SET state = $state, decided_by = $by, decided_at = $now, comment = $comment, rev = rev + 1 WHERE approval_id = $id;",
                ("$state", (int)to), ("$by", decider.ToByteArray()), ("$now", transaction.NowMicroseconds), ("$comment", comment), ("$id", key));
        }
        else
        {
            transaction.Execute("UPDATE approval SET state = $state, rev = rev + 1 WHERE approval_id = $id;", ("$state", (int)to), ("$id", key));
        }

        var approval = Get(transaction, key) ?? throw new InvalidOperationException("The approval vanished in its own transaction.");
        context.Emit(EventTopic.Approvals, new NodeEvent { Approval = approval.View });
        return approval;
    }

    private static StoredApproval Read(SqliteDataReader rows)
    {
        var view = new Approval
        {
            ApprovalId = new Id { Value = ByteString.CopyFrom((byte[])rows.GetValue(0)) },
            State = (ApprovalState)rows.GetInt32(1),
            Operation = rows.GetString(2),
            Summary = rows.GetString(3),
            Risk = (RiskClass)rows.GetInt32(5),
            Requester = ActorRef.Parser.ParseFrom((byte[])rows.GetValue(6)),
            CommandId = new Id { Value = ByteString.CopyFrom((byte[])rows.GetValue(7)) },
            RequestDigest = Convert.ToHexStringLower((byte[])rows.GetValue(9)),
            CreatedAt = Notifications.Time(rows.GetInt64(11)),
            ExpiresAt = Notifications.Time(rows.GetInt64(12)),
        };
        view.Details.Add(ReadDetails(rows.GetString(4)));
        if (!rows.IsDBNull(10))
        {
            view.FindingId = new Id { Value = ByteString.CopyFrom((byte[])rows.GetValue(10)) };
        }

        if (!rows.IsDBNull(13))
        {
            view.DecidedBy = ActorRef.Parser.ParseFrom((byte[])rows.GetValue(13));
        }

        if (!rows.IsDBNull(14))
        {
            view.DecidedAt = Notifications.Time(rows.GetInt64(14));
        }

        if (!rows.IsDBNull(15))
        {
            view.Comment = rows.GetString(15);
        }

        byte[]? outcome = rows.IsDBNull(16) ? null : (byte[])rows.GetValue(16);
        if (view.State == ApprovalState.Executed)
        {
            view.Outcome = new Receipt { CommandId = view.CommandId, Effect = EffectCertainty.Happened };
        }
        else if (view.State == ApprovalState.Failed && outcome is not null && OutcomeError(outcome) is { } error)
        {
            view.OutcomeError = error;
        }

        return new StoredApproval(view, (byte[])rows.GetValue(8), (byte[])rows.GetValue(9), outcome);
    }

    /// <summary>
    /// The <c>error</c> of a serialized <c>&lt;Method&gt;Response</c>: every node response has <c>meta = 1</c> and the <c>outcome</c> oneof
    /// with <c>value = 2</c> and <c>error = 3</c> (contracts README section 4), so field 3 is read without knowing the response type.
    /// </summary>
    public static ArcError? OutcomeError(byte[] response)
    {
        ArgumentNullException.ThrowIfNull(response);
        var input = new CodedInputStream(response);
        while (input.ReadTag() is var tag and not 0)
        {
            if (WireFormat.GetTagFieldNumber(tag) == 3 && WireFormat.GetTagWireType(tag) == WireFormat.WireType.LengthDelimited)
            {
                var error = new ArcError();
                input.ReadMessage(error);
                return error;
            }

            input.SkipLastField();
        }

        return null;
    }

    private static string DetailsJson(IReadOnlyList<KeyValue> details)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartArray();
            foreach (var detail in details.Take(32))
            {
                writer.WriteStartObject();
                writer.WriteString("name", Truncate(detail.Name, 100));
                writer.WriteString("value", detail.Redacted ? string.Empty : Truncate(detail.Value, 500));
                writer.WriteBoolean("redacted", detail.Redacted);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static List<KeyValue> ReadDetails(string json)
    {
        using var document = JsonDocument.Parse(json);
        var details = new List<KeyValue>();
        foreach (var item in document.RootElement.EnumerateArray())
        {
            var detail = new KeyValue
            {
                Name = item.GetProperty("name").GetString() ?? string.Empty,
                Value = item.GetProperty("value").GetString() ?? string.Empty,
            };
            if (item.TryGetProperty("redacted", out var redacted) && redacted.GetBoolean())
            {
                detail.Redacted = true;
            }

            details.Add(detail);
        }

        return details;
    }

    private static string Truncate(string text, int length) => text.Length <= length ? text : text[..length];
}
