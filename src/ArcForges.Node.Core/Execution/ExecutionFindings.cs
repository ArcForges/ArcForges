// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Proto;
using Google.Protobuf;

namespace ArcForges.Node.Core.Execution;

/// <summary>
/// The findings execution raises (node-store.md <c>finding</c>; SM-FINDING): a finding is deduplicated by its open subject (a repeat
/// raises its occurrence count and last-seen time) and journaled on topic FINDINGS. The finding catalogue, remedies and their service
/// belong to AF-DIAG-01; execution raises <c>QUOTA_EXCEEDED</c> for an output limit under <c>NOTIFY</c> (06 section 5),
/// <c>TERMINATION_INCOMPLETE</c> (04 section 6 step 5) and <c>LEFTOVER_PROCESSES</c> (04 section 3).
/// </summary>
public static class ExecutionFindings
{
    /// <summary>Raises (or repeats) a finding about <paramref name="subjectKind"/>/<paramref name="subjectId"/>.</summary>
    public static Finding Raise(CommandContext context, FindingKind kind, Severity severity, string subjectKind, ReadOnlySpan<byte> subjectId,
        string title, string explanation, IReadOnlyList<(string Name, string Value)> evidence)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(evidence);
        var transaction = context.Transaction;
        var now = transaction.NowMicroseconds;
        var evidenceJson = JsonSerializer.Serialize(evidence.ToDictionary(item => item.Name, item => item.Value, StringComparer.Ordinal),
            ExecutionJsonContext.Default.DictionaryStringString);
        var existing = transaction.Scalar(
            "SELECT finding_id FROM finding WHERE kind = $kind AND subject_kind = $subjectKind AND subject_id = $subject AND state IN (1, 2, 5);",
            ("$kind", (int)kind), ("$subjectKind", subjectKind), ("$subject", subjectId.ToArray())) as byte[];
        byte[] id;
        if (existing is null)
        {
            id = StoreIds.NewUuid7(transaction.Clock);
            transaction.Execute(
                """
                INSERT INTO finding (finding_id, kind, severity, state, subject_kind, subject_id, title, explanation, evidence_json, actions,
                                     first_seen, last_seen, occurrences, clear_checks, rev)
                VALUES ($id, $kind, $severity, 1, $subjectKind, $subject, $title, $explanation, $evidence, $actions, $now, $now, 1, 0, 0);
                """,
                ("$id", id), ("$kind", (int)kind), ("$severity", (int)severity), ("$subjectKind", subjectKind), ("$subject", subjectId.ToArray()),
                ("$title", title), ("$explanation", explanation), ("$evidence", evidenceJson), ("$actions", new FindingActions().ToByteArray()),
                ("$now", now));
        }
        else
        {
            id = existing;
            transaction.Execute(
                "UPDATE finding SET last_seen = $now, occurrences = occurrences + 1, evidence_json = $evidence, rev = rev + 1 WHERE finding_id = $id;",
                ("$now", now), ("$evidence", evidenceJson), ("$id", id));
        }

        var finding = Read(transaction, id);
        context.Emit(EventTopic.Findings, new NodeEvent { Finding = finding });
        return finding;
    }

    /// <summary>The open findings about a subject.</summary>
    public static List<Finding> OpenFor(StoreReader reader, string subjectKind, ReadOnlySpan<byte> subjectId)
    {
        ArgumentNullException.ThrowIfNull(reader);
        using var command = reader.CreateCommand("SELECT finding_id FROM finding WHERE subject_kind = $kind AND subject_id = $id AND state IN (1, 2, 5);");
        command.Parameters.AddWithValue("$kind", subjectKind);
        command.Parameters.AddWithValue("$id", subjectId.ToArray());
        var ids = new List<byte[]>();
        using (var rows = command.ExecuteReader())
        {
            while (rows.Read())
            {
                ids.Add((byte[])rows.GetValue(0));
            }
        }

        return [.. ids.Select(id => Read(reader, id))];
    }

    private static Finding Read(StoreReader reader, byte[] id)
    {
        using var command = reader.CreateCommand(
            "SELECT kind, severity, state, subject_kind, subject_id, title, explanation, evidence_json, first_seen, last_seen, occurrences, rev " +
            "FROM finding WHERE finding_id = $id;");
        command.Parameters.AddWithValue("$id", id);
        using var rows = command.ExecuteReader();
        rows.Read();
        var finding = new Finding
        {
            FindingId = new Id { Value = ByteString.CopyFrom(id) },
            Kind = (FindingKind)rows.GetInt32(0),
            Severity = (Severity)rows.GetInt32(1),
            State = (FindingState)rows.GetInt32(2),
            Subject = new AggregateRef { Kind = rows.GetString(3), Id = new Id { Value = ByteString.CopyFrom((byte[])rows.GetValue(4)) } },
            Title = rows.GetString(5),
            Explanation = rows.GetString(6),
            FirstSeen = Notifications.Time(rows.GetInt64(8)),
            LastSeen = Notifications.Time(rows.GetInt64(9)),
            Occurrences = (uint)rows.GetInt32(10),
            Revision = new Revision { Value = rows.GetInt64(11) },
        };
        foreach (var (name, value) in JsonSerializer.Deserialize(rows.GetString(7), ExecutionJsonContext.Default.DictionaryStringString) ?? [])
        {
            finding.Evidence.Add(new KeyValue { Name = name, Value = value });
        }

        return finding;
    }
}
