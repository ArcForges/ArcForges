// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;

namespace ArcForges.Node.Store.Policy;

/// <summary>A stored policy revision.</summary>
public sealed class StoredPolicy
{
    internal StoredPolicy(long revision, PolicyDocument document, ReadOnlyMemory<byte> digest, long createdAt, ActorRef actor, string? comment)
    {
        Revision = revision;
        Document = document;
        Digest = digest;
        CreatedAt = createdAt;
        Actor = actor;
        Comment = comment;
    }

    /// <summary>The revision number (1 is the default document written at store creation).</summary>
    public long Revision { get; }

    /// <summary>The document.</summary>
    public PolicyDocument Document { get; }

    /// <summary>SHA-256 of the canonical binary document (<c>PolicyRevision.digest</c>).</summary>
    public ReadOnlyMemory<byte> Digest { get; }

    /// <summary>When the revision was written (microseconds since the Unix epoch).</summary>
    public long CreatedAt { get; }

    /// <summary>Who wrote the revision.</summary>
    public ActorRef Actor { get; }

    /// <summary>The revision comment.</summary>
    public string? Comment { get; }
}

/// <summary>
/// <c>policy_document</c>: revisioned <see cref="PolicyDocument"/>s with exactly one current revision. The store writes
/// revision 1 (the default document) when it is created; the policy engine (AF-SCHED-01) adds revisions.
/// </summary>
public sealed class PolicyDocuments
{
    /// <summary>The comment of revision 1.</summary>
    public const string DefaultComment = "Default policy, written when the node store was created.";

    private readonly NodeStore _store;

    internal PolicyDocuments(NodeStore store) => _store = store;

    /// <summary>SHA-256 of the canonical binary encoding of <paramref name="document"/>.</summary>
    public static byte[] Digest(PolicyDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        return SHA256.HashData(document.ToByteArray());
    }

    /// <summary>The current revision.</summary>
    public StoredPolicy Current() => _store.Read(Current);

    /// <summary>The current revision, read in an open transaction.</summary>
    public static StoredPolicy Current(StoreReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        using var command = reader.CreateCommand(
            "SELECT revision, document, digest, created_at, actor, comment FROM policy_document WHERE is_current = 1;");
        using var row = command.ExecuteReader();
        if (!row.Read())
        {
            throw new InvalidOperationException("The node store has no current policy revision.");
        }

        return new StoredPolicy(
            row.GetInt64(0),
            PolicyDocument.Parser.ParseFrom((byte[])row.GetValue(1)),
            (byte[])row.GetValue(2),
            row.GetInt64(3),
            ActorRef.Parser.ParseFrom((byte[])row.GetValue(4)),
            row.IsDBNull(5) ? null : row.GetString(5));
    }

    internal static void InsertDefault(StoreTransaction transaction)
    {
        var document = DefaultPolicy.Create();
        var actor = new ActorRef { Origin = Origin.Node };
        transaction.Execute(
            """
            INSERT INTO policy_document (revision, document, digest, created_at, actor, comment, approval_id, is_current)
            VALUES (1, $document, $digest, $now, $actor, $comment, NULL, 1);
            """,
            ("$document", document.ToByteArray()),
            ("$digest", Digest(document)),
            ("$now", transaction.NowMicroseconds),
            ("$actor", actor.ToByteArray()),
            ("$comment", DefaultComment));
    }
}
