// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Core;

/// <summary>One page of the notification centre.</summary>
public sealed record NotificationPage(IReadOnlyList<NodeNotification> Items, string? NextCursor, uint UnreadCount);

/// <summary>
/// The node's notification centre (node-store.md <c>notification</c>, the last 500 entries; Desktop D-21): listing newest first,
/// marking entries read (by ID, or every entry created up to a time; marking twice succeeds), and the NOTIFICATIONS events that
/// carry each change to subscribers.
/// </summary>
public static class Notifications
{
    /// <summary>The entries kept.</summary>
    public const int Retained = 500;

    /// <summary>A page, newest first; <paramref name="cursor"/> continues a previous page.</summary>
    public static NotificationPage List(StoreReader reader, bool unreadOnly, PageCursor? cursor, int limit)
    {
        ArgumentNullException.ThrowIfNull(reader);
        var sql = "SELECT notification_id, kind, severity, title, body, link, created_at, read_at FROM notification WHERE 1 = 1"
            + (unreadOnly ? " AND read_at IS NULL" : string.Empty)
            + (cursor is null ? string.Empty : " AND (created_at < $created OR (created_at = $created AND notification_id < $id))")
            + " ORDER BY created_at DESC, notification_id DESC LIMIT $limit;";
        var items = new List<NodeNotification>();
        using (var command = reader.CreateCommand(sql))
        {
            if (cursor is { } position)
            {
                command.Parameters.AddWithValue("$created", position.CreatedAt);
                command.Parameters.AddWithValue("$id", position.Id);
            }

            command.Parameters.AddWithValue("$limit", limit + 1);
            using var rows = command.ExecuteReader();
            while (rows.Read())
            {
                items.Add(Read(rows));
            }
        }

        string? next = null;
        if (items.Count > limit)
        {
            items.RemoveAt(items.Count - 1);
            var last = items[^1];
            next = new PageCursor(Micros(last.CreatedAt), last.NotificationId.Value.ToByteArray()).ToString();
        }

        return new NotificationPage(items, next, Unread(reader));
    }

    /// <summary>The number of unread entries.</summary>
    public static uint Unread(StoreReader reader) =>
        Convert.ToUInt32(reader.Scalar("SELECT count(*) FROM notification WHERE read_at IS NULL;"), CultureInfo.InvariantCulture);

    /// <summary>
    /// Marks the listed entries read, or, with no IDs, every entry created up to <paramref name="upTo"/>. Entries already read keep
    /// their time. Each entry that changed is journaled on topic NOTIFICATIONS. Returns the unread count after the change.
    /// </summary>
    public static uint MarkRead(CommandContext context, IReadOnlyList<byte[]> ids, long? upTo)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(ids);
        var transaction = context.Transaction;
        var now = transaction.NowMicroseconds;
        var changed = new List<byte[]>();
        if (ids.Count > 0)
        {
            foreach (var id in ids.Distinct(ByteArrayComparer.Instance))
            {
                if (transaction.Execute("UPDATE notification SET read_at = $now WHERE notification_id = $id AND read_at IS NULL;", ("$now", now), ("$id", id)) == 1)
                {
                    changed.Add(id);
                }
            }
        }
        else if (upTo is { } limit)
        {
            using (var command = transaction.CreateCommand("SELECT notification_id FROM notification WHERE read_at IS NULL AND created_at <= $upTo;"))
            {
                command.Parameters.AddWithValue("$upTo", limit);
                using var rows = command.ExecuteReader();
                while (rows.Read())
                {
                    changed.Add((byte[])rows.GetValue(0));
                }
            }

            transaction.Execute("UPDATE notification SET read_at = $now WHERE read_at IS NULL AND created_at <= $upTo;", ("$now", now), ("$upTo", limit));
        }

        foreach (var id in changed)
        {
            var updated = Get(transaction, id);
            if (updated is not null)
            {
                context.Emit(EventTopic.Notifications, new NodeEvent { Notification = updated });
            }
        }

        return Unread(transaction);
    }

    /// <summary>Adds an entry and journals it on topic NOTIFICATIONS.</summary>
    /// <param name="context">The writer's command.</param>
    /// <param name="kind"><c>task_failed</c>, <c>task_finished</c>, <c>approval_needed</c>, <c>finding</c>, <c>update</c> or <c>node</c>.</param>
    /// <param name="severity">The severity.</param>
    /// <param name="title">The title.</param>
    /// <param name="body">The body.</param>
    /// <param name="link">An <c>arcforges://</c> link to the subject.</param>
    public static NodeNotification Add(CommandContext context, string kind, Severity severity, string title, string body, string? link = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        var transaction = context.Transaction;
        var id = StoreIds.NewUuid7(transaction.Clock);
        transaction.Execute(
            "INSERT INTO notification (notification_id, kind, severity, title, body, link, created_at, read_at) VALUES ($id, $kind, $severity, $title, $body, $link, $now, NULL);",
            ("$id", id), ("$kind", kind), ("$severity", (int)severity), ("$title", title), ("$body", body), ("$link", link), ("$now", transaction.NowMicroseconds));
        var item = Get(transaction, id)!;
        context.Emit(EventTopic.Notifications, new NodeEvent { Notification = item });
        return item;
    }

    /// <summary>All entries (the snapshot of topic NOTIFICATIONS), newest first.</summary>
    public static List<NodeNotification> All(StoreReader reader)
    {
        var items = new List<NodeNotification>();
        using var command = reader.CreateCommand(
            "SELECT notification_id, kind, severity, title, body, link, created_at, read_at FROM notification ORDER BY created_at DESC, notification_id DESC LIMIT $limit;");
        command.Parameters.AddWithValue("$limit", Retained);
        using var rows = command.ExecuteReader();
        while (rows.Read())
        {
            items.Add(Read(rows));
        }

        return items;
    }

    /// <summary>Retention (housekeeping): keeps the newest 500 entries.</summary>
    internal static int Prune(StoreTransaction transaction) => transaction.Execute(
        """
        DELETE FROM notification WHERE notification_id NOT IN
          (SELECT notification_id FROM notification ORDER BY created_at DESC, notification_id DESC LIMIT $keep);
        """,
        ("$keep", Retained));

    private static NodeNotification? Get(StoreReader reader, byte[] id)
    {
        using var command = reader.CreateCommand(
            "SELECT notification_id, kind, severity, title, body, link, created_at, read_at FROM notification WHERE notification_id = $id;");
        command.Parameters.AddWithValue("$id", id);
        using var rows = command.ExecuteReader();
        return rows.Read() ? Read(rows) : null;
    }

    private static NodeNotification Read(SqliteDataReader rows)
    {
        var item = new NodeNotification
        {
            NotificationId = new Id { Value = ByteString.CopyFrom((byte[])rows.GetValue(0)) },
            Kind = rows.GetString(1),
            Severity = (Severity)rows.GetInt32(2),
            Title = rows.GetString(3),
            Body = rows.GetString(4),
            CreatedAt = Time(rows.GetInt64(6)),
        };
        if (!rows.IsDBNull(5))
        {
            item.Link = rows.GetString(5);
        }

        if (!rows.IsDBNull(7))
        {
            item.ReadAt = Time(rows.GetInt64(7));
        }

        return item;
    }

    internal static Instant Time(long microseconds) => ArcForges.Client.ProtoTime.ToInstant(StoreTime.FromMicroseconds(microseconds));

    internal static long Micros(Instant instant) =>
        StoreTime.ToMicroseconds(ArcForges.Client.ProtoTime.ToDateTimeOffset(instant) ?? DateTimeOffset.UnixEpoch);
}

/// <summary>Compares byte arrays by content.</summary>
internal sealed class ByteArrayComparer : IEqualityComparer<byte[]>
{
    public static readonly ByteArrayComparer Instance = new();

    public bool Equals(byte[]? x, byte[]? y) => x is null ? y is null : y is not null && x.AsSpan().SequenceEqual(y);

    public int GetHashCode(byte[] obj)
    {
        var hash = default(HashCode);
        hash.AddBytes(obj);
        return hash.ToHashCode();
    }
}
