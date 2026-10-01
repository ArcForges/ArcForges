// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Desktop.Shell.Localization;

namespace ArcForges.Desktop.Shell;

public enum AttentionDurability
{
    Transient,
    Durable
}

public enum AttentionSensitivity
{
    NonSensitive,
    Sensitive
}

public enum NotificationPreviewConsent
{
    NotGranted,
    Granted
}

/// <summary>A shell projection of an owner-controlled attention condition.</summary>
public sealed record AttentionItem
{
    public AttentionItem(
        string id,
        string title,
        string body,
        AttentionDurability durability,
        AttentionSensitivity sensitivity = AttentionSensitivity.Sensitive)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(title);
        ArgumentException.ThrowIfNullOrWhiteSpace(body);
        if (!Enum.IsDefined(durability))
        {
            throw new ArgumentOutOfRangeException(nameof(durability));
        }

        if (!Enum.IsDefined(sensitivity))
        {
            throw new ArgumentOutOfRangeException(nameof(sensitivity));
        }

        Id = id;
        Title = title;
        Body = body;
        Durability = durability;
        Sensitivity = sensitivity;
    }

    public string Id { get; }

    public string Title { get; }

    public string Body { get; }

    public AttentionDurability Durability { get; }

    public AttentionSensitivity Sensitivity { get; }
}

public sealed record SystemNotificationContent(string Title, string Body);

/// <summary>
/// Keeps durable attention independent of best-effort notification delivery. Domain owners remain responsible
/// for creating and resolving their conditions; this model only keeps their current shell projection visible.
/// </summary>
public sealed class AttentionModel
{
    private const string GenericNotificationTitleKey = "attention.notification.generic_title";
    private const string GenericNotificationBodyKey = "attention.notification.generic_body";

    private readonly object _gate = new();
    private readonly Dictionary<string, AttentionItem> _durableItems = new(StringComparer.Ordinal);

    /// <summary>
    /// Publishes the current owner projection before attempting notification delivery. Durable items are
    /// upserted by stable ID and are unaffected when the callback is absent or reports a missed notification.
    /// Transient items are never retained.
    /// </summary>
    public bool Publish(
        AttentionItem item,
        Func<SystemNotificationContent, bool>? tryNotify = null,
        NotificationPreviewConsent previewConsent = NotificationPreviewConsent.NotGranted)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (!Enum.IsDefined(previewConsent))
        {
            throw new ArgumentOutOfRangeException(nameof(previewConsent));
        }

        if (item.Durability == AttentionDurability.Durable)
        {
            lock (_gate)
            {
                _durableItems[item.Id] = item;
            }
        }

        var content = CreateSystemNotificationContent(item, previewConsent);
        return tryNotify?.Invoke(content) ?? false;
    }

    /// <summary>Returns a stable, read-only snapshot of unresolved durable items.</summary>
    public IReadOnlyList<AttentionItem> Snapshot()
    {
        lock (_gate)
        {
            return Array.AsReadOnly(_durableItems.Values
                .OrderBy(static item => item.Id, StringComparer.Ordinal)
                .ToArray());
        }
    }

    /// <summary>Removes an item only after its owning domain reports it resolved.</summary>
    public bool RemoveResolved(string id)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        lock (_gate)
        {
            return _durableItems.Remove(id);
        }
    }

    /// <summary>Creates system-safe content; sensitive details require explicit preview consent.</summary>
    public static SystemNotificationContent CreateSystemNotificationContent(
        AttentionItem item,
        NotificationPreviewConsent previewConsent = NotificationPreviewConsent.NotGranted)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (!Enum.IsDefined(previewConsent))
        {
            throw new ArgumentOutOfRangeException(nameof(previewConsent));
        }

        if (item.Sensitivity == AttentionSensitivity.Sensitive && previewConsent != NotificationPreviewConsent.Granted)
        {
            return new SystemNotificationContent(
                GetRequiredResource(GenericNotificationTitleKey),
                GetRequiredResource(GenericNotificationBodyKey));
        }

        return new SystemNotificationContent(item.Title, item.Body);
    }

    private static string GetRequiredResource(string key) =>
        ShellText.TryGetText(ShellText.ErrorSet, key, CultureInfo.CurrentUICulture)
        ?? throw new InvalidOperationException("The safe attention notification resources are unavailable.");
}
