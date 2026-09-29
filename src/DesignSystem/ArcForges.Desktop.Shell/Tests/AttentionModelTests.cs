// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Resources;
using Xunit;

namespace ArcForges.Desktop.Shell.Tests;

public sealed class AttentionModelTests
{
    [Fact]
    public void MissedNotificationLeavesDurableAttentionUntilOwnerResolvesIt()
    {
        var model = new AttentionModel();
        var pending = new AttentionItem(
            "approval-17",
            "Access approval required",
            "Review the requested project access.",
            AttentionDurability.Durable);

        var delivered = model.Publish(pending, static _ => false);

        Assert.False(delivered);
        Assert.Equal(pending, Assert.Single(model.Snapshot()));

        var updated = new AttentionItem(
            pending.Id,
            "Access approval required",
            "The approval request changed.",
            AttentionDurability.Durable);
        Assert.False(model.Publish(updated, static _ => false));
        Assert.Equal(updated, Assert.Single(model.Snapshot()));

        Assert.True(model.RemoveResolved(pending.Id));
        Assert.False(model.RemoveResolved(pending.Id));
        Assert.Empty(model.Snapshot());
    }

    [Fact]
    public void TransientNotificationIsBestEffortAndNeverEntersDurableSnapshot()
    {
        var model = new AttentionModel();
        var attempts = 0;
        var transient = new AttentionItem(
            "saved-toast",
            "Saved",
            "Your local changes were saved.",
            AttentionDurability.Transient,
            AttentionSensitivity.NonSensitive);

        var delivered = model.Publish(transient, _ =>
        {
            attempts++;
            return false;
        });

        Assert.False(delivered);
        Assert.Equal(1, attempts);
        Assert.Empty(model.Snapshot());
    }

    [Fact]
    public void SensitiveSystemNotificationUsesGenericContentUnlessPreviewConsentIsExplicit()
    {
        var sensitive = new AttentionItem(
            "approval-18",
            "Project Phoenix access approval",
            "Private project and requester details.",
            AttentionDurability.Durable);

        var safeDefault = AttentionModel.CreateSystemNotificationContent(sensitive);

        var resources = new ResourceManager(
            "ArcForges.Desktop.Shell.Errors.ErrorPresentationStrings",
            typeof(AttentionModel).Assembly);
        string expectedTitle = resources.GetString("attention.notification.generic_title", CultureInfo.CurrentUICulture)
            ?? throw new InvalidOperationException("The generic attention title resource is missing.");
        string expectedBody = resources.GetString("attention.notification.generic_body", CultureInfo.CurrentUICulture)
            ?? throw new InvalidOperationException("The generic attention body resource is missing.");
        Assert.Equal(expectedTitle, safeDefault.Title);
        Assert.Equal(expectedBody, safeDefault.Body);
        Assert.DoesNotContain("Phoenix", safeDefault.Title + safeDefault.Body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Private project", safeDefault.Title + safeDefault.Body, StringComparison.OrdinalIgnoreCase);

        var consented = AttentionModel.CreateSystemNotificationContent(sensitive, NotificationPreviewConsent.Granted);
        Assert.Equal(new SystemNotificationContent(sensitive.Title, sensitive.Body), consented);
    }

    [Fact]
    public void ExplicitlyNonSensitiveContentCanBeShownWithoutSensitivePreviewConsent()
    {
        var publicItem = new AttentionItem(
            "sync-complete",
            "Sync complete",
            "Your workspace is up to date.",
            AttentionDurability.Transient,
            AttentionSensitivity.NonSensitive);

        var content = AttentionModel.CreateSystemNotificationContent(publicItem);

        Assert.Equal(new SystemNotificationContent(publicItem.Title, publicItem.Body), content);
    }
}
