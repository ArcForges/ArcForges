// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Foundation.Errors;
using IdentityGeneration = ArcForges.Foundation.IdentityGeneration;

namespace ArcForges.Capabilities.Tests;

public sealed class InProcessStateHintTests
{
    [Xunit.Fact]
    public async Task DuplicateHintsCoalesceAndEveryHintPageRequiresAnAuthoritativeRead()
    {
        var feed = new InProcessStateHintFeed(NewInstance());
        int reads = 0;
        var initial = await feed.PollAndReadAsync<string>(null, (hints, reset, _) =>
        {
            reads++;
            Xunit.Assert.True(reset);
            Xunit.Assert.Empty(hints);
            return ValueTask.FromResult(Outcome.Success("initial-authoritative-state"));
        }, cancellationToken: Xunit.TestContext.Current.CancellationToken);
        var initialPage = Value(initial);
        Xunit.Assert.True(initialPage.ResetRequired);
        Xunit.Assert.True(initialPage.HasAuthoritativeState);
        Xunit.Assert.Equal("initial-authoritative-state", initialPage.AuthoritativeState);

        Xunit.Assert.True(feed.Publish(StateHintKind.Health, "instance-1"));
        Xunit.Assert.True(feed.Publish(StateHintKind.Health, "instance-1"));
        Xunit.Assert.True(feed.Publish(StateHintKind.Resource, "resource-1"));
        Xunit.Assert.True(feed.Publish(StateHintKind.Context, "context-1"));
        Xunit.Assert.True(feed.Publish(StateHintKind.ProductJob, "job-1"));
        Xunit.Assert.False(feed.Publish((StateHintKind)0, "invalid-kind"));
        Xunit.Assert.False(feed.Publish(StateHintKind.Health, "../secret"));

        var updated = await feed.PollAndReadAsync<string>(initialPage.Cursor, (hints, reset, _) =>
        {
            reads++;
            Xunit.Assert.False(reset);
            Xunit.Assert.Equal(4, hints.Count);
            Xunit.Assert.Contains(hints, hint => hint.Kind == StateHintKind.Health && hint.TargetId == "instance-1");
            Xunit.Assert.Contains(hints, hint => hint.Kind == StateHintKind.Resource && hint.TargetId == "resource-1");
            Xunit.Assert.Contains(hints, hint => hint.Kind == StateHintKind.Context && hint.TargetId == "context-1");
            Xunit.Assert.Contains(hints, hint => hint.Kind == StateHintKind.ProductJob && hint.TargetId == "job-1");
            return ValueTask.FromResult(Outcome.Success("fresh-health-and-resource-state"));
        }, cancellationToken: Xunit.TestContext.Current.CancellationToken);
        var updatedPage = Value(updated);
        Xunit.Assert.True(updatedPage.HasAuthoritativeState);
        Xunit.Assert.Equal("fresh-health-and-resource-state", updatedPage.AuthoritativeState);
        Xunit.Assert.Equal(2, reads);

        var quiet = await feed.PollAndReadAsync<string>(updatedPage.Cursor, (_, _, _) =>
        {
            reads++;
            return ValueTask.FromResult(Outcome.Success("unexpected-read"));
        }, cancellationToken: Xunit.TestContext.Current.CancellationToken);
        var quietPage = Value(quiet);
        Xunit.Assert.Empty(quietPage.Hints);
        Xunit.Assert.False(quietPage.ResetRequired);
        Xunit.Assert.False(quietPage.HasAuthoritativeState);
        Xunit.Assert.Equal(2, reads);
    }

    [Xunit.Fact]
    public async Task SmallPagesAdvanceWithoutSkippingHintsOrOwnerReads()
    {
        var feed = new InProcessStateHintFeed(NewInstance());
        var start = Value(await feed.PollAndReadAsync<string>(null, (_, reset, _) =>
        {
            Xunit.Assert.True(reset);
            return ValueTask.FromResult(Outcome.Success("initial"));
        }, cancellationToken: Xunit.TestContext.Current.CancellationToken));

        Xunit.Assert.True(feed.Publish(StateHintKind.Resource, "resource-1"));
        Xunit.Assert.True(feed.Publish(StateHintKind.Resource, "resource-2"));
        Xunit.Assert.True(feed.Publish(StateHintKind.Resource, "resource-3"));

        var first = Value(await feed.PollAndReadAsync<string>(start.Cursor, (hints, reset, _) =>
        {
            Xunit.Assert.False(reset);
            Xunit.Assert.Equal(new[] { "resource-1" }, hints.Select(hint => hint.TargetId));
            return ValueTask.FromResult(Outcome.Success("first-page-read"));
        }, limit: 1, cancellationToken: Xunit.TestContext.Current.CancellationToken));
        Xunit.Assert.True(first.HasAuthoritativeState);

        var second = Value(await feed.PollAndReadAsync<string>(first.Cursor, (hints, reset, _) =>
        {
            Xunit.Assert.False(reset);
            Xunit.Assert.Equal(new[] { "resource-2", "resource-3" }, hints.Select(hint => hint.TargetId));
            return ValueTask.FromResult(Outcome.Success("second-page-read"));
        }, limit: 2, cancellationToken: Xunit.TestContext.Current.CancellationToken));
        Xunit.Assert.True(second.HasAuthoritativeState);
    }

    [Xunit.Fact]
    public async Task ExpiredCursorAndRestartForceFullReadBeforeContinuing()
    {
        var clock = new ManualTimeProvider();
        var instance = NewInstance();
        var feed = new InProcessStateHintFeed(instance, clock);
        int reads = 0;
        var start = Value(await feed.PollAndReadAsync<string>(null, FullRead,
            cancellationToken: Xunit.TestContext.Current.CancellationToken));

        clock.Advance(TimeSpan.FromSeconds(61));
        var expired = Value(await feed.PollAndReadAsync<string>(start.Cursor, FullRead,
            cancellationToken: Xunit.TestContext.Current.CancellationToken));
        Xunit.Assert.True(expired.ResetRequired);
        Xunit.Assert.True(expired.HasAuthoritativeState);

        var restartedIdentity = new InstanceIdentity(instance.Installation, IdentityGeneration.NewInstance(), instance.Epoch + 1);
        var restarted = new InProcessStateHintFeed(restartedIdentity, clock);
        var stale = await restarted.PollAndReadAsync<string>(expired.Cursor, (hints, reset, _) =>
        {
            reads++;
            Xunit.Assert.True(reset);
            Xunit.Assert.Empty(hints);
            return ValueTask.FromResult(Outcome.Success("after-restart"));
        }, cancellationToken: Xunit.TestContext.Current.CancellationToken);
        Xunit.Assert.True(Value(stale).ResetRequired);
        Xunit.Assert.Equal(3, reads);

        ValueTask<Outcome<string>> FullRead(IReadOnlyList<StateHint> hints, bool reset, CancellationToken _)
        {
            reads++;
            Xunit.Assert.True(reset);
            Xunit.Assert.Empty(hints);
            return ValueTask.FromResult(Outcome.Success("authoritative"));
        }
    }

    [Xunit.Fact]
    public async Task DroppedHistoryOrMissingOwnerContentResetsWithoutFallbackLaunch()
    {
        var feed = new InProcessStateHintFeed(NewInstance());
        var initial = Value(await feed.PollAndReadAsync<string>(null, (_, _, _) =>
            ValueTask.FromResult(Outcome.Success("initial")), cancellationToken: Xunit.TestContext.Current.CancellationToken));
        for (int index = 0; index < 257; index++)
        {
            Xunit.Assert.True(feed.Publish(StateHintKind.Resource, "resource-" + index));
        }

        int ownerReads = 0;
        var result = await feed.PollAndReadAsync<string>(initial.Cursor, (hints, reset, _) =>
        {
            ownerReads++;
            Xunit.Assert.True(reset);
            Xunit.Assert.Empty(hints);
            return ValueTask.FromResult(Outcome.Failure<string>(TypedFailure.Create("resource.unavailable")));
        }, cancellationToken: Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.True(result.TryGetFailure(out var failure));
        Xunit.Assert.Equal("resource.unavailable", failure!.Code);
        Xunit.Assert.Equal(1, ownerReads);
        Xunit.Assert.True(feed.Publish(StateHintKind.Capability, "target-1"));
    }

    [Xunit.Fact]
    public async Task PageBoundsAndForeignCursorsRefuseOrResetBeforeDataIsTrusted()
    {
        var instance = NewInstance();
        var firstFeed = new InProcessStateHintFeed(instance);
        var first = Value(await firstFeed.PollAndReadAsync<string>(null, (_, _, _) =>
            ValueTask.FromResult(Outcome.Success("initial")), cancellationToken: Xunit.TestContext.Current.CancellationToken));
        var secondFeed = new InProcessStateHintFeed(instance);
        int reads = 0;
        var crossFeed = Value(await secondFeed.PollAndReadAsync<string>(first.Cursor, (hints, reset, _) =>
        {
            reads++;
            Xunit.Assert.True(reset);
            Xunit.Assert.Empty(hints);
            return ValueTask.FromResult(Outcome.Success("fresh"));
        }, cancellationToken: Xunit.TestContext.Current.CancellationToken));
        Xunit.Assert.True(crossFeed.ResetRequired);
        Xunit.Assert.Equal(1, reads);

        var invalidLimit = await secondFeed.PollAndReadAsync<string>(crossFeed.Cursor, (_, _, _) =>
            ValueTask.FromResult(Outcome.Success("must-not-read")), limit: 129,
            cancellationToken: Xunit.TestContext.Current.CancellationToken);
        Xunit.Assert.True(invalidLimit.TryGetFailure(out var failure));
        Xunit.Assert.Equal("validation.invalid_request", failure!.Code);
        Xunit.Assert.Equal(1, reads);
    }

    private static InstanceIdentity NewInstance()
    {
        var installation = new InstallationIdentity(AppIdentity.ArcScope,
            IdentityGeneration.NewDevice(), IdentityGeneration.NewInstallation());
        return new InstanceIdentity(installation, IdentityGeneration.NewInstance(), 1);
    }

    private static StateHintReconciliation<string> Value(Outcome<StateHintReconciliation<string>> outcome)
    {
        Xunit.Assert.True(outcome.TryGetValue(out var value));
        return value;
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private long _timestamp;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override long GetTimestamp() => _timestamp;

        public void Advance(TimeSpan duration) => _timestamp += duration.Ticks;
    }
}
