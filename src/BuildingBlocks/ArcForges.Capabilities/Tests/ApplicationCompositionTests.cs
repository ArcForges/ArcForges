// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;

namespace ArcForges.Capabilities.Tests;

public sealed class ApplicationCompositionTests
{
    private static readonly DeviceId Device = new(new Guid("10000000-0000-0000-0000-000000000001"));
    private static readonly InstallationId Installation = new(new Guid("20000000-0000-0000-0000-000000000001"));

    private static InstallationIdentity Installed(AppIdentity? app = null) => new(app ?? AppIdentity.ArcScope, Device, Installation);
    private static ApplicationComposition<FixtureOwner> Start(InstallationIdentity? installation = null, ulong epoch = 1)
        => ApplicationComposition<FixtureOwner>.Start(installation ?? Installed(), epoch, identity => new FixtureOwner(identity));
    private static ApplicationHandler<FixtureOwner, string, string> Bind(ApplicationComposition<FixtureOwner> root)
        => root.Bind<string, string>((owner, value, _) =>
        {
            owner.Sessions.Add(value);
            owner.History.Add(value);
            owner.Capabilities.Add(value);
            return ValueTask.FromResult(Outcome.Success(owner.Identity.Installation.App.ProductId + ":" + owner.History.Count));
        });

    [Xunit.Fact]
    public void StableProductsAreClosedAndCompanionDoesNotEncodePlatform()
    {
        Xunit.Assert.Same(AppIdentity.ArcScope, AppIdentity.Parse("arcscope"));
        Xunit.Assert.Same(AppIdentity.Companion, AppIdentity.Parse("companion"));
        foreach (var invalid in new[] { "", "ArcScope", "companion-android", "companion-web", "arcscope-v2" })
        {
            Xunit.Assert.Throws<ArgumentException>(() => AppIdentity.Parse(invalid));
        }
    }

    [Xunit.Fact]
    public void DefaultStrongIdentifiersAndAbsentEpochCannotEnterAComposition()
    {
        Xunit.Assert.Throws<ArgumentException>(() => new InstallationIdentity(AppIdentity.ArcScope, default, Installation));
        Xunit.Assert.Throws<ArgumentException>(() => new InstallationIdentity(AppIdentity.ArcScope, Device, default));
        Xunit.Assert.Throws<ArgumentNullException>(() => new InstallationIdentity(null!, Device, Installation));
        Xunit.Assert.Throws<ArgumentException>(() => new InstanceIdentity(Installed(), default, 1));
        Xunit.Assert.Throws<ArgumentNullException>(() => new InstanceIdentity(Installed(), IdentityGeneration.NewInstance(), null));
        Xunit.Assert.Equal(0ul, Start(epoch: 0).Identity.Epoch);
        Xunit.Assert.Equal(ulong.MaxValue, Start(epoch: ulong.MaxValue).Identity.Epoch);
        Xunit.Assert.Throws<ArgumentNullException>(() => ApplicationComposition<FixtureOwner>.Start(Installed(), 1, null!));
        Xunit.Assert.Throws<ArgumentException>(() => ApplicationComposition<FixtureOwner>.Start(Installed(), 1, _ => null!));
    }

    [Xunit.Fact]
    public void GeneratedApplicationScopeIsAnOwnedCopy()
    {
        var installation = Installed();
        var scope = installation.ToApplicationScope();
        scope.ProductId = "changed";
        scope.InstallationId.Value = Google.Protobuf.ByteString.Empty;
        var fresh = installation.ToApplicationScope();
        Xunit.Assert.Equal("arcscope", fresh.ProductId);
        Xunit.Assert.Equal(Installation, InstallationId.FromWire(fresh.InstallationId));
    }

    [Xunit.Fact]
    public async Task TwoProductsOnOneDeviceOwnSeparateSessionHistoryAndCapabilityState()
    {
        var first = Start();
        var second = Start(Installed(AppIdentity.Companion));
        var firstHandler = Bind(first);
        var secondHandler = Bind(second);
        Xunit.Assert.Equal("arcscope:1", Value(await first.DispatchAsync(firstHandler, first.Identity, "first")));
        Xunit.Assert.Equal("companion:1", Value(await second.DispatchAsync(secondHandler, second.Identity, "second")));
        Xunit.Assert.Equal("arcscope:2", Value(await first.DispatchAsync(firstHandler, first.Identity, "third")));
        Refused(await first.DispatchAsync(firstHandler, second.Identity, "forged"), "perm.capability_denied");
        Refused(await first.DispatchAsync(secondHandler, first.Identity, "foreign registration"), "perm.capability_denied");
        Xunit.Assert.Equal("companion:2", Value(await second.DispatchAsync(secondHandler, second.Identity, "fourth")));
    }

    [Xunit.Fact]
    public async Task MissingDeviceInstallationInstanceAndEpochTargetsNeverReachHandler()
    {
        var root = Start();
        var handler = Bind(root);
        Refused(await root.DispatchAsync(handler, null, "missing"), "validation.invalid_request");
        var foreignDevice = new InstallationIdentity(AppIdentity.ArcScope, IdentityGeneration.NewDevice(), Installation);
        var reinstalled = new InstallationIdentity(AppIdentity.ArcScope, Device, IdentityGeneration.NewInstallation());
        foreach (var installation in new[] { foreignDevice, reinstalled })
        {
            Refused(await root.DispatchAsync(handler, new InstanceIdentity(installation, root.Identity.InstanceId, 1), "foreign"), "perm.capability_denied");
        }

        Refused(await root.DispatchAsync(handler, new InstanceIdentity(Installed(), IdentityGeneration.NewInstance(), 1), "instance"), "state.gone");
        Refused(await root.DispatchAsync(handler, new InstanceIdentity(Installed(), root.Identity.InstanceId, 2), "epoch"), "state.gone");
        Xunit.Assert.Equal("arcscope:1", Value(await root.DispatchAsync(handler, root.Identity, "accepted")));
    }

    [Xunit.Fact]
    public async Task ConcurrentInstancesAndRestartNeverRetargetCapturedCalls()
    {
        var installation = Installed();
        var first = Start(installation);
        var concurrent = Start(installation);
        Xunit.Assert.NotEqual(first.Identity.InstanceId, concurrent.Identity.InstanceId);
        Refused(await concurrent.DispatchAsync(Bind(concurrent), first.Identity, "captured"), "state.gone");
        first.Stop();
        var restarted = Start(installation, 2);
        Xunit.Assert.Equal(first.Identity.Installation, restarted.Identity.Installation);
        Xunit.Assert.NotEqual(first.Identity.InstanceId, restarted.Identity.InstanceId);
        Refused(await restarted.DispatchAsync(Bind(restarted), first.Identity, "stale"), "state.gone");
        Xunit.Assert.Equal("arcscope:1", Value(await restarted.DispatchAsync(Bind(restarted), restarted.Identity, "fresh")));
    }

    [Xunit.Fact]
    public async Task StopFencesNewAdmissionButDoesNotEraseIdentityOrRollBackAdmittedEffects()
    {
        var root = Start();
        var identity = root.Identity;
        var effect = new TaskCompletionSource<Outcome<string>>(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = root.Bind<string, string>((_, _, _) => new ValueTask<Outcome<string>>(effect.Task));
        var admitted = root.DispatchAsync(handler, identity, "started");
        root.Stop();
        root.Stop();
        Refused(await root.DispatchAsync(handler, identity, "later"), "state.gone");
        Xunit.Assert.Throws<InvalidOperationException>(() => Bind(root));
        effect.SetResult(Outcome.Success("committed"));
        Xunit.Assert.Equal("committed", Value(await admitted));
        Xunit.Assert.Equal(identity, root.Identity);
    }

    [Xunit.Fact]
    public async Task CancellationBeforeAdmissionDoesNotInvokeOwner()
    {
        var root = Start();
        var handler = Bind(root);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        Xunit.Assert.Throws<OperationCanceledException>(() => root.DispatchAsync(handler, root.Identity, "cancelled", cancellation.Token));
        Xunit.Assert.Equal("arcscope:1", Value(await root.DispatchAsync(handler, root.Identity, "accepted")));
    }

    private static string Value(Outcome<string> outcome)
    {
        Xunit.Assert.True(outcome.TryGetValue(out var value));
        return value;
    }

    private static void Refused(Outcome<string> outcome, string code)
    {
        Xunit.Assert.True(outcome.TryGetFailure(out var failure));
        Xunit.Assert.Equal(code, failure.Code);
        Xunit.Assert.Equal(EffectCertainty.DidNotHappen, failure.Effect);
        Xunit.Assert.Equal(RetryMode.Never, failure.Retry);
    }

    private sealed class FixtureOwner(InstanceIdentity identity)
    {
        public InstanceIdentity Identity { get; } = identity;
        public List<string> Sessions { get; } = [];
        public List<string> History { get; } = [];
        public List<string> Capabilities { get; } = [];
    }
}
