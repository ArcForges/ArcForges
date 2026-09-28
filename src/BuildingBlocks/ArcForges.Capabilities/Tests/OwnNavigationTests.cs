// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;
using IdentityGeneration = ArcForges.Foundation.IdentityGeneration;

namespace ArcForges.Capabilities.Tests;

public sealed class OwnNavigationTests
{
    [Xunit.Fact]
    public async Task OwnedArtifactAndDeepLinkReachOnlyTheRegisteredApplicationHandlers()
    {
        var registry = new ArtifactHandlerRegistry<string>(AppIdentity.ArcScope);
        int permissionChecks = 0;
        int artifactOpens = 0;
        registry.Register("arcscope.report", "report-open", 1, [ArtifactAction.Open],
            (_, _, _) =>
            {
                permissionChecks++;
                return ValueTask.FromResult(Outcome.Success(true));
            },
            (_, _, _) =>
            {
                artifactOpens++;
                return ValueTask.FromResult(Outcome.Success("artifact-opened"));
            });

        var router = new OwnAppNavigationRouter<string>(AppIdentity.ArcScope, registry);
        int routeCalls = 0;
        router.RegisterRoute("report", (intent, _) =>
        {
            routeCalls++;
            Xunit.Assert.Same(AppIdentity.ArcScope, intent.Owner);
            Xunit.Assert.Equal("report", intent.RouteId);
            Xunit.Assert.Equal("report-123", intent.TargetId);
            Xunit.Assert.True(intent.IsUntrusted);
            return ValueTask.FromResult(Outcome.Success("deep-link-opened"));
        });

        Xunit.Assert.Equal("artifact-opened", Value(await router.OpenArtifactAsync(Artifact(), ArtifactAction.Open,
            cancellationToken: Xunit.TestContext.Current.CancellationToken)));
        Xunit.Assert.Equal("deep-link-opened", Value(await router.HandleDeepLinkAsync(
            "arcforges://arcscope/report/report-123", Xunit.TestContext.Current.CancellationToken)));
        Refused(await router.OpenArtifactAsync(Artifact("companion.report", "companion"), ArtifactAction.Open,
            cancellationToken: Xunit.TestContext.Current.CancellationToken), "resource.unavailable");

        Xunit.Assert.Equal(1, permissionChecks);
        Xunit.Assert.Equal(1, artifactOpens);
        Xunit.Assert.Equal(1, routeCalls);
    }

    [Xunit.Fact]
    public async Task HostileForeignAndMissingContentLinksFailClosedWithoutProductLaunch()
    {
        var registry = new ArtifactHandlerRegistry<string>(AppIdentity.ArcScope);
        var router = new OwnAppNavigationRouter<string>(AppIdentity.ArcScope, registry);
        var available = new HashSet<string>(StringComparer.Ordinal) { "present" };
        int routeCalls = 0;
        router.RegisterRoute("resource", (intent, _) =>
        {
            routeCalls++;
            return ValueTask.FromResult(available.Contains(intent.TargetId)
                ? Outcome.Success("opened")
                : Outcome.Failure<string>(TypedFailure.Create("resource.unavailable")));
        });

        Xunit.Assert.Equal("opened", Value(await router.HandleDeepLinkAsync(
            "arcforges://arcscope/resource/present", Xunit.TestContext.Current.CancellationToken)));
        Refused(await router.HandleDeepLinkAsync("arcforges://arcscope/resource/missing",
            Xunit.TestContext.Current.CancellationToken), "resource.unavailable");

        foreach (var hostile in new[]
        {
            "arcforges://arcscope/resource/present?token=secret",
            "arcforges://arcscope/resource/present?",
            "arcforges://arcscope/resource/present#fragment",
            "arcforges://arcscope/resource/present#",
            "arcforges://user@arcscope/resource/present",
            "arcforges://@arcscope/resource/present",
            "arcforges://arcscope:443/resource/present",
            "arcforges://arcscope/resource%2fpresent",
            " arcforges://arcscope/resource/present",
            "file:///C:/private/report.pdf",
            "arcforges://arcscope/../resource/present",
            "arcforges://arcscope//resource/present",
        })
        {
            Refused(await router.HandleDeepLinkAsync(hostile, Xunit.TestContext.Current.CancellationToken),
                "validation.invalid_request");
        }

        Refused(await router.HandleDeepLinkAsync("arcforges://companion/resource/present",
            Xunit.TestContext.Current.CancellationToken), "resource.unavailable");
        Xunit.Assert.Equal(2, routeCalls);
    }

    [Xunit.Fact]
    public async Task ArtifactRouterCannotDispatchAnotherApplicationsRegistry()
    {
        var registry = new ArtifactHandlerRegistry<string>(AppIdentity.Companion);
        int permissionChecks = 0;
        int opens = 0;
        registry.Register("companion.report", "report-open", 1, [ArtifactAction.Open],
            (_, _, _) =>
            {
                permissionChecks++;
                return ValueTask.FromResult(Outcome.Success(true));
            },
            (_, _, _) =>
            {
                opens++;
                return ValueTask.FromResult(Outcome.Success("unexpected-open"));
            });
        var router = new OwnAppNavigationRouter<string>(AppIdentity.ArcScope, registry);

        Refused(await router.OpenArtifactAsync(Artifact("companion.report", "companion"), ArtifactAction.Open,
            cancellationToken: Xunit.TestContext.Current.CancellationToken), "resource.unavailable");
        Xunit.Assert.Equal(0, permissionChecks);
        Xunit.Assert.Equal(0, opens);
    }

    [Xunit.Fact]
    public void RouteRegistrationRejectsMalformedAndDuplicateRoutes()
    {
        var router = new OwnAppNavigationRouter<string>(AppIdentity.ArcScope,
            new ArtifactHandlerRegistry<string>(AppIdentity.ArcScope));
        OwnAppDeepLinkHandler<string> handler = (_, _) => ValueTask.FromResult(Outcome.Success("ok"));

        Xunit.Assert.Throws<ArgumentException>(() => router.RegisterRoute("../report", handler));
        Xunit.Assert.Throws<ArgumentException>(() => router.RegisterRoute("Report", handler));
        router.RegisterRoute("report.v1", handler);
        Xunit.Assert.Throws<InvalidOperationException>(() => router.RegisterRoute("report.v1", handler));
    }

    [Xunit.Fact]
    public void HealthDimensionIsExactlyTheFiveClosedProbeAspectKeys()
    {
        Xunit.Assert.Equal(new[]
        {
            HealthDimension.Reachable,
            HealthDimension.Ready,
            HealthDimension.Healthy,
            HealthDimension.Degraded,
            HealthDimension.Capacity,
        }, Enum.GetValues<HealthDimension>());
        Xunit.Assert.False(Enum.IsDefined((HealthDimension)0));
        Xunit.Assert.All(Enum.GetNames<HealthDimension>(), key => Xunit.Assert.DoesNotContain('_', key));
    }

    private static ArtifactRef Artifact(string kind = "arcscope.report", string owner = "arcscope") => new()
    {
        ArtifactId = IdentityGeneration.NewArtifact().ToWire(),
        Kind = kind,
        Owner = new AggregateRef { Kind = owner + ".report", Id = IdentityGeneration.NewResource().ToWire() },
        Actor = new ActorChain
        {
            Initiator = IdentityGeneration.NewUser().ToWire(),
            Owner = IdentityGeneration.NewUser().ToWire(),
        },
        CreatedAt = new Instant { UnixSeconds = 1, Nanos = 0 },
        Availability = "available",
    };

    private static string Value(Outcome<string> outcome)
    {
        Xunit.Assert.True(outcome.TryGetValue(out var value));
        return value;
    }

    private static void Refused<T>(Outcome<T> outcome, string code)
    {
        Xunit.Assert.True(outcome.TryGetFailure(out var failure));
        Xunit.Assert.Equal(code, failure.Code);
        Xunit.Assert.Equal(EffectCertainty.DidNotHappen, failure.Effect);
        Xunit.Assert.Equal(RetryMode.Never, failure.Retry);
    }
}
