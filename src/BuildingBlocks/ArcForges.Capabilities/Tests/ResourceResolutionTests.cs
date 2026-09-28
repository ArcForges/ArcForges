// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;
using IdentityGeneration = ArcForges.Foundation.IdentityGeneration;

namespace ArcForges.Capabilities.Tests;

public sealed class ResourceResolutionTests
{
    [Xunit.Fact]
    public async Task FloatingResolutionUsesTheRegisteredOwnerAndRechecksPermissionOnEveryAccess()
    {
        var registry = new ResourceResolutionRegistry<string>(AppIdentity.ArcScope);
        var reference = FloatingResource();
        bool permitted = true;
        int permissionChecks = 0;
        int opens = 0;
        Guid resolvedId = Guid.Empty;
        bool displayHintStripped = true;
        registry.Register("arcscope.session",
            (candidate, _) =>
            {
                permissionChecks++;
                displayHintStripped &= !candidate.HasDisplayHint;
                candidate.ResourceId = IdentityGeneration.NewResource().ToWire();
                return ValueTask.FromResult(Outcome.Success(permitted));
            },
            (candidate, _) =>
            {
                opens++;
                displayHintStripped &= !candidate.HasDisplayHint;
                resolvedId = ArcForges.Contracts.Foundation.Values.ResourceId.FromWire(candidate.ResourceId).Value;
                return ValueTask.FromResult(Outcome.Success("current"));
            },
            (_, _) => throw new Xunit.Sdk.XunitException("Floating access must not call pinned authorization."),
            (_, _) => throw new Xunit.Sdk.XunitException("Floating access must not call pinned resolution."));

        var first = await registry.ResolveCurrentAsync(reference, Xunit.TestContext.Current.CancellationToken);
        Xunit.Assert.Equal("current", Value(first));
        Xunit.Assert.Equal(1, permissionChecks);
        Xunit.Assert.Equal(1, opens);
        Xunit.Assert.Equal(ArcForges.Contracts.Foundation.Values.ResourceId.FromWire(reference.ResourceId).Value, resolvedId);
        Xunit.Assert.True(displayHintStripped);
        Xunit.Assert.True(reference.HasDisplayHint);

        permitted = false;
        Refused(await registry.ResolveCurrentAsync(reference, Xunit.TestContext.Current.CancellationToken), "perm.resource_denied");
        Xunit.Assert.Equal(2, permissionChecks);
        Xunit.Assert.Equal(1, opens);
    }

    [Xunit.Fact]
    public async Task MissingOwnerRegistrationAndMissingKindReturnUnavailableWithoutDiscovery()
    {
        var registry = new ResourceResolutionRegistry<string>(AppIdentity.ArcScope);
        Refused(await registry.ResolveCurrentAsync(FloatingResource(), Xunit.TestContext.Current.CancellationToken), "resource.unavailable");

        RegisterAllowed(registry, "arcscope.session");
        Refused(await registry.ResolveCurrentAsync(FloatingResource(owner: "companion", kind: "companion.session"), Xunit.TestContext.Current.CancellationToken), "resource.unavailable");
        Refused(await registry.ResolveCurrentAsync(FloatingResource(kind: "arcscope.annotation"), Xunit.TestContext.Current.CancellationToken), "resource.unavailable");
        Xunit.Assert.Throws<ArgumentException>(() => RegisterAllowed(registry, "companion.session"));
    }

    [Xunit.Fact]
    public async Task PermissionDenialNeverFallsThroughToResourceResolution()
    {
        var registry = new ResourceResolutionRegistry<string>(AppIdentity.ArcScope);
        int opens = 0;
        registry.Register("arcscope.session",
            (_, _) => ValueTask.FromResult(Outcome.Success(false)),
            (_, _) =>
            {
                opens++;
                return ValueTask.FromResult(Outcome.Success("not opened"));
            },
            (_, _) => ValueTask.FromResult(Outcome.Success(true)),
            (_, _) => ValueTask.FromResult(Outcome.Success("pinned")));

        Refused(await registry.ResolveCurrentAsync(FloatingResource(), Xunit.TestContext.Current.CancellationToken), "perm.resource_denied");
        Xunit.Assert.Equal(0, opens);
    }

    [Xunit.Fact]
    public async Task PinnedResolutionPreservesTheExactRevisionAndNeverFallsBackToFloating()
    {
        var registry = new ResourceResolutionRegistry<string>(AppIdentity.ArcScope);
        var pinned = PinnedResource(FloatingResource());
        int floatingChecks = 0;
        int pinnedChecks = 0;
        int pinnedOpens = 0;
        bool pinnedPermitted = true;
        long resolvedRevision = 0;
        registry.Register("arcscope.session",
            (_, _) =>
            {
                floatingChecks++;
                return ValueTask.FromResult(Outcome.Success(true));
            },
            (_, _) => ValueTask.FromResult(Outcome.Success("floating")),
            (candidate, _) =>
            {
                pinnedChecks++;
                candidate.Cloud.Value = 99;
                return ValueTask.FromResult(Outcome.Success(pinnedPermitted));
            },
            (candidate, _) =>
            {
                pinnedOpens++;
                resolvedRevision = candidate.Cloud.Value;
                return ValueTask.FromResult(Outcome.Success("pinned"));
            });

        Xunit.Assert.Equal("pinned", Value(await registry.ResolvePinnedAsync(pinned, Xunit.TestContext.Current.CancellationToken)));
        Xunit.Assert.Equal(0, floatingChecks);
        Xunit.Assert.Equal(1, pinnedChecks);
        Xunit.Assert.Equal(1, pinnedOpens);
        Xunit.Assert.Equal(42, resolvedRevision);
        Xunit.Assert.Equal(42, pinned.Cloud.Value);

        pinnedPermitted = false;
        Refused(await registry.ResolvePinnedAsync(pinned, Xunit.TestContext.Current.CancellationToken), "perm.resource_denied");
        Xunit.Assert.Equal(2, pinnedChecks);
        Xunit.Assert.Equal(1, pinnedOpens);

        var unpinned = new ResourceVersionRef { Resource = FloatingResource() };
        Refused(await registry.ResolvePinnedAsync(unpinned, Xunit.TestContext.Current.CancellationToken), "validation.invalid_request");
        Xunit.Assert.Equal(0, floatingChecks);
    }

    [Xunit.Fact]
    public async Task MalformedOrForeignResourceKindCannotReachAnOwnerHandler()
    {
        var registry = new ResourceResolutionRegistry<string>(AppIdentity.ArcScope);
        int calls = 0;
        registry.Register("arcscope.session",
            (_, _) =>
            {
                calls++;
                return ValueTask.FromResult(Outcome.Success(true));
            },
            (_, _) => ValueTask.FromResult(Outcome.Success("current")),
            (_, _) => ValueTask.FromResult(Outcome.Success(true)),
            (_, _) => ValueTask.FromResult(Outcome.Success("pinned")));

        var malformed = FloatingResource();
        malformed.ResourceId = null!;
        Refused(await registry.ResolveCurrentAsync(malformed, Xunit.TestContext.Current.CancellationToken), "validation.invalid_request");
        Refused(await registry.ResolveCurrentAsync(FloatingResource(kind: "companion.session"), Xunit.TestContext.Current.CancellationToken), "validation.invalid_request");
        Xunit.Assert.Equal(0, calls);
    }

    [Xunit.Fact]
    public void PublishedReferencesHaveNoPhysicalLocationOrAccessHandleFields()
    {
        var visited = new HashSet<string>(StringComparer.Ordinal);
        foreach (var field in new[] { ResourceRef.Descriptor, ResourceVersionRef.Descriptor, ArtifactRef.Descriptor }
            .SelectMany(descriptor => ReachableFields(descriptor, visited)))
        {
            string name = field.Name.Replace("_", string.Empty, StringComparison.Ordinal);
            Xunit.Assert.DoesNotContain("path", name, StringComparison.OrdinalIgnoreCase);
            Xunit.Assert.DoesNotContain("pointer", name, StringComparison.OrdinalIgnoreCase);
            Xunit.Assert.DoesNotContain("handle", name, StringComparison.OrdinalIgnoreCase);
            Xunit.Assert.DoesNotContain("credential", name, StringComparison.OrdinalIgnoreCase);
            Xunit.Assert.DoesNotContain("location", name, StringComparison.OrdinalIgnoreCase);
            Xunit.Assert.DoesNotContain("locator", name, StringComparison.OrdinalIgnoreCase);
            Xunit.Assert.DoesNotContain("url", name, StringComparison.OrdinalIgnoreCase);
            Xunit.Assert.DoesNotContain("uri", name, StringComparison.OrdinalIgnoreCase);
            Xunit.Assert.False(name.Equals("content", StringComparison.OrdinalIgnoreCase));
        }
    }

    private static IEnumerable<Google.Protobuf.Reflection.FieldDescriptor> ReachableFields(
        Google.Protobuf.Reflection.MessageDescriptor descriptor, HashSet<string> visited)
    {
        if (!visited.Add(descriptor.FullName)) yield break;

        foreach (var field in descriptor.Fields.InDeclarationOrder())
        {
            yield return field;
            if (field.FieldType != Google.Protobuf.Reflection.FieldType.Message) continue;
            foreach (var nested in ReachableFields(field.MessageType, visited)) yield return nested;
        }
    }

    private static void RegisterAllowed(ResourceResolutionRegistry<string> registry, string kind) =>
        registry.Register(kind,
            (_, _) => ValueTask.FromResult(Outcome.Success(true)),
            (_, _) => ValueTask.FromResult(Outcome.Success("current")),
            (_, _) => ValueTask.FromResult(Outcome.Success(true)),
            (_, _) => ValueTask.FromResult(Outcome.Success("pinned")));

    private static ResourceRef FloatingResource(string owner = "arcscope", string kind = "arcscope.session") => new()
    {
        RealmId = IdentityGeneration.NewRealm().ToWire(),
        WorkspaceId = IdentityGeneration.NewWorkspace().ToWire(),
        OwnerAppId = owner,
        ResourceKind = kind,
        ResourceId = IdentityGeneration.NewResource().ToWire(),
        Availability = ResourceAvailability.AvailableOffline,
        DisplayHint = "Session",
    };

    private static ResourceVersionRef PinnedResource(ResourceRef resource) => new()
    {
        Resource = resource.Clone(),
        Cloud = new Revision { Value = 42 },
        ContentHash = new string('a', 64),
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
