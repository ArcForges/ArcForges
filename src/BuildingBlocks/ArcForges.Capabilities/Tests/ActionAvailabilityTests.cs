// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using FoundationActionDescriptor = ArcForges.Contracts.Foundation.V1.ActionDescriptor;

namespace ArcForges.Capabilities.Tests;

// These tests construct synthetic immutable snapshots; they do not implement or claim PLT.38 or COM.05/06 producers.
public sealed class ActionAvailabilityTests
{
    private static readonly DateTimeOffset AsOfUtc = new(2026, 9, 29, 9, 0, 0, TimeSpan.Zero);

    [Xunit.Fact]
    public void ForProductInstanceBindsTheExactIdentityAndRejectsNull()
    {
        var identity = Instance(AppIdentity.ArcScope);

        var key = AvailabilityTargetKey.ForProductInstance(identity);

        Xunit.Assert.Equal(AvailabilityTargetKind.ProductInstance, key.Kind);
        Xunit.Assert.Equal(
            string.Join(
                ':',
                "product",
                "arcscope",
                identity.Installation.DeviceId.Value.ToString("N"),
                identity.Installation.InstallationId.Value.ToString("N"),
                identity.InstanceId.Value.ToString("N"),
                identity.Epoch.ToString("D20", System.Globalization.CultureInfo.InvariantCulture)),
            key.Value);
        Xunit.Assert.Same(identity, key.ProductInstance);
        Xunit.Assert.Null(key.CloudService);
        Xunit.Assert.Throws<ArgumentNullException>(() => AvailabilityTargetKey.ForProductInstance(null!));
    }

    [Xunit.Fact]
    public void ForCloudSearchServiceBindsTheCanonicalCatalogueIdentityAndRejectsOtherValues()
    {
        var service = SearchService.Instance;

        var key = AvailabilityTargetKey.ForCloudSearchService(service);

        Xunit.Assert.Equal(AvailabilityTargetKind.CloudSearchService, key.Kind);
        Xunit.Assert.Equal("cloud.search", key.Value);
        Xunit.Assert.Null(key.ProductInstance);
        Xunit.Assert.Same(service, key.CloudService);
        Xunit.Assert.Throws<ArgumentNullException>(() => AvailabilityTargetKey.ForCloudSearchService(null!));

        var nonCanonicalService = service with { };
        Xunit.Assert.NotSame(service, nonCanonicalService);
        Xunit.Assert.Throws<ArgumentException>(() => AvailabilityTargetKey.ForCloudSearchService(nonCanonicalService));
    }

    [Xunit.Fact]
    public async Task EvaluateAvailabilityAsyncReturnsEachOfTheNineAuthorizedFacts()
    {
        var expected = new[]
        {
            AvailabilityResult.Available,
            AvailabilityResult.NotApplicableToContext,
            AvailabilityResult.AppNotInstalled,
            AvailabilityResult.AppNotRunning,
            AvailabilityResult.IncompatibleVersion,
            AvailabilityResult.PermissionRequired,
            AvailabilityResult.EntitlementRequired,
            AvailabilityResult.PolicyDisabled,
            AvailabilityResult.TemporarilyUnavailable,
        };
        Xunit.Assert.Equal(expected, System.Enum.GetValues<AvailabilityResult>());

        var scope = ProviderScope();
        var actions = expected.Select((_, index) => Action(
            $"test.action.{index:D2}",
            index == 1 ? [BoolValue.Descriptor.FullName] : [StringValue.Descriptor.FullName])).ToArray();
        var rows = actions.Select((action, index) => Evidence(
            action.Key.Value,
            "IScopeOperations.GetSession",
            scope,
            installed: index == 2 ? AvailabilityFactState.No : AvailabilityFactState.Yes,
            running: index is 2 or 3 ? AvailabilityFactState.No : AvailabilityFactState.Yes,
            compatible: index == 4 ? AvailabilityFactState.No : AvailabilityFactState.Yes,
            ready: index == 8 ? AvailabilityFactState.No : AvailabilityFactState.Yes,
            permission: index == 5 ? AvailabilityPermissionDisposition.Required : AvailabilityPermissionDisposition.Granted,
            entitlement: index == 6 ? AvailabilityEntitlementDisposition.Required : AvailabilityEntitlementDisposition.Satisfied,
            policy: index == 7 ? AvailabilityPolicyDisposition.Disabled : AvailabilityPolicyDisposition.Enabled)).ToArray();
        var provider = CreateProvider(scope, actions, rows);
        var context = Context(scope.Owner, new StringValue { Value = "captured" });

        for (var index = 0; index < expected.Length; index++)
        {
            var actual = await Evaluate(provider, actions[index].Key.Value, context);
            Xunit.Assert.Equal(expected[index], actual);
        }
    }

    [Xunit.Fact]
    public async Task ContextAndExplicitHealthFactsDriveAvailabilityResults()
    {
        var scope = ProviderScope();
        var action = Action(
            "test.action.context-health",
            [StringValue.Descriptor.FullName]);
        var healthyProvider = CreateProvider(scope, [action]);
        var contextMatch = Context(scope.Owner, new StringValue { Value = "captured" });
        var contextMismatch = Context(scope.Owner, new BoolValue { Value = true });

        Xunit.Assert.Equal(AvailabilityResult.Available,
            await Evaluate(healthyProvider, action.Key.Value, contextMatch));
        Xunit.Assert.Equal(AvailabilityResult.NotApplicableToContext,
            await Evaluate(healthyProvider, action.Key.Value, contextMismatch));

        var notReady = Evidence(
            action.Key.Value,
            "IScopeOperations.GetSession",
            scope,
            ready: AvailabilityFactState.No);
        var unhealthyProvider = CreateProvider(scope, [action], [notReady]);
        Xunit.Assert.Equal(AvailabilityResult.TemporarilyUnavailable,
            await Evaluate(unhealthyProvider, action.Key.Value, contextMatch));
    }

    [Xunit.Fact]
    public void ActionRegistrationPreservesTheGeneratedFoundationDescriptorAndReturnsOnlyClones()
    {
        var source = Descriptor(
            "test.action.metadata",
            ["IScopeOperations.GetSession"],
            [StringValue.Descriptor.FullName]);
        source.DescriptionKey = "test.action.metadata.description";
        var action = new ActionAvailabilityRegistration(source);

        source.TitleKey = "mutated.after.registration";
        source.Capabilities.Clear();
        var returned = action.Descriptor;
        Xunit.Assert.Equal("test.action.metadata", returned.Key);
        Xunit.Assert.Equal("test.action.metadata.title", returned.TitleKey);
        Xunit.Assert.Equal("test.action.metadata.description", returned.DescriptionKey);
        Xunit.Assert.Equal([StringValue.Descriptor.FullName], returned.AcceptedContext);
        Xunit.Assert.Equal(["IScopeOperations.GetSession"], returned.Capabilities);
        Xunit.Assert.Equal("capability.availability.v1", returned.AvailabilityRule);

        returned.TitleKey = "mutated.returned.clone";
        returned.Capabilities.Clear();
        Xunit.Assert.Equal("test.action.metadata.title", action.Descriptor.TitleKey);
        Xunit.Assert.Equal(["IScopeOperations.GetSession"], action.Descriptor.Capabilities);
    }

    [Xunit.Fact]
    public async Task RepeatedEvaluationDoesNotMutateFrozenContextRegistryOrEvidence()
    {
        var source = new StringValue { Value = "captured" };
        var scope = ProviderScope();
        var context = Context(scope.Owner, source);
        source.Value = "changed after freeze";
        var action = Action("test.action.pure", [StringValue.Descriptor.FullName]);
        var constraints = new[] { "constraint.read", "constraint.owner" };
        var permission = Permission(scope, "IScopeOperations.GetSession", constraints: constraints);
        var row = Evidence(action.Key.Value, "IScopeOperations.GetSession", scope, permissionEvidence: permission);
        var snapshot = new AvailabilityEvidenceSnapshot(
            scope,
            AsOfUtc,
            AvailabilityFreshnessDisposition.Current,
            [row]);
        var capabilityRegistry = CapabilityRegistry.CreateInitial();
        var provider = CreateProvider(scope, [action], snapshot, capabilityRegistry);

        var contextBefore = context.Items.Select(item => item.Deserialize().ToByteArray()).ToArray();
        var capabilityBefore = capabilityRegistry.Find("IScopeOperations.GetSession")!.Descriptor.ToByteArray();
        var evidenceBefore = ProviderSnapshot(snapshot.Records.Single());
        constraints[0] = "mutated.source.array";

        var first = await Evaluate(provider, action.Key.Value, context);
        var second = await Evaluate(provider, action.Key.Value, context);

        Xunit.Assert.Equal(AvailabilityResult.Available, first);
        Xunit.Assert.Equal(first, second);
        Xunit.Assert.Equal("captured", Xunit.Assert.IsType<StringValue>(context.Items.Single().Deserialize()).Value);
        Xunit.Assert.Equal(contextBefore, context.Items.Select(item => item.Deserialize().ToByteArray()).ToArray());
        Xunit.Assert.Equal(capabilityBefore, capabilityRegistry.Find("IScopeOperations.GetSession")!.Descriptor.ToByteArray());
        Xunit.Assert.Equal("constraint.read", snapshot.Records.Single().Permission.Constraints[0]);
        Xunit.Assert.Equal(evidenceBefore, ProviderSnapshot(snapshot.Records.Single()));
    }

    [Xunit.Fact]
    public void EvidenceRequiresExactActionCapabilityTargetAndProviderBindings()
    {
        var scope = ProviderScope();
        var action = Action("test.action.bound", [StringValue.Descriptor.FullName]);

        var missing = new AvailabilityEvidenceSnapshot(scope, AsOfUtc, AvailabilityFreshnessDisposition.Current, []);
        Xunit.Assert.Throws<ArgumentException>(() => CreateProvider(scope, [action], missing));

        var row = Evidence(action.Key.Value, "IScopeOperations.GetSession", scope);
        Xunit.Assert.Throws<ArgumentException>(() =>
            new AvailabilityEvidenceSnapshot(scope, AsOfUtc, AvailabilityFreshnessDisposition.Current, [row, row]));

        var unknownAction = Evidence("test.action.unknown", "IScopeOperations.GetSession", scope);
        var extraRowSnapshot = new AvailabilityEvidenceSnapshot(
            scope,
            AsOfUtc,
            AvailabilityFreshnessDisposition.Current,
            [row, unknownAction]);
        Xunit.Assert.Throws<ArgumentException>(() => CreateProvider(scope, [action], extraRowSnapshot));

        var mismatchedScope = new AvailabilityProviderScope(scope.Owner, "principal.other", scope.SessionKey);
        var singleRowSnapshot = new AvailabilityEvidenceSnapshot(scope, AsOfUtc, AvailabilityFreshnessDisposition.Current, [row]);
        Xunit.Assert.Throws<ArgumentException>(() =>
            new CapabilityAvailabilityProvider(CapabilityRegistry.CreateInitial(), [action], mismatchedScope, singleRowSnapshot));

        var mismatchedSession = new AvailabilityProviderScope(scope.Owner, scope.PrincipalKey, "session.other");
        Xunit.Assert.Throws<ArgumentException>(() =>
            new CapabilityAvailabilityProvider(CapabilityRegistry.CreateInitial(), [action], mismatchedSession, singleRowSnapshot));

        var wrongProductTarget = AvailabilityTargetKey.ForProductInstance(Instance(AppIdentity.Companion));
        var wrongTargetRow = Evidence(
            action.Key.Value,
            "IScopeOperations.GetSession",
            scope,
            target: wrongProductTarget);
        Xunit.Assert.Throws<ArgumentException>(() => CreateProvider(scope, [action], [wrongTargetRow]));

        var permissionFromAnotherOwner = Permission(
            ProviderScope(),
            "IScopeOperations.GetSession");
        var mismatchedPermission = Evidence(
            action.Key.Value,
            "IScopeOperations.GetSession",
            scope,
            permissionEvidence: permissionFromAnotherOwner);
        Xunit.Assert.Throws<ArgumentException>(() =>
            new AvailabilityEvidenceSnapshot(scope, AsOfUtc, AvailabilityFreshnessDisposition.Current, [mismatchedPermission]));
    }

    [Xunit.Theory]
    [Xunit.InlineData(AvailabilityFreshnessDisposition.Unknown)]
    [Xunit.InlineData(AvailabilityFreshnessDisposition.StaleAtCapture)]
    public async Task UnknownOrStaleAtCaptureEvidenceNeverProducesAvailable(AvailabilityFreshnessDisposition freshness)
    {
        var scope = ProviderScope();
        var action = Action("test.action.stale", [StringValue.Descriptor.FullName]);
        var row = Evidence(action.Key.Value, "IScopeOperations.GetSession", scope);
        var provider = CreateProvider(scope, [action], [row], freshness);

        var result = await Evaluate(provider, action.Key.Value, Context(scope.Owner, new StringValue { Value = "captured" }));

        Xunit.Assert.Equal(AvailabilityResult.TemporarilyUnavailable, result);
    }

    [Xunit.Fact]
    public async Task UnknownProductPermissionEntitlementAndPolicyFactsFailClosed()
    {
        var scope = ProviderScope();
        var actionKeys = new[]
        {
            "test.action.unknown-install",
            "test.action.unknown-permission",
            "test.action.unknown-entitlement",
            "test.action.unknown-policy",
        };
        var rows = new[]
        {
            Evidence(actionKeys[0], "IScopeOperations.GetSession", scope, installed: AvailabilityFactState.Unknown),
            Evidence(actionKeys[1], "IScopeOperations.GetSession", scope, permission: AvailabilityPermissionDisposition.Unknown),
            Evidence(actionKeys[2], "IScopeOperations.GetSession", scope, entitlement: AvailabilityEntitlementDisposition.Unknown),
            Evidence(actionKeys[3], "IScopeOperations.GetSession", scope, policy: AvailabilityPolicyDisposition.Unknown),
        };

        for (var index = 0; index < actionKeys.Length; index++)
        {
            var action = Action(actionKeys[index], []);
            var provider = CreateProvider(scope, [action], [rows[index]]);
            var result = await Evaluate(provider, action.Key.Value, Context(scope.Owner));
            Xunit.Assert.Equal(AvailabilityResult.TemporarilyUnavailable, result);
        }
    }

    [Xunit.Fact]
    public async Task ExpiredPermissionAtCaptureRequiresANewHostSnapshotAndProvider()
    {
        var scope = ProviderScope();
        var action = Action("test.action.refresh", [StringValue.Descriptor.FullName]);
        var expiredPermission = Permission(
            scope,
            "IScopeOperations.GetSession",
            validFromUtc: AsOfUtc.AddHours(-2),
            validUntilUtc: AsOfUtc.AddMinutes(-1));
        var expiredSnapshot = new AvailabilityEvidenceSnapshot(
            scope,
            AsOfUtc,
            AvailabilityFreshnessDisposition.Current,
            [Evidence(
                action.Key.Value,
                "IScopeOperations.GetSession",
                scope,
                permissionEvidence: expiredPermission)]);
        Xunit.Assert.Equal(AvailabilityFreshnessDisposition.StaleAtCapture, expiredSnapshot.Freshness);
        var staleProvider = CreateProvider(scope, [action], expiredSnapshot);
        var refreshedAsOf = AsOfUtc.AddMinutes(5);
        var refreshedRow = Evidence(
            action.Key.Value,
            "IScopeOperations.GetSession",
            scope,
            asOfUtc: refreshedAsOf,
            targetGeneration: "target.generation.refresh");
        var refreshedProvider = CreateProvider(
            scope,
            [action],
            new AvailabilityEvidenceSnapshot(
                scope,
                refreshedAsOf,
                AvailabilityFreshnessDisposition.Current,
                [refreshedRow]));
        var context = Context(scope.Owner, new StringValue { Value = "captured" });

        Xunit.Assert.Equal(AvailabilityResult.TemporarilyUnavailable,
            await Evaluate(staleProvider, action.Key.Value, context));
        Xunit.Assert.Equal(AvailabilityResult.Available,
            await Evaluate(refreshedProvider, action.Key.Value, context));
        Xunit.Assert.Equal(AvailabilityResult.TemporarilyUnavailable,
            await Evaluate(staleProvider, action.Key.Value, context));
    }

    [Xunit.Fact]
    public async Task CloudSearchUsesStaticCatalogueEvidenceAndNeverRequiresALocalTarget()
    {
        var scope = ProviderScope();
        var action = new ActionAvailabilityRegistration(Descriptor(
            "test.action.cloud-search",
            ["search.query"],
            [StringValue.Descriptor.FullName]));
        var cloudTarget = AvailabilityTargetKey.ForCloudSearchService(SearchService.Instance);
        var row = Evidence(
            action.Key.Value,
            "search.query",
            scope,
            target: cloudTarget,
            targetFacts: TargetFacts(
                AvailabilityFactState.Unknown,
                AvailabilityFactState.Unknown,
                AvailabilityFactState.Unknown,
                AvailabilityFactState.Unknown,
                AvailabilityFactState.Unknown,
                productVersion: null));
        var provider = CreateProvider(scope, [action], [row]);

        var result = await Evaluate(provider, action.Key.Value, Context(scope.Owner, new StringValue { Value = "query" }));

        Xunit.Assert.Equal(AvailabilityResult.Available, result);
        Xunit.Assert.Null(cloudTarget.ProductInstance);
        Xunit.Assert.Same(SearchService.Instance, cloudTarget.CloudService);
    }

    [Xunit.Fact]
    public async Task ContextOwnerMismatchAndUnknownActionFailWithTypedErrors()
    {
        var scope = ProviderScope();
        var action = Action("test.action.request", [StringValue.Descriptor.FullName]);
        var provider = CreateProvider(scope, [action]);

        var ownerMismatch = await ((ICapabilityProvider)provider).EvaluateAvailabilityAsync(
            action.Key,
            Context(Instance(AppIdentity.Companion)),
            Xunit.TestContext.Current.CancellationToken);
        var unknownAction = await ((ICapabilityProvider)provider).EvaluateAvailabilityAsync(
            new ActionKey("test.action.missing"),
            Context(scope.Owner),
            Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.Equal(OutcomeKind.Failure, ownerMismatch.Kind);
        Xunit.Assert.True(ownerMismatch.TryGetFailure(out var ownerFailure));
        Xunit.Assert.Equal("validation.invalid_request", ownerFailure!.Code);
        Xunit.Assert.Equal(OutcomeKind.Failure, unknownAction.Kind);
        Xunit.Assert.True(unknownAction.TryGetFailure(out var unknownFailure));
        Xunit.Assert.Equal("validation.invalid_request", unknownFailure!.Code);
    }

    [Xunit.Fact]
    public void RegistrationRejectsUnknownRulesDuplicateCapabilitiesAndUnregisteredBindings()
    {
        var unknownRule = Descriptor("test.action.unknown-rule", ["IScopeOperations.GetSession"]);
        unknownRule.AvailabilityRule = "test.caller.supplied.rule";
        Xunit.Assert.Throws<ArgumentException>(() => new ActionAvailabilityRegistration(unknownRule));

        Xunit.Assert.Throws<ArgumentException>(() => new ActionAvailabilityRegistration(
            Descriptor("test.action.duplicate-capability", ["IScopeOperations.GetSession", "IScopeOperations.GetSession"])));

        var scope = ProviderScope();
        var unknownCapability = new ActionAvailabilityRegistration(Descriptor(
            "test.action.unknown-capability",
            ["missing.capability"],
            [StringValue.Descriptor.FullName]));
        var unknownRow = Evidence(unknownCapability.Key.Value, "missing.capability", scope);
        Xunit.Assert.Throws<ArgumentException>(() => CreateProvider(scope, [unknownCapability], [unknownRow]));

        var duplicateAction = Action("test.action.duplicate", [StringValue.Descriptor.FullName]);
        Xunit.Assert.Throws<ArgumentException>(() =>
            CreateProvider(scope, [duplicateAction, duplicateAction]));

        Xunit.Assert.Throws<ArgumentException>(() => new AvailabilityTargetFacts(
            AvailabilityFactState.No,
            AvailabilityFactState.Yes,
            AvailabilityFactState.Unknown,
            AvailabilityFactState.Unknown,
            AvailabilityFactState.Unknown,
            productVersion: null,
            sourceGeneration: "generation.1",
            observedAtUtc: AsOfUtc));
    }

    [Xunit.Fact]
    public async Task CancellationIsObservedBeforeAvailabilityProjection()
    {
        var scope = ProviderScope();
        var action = Action("test.action.cancel", [StringValue.Descriptor.FullName]);
        var provider = CreateProvider(scope, [action]);
        using var source = new CancellationTokenSource();
        await source.CancelAsync().ConfigureAwait(true);

        await Xunit.Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await ((ICapabilityProvider)provider).EvaluateAvailabilityAsync(
                action.Key,
                Context(scope.Owner),
                source.Token).ConfigureAwait(true));
    }

    private static ActionAvailabilityRegistration Action(string key, IEnumerable<string> acceptedContext) =>
        new(Descriptor(key, ["IScopeOperations.GetSession"], acceptedContext));

    private static FoundationActionDescriptor Descriptor(
        string key,
        IEnumerable<string> capabilities,
        IEnumerable<string>? acceptedContext = null) =>
        new()
        {
            Key = key,
            TitleKey = $"{key}.title",
            AvailabilityRule = "capability.availability.v1",
            Capabilities = { capabilities },
            AcceptedContext = { acceptedContext ?? [] },
        };

    private static AvailabilityProviderScope ProviderScope() =>
        new(Instance(AppIdentity.ArcScope), "principal:test-user", "session:enumeration-1");

    private static InstanceIdentity Instance(AppIdentity app) =>
        new(
            new InstallationIdentity(
                app,
                IdentityGeneration.NewDevice(),
                IdentityGeneration.NewInstallation()),
            IdentityGeneration.NewInstance(),
            1);

    private static FrozenContextSnapshot Context(InstanceIdentity owner, params IMessage[] messages) =>
        FrozenContextSnapshot.Freeze(owner, messages, ContextSnapshotBudget.Default);

    private static CapabilityAvailabilityProvider CreateProvider(
        AvailabilityProviderScope scope,
        IEnumerable<ActionAvailabilityRegistration> actions,
        IReadOnlyList<AvailabilityEvidenceRecord>? rows = null,
        AvailabilityFreshnessDisposition freshness = AvailabilityFreshnessDisposition.Current,
        CapabilityRegistry? capabilities = null)
    {
        var actionArray = actions.ToArray();
        var evidence = rows ?? actionArray
            .SelectMany(action => action.CapabilityKeys.Select(capability =>
                Evidence(action.Key.Value, capability, scope)))
            .ToArray();
        return CreateProvider(
            scope,
            actionArray,
            new AvailabilityEvidenceSnapshot(scope, AsOfUtc, freshness, evidence),
            capabilities);
    }

    private static CapabilityAvailabilityProvider CreateProvider(
        AvailabilityProviderScope scope,
        IEnumerable<ActionAvailabilityRegistration> actions,
        AvailabilityEvidenceSnapshot evidenceSnapshot,
        CapabilityRegistry? capabilities = null) =>
        new(capabilities ?? CapabilityRegistry.CreateInitial(), actions, scope, evidenceSnapshot);

    private static AvailabilityEvidenceRecord Evidence(
        string actionKey,
        string capabilityKey,
        AvailabilityProviderScope scope,
        AvailabilityFactState installed = AvailabilityFactState.Yes,
        AvailabilityFactState running = AvailabilityFactState.Yes,
        AvailabilityFactState compatible = AvailabilityFactState.Yes,
        AvailabilityFactState ready = AvailabilityFactState.Yes,
        AvailabilityFactState acceptsWork = AvailabilityFactState.Yes,
        AvailabilityPermissionDisposition permission = AvailabilityPermissionDisposition.Granted,
        AvailabilityEntitlementDisposition entitlement = AvailabilityEntitlementDisposition.Satisfied,
        AvailabilityPolicyDisposition policy = AvailabilityPolicyDisposition.Enabled,
        AvailabilityTargetKey? target = null,
        AvailabilityTargetFacts? targetFacts = null,
        AvailabilityPermissionEvidence? permissionEvidence = null,
        DateTimeOffset? asOfUtc = null,
        string targetGeneration = "target.generation.1")
    {
        var effectiveAsOf = asOfUtc ?? AsOfUtc;
        var effectiveTarget = target ?? AvailabilityTargetKey.ForProductInstance(Instance(AppIdentity.ArcScope));
        var facts = targetFacts ?? TargetFacts(installed, running, compatible, ready, acceptsWork, "2.4.0", targetGeneration, effectiveAsOf);
        var permissionFacts = permissionEvidence ?? Permission(
            scope,
            capabilityKey,
            disposition: permission,
            validFromUtc: effectiveAsOf.AddHours(-1),
            validUntilUtc: effectiveAsOf.AddHours(1));
        var entitlementFacts = new AvailabilityEntitlementEvidence(
            capabilityKey,
            entitlement,
            entitlement == AvailabilityEntitlementDisposition.Required ? "entitlement.required" : "entitlement.satisfied",
            "com05.version.7",
            "com06.generation.3");
        var policyFacts = new AvailabilityPolicyEvidence(policy, "test.policy-source", "test.policy.revision.4");
        return new AvailabilityEvidenceRecord(
            new ActionKey(actionKey),
            capabilityKey,
            effectiveTarget,
            facts,
            permissionFacts,
            entitlementFacts,
            policyFacts);
    }

    private static AvailabilityTargetFacts TargetFacts(
        AvailabilityFactState installed,
        AvailabilityFactState running,
        AvailabilityFactState compatible,
        AvailabilityFactState ready,
        AvailabilityFactState acceptsWork,
        string? productVersion,
        string sourceGeneration = "target.generation.1",
        DateTimeOffset? asOfUtc = null) =>
        new(
            installed,
            running,
            compatible,
            ready,
            acceptsWork,
            productVersion,
            sourceGeneration,
            (asOfUtc ?? AsOfUtc).AddMinutes(-1));

    private static AvailabilityPermissionEvidence Permission(
        AvailabilityProviderScope scope,
        string capabilityKey,
        IEnumerable<string>? constraints = null,
        AvailabilityPermissionDisposition disposition = AvailabilityPermissionDisposition.Granted,
        DateTimeOffset? validFromUtc = null,
        DateTimeOffset? validUntilUtc = null) =>
        new(
            scope.Owner,
            scope.PrincipalKey,
            capabilityKey,
            disposition,
            "scope:current-user",
            constraints ?? ["constraint.owner", "constraint.read"],
            validFromUtc ?? AsOfUtc.AddHours(-1),
            validUntilUtc ?? AsOfUtc.AddHours(1),
            "permission.generation.12");

    private static async Task<AvailabilityResult> Evaluate(
        ICapabilityProvider provider,
        string actionKey,
        FrozenContextSnapshot context)
    {
        var outcome = await provider.EvaluateAvailabilityAsync(
            new ActionKey(actionKey),
            context,
            Xunit.TestContext.Current.CancellationToken).ConfigureAwait(true);
        Xunit.Assert.Equal(OutcomeKind.Success, outcome.Kind);
        Xunit.Assert.True(outcome.TryGetValue(out var result));
        Xunit.Assert.False(outcome.TryGetFailure(out _));
        return result;
    }

    private static byte[] ProviderSnapshot(AvailabilityEvidenceRecord row)
    {
        var invariant = System.Globalization.CultureInfo.InvariantCulture;
        var values = new[]
        {
            row.ActionKey.Value,
            row.CapabilityKey,
            row.TargetKey.Value,
            row.TargetKey.Kind.ToString(),
            IdentitySnapshot(row.TargetKey.ProductInstance),
            row.TargetFacts.Installed.ToString(),
            row.TargetFacts.Running.ToString(),
            row.TargetFacts.Compatible.ToString(),
            row.TargetFacts.Ready.ToString(),
            row.TargetFacts.AcceptsWork.ToString(),
            row.TargetFacts.ProductVersion ?? "<null>",
            row.TargetFacts.SourceGeneration,
            row.TargetFacts.ObservedAtUtc.ToString("O", invariant),
            IdentitySnapshot(row.Permission.IssuerOwner),
            row.Permission.PrincipalKey,
            row.Permission.CapabilityKey,
            row.Permission.Disposition.ToString(),
            row.Permission.ScopeKey,
            string.Join('|', row.Permission.Constraints),
            row.Permission.ValidFromUtc.ToString("O", invariant),
            row.Permission.ValidUntilUtc.ToString("O", invariant),
            row.Permission.SourceGeneration,
            row.Entitlement.CapabilityKey,
            row.Entitlement.Disposition.ToString(),
            row.Entitlement.ReasonCode,
            row.Entitlement.ProducerVersion,
            row.Entitlement.SourceGeneration,
            row.Policy.Disposition.ToString(),
            row.Policy.SourceKey,
            row.Policy.Revision,
        };
        return System.Text.Encoding.UTF8.GetBytes(string.Join('\n', values));
    }

    private static string IdentitySnapshot(InstanceIdentity? identity) => identity is null
        ? "<null>"
        : string.Join(':',
            identity.Installation.App.ProductId,
            identity.Installation.DeviceId.Value.ToString("N"),
            identity.Installation.InstallationId.Value.ToString("N"),
            identity.InstanceId.Value.ToString("N"),
            identity.Epoch.ToString(System.Globalization.CultureInfo.InvariantCulture));
}
