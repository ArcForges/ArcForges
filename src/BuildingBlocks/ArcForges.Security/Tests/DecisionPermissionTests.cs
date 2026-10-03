// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Security.Approvals;
using ArcForges.Security.Decisions;
using Xunit;

namespace ArcForges.Security.Tests;

/// <summary>Permission grants at their exact boundaries, the read-only permission projection, and the grant and request value types.</summary>
public sealed class DecisionPermissionTests
{
    private static async Task<SecurityDecision> EvaluateAsync(DecisionHarness harness, DecisionRequest request) =>
        await harness.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);

    [Fact]
    public async Task AGrantIsValidFromItsExactStartUntilTheInstantBeforeItsEnd()
    {
        var harness = new DecisionHarness();
        harness.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(harness.Grant(
            request, validFromOffset: TimeSpan.Zero, validUntilOffset: TimeSpan.FromTicks(1)));

        var decision = await EvaluateAsync(harness, harness.Request().Build());

        Assert.True(decision.Allowed);
        Assert.Equal(PermissionDisposition.Granted, decision.Permission!.Disposition);
    }

    [Fact]
    public async Task AGrantExpiresAtUseNotAtIssue()
    {
        var harness = new DecisionHarness();
        var request = harness.Request().Build();
        harness.Permissions.Behavior = (r, _) => ValueTask.FromResult<PermissionGrantRecord?>(harness.Grant(
            r, validFromOffset: TimeSpan.FromHours(-1), validUntilOffset: TimeSpan.FromMinutes(10)));
        var pipeline = harness.Pipeline();
        var first = await pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);
        Assert.True(first.Allowed);

        // The source still returns the same record; the clock has moved past its end.
        var fixedGrant = harness.Grant(request, validFromOffset: TimeSpan.FromHours(-1), validUntilOffset: TimeSpan.FromMinutes(10));
        harness.Permissions.Behavior = (_, _) => ValueTask.FromResult<PermissionGrantRecord?>(fixedGrant);
        harness.Clock.Advance(TimeSpan.FromMinutes(10));
        var second = await pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken);

        Assert.False(second.Allowed);
        Assert.Equal(DecisionReason.S06OutsideLifetime, second.Reason);
    }

    [Fact]
    public async Task TheLifetimeIsJudgedAfterTheSourceAnswersSoASlowSourceCannotExtendAGrant()
    {
        var harness = new DecisionHarness();
        harness.Permissions.Behavior = (request, _) =>
        {
            var grant = harness.Grant(request, validFromOffset: TimeSpan.FromHours(-1), validUntilOffset: TimeSpan.FromMinutes(30));
            harness.Clock.Advance(TimeSpan.FromHours(1));
            return ValueTask.FromResult<PermissionGrantRecord?>(grant);
        };

        var decision = await EvaluateAsync(harness, harness.Request().Build());

        Assert.False(decision.Allowed);
        Assert.Equal(DecisionReason.S06OutsideLifetime, decision.Reason);
        Assert.Equal(harness.Clock.UtcNow, decision.Permission!.ObservedAtUtc);
    }

    [Fact]
    public async Task ConstraintsThatAreUnderstoodAndMetPassAndAreEnforcedIndependently()
    {
        var harness = new DecisionHarness();
        var builder = harness.Request();
        var request = builder.Build();
        harness.Permissions.Behavior = (r, _) => ValueTask.FromResult<PermissionGrantRecord?>(harness.Grant(
            r, constraints: [PermissionConstraints.LocalOriginOnly, PermissionConstraints.DeviceBound(r.Actors.Device)]));

        var decision = await EvaluateAsync(harness, request);

        Assert.True(decision.Allowed);
        Assert.Equal(2, decision.Permission!.Constraints.Count);
        Assert.Equal(PermissionConstraints.LocalOriginOnly, decision.Permission.Constraints[0]);
        Assert.Equal(PermissionConstraints.DeviceBound(request.Actors.Device), decision.Permission.Constraints[1]);
    }

    [Fact]
    public void ADeviceConstraintNamesTheDeviceInCanonicalForm()
    {
        var device = new DeviceId(Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"));
        Assert.Equal("device:00112233445566778899aabbccddeeff", PermissionConstraints.DeviceBound(device));
        Assert.Equal("origin.local-only", PermissionConstraints.LocalOriginOnly);
    }

    [Fact]
    public async Task TheProjectionPreservesPrincipalCapabilityScopeConstraintsAndLifetime()
    {
        var harness = new DecisionHarness();
        var request = harness.Request().Build();
        harness.Permissions.Behavior = (r, _) => ValueTask.FromResult<PermissionGrantRecord?>(harness.Grant(
            r, constraints: [PermissionConstraints.LocalOriginOnly], validFromOffset: TimeSpan.FromMinutes(-5), validUntilOffset: TimeSpan.FromMinutes(20)));

        var evidence = await harness.Pipeline().ProjectPermissionAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(PermissionDisposition.Granted, evidence.Disposition);
        Assert.Equal(DecisionReason.None, evidence.Reason);
        Assert.Equal(request.PrincipalKey, evidence.PrincipalKey);
        Assert.Equal(DecisionHarness.DefaultCapability, evidence.CapabilityKey);
        Assert.Equal(request.ScopeKey, evidence.ScopeKey);
        Assert.Equal([PermissionConstraints.LocalOriginOnly], evidence.Constraints);
        Assert.Equal(harness.Clock.UtcNow.AddMinutes(-5), evidence.ValidFromUtc);
        Assert.Equal(harness.Clock.UtcNow.AddMinutes(20), evidence.ValidUntilUtc);
        Assert.Equal("generation-1", evidence.SourceGeneration);
        Assert.Equal("owner.test", evidence.IssuerKey);
        Assert.Equal(harness.Clock.UtcNow, evidence.ObservedAtUtc);
        Assert.StartsWith("principal:", evidence.PrincipalKey, StringComparison.Ordinal);
        Assert.Equal($"principal:{request.Actors.Owner.Realm.Value:N}/{request.Actors.Owner.Id.Value:N}", evidence.PrincipalKey);
        Assert.Equal($"realm:{request.Scope.Realm.Value:N}/workspace:{request.Scope.Workspace!.Value.Value:N}", evidence.ScopeKey);
        Assert.Equal(["permission"], harness.Log.Entries);
        Assert.Empty(harness.Audit.Records);
    }

    [Fact]
    public async Task TheProjectionOfAScopeWithoutAWorkspaceNamesNoWorkspace()
    {
        var harness = new DecisionHarness();
        var builder = harness.Request();
        builder.Scope = new DecisionScope(builder.Actors.Owner.Realm, null);

        var evidence = await harness.Pipeline().ProjectPermissionAsync(builder.Build(), TestContext.Current.CancellationToken);

        Assert.Equal($"realm:{builder.Actors.Owner.Realm.Value:N}/workspace:-", evidence.ScopeKey);
    }

    [Theory]
    [InlineData(PermissionGrantState.NotGranted, PermissionDisposition.Required, DecisionReason.S06NotGranted)]
    [InlineData(PermissionGrantState.ExplicitlyDenied, PermissionDisposition.Denied, DecisionReason.S06ExplicitlyDenied)]
    public async Task TheProjectionDistinguishesNotGrantedFromExplicitlyDeniedAndKeepsTheRecord(
        PermissionGrantState state, PermissionDisposition disposition, DecisionReason reason)
    {
        var harness = new DecisionHarness();
        harness.Permissions.Behavior = (r, _) => ValueTask.FromResult<PermissionGrantRecord?>(harness.Grant(r, state, constraints: ["origin.local-only"]));

        var evidence = await harness.Pipeline().ProjectPermissionAsync(harness.Request().Build(), TestContext.Current.CancellationToken);

        Assert.Equal(disposition, evidence.Disposition);
        Assert.Equal(reason, evidence.Reason);
        Assert.Equal(["origin.local-only"], evidence.Constraints);
        Assert.Equal("generation-1", evidence.SourceGeneration);
    }

    [Fact]
    public async Task TheProjectionOfAMissingExpiredOrUnavailableGrantStatesWhatIsKnown()
    {
        var harness = new DecisionHarness();
        var request = harness.Request().Build();
        var pipeline = harness.Pipeline();

        harness.Permissions.Behavior = (_, _) => ValueTask.FromResult<PermissionGrantRecord?>(null);
        var missing = await pipeline.ProjectPermissionAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(PermissionDisposition.Required, missing.Disposition);
        Assert.Equal(DecisionReason.S06NotGranted, missing.Reason);
        Assert.Empty(missing.Constraints);
        Assert.Null(missing.ValidFromUtc);
        Assert.Null(missing.ValidUntilUtc);
        Assert.Null(missing.SourceGeneration);
        Assert.Null(missing.IssuerKey);

        harness.Permissions.Behavior = (r, _) => ValueTask.FromResult<PermissionGrantRecord?>(harness.Grant(r, validFromOffset: TimeSpan.FromHours(-2), validUntilOffset: TimeSpan.FromHours(-1)));
        var expired = await pipeline.ProjectPermissionAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(PermissionDisposition.Required, expired.Disposition);
        Assert.Equal(DecisionReason.S06OutsideLifetime, expired.Reason);
        Assert.Equal(harness.Clock.UtcNow.AddHours(-1), expired.ValidUntilUtc);

        harness.Permissions.Behavior = (_, _) => throw new InvalidOperationException("offline");
        var unavailable = await pipeline.ProjectPermissionAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(PermissionDisposition.Unknown, unavailable.Disposition);
        Assert.Equal(DecisionReason.S06Unavailable, unavailable.Reason);

        harness.Permissions.Behavior = (r, _) => ValueTask.FromResult<PermissionGrantRecord?>(new PermissionGrantRecord(
            "owner.test", "principal:other", r.CapabilityKey, r.ScopeKey, PermissionGrantState.Granted, ["origin.local-only"],
            harness.Clock.UtcNow.AddHours(-1), harness.Clock.UtcNow.AddHours(1), "generation-9"));
        var foreign = await pipeline.ProjectPermissionAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(PermissionDisposition.Unknown, foreign.Disposition);
        Assert.Equal(DecisionReason.S06GrantMismatch, foreign.Reason);
        Assert.Empty(foreign.Constraints);
        Assert.Null(foreign.SourceGeneration);
    }

    [Fact]
    public async Task AGrantWithUnmetOrUnknownConstraintsProjectsAsRequiredWithItsRecord()
    {
        var harness = new DecisionHarness();
        var builder = harness.Request();
        builder.Origin = DecisionOrigin.Remote;
        var request = builder.Build();
        harness.Permissions.Behavior = (r, _) => ValueTask.FromResult<PermissionGrantRecord?>(harness.Grant(r, constraints: [PermissionConstraints.LocalOriginOnly]));
        var unmet = await harness.Pipeline().ProjectPermissionAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(PermissionDisposition.Required, unmet.Disposition);
        Assert.Equal(DecisionReason.S06ConstraintUnmet, unmet.Reason);
        Assert.Equal([PermissionConstraints.LocalOriginOnly], unmet.Constraints);

        harness.Permissions.Behavior = (r, _) => ValueTask.FromResult<PermissionGrantRecord?>(harness.Grant(r, constraints: ["quota:5"]));
        var unknown = await harness.Pipeline().ProjectPermissionAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(PermissionDisposition.Required, unknown.Disposition);
        Assert.Equal(DecisionReason.S06ConstraintUnknown, unknown.Reason);
    }

    [Fact]
    public async Task AProjectionIsAnImmutableSnapshotAndGrantsNothing()
    {
        var harness = new DecisionHarness();
        var request = harness.Request().Build();
        var constraints = new List<string> { PermissionConstraints.LocalOriginOnly };
        harness.Permissions.Behavior = (r, _) => ValueTask.FromResult<PermissionGrantRecord?>(harness.Grant(r, constraints: constraints));

        var evidence = await harness.Pipeline().ProjectPermissionAsync(request, TestContext.Current.CancellationToken);
        constraints.Add("origin.remote");
        harness.Clock.Advance(TimeSpan.FromDays(1));
        var again = await harness.Pipeline().ProjectPermissionAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal([PermissionConstraints.LocalOriginOnly], evidence.Constraints);
        Assert.IsAssignableFrom<System.Collections.ObjectModel.ReadOnlyCollection<string>>(evidence.Constraints);
        Assert.Equal(PermissionDisposition.Granted, evidence.Disposition);
        Assert.Equal(DecisionReason.S06ConstraintUnknown, again.Reason);
        Assert.Equal(0, harness.OwnerOperation.Calls);
        Assert.Empty(harness.Recorder.Records);
    }

    [Fact]
    public async Task TheCallerPreCheckCarriesTheSameProjectionAsADecision()
    {
        var harness = new DecisionHarness();
        harness.Permissions.Behavior = (r, _) => ValueTask.FromResult<PermissionGrantRecord?>(harness.Grant(r, PermissionGrantState.ExplicitlyDenied));

        var decision = await harness.Pipeline().EvaluateAsync(EnforcementPoint.CallerPreCheck, harness.Request().Build(), TestContext.Current.CancellationToken);

        Assert.False(decision.Allowed);
        Assert.Equal(PermissionDisposition.Denied, decision.Permission!.Disposition);
        Assert.Equal(DecisionReason.S06ExplicitlyDenied, decision.Permission.Reason);
        Assert.Null(decision.Risk);
    }

    [Fact]
    public void GrantRecordsRefuseEveryMalformedField()
    {
        var from = new DateTimeOffset(2026, 9, 30, 12, 0, 0, TimeSpan.Zero);
        var until = from.AddHours(1);
        PermissionGrantRecord Make(
            string issuer = "i", string principal = "p", string capability = "c", string scope = "s",
            PermissionGrantState state = PermissionGrantState.Granted, IEnumerable<string>? constraints = null,
            DateTimeOffset? validFrom = null, DateTimeOffset? validUntil = null, string generation = "g") =>
            new(issuer, principal, capability, scope, state, constraints ?? [], validFrom ?? from, validUntil ?? until, generation);

        _ = Make();
        _ = Assert.Throws<ArgumentException>(() => Make(issuer: ""));
        _ = Assert.Throws<ArgumentException>(() => Make(principal: " "));
        _ = Assert.Throws<ArgumentException>(() => Make(capability: ""));
        _ = Assert.Throws<ArgumentException>(() => Make(scope: ""));
        _ = Assert.Throws<ArgumentException>(() => Make(generation: ""));
        _ = Assert.Throws<ArgumentException>(() => Make(principal: new string('x', 257)));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => Make(state: PermissionGrantState.None));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => Make(state: (PermissionGrantState)9));
        _ = Assert.Throws<ArgumentNullException>(() => new PermissionGrantRecord("i", "p", "c", "s", PermissionGrantState.Granted, null!, from, until, "g"));
        _ = Assert.Throws<ArgumentException>(() => Make(constraints: ["a", "a"]));
        _ = Assert.Throws<ArgumentException>(() => Make(constraints: [""]));
        _ = Make(constraints: Enumerable.Range(0, 64).Select(index => "k" + index));
        _ = Assert.Throws<ArgumentException>(() => Make(constraints: Enumerable.Range(0, 65).Select(index => "k" + index)));
        _ = Assert.Throws<ArgumentException>(() => Make(validFrom: from.ToOffset(TimeSpan.FromHours(2))));
        _ = Assert.Throws<ArgumentException>(() => Make(validUntil: until.ToOffset(TimeSpan.FromHours(2))));
        _ = Assert.Throws<ArgumentException>(() => Make(validUntil: from));
        _ = Assert.Throws<ArgumentException>(() => Make(validUntil: from.AddTicks(-1)));
        _ = Make(validUntil: from.AddTicks(1));
    }

    [Fact]
    public void RequestsRefuseMalformedEvidence()
    {
        var harness = new DecisionHarness();
        var chain = DecisionHarness.Chain();
        var scope = new DecisionScope(chain.Owner.Realm, null);
        var resource = new ResourceReference("r", "v");
        var command = new CommandId(Guid.NewGuid());
        DecisionRequest Make(
            ActorChain? actors = null, string capability = "c", DecisionScope? scopeValue = null, ResourceReference? resourceValue = null,
            string? effect = null, DecisionOrigin origin = DecisionOrigin.Local, ITransportSession? transport = null,
            string? destination = null, string? secret = null, Guid? approval = null, SensitiveOperation? operation = null) =>
            new(actors ?? chain, capability, scopeValue ?? scope, command, resourceValue ?? resource, effect ?? DecisionHarness.Sha(), origin,
                transport ?? harness.Transport, null, destination, secret, approval, null,
                operation ?? SensitiveOperation.None);

        var good = Make();
        Assert.Equal("c", good.CapabilityKey);
        Assert.Same(RiskFacts.None, good.DeclaredFacts);
        _ = Assert.Throws<ArgumentNullException>(() => new DecisionRequest(null!, "c", scope, command, resource, DecisionHarness.Sha(), DecisionOrigin.Local, harness.Transport));
        _ = Assert.Throws<ArgumentException>(() => Make(capability: ""));
        _ = Assert.Throws<ArgumentException>(() => Make(capability: new string('c', 257)));
        _ = Assert.Throws<ArgumentNullException>(() => new DecisionRequest(chain, "c", null!, command, resource, DecisionHarness.Sha(), DecisionOrigin.Local, harness.Transport));
        _ = Assert.Throws<ArgumentException>(() => new DecisionRequest(chain, "c", scope, default, resource, DecisionHarness.Sha(), DecisionOrigin.Local, harness.Transport));
        _ = Assert.Throws<ArgumentNullException>(() => new DecisionRequest(chain, "c", scope, command, null!, DecisionHarness.Sha(), DecisionOrigin.Local, harness.Transport));
        _ = Assert.Throws<ArgumentException>(() => Make(effect: "abc"));
        _ = Assert.Throws<ArgumentException>(() => Make(effect: new string('a', 64)));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => Make(origin: DecisionOrigin.None));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => Make(origin: (DecisionOrigin)5));
        _ = Assert.Throws<ArgumentNullException>(() => new DecisionRequest(chain, "c", scope, command, resource, DecisionHarness.Sha(), DecisionOrigin.Local, null!));
        _ = Assert.Throws<ArgumentException>(() => Make(destination: ""));
        _ = Assert.Throws<ArgumentException>(() => Make(destination: new string('d', 513)));
        _ = Assert.Throws<ArgumentException>(() => Make(secret: ""));
        _ = Assert.Throws<ArgumentException>(() => Make(secret: new string('s', 257)));
        _ = Assert.Throws<ArgumentException>(() => Make(approval: Guid.Empty));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => Make(operation: (SensitiveOperation)99));
        _ = Assert.Throws<ArgumentException>(() => new ResourceReference("", "v"));
        _ = Assert.Throws<ArgumentException>(() => new ResourceReference("r", ""));
        _ = Assert.Throws<ArgumentException>(() => new ResourceReference(new string('r', 513), "v"));
        _ = Assert.Throws<ArgumentException>(() => new ResourceReference("r", new string('v', 257)));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new RiskFacts((RiskScope)7, RiskTarget.Ordinary, RiskReversibility.Reversible, false));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new RiskFacts(RiskScope.Bulk, (RiskTarget)7, RiskReversibility.Reversible, false));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new RiskFacts(RiskScope.Bulk, RiskTarget.Ordinary, (RiskReversibility)7, false));
    }
}
