// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;
using ArcForges.Security.Approvals;
using ArcForges.Security.Decisions;
using Xunit;

namespace ArcForges.Security.Tests;

/// <summary>
/// The refusal matrix: for every decision step each way it can refuse, the decision names exactly that step and reason, every
/// earlier step passed, no later decision step ran, the refusal reached the audit sink, and the owner operation never ran.
/// </summary>
public sealed class DecisionRefusalMatrixTests
{
    private const string Capability = DecisionHarness.DefaultCapability;

    private static readonly RefusalCase[] Cases = BuildCases();

    public static TheoryData<string> Names => [.. Cases.Select(item => item.Name)];

    [Theory]
    [MemberData(nameof(Names))]
    public async Task EveryRefusalNamesItsStepAndReasonAndReachesNoOwner(string name)
    {
        var item = Cases.Single(candidate => candidate.Name == name);
        var (harness, request, decision) = await RunAsync(item);
        var point = item.Reason >= DecisionReason.S11OwnerRefused ? EnforcementPoint.OwnerFinalValidation : EnforcementPoint.ServiceDecision;

        var expected = DecisionReasons.Describe(item.Reason);
        Assert.False(decision.Allowed);
        Assert.True(decision.IsAuthority);
        Assert.Equal(point, decision.Point);
        Assert.Equal(expected.Step, decision.FailedStep);
        Assert.Equal(item.Reason, decision.Reason);
        Assert.Equal(expected.Code, decision.ReasonCode);
        Assert.Equal(expected.RegisteredCode, decision.RegisteredCode);
        Assert.True(ReasonCodes.TryGet(decision.RegisteredCode, out _));
        Assert.Equal(14, decision.Steps.Count);
        for (var index = 0; index < 14; index++)
        {
            var step = (DecisionStep)(index + 1);
            var outcome = decision.Steps[index];
            Assert.Equal(step, outcome.Step);
            if (step < expected.Step)
            {
                Assert.True(outcome.Disposition is StepDisposition.Passed or StepDisposition.NotRequired, $"{step} before the failing step");
                Assert.Equal(DecisionReason.None, outcome.Reason);
            }
            else if (step == expected.Step)
            {
                Assert.Equal(StepDisposition.Refused, outcome.Disposition);
                Assert.Equal(item.Reason, outcome.Reason);
            }
            else if (step == DecisionStep.AuditWrite)
            {
                Assert.Equal(StepDisposition.Passed, outcome.Disposition);
            }
            else
            {
                Assert.Equal(StepDisposition.NotRun, outcome.Disposition);
                Assert.Equal(DecisionReason.None, outcome.Reason);
            }
        }

        Assert.Equal(DecisionAuditStatus.Written, decision.Audit);
        var audit = Assert.Single(harness.Audit.Records);
        Assert.Equal(SecurityAuditKind.Refused, audit.Kind);
        Assert.Equal(point, audit.Point);
        Assert.Equal(expected.Step, audit.FailedStep);
        Assert.Equal(expected.Code, audit.ReasonCode);
        Assert.Equal(expected.RegisteredCode, audit.RegisteredCode);
        Assert.Equal(EffectCertainty.DidNotHappen, audit.Effect);
        Assert.Same(request.Actors, audit.Actors);
        Assert.Equal(Capability, audit.CapabilityKey);
        Assert.Equal(request.CommandId, audit.Correlation);
        Assert.Empty(harness.Recorder.Records);
        Assert.Equal(0, harness.OwnerOperation.Calls);
        Assert.Equal(0, harness.Log.Count("owner-op"));
        Assert.Equal(point == EnforcementPoint.OwnerFinalValidation ? 1 : 0, harness.Log.Count("owner"));
        Assert.Equal(0, harness.Log.Count("record"));

        // The same request through the executing route is refused with the same typed failure and runs nothing.
        var second = new DecisionHarness();
        var secondBuilder = second.Request();
        await item.Arrange(second, secondBuilder);
        var execution = await second.Pipeline().ExecuteAsync(secondBuilder.Build(), second.OwnerOperation.Operation, TestContext.Current.CancellationToken);
        Assert.Equal(ExecutionStatus.Refused, execution.Status);
        Assert.Equal(EffectCertainty.DidNotHappen, execution.Effect);
        Assert.Equal(expected.RegisteredCode, DecisionHarness.FailureCode(execution.Result));
        Assert.Null(execution.OwnerResult);
        Assert.Equal(item.Reason, execution.Decision.Reason);
        Assert.Equal(0, second.OwnerOperation.Calls);
    }

    [Fact]
    public void TheMatrixCoversEveryReasonOfTheElevenDecisionStepsExceptTheServiceDecisionChecks()
    {
        // The service-decision, execution and bookkeeping reasons are covered by DecisionExecutionTests.
        var elsewhere = new[]
        {
            DecisionReason.S11ServiceDecisionInvalid,
            DecisionReason.S11ServiceDecisionStale,
            DecisionReason.S12OwnerFailed,
            DecisionReason.S13RecordFailed,
            DecisionReason.S14AuditFailed,
        };
        var expected = Enum.GetValues<DecisionReason>().Where(reason => reason != DecisionReason.None).Except(elsewhere).OrderBy(reason => (int)reason);
        Assert.Equal(expected, Cases.Select(item => item.Reason).Distinct().OrderBy(reason => (int)reason));
        Assert.Equal(Cases.Length, Cases.Select(item => item.Name).Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public async Task EachFailingStepHasADistinctReasonCodeAcrossTheWholeMatrix()
    {
        var seen = new Dictionary<DecisionStep, HashSet<string>>();
        var codes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in Cases)
        {
            var (_, _, decision) = await RunAsync(item);
            Assert.False(decision.Allowed, item.Name);
            _ = codes.Add(decision.ReasonCode);
            if (!seen.TryGetValue(decision.FailedStep, out var set))
            {
                seen[decision.FailedStep] = set = new HashSet<string>(StringComparer.Ordinal);
            }

            _ = set.Add(decision.ReasonCode);
        }

        Assert.Equal(Enumerable.Range(1, 11).Select(value => (DecisionStep)value), seen.Keys.OrderBy(step => (int)step));
        Assert.Equal(DecisionReasons.All.Count(info => info.Step <= DecisionStep.OwnerValidation) - 2, codes.Count);
        foreach (var codeSet in seen.Values)
        {
            Assert.All(codeSet, code => Assert.Equal(1, seen.Values.Count(other => other.Contains(code))));
        }
    }

    private static async Task<(DecisionHarness Harness, DecisionRequest Request, SecurityDecision Decision)> RunAsync(RefusalCase item)
    {
        var harness = new DecisionHarness();
        var builder = harness.Request();
        await item.Arrange(harness, builder);
        var request = builder.Build();
        var pipeline = harness.Pipeline();
        if (item.Reason >= DecisionReason.S11OwnerRefused)
        {
            // The owner's validation is the last decision step and is reached only through the executing route.
            var execution = await pipeline.ExecuteAsync(request, harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);
            return (harness, request, execution.Decision);
        }

        return (harness, request, await pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, request, TestContext.Current.CancellationToken));
    }

    private static RefusalCase[] BuildCases()
    {
        var cases = new List<RefusalCase>();

        void Add(string name, DecisionReason reason, Func<DecisionHarness, RequestBuilder, Task> arrange) =>
            cases.Add(new RefusalCase(name, reason, arrange));

        void Sync(string name, DecisionReason reason, Action<DecisionHarness, RequestBuilder> arrange) =>
            Add(name, reason, (harness, builder) =>
            {
                arrange(harness, builder);
                return Task.CompletedTask;
            });

        // Step 1: the capability exists in the authoritative catalogue.
        Sync("s01 no such capability", DecisionReason.S01CapabilityUnknown, (h, _) =>
            h.Catalogue.Behavior = (_, _) => ValueTask.FromResult<CapabilityDescriptor?>(null));
        Sync("s01 catalogue answers for another capability", DecisionReason.S01CapabilityUnknown, (h, _) =>
            h.Catalogue.Behavior = (_, _) => ValueTask.FromResult<CapabilityDescriptor?>(DecisionHarness.Describe("test.capability.other", "R1", "none", "none")));
        Sync("s01 descriptor without a key", DecisionReason.S01CapabilityUnknown, (h, _) =>
            h.Catalogue.Behavior = (_, _) => ValueTask.FromResult<CapabilityDescriptor?>(new CapabilityDescriptor { Risk = "R1" }));
        Sync("s01 catalogue throws", DecisionReason.S01Unavailable, (h, _) =>
            h.Catalogue.Behavior = (_, _) => throw new InvalidOperationException("catalogue offline"));

        // Step 2: product policy.
        Sync("s02 policy disabled", DecisionReason.S02PolicyDisabled, (h, _) =>
            h.Policy.Behavior = (_, _) => ValueTask.FromResult(PolicyVerdict.Disabled));
        Sync("s02 policy unknown", DecisionReason.S02PolicyUnknown, (h, _) =>
            h.Policy.Behavior = (_, _) => ValueTask.FromResult(PolicyVerdict.Unknown));
        Sync("s02 policy undefined value", DecisionReason.S02PolicyUnknown, (h, _) =>
            h.Policy.Behavior = (_, _) => ValueTask.FromResult((PolicyVerdict)77));
        Sync("s02 policy throws", DecisionReason.S02Unavailable, (h, _) =>
            h.Policy.Behavior = (_, _) => throw new InvalidOperationException("policy offline"));

        // Step 3: actor identity and the transport boundary.
        Sync("s03 unauthenticated", DecisionReason.S03Unauthenticated, (h, _) =>
            h.Identity.Behavior = (_, _) => ValueTask.FromResult(ActorIdentityVerdict.Unauthenticated));
        Sync("s03 session expired", DecisionReason.S03SessionExpired, (h, _) =>
            h.Identity.Behavior = (_, _) => ValueTask.FromResult(ActorIdentityVerdict.SessionExpired));
        Sync("s03 identity unknown", DecisionReason.S03Unavailable, (h, _) =>
            h.Identity.Behavior = (_, _) => ValueTask.FromResult(ActorIdentityVerdict.Unknown));
        Sync("s03 identity undefined value", DecisionReason.S03Unavailable, (h, _) =>
            h.Identity.Behavior = (_, _) => ValueTask.FromResult((ActorIdentityVerdict)40));
        Sync("s03 identity throws", DecisionReason.S03Unavailable, (h, _) =>
            h.Identity.Behavior = (_, _) => throw new InvalidOperationException("identity offline"));
        foreach (var refusal in Enum.GetValues<TransportRefusal>().Where(value => value != TransportRefusal.None))
        {
            var captured = refusal;
            Sync($"s03 transport refuses {captured}", DecisionReason.S03TransportRefused, (h, _) =>
                h.Transport.Behavior = _ => ValueTask.FromResult(new TransportVerdict(captured, null)));
        }

        Sync("s03 transport refusal even with a binding", DecisionReason.S03TransportRefused, (h, _) =>
            h.Transport.Behavior = _ => ValueTask.FromResult(new TransportVerdict(
                TransportRefusal.Revoked, new TransportBinding(TransportKind.InProcess, TransportAssurance.InProcessHost))));
        Sync("s03 transport undefined refusal", DecisionReason.S03TransportRefused, (h, _) =>
            h.Transport.Behavior = _ => ValueTask.FromResult(new TransportVerdict(
                (TransportRefusal)99, new TransportBinding(TransportKind.InProcess, TransportAssurance.InProcessHost))));
        Sync("s03 transport verifies without a binding", DecisionReason.S03TransportRefused, (h, _) =>
            h.Transport.Behavior = _ => ValueTask.FromResult(new TransportVerdict(TransportRefusal.None, null)));
        Sync("s03 transport returns no verdict", DecisionReason.S03TransportRefused, (h, _) =>
            h.Transport.Behavior = _ => ValueTask.FromResult<TransportVerdict>(null!));
        Sync("s03 binding kind differs from the session kind", DecisionReason.S03TransportRefused, (h, _) =>
            h.Transport.Behavior = _ => ValueTask.FromResult(new TransportVerdict(
                TransportRefusal.None, new TransportBinding(TransportKind.LocalRpcChild, TransportAssurance.LaunchClaimWithSecretProof))));
        Sync("s03 session has no kind", DecisionReason.S03TransportRefused, (h, _) => h.Transport.KindValue = TransportKind.None);
        Sync("s03 transport bound another caller instance", DecisionReason.S03CallerInstanceMismatch, (h, _) =>
            h.Transport.Behavior = _ => ValueTask.FromResult(new TransportVerdict(
                TransportRefusal.None,
                new TransportBinding(TransportKind.InProcess, TransportAssurance.InProcessHost, boundCallerInstance: new InstanceId(Guid.NewGuid())))));
        Sync("s03 transport throws", DecisionReason.S03Unavailable, (h, _) =>
            h.Transport.Behavior = _ => throw new InvalidOperationException("transport offline"));

        // Step 4: realm and workspace scope.
        Sync("s04 realm differs from the owner's realm", DecisionReason.S04RealmMismatch, (_, b) =>
            b.Scope = new DecisionScope(new RealmId(Guid.NewGuid()), b.Scope.Workspace));
        Sync("s04 workspace invalid", DecisionReason.S04WorkspaceInvalid, (h, _) =>
            h.Scope.Behavior = (_, _) => ValueTask.FromResult(ScopeVerdict.Invalid));
        Sync("s04 scope unknown", DecisionReason.S04Unavailable, (h, _) =>
            h.Scope.Behavior = (_, _) => ValueTask.FromResult(ScopeVerdict.Unknown));
        Sync("s04 scope undefined value", DecisionReason.S04Unavailable, (h, _) =>
            h.Scope.Behavior = (_, _) => ValueTask.FromResult((ScopeVerdict)9));
        Sync("s04 scope throws", DecisionReason.S04Unavailable, (h, _) =>
            h.Scope.Behavior = (_, _) => throw new InvalidOperationException("scope offline"));

        // Step 5: software and package trust.
        Sync("s05 trust revoked", DecisionReason.S05TrustRevoked, (h, _) =>
            h.Trust.Behavior = (_, _) => ValueTask.FromResult(TrustVerdict.Revoked));
        Sync("s05 trust unknown", DecisionReason.S05TrustUnknown, (h, _) =>
            h.Trust.Behavior = (_, _) => ValueTask.FromResult(TrustVerdict.Unknown));
        Sync("s05 trust undefined value", DecisionReason.S05TrustUnknown, (h, _) =>
            h.Trust.Behavior = (_, _) => ValueTask.FromResult((TrustVerdict)12));
        Sync("s05 trust throws", DecisionReason.S05Unavailable, (h, _) =>
            h.Trust.Behavior = (_, _) => throw new InvalidOperationException("trust offline"));

        // Step 6: capability permission with scope, constraints and lifetime.
        Sync("s06 no grant", DecisionReason.S06NotGranted, (h, _) =>
            h.Permissions.Behavior = (_, _) => ValueTask.FromResult<PermissionGrantRecord?>(null));
        Sync("s06 record says not granted", DecisionReason.S06NotGranted, (h, _) =>
            h.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(h.Grant(request, PermissionGrantState.NotGranted)));
        Sync("s06 explicitly denied", DecisionReason.S06ExplicitlyDenied, (h, _) =>
            h.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(h.Grant(request, PermissionGrantState.ExplicitlyDenied)));
        Sync("s06 grant of another principal", DecisionReason.S06GrantMismatch, (h, _) =>
            h.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(new PermissionGrantRecord(
                "owner.test", "principal:someone-else", request.CapabilityKey, request.ScopeKey, PermissionGrantState.Granted, [],
                h.Clock.UtcNow.AddHours(-1), h.Clock.UtcNow.AddHours(1), "generation-1")));
        Sync("s06 grant of another capability", DecisionReason.S06GrantMismatch, (h, _) =>
            h.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(new PermissionGrantRecord(
                "owner.test", request.PrincipalKey, "test.capability.other", request.ScopeKey, PermissionGrantState.Granted, [],
                h.Clock.UtcNow.AddHours(-1), h.Clock.UtcNow.AddHours(1), "generation-1")));
        Sync("s06 grant of another scope", DecisionReason.S06GrantMismatch, (h, _) =>
            h.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(new PermissionGrantRecord(
                "owner.test", request.PrincipalKey, request.CapabilityKey, "realm:other/workspace:other", PermissionGrantState.Granted, [],
                h.Clock.UtcNow.AddHours(-1), h.Clock.UtcNow.AddHours(1), "generation-1")));
        Sync("s06 lifetime has not begun", DecisionReason.S06OutsideLifetime, (h, _) =>
            h.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(h.Grant(
                request, validFromOffset: TimeSpan.FromTicks(1), validUntilOffset: TimeSpan.FromHours(1))));
        Sync("s06 lifetime ends exactly now", DecisionReason.S06OutsideLifetime, (h, _) =>
            h.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(h.Grant(
                request, validFromOffset: TimeSpan.FromHours(-1), validUntilOffset: TimeSpan.Zero)));
        Sync("s06 lifetime ended long ago", DecisionReason.S06OutsideLifetime, (h, _) =>
            h.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(h.Grant(
                request, validFromOffset: TimeSpan.FromHours(-3), validUntilOffset: TimeSpan.FromHours(-2))));
        Sync("s06 local-origin-only constraint and a remote request", DecisionReason.S06ConstraintUnmet, (h, b) =>
        {
            b.Origin = DecisionOrigin.Remote;
            h.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(h.Grant(request, constraints: [PermissionConstraints.LocalOriginOnly]));
        });
        Sync("s06 device-bound constraint for another device", DecisionReason.S06ConstraintUnmet, (h, _) =>
            h.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(h.Grant(
                request, constraints: [PermissionConstraints.DeviceBound(new DeviceId(Guid.NewGuid()))])));
        Sync("s06 one unmet constraint among met ones", DecisionReason.S06ConstraintUnmet, (h, b) =>
        {
            h.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(h.Grant(
                request, constraints: [PermissionConstraints.LocalOriginOnly, PermissionConstraints.DeviceBound(new DeviceId(Guid.NewGuid()))]));
        });
        Sync("s06 constraint the pipeline cannot read", DecisionReason.S06ConstraintUnknown, (h, _) =>
            h.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(h.Grant(request, constraints: ["max-volume:10"])));
        Sync("s06 unreadable constraint beside a met one", DecisionReason.S06ConstraintUnknown, (h, _) =>
            h.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(h.Grant(
                request, constraints: [PermissionConstraints.LocalOriginOnly, "time-window:office-hours"])));
        Sync("s06 unreadable constraint beside an unmet one", DecisionReason.S06ConstraintUnknown, (h, b) =>
        {
            b.Origin = DecisionOrigin.Remote;
            h.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(h.Grant(
                request, constraints: [PermissionConstraints.LocalOriginOnly, "time-window:office-hours"]));
        });
        Sync("s06 permission source throws", DecisionReason.S06Unavailable, (h, _) =>
            h.Permissions.Behavior = (_, _) => throw new InvalidOperationException("grants offline"));

        // Step 7: resource authorization.
        Sync("s07 resource denied", DecisionReason.S07ResourceDenied, (h, _) =>
            h.Resources.Behavior = (_, _) => ValueTask.FromResult<ResourceVerdict?>(new ResourceVerdict(ResourceDisposition.Denied, RiskFacts.None)));
        Sync("s07 no verdict", DecisionReason.S07Unavailable, (h, _) =>
            h.Resources.Behavior = (_, _) => ValueTask.FromResult<ResourceVerdict?>(null));
        Sync("s07 unknown disposition", DecisionReason.S07Unavailable, (h, _) =>
            h.Resources.Behavior = (_, _) => ValueTask.FromResult<ResourceVerdict?>(new ResourceVerdict(ResourceDisposition.Unknown, RiskFacts.None)));
        Sync("s07 undefined disposition", DecisionReason.S07Unavailable, (h, _) =>
            h.Resources.Behavior = (_, _) => ValueTask.FromResult<ResourceVerdict?>(new ResourceVerdict((ResourceDisposition)8, RiskFacts.None)));
        Sync("s07 authorized without facts", DecisionReason.S07Unavailable, (h, _) =>
            h.Resources.Behavior = (_, _) => ValueTask.FromResult<ResourceVerdict?>(new ResourceVerdict(ResourceDisposition.Authorized, null!)));
        Sync("s07 resource authorizer throws", DecisionReason.S07Unavailable, (h, _) =>
            h.Resources.Behavior = (_, _) => throw new InvalidOperationException("owner offline"));

        // Step 8: secret use and data egress.
        Sync("s08 destination named for a capability without egress", DecisionReason.S08EgressNotDeclared, (_, b) =>
            b.EgressDestination = "destination.example");
        Sync("s08 egress declared without a destination", DecisionReason.S08EgressDestinationUnspecified, (h, _) =>
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "none", "ownedContent"));
        Sync("s08 external egress without a destination", DecisionReason.S08EgressDestinationUnspecified, (h, _) =>
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "none", "webSearch"));
        Sync("s08 secret use denied", DecisionReason.S08SecretUseDenied, (h, b) =>
        {
            b.SecretUseKey = "secret-ref-1";
            h.DataBoundary.SecretBehavior = (_, _) => ValueTask.FromResult(BoundaryVerdict.Denied);
        });
        Sync("s08 secret use unknown", DecisionReason.S08Unavailable, (h, b) =>
        {
            b.SecretUseKey = "secret-ref-1";
            h.DataBoundary.SecretBehavior = (_, _) => ValueTask.FromResult(BoundaryVerdict.Unknown);
        });
        Sync("s08 secret use undefined value", DecisionReason.S08Unavailable, (h, b) =>
        {
            b.SecretUseKey = "secret-ref-1";
            h.DataBoundary.SecretBehavior = (_, _) => ValueTask.FromResult((BoundaryVerdict)6);
        });
        Sync("s08 secret use throws", DecisionReason.S08Unavailable, (h, b) =>
        {
            b.SecretUseKey = "secret-ref-1";
            h.DataBoundary.SecretBehavior = (_, _) => throw new InvalidOperationException("broker offline");
        });
        Sync("s08 egress denied", DecisionReason.S08EgressDenied, (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "none", "ownedContent");
            b.EgressDestination = "owned.helper/1";
            h.DataBoundary.EgressBehavior = (_, _, _) => ValueTask.FromResult(BoundaryVerdict.Denied);
        });
        Sync("s08 egress unknown", DecisionReason.S08Unavailable, (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "none", "ownedContent");
            b.EgressDestination = "owned.helper/1";
            h.DataBoundary.EgressBehavior = (_, _, _) => ValueTask.FromResult(BoundaryVerdict.Unknown);
        });
        Sync("s08 egress undefined value", DecisionReason.S08Unavailable, (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "none", "ownedContent");
            b.EgressDestination = "owned.helper/1";
            h.DataBoundary.EgressBehavior = (_, _, _) => ValueTask.FromResult((BoundaryVerdict)6);
        });
        Sync("s08 egress throws", DecisionReason.S08Unavailable, (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "none", "webSearch");
            b.EgressDestination = "search.example";
            h.DataBoundary.EgressBehavior = (_, _, _) => throw new InvalidOperationException("egress offline");
        });
        Sync("s08 egress denied after secret use was allowed", DecisionReason.S08EgressDenied, (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "none", "webSearch");
            b.EgressDestination = "search.example";
            b.SecretUseKey = "secret-ref-1";
            h.DataBoundary.EgressBehavior = (_, _, _) => ValueTask.FromResult(BoundaryVerdict.Denied);
        });

        // Step 9: effective risk cannot be classified.
        foreach (var risk in new[] { "R9", "r1", "", "R", "R10" })
        {
            var captured = risk;
            Sync($"s09 descriptor risk '{captured}'", DecisionReason.S09RiskUnclassifiable, (h, _) =>
                h.Descriptor = DecisionHarness.Describe(Capability, captured, "none", "none"));
        }

        // Step 10: approval, step-up and local presence.
        Sync("s10 approval required without an approval", DecisionReason.S10ApprovalRequired, (h, _) =>
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none"));
        Sync("s10 approval required by a descriptor with no approval posture", DecisionReason.S10ApprovalRequired, (h, _) =>
            h.Descriptor = new CapabilityDescriptor { Key = Capability, Risk = "R1", Egress = "none" });
        Sync("s10 approval required by risk R3 though the descriptor says none", DecisionReason.S10ApprovalRequired, (h, _) =>
            h.Descriptor = DecisionHarness.Describe(Capability, "R3", "none", "none"));
        Sync("s10 approval required by a remote origin raising R1 to R3", DecisionReason.S10ApprovalRequired, (_, b) =>
            b.Origin = DecisionOrigin.Remote);
        Sync("s10 approval identity not found", DecisionReason.S10ApprovalRequired, (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none");
            b.ApprovalId = Guid.NewGuid();
        });
        Add("s10 approval still pending", DecisionReason.S10ApprovalPending, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none");
            var request = b.Build();
            var intent = new ApprovalIntent(Guid.NewGuid(), request.CommandId, request.Actors.Owner, Capability, request.Resource.Id,
                request.Resource.Revision, request.EffectSha256, RiskLevel.R1);
            _ = DecisionHarness.Value(await h.Approvals.RequestAsync(intent, TimeSpan.FromMinutes(5), TestContext.Current.CancellationToken));
            b.ApprovalId = intent.ApprovalId;
        });
        Add("s10 approval denied", DecisionReason.S10ApprovalDenied, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none");
            var request = b.Build();
            var intent = new ApprovalIntent(Guid.NewGuid(), request.CommandId, request.Actors.Owner, Capability, request.Resource.Id,
                request.Resource.Revision, request.EffectSha256, RiskLevel.R1);
            _ = DecisionHarness.Value(await h.Approvals.RequestAsync(intent, TimeSpan.FromMinutes(5), TestContext.Current.CancellationToken));
            _ = DecisionHarness.Value(await h.Approvals.DecideAsync(
                intent.ApprovalId,
                new ApprovalDecisionRequest(Guid.NewGuid(), ApprovalDecisionKind.Deny, request.Actors.Owner, request.Actors.Device, ApprovalOrigin.Local, "no"),
                TestContext.Current.CancellationToken));
            b.ApprovalId = intent.ApprovalId;
        });
        Add("s10 approval cancelled", DecisionReason.S10ApprovalDenied, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none");
            var request = b.Build();
            var intent = new ApprovalIntent(Guid.NewGuid(), request.CommandId, request.Actors.Owner, Capability, request.Resource.Id,
                request.Resource.Revision, request.EffectSha256, RiskLevel.R1);
            _ = DecisionHarness.Value(await h.Approvals.RequestAsync(intent, TimeSpan.FromMinutes(5), TestContext.Current.CancellationToken));
            _ = DecisionHarness.Value(await h.Approvals.CancelAsync(intent.ApprovalId, request.Actors.Owner, TestContext.Current.CancellationToken));
            b.ApprovalId = intent.ApprovalId;
        });
        Add("s10 pending approval expired unanswered", DecisionReason.S10ApprovalExpired, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none");
            var request = b.Build();
            var intent = new ApprovalIntent(Guid.NewGuid(), request.CommandId, request.Actors.Owner, Capability, request.Resource.Id,
                request.Resource.Revision, request.EffectSha256, RiskLevel.R1);
            _ = DecisionHarness.Value(await h.Approvals.RequestAsync(intent, TimeSpan.FromMinutes(1), TestContext.Current.CancellationToken));
            b.ApprovalId = intent.ApprovalId;
            h.Clock.Advance(TimeSpan.FromMinutes(1));
        });
        Add("s10 approved approval used at its exact expiry", DecisionReason.S10ApprovalExpired, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none");
            b.ApprovalId = await h.ApproveAsync(b.Build(), RiskLevel.R1, lifetime: TimeSpan.FromMinutes(5));
            h.Clock.Advance(TimeSpan.FromMinutes(5));
        });
        Add("s10 approved approval used long after expiry", DecisionReason.S10ApprovalExpired, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none");
            b.ApprovalId = await h.ApproveAsync(b.Build(), RiskLevel.R1, lifetime: TimeSpan.FromMinutes(5));
            h.Clock.Advance(TimeSpan.FromHours(2));
        });
        Add("s10 approval for another command", DecisionReason.S10ApprovalMismatch, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none");
            b.ApprovalId = await h.ApproveAsync(b.Build(), RiskLevel.R1);
            b.CommandId = new CommandId(Guid.NewGuid());
        });
        Add("s10 approval for another capability", DecisionReason.S10ApprovalMismatch, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none");
            b.Capability = "test.capability.other";
            b.ApprovalId = await h.ApproveAsync(b.Build(), RiskLevel.R1);
            b.Capability = Capability;
        });
        Add("s10 approval for another resource", DecisionReason.S10ApprovalMismatch, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none");
            b.ApprovalId = await h.ApproveAsync(b.Build(), RiskLevel.R1);
            b.Resource = new ResourceReference("resource/other", b.Resource.Revision);
        });
        Add("s10 approval for another revision of the resource", DecisionReason.S10ApprovalMismatch, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none");
            b.ApprovalId = await h.ApproveAsync(b.Build(), RiskLevel.R1);
            b.Resource = new ResourceReference(b.Resource.Id, "revision:8");
        });
        Add("s10 approval for another effect", DecisionReason.S10ApprovalMismatch, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none");
            b.ApprovalId = await h.ApproveAsync(b.Build(), RiskLevel.R1);
            b.Effect = DecisionHarness.Sha('B');
        });
        Add("s10 approval granted at another risk than the request now has", DecisionReason.S10ApprovalMismatch, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none");
            b.ApprovalId = await h.ApproveAsync(b.Build(), RiskLevel.R2);
        });
        Add("s10 approval granted at a lower risk than the request now has", DecisionReason.S10ApprovalMismatch, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R3", "perOperation", "none");
            b.ApprovalId = await h.ApproveAsync(b.Build(), RiskLevel.R2);
        });
        Add("s10 approval decided by another person", DecisionReason.S10ApprovalMismatch, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none");
            var other = new HumanPrincipal(new RealmId(Guid.NewGuid()), new UserId(Guid.NewGuid()), HumanIdentityKind.CloudUser);
            b.ApprovalId = await h.ApproveAsync(b.Build(), RiskLevel.R1, decidedBy: other);
        });
        Add("s10 approval belongs to another owner", DecisionReason.S10ApprovalMismatch, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none");
            b.ApprovalId = await h.ApproveAsync(b.Build(), RiskLevel.R1);
            _ = b.WithActors();
        });
        Sync("s10 approval store throws", DecisionReason.S10Unavailable, (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R1", "perOperation", "none");
            b.ApprovalId = Guid.NewGuid();
            h.ApprovalStore.FailReads = true;
        });
        Sync("s10 step-up required for an enumerated operation without a proof", DecisionReason.S10StepUpRequired, (_, b) =>
            b.Operation = SensitiveOperation.ChangeEmail);
        Add("s10 step-up proof for another operation", DecisionReason.S10StepUpInvalid, async (h, b) =>
        {
            b.Operation = SensitiveOperation.ChangeEmail;
            b.Proof = await h.ProofAsync(b.Build(), SensitiveOperation.RemoveAllPasskeys, RiskLevel.R1);
        });
        Add("s10 step-up proof for another command", DecisionReason.S10StepUpInvalid, async (h, b) =>
        {
            b.Operation = SensitiveOperation.ChangeEmail;
            b.Proof = await h.ProofAsync(b.Build(), SensitiveOperation.ChangeEmail, RiskLevel.R1);
            b.CommandId = new CommandId(Guid.NewGuid());
        });
        Add("s10 step-up proof for another owner", DecisionReason.S10StepUpInvalid, async (h, b) =>
        {
            b.Operation = SensitiveOperation.ChangeEmail;
            b.Proof = await h.ProofAsync(b.Build(), SensitiveOperation.ChangeEmail, RiskLevel.R1);
            _ = b.WithActors();
        });
        Add("s10 step-up proof assessed at another risk", DecisionReason.S10StepUpInvalid, async (h, b) =>
        {
            b.Operation = SensitiveOperation.ChangeEmail;
            b.Proof = await h.ProofAsync(b.Build(), SensitiveOperation.ChangeEmail, RiskLevel.R2);
        });
        Add("s10 step-up proof already spent", DecisionReason.S10StepUpInvalid, async (h, b) =>
        {
            b.Operation = SensitiveOperation.ChangeEmail;
            var request = b.Build();
            var proof = await h.ProofAsync(request, SensitiveOperation.ChangeEmail, RiskLevel.R1);
            Assert.True(h.StepUp.TryConsume(proof, request.Actors.Owner, request.CommandId, SensitiveOperation.ChangeEmail, DecisionHarness.AssessmentOf(RiskLevel.R1)));
            b.Proof = proof;
        });
        Add("s10 step-up proof expired", DecisionReason.S10StepUpInvalid, async (h, b) =>
        {
            b.Operation = SensitiveOperation.ChangeEmail;
            b.Proof = await h.ProofAsync(b.Build(), SensitiveOperation.ChangeEmail, RiskLevel.R1);
            h.Clock.Advance(TimeSpan.FromMinutes(2));
        });
        Add("s10 R4 without an enumerated operation", DecisionReason.S10StepUpOperationUnspecified, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R4", "none", "none");
            b.ApprovalId = await h.ApproveAsync(b.Build(), RiskLevel.R4);
        });
        Add("s10 R4 without a step-up proof", DecisionReason.S10StepUpRequired, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R4", "none", "none");
            b.Operation = SensitiveOperation.DeleteAccount;
            b.ApprovalId = await h.ApproveAsync(b.Build(), RiskLevel.R4);
        });
        Add("s10 R4 proof that never carried local presence", DecisionReason.S10LocalPresenceRequired, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R4", "none", "none");
            b.Operation = SensitiveOperation.DeleteAccount;
            b.ApprovalId = await h.ApproveAsync(b.Build(), RiskLevel.R4);
            b.Proof = await h.ProofAsync(b.Build(), SensitiveOperation.DeleteAccount, RiskLevel.R3);
        });
        Add("s10 R4 requested remotely", DecisionReason.S10LocalPresenceRequired, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R4", "none", "none");
            b.Operation = SensitiveOperation.DeleteAccount;
            b.ApprovalId = await h.ApproveAsync(b.Build(), RiskLevel.R4);
            b.Proof = await h.ProofAsync(b.Build(), SensitiveOperation.DeleteAccount, RiskLevel.R4);
            b.Origin = DecisionOrigin.Remote;
        });
        Add("s10 R4 approved from a remote device", DecisionReason.S10LocalPresenceRequired, async (h, b) =>
        {
            h.Descriptor = DecisionHarness.Describe(Capability, "R4", "none", "none");
            b.Operation = SensitiveOperation.DeleteAccount;
            b.ApprovalId = await h.ApproveAsync(b.Build(), RiskLevel.R4, origin: ApprovalOrigin.Remote);
            b.Proof = await h.ProofAsync(b.Build(), SensitiveOperation.DeleteAccount, RiskLevel.R4);
        });

        // Step 11: the owner validates last (the service-decision checks are in DecisionExecutionTests).
        Add("s11 owner refuses", DecisionReason.S11OwnerRefused, (h, _) =>
        {
            h.Owner.Behavior = (_, _) => ValueTask.FromResult(OwnerVerdict.Refused);
            return Task.CompletedTask;
        });
        Add("s11 owner reports the revision changed", DecisionReason.S11OwnerRevisionChanged, (h, _) =>
        {
            h.Owner.Behavior = (_, _) => ValueTask.FromResult(OwnerVerdict.RevisionChanged);
            return Task.CompletedTask;
        });
        Add("s11 owner unknown", DecisionReason.S11Unavailable, (h, _) =>
        {
            h.Owner.Behavior = (_, _) => ValueTask.FromResult(OwnerVerdict.Unknown);
            return Task.CompletedTask;
        });
        Add("s11 owner undefined value", DecisionReason.S11Unavailable, (h, _) =>
        {
            h.Owner.Behavior = (_, _) => ValueTask.FromResult((OwnerVerdict)5);
            return Task.CompletedTask;
        });
        Add("s11 owner throws", DecisionReason.S11Unavailable, (h, _) =>
        {
            h.Owner.Behavior = (_, _) => throw new InvalidOperationException("owner offline");
            return Task.CompletedTask;
        });

        return [.. cases];
    }

    private sealed record RefusalCase(string Name, DecisionReason Reason, Func<DecisionHarness, RequestBuilder, Task> Arrange);
}
