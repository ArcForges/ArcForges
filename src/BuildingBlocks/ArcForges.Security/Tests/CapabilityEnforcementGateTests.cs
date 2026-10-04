// SPDX-License-Identifier: AGPL-3.0-only
using System.Reflection;
using ArcForges.Capabilities;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Errors;
using ArcForges.Security.Approvals;
using ArcForges.Security.CapabilityEnforcement;
using ArcForges.Security.Decisions;
using ArcForges.Security.Leases;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Xunit;
using SdkContext = ArcForges.Sdk.Contracts.V1.FrozenContext;
using SdkInvocation = ArcForges.Sdk.Contracts.V1.Invocation;

namespace ArcForges.Security.Tests;

/// <summary>The adapter on its own: what it takes from the invocation, what it will not take from the host, and how admission is spent.</summary>
public sealed class CapabilityEnforcementGateTests
{
    private static CancellationToken Token => TestContext.Current.CancellationToken;

    private static FrozenContextSnapshot Context(EnforcementWorld w) =>
        FrozenContextSnapshot.Freeze(w.Identity, [new StringValue { Value = "frozen" }], ContextSnapshotBudget.Default);

    private static CapabilityOwnerOperation<string, EnforcedOwnerResult> Owner(EnforcementWorld w, Action<AuthorizedExecution>? seen = null) =>
        w.Gate.Enforce<string, EnforcedOwnerResult>((ticket, _, _, _, _, _) =>
        {
            seen?.Invoke(ticket);
            w.Log.Add("owner-op");
            return ValueTask.FromResult(w.OwnerBehavior());
        });

    private static ValueTask<Outcome<bool>> AuthorizeAsync(EnforcementWorld w, SdkInvocation invocation, FrozenContextSnapshot context) =>
        w.Gate.AuthorizeAsync(w.Registration, invocation, w.Target, context, Token);

    private static ValueTask<Outcome<EnforcedOwnerResult>> RunAsync(
        CapabilityOwnerOperation<string, EnforcedOwnerResult> owner,
        EnforcementWorld w,
        SdkInvocation invocation,
        FrozenContextSnapshot context) =>
        owner(w.Target, invocation, "argument", context, Token);

    [Fact]
    public async Task AnAdmissionIsSpentByTheOwnerSideOfItsOwnInvocationOnlyAndOnlyOnce()
    {
        var w = new EnforcementWorld();
        var invocation = w.Invocation();
        var context = Context(w);
        var owner = Owner(w);

        Assert.True((await AuthorizeAsync(w, invocation, context)).TryGetValue(out var allowed) && allowed);
        var first = await RunAsync(owner, w, invocation, context);
        var second = await RunAsync(owner, w, invocation, context);

        Assert.Equal(OutcomeKind.Success, first.Kind);
        Assert.Equal("perm.capability_denied", Code(second));
        Assert.Equal(1, w.Log.Count("owner-op"));
        Assert.Single(w.Decisions.Recorder.Records);
        Assert.Single(w.Decisions.Audit.Records);
    }

    [Fact]
    public async Task AnOwnerOperationWithoutAnAdmissionIsRefusedAndNeitherTheOwnerNorTheDecisionPipelineIsReached()
    {
        var w = new EnforcementWorld();
        var owner = Owner(w);

        var outcome = await RunAsync(owner, w, w.Invocation(), Context(w));

        Assert.True(outcome.TryGetFailure(out var failure));
        Assert.Equal("perm.capability_denied", failure!.Code);
        Assert.Empty(w.Log.Entries);
        Assert.Empty(w.Decisions.Recorder.Records);
        Assert.Empty(w.Decisions.Audit.Records);
    }

    [Fact]
    public async Task AnAdmissionBelongsToItsOwnFrozenContext()
    {
        var w = new EnforcementWorld();
        var invocation = w.Invocation();
        var context = Context(w);
        var owner = Owner(w);
        Assert.Equal(OutcomeKind.Success, (await AuthorizeAsync(w, invocation, context)).Kind);

        var elsewhere = await RunAsync(owner, w, invocation, Context(w));
        Assert.Equal(OutcomeKind.Failure, elsewhere.Kind);
        Assert.Equal(0, w.Log.Count("owner-op"));

        var own = await RunAsync(owner, w, invocation, context);
        Assert.Equal(OutcomeKind.Success, own.Kind);
    }

    [Fact]
    public async Task AnAdmissionIsSpentOnlyOnTheEffectThatWasAuthorized()
    {
        var w = new EnforcementWorld();
        var command = Guid.NewGuid();
        var invocation = w.Invocation(command: command);
        var context = Context(w);
        var owner = Owner(w);
        Assert.Equal(OutcomeKind.Success, (await AuthorizeAsync(w, invocation, context)).Kind);

        var otherArguments = w.Invocation("a different effect", command: command);
        Assert.Equal(OutcomeKind.Failure, (await RunAsync(owner, w, otherArguments, context)).Kind);

        var otherPrecondition = invocation.Clone();
        otherPrecondition.ExpectedRev = new Revision { Value = 8 };
        Assert.Equal(OutcomeKind.Failure, (await RunAsync(owner, w, otherPrecondition, context)).Kind);

        var elsewhere = new EnforcementWorld();
        var otherTarget = await owner(elsewhere.Target, invocation, "argument", context, Token);
        Assert.Equal(OutcomeKind.Failure, otherTarget.Kind);
        var otherEpoch = new CapabilityTarget(
            new InstanceIdentity(w.Identity.Installation, w.Identity.InstanceId, 2), w.Registration.Descriptor, InstanceHealth.Ready, acceptsWork: true);
        Assert.Equal(OutcomeKind.Failure, (await owner(otherEpoch, invocation, "argument", context, Token)).Kind);

        Assert.Equal(0, w.Log.Count("owner-op"));
        Assert.Empty(w.Decisions.Recorder.Records);
        Assert.Equal(OutcomeKind.Success, (await RunAsync(owner, w, invocation, context)).Kind);
        Assert.Equal(1, w.Log.Count("owner-op"));
    }

    [Fact]
    public async Task AnEvidenceSourceThatNeverAnswersIsBoundedAndRefusesTheInvocation()
    {
        var w = new EnforcementWorld(evidenceTimeout: TimeSpan.FromMilliseconds(100));
        w.Evidence.Behavior = (_, _, _) => new ValueTask<CapabilityEvidence?>(new TaskCompletionSource<CapabilityEvidence?>().Task);

        var started = System.Diagnostics.Stopwatch.StartNew();
        var outcome = await AuthorizeAsync(w, w.Invocation(), Context(w));

        Assert.True(started.Elapsed < TimeSpan.FromSeconds(10));
        Assert.Equal("resource.unavailable", Code(outcome));
        Assert.Empty(w.Decisions.Audit.Records);
        Assert.DoesNotContain("policy", w.Log.Entries);

        var full = await w.InvokeAsync(w.Invocation(), cancellationToken: Token);
        Assert.Equal("resource.unavailable", full.Failure!.Code);
        Assert.Equal(0, w.Records.BeginCalls);
        Assert.Equal(0, w.OwnerRuns);

        using var cancelled = new CancellationTokenSource();
        var slow = new EnforcementWorld(evidenceTimeout: TimeSpan.FromMinutes(1));
        slow.Evidence.Behavior = (_, _, _) => new ValueTask<CapabilityEvidence?>(new TaskCompletionSource<CapabilityEvidence?>().Task);
        var pending = slow.Gate.AuthorizeAsync(slow.Registration, slow.Invocation(), slow.Target, Context(slow), cancelled.Token).AsTask();
        await cancelled.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);

        Assert.Throws<ArgumentOutOfRangeException>(() => new CapabilityEnforcementGate(w.DecisionPipeline, w.Evidence, TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => new CapabilityEnforcementGate(w.DecisionPipeline, w.Evidence, TimeSpan.FromMinutes(6)));
    }

    [Fact]
    public async Task AnAdmissionDoesNotCoverAnotherCommandOrCapabilityAndIsNotBurnedByTheAttempt()
    {
        var w = new EnforcementWorld();
        var invocation = w.Invocation();
        var context = Context(w);
        var owner = Owner(w);
        Assert.Equal(OutcomeKind.Success, (await AuthorizeAsync(w, invocation, context)).Kind);

        var otherCommand = invocation.Clone();
        otherCommand.CommandId = UuidBoundary.ToWire(Guid.NewGuid());
        Assert.Equal(OutcomeKind.Failure, (await RunAsync(owner, w, otherCommand, context)).Kind);

        var otherCapability = invocation.Clone();
        otherCapability.Capability = EnforcementWorld.ListSessionsKey;
        Assert.Equal(OutcomeKind.Failure, (await RunAsync(owner, w, otherCapability, context)).Kind);
        Assert.Equal(0, w.Log.Count("owner-op"));

        Assert.Equal(OutcomeKind.Success, (await RunAsync(owner, w, invocation, context)).Kind);
    }

    [Fact]
    public async Task ARefusedAuthorizationLeavesNoAdmissionBehind()
    {
        var w = new EnforcementWorld();
        w.Decisions.Permissions.Behavior = (_, _) => ValueTask.FromResult<PermissionGrantRecord?>(null);
        var invocation = w.Invocation();
        var context = Context(w);

        var authorization = await AuthorizeAsync(w, invocation, context);
        Assert.True(authorization.TryGetFailure(out var refusal));
        Assert.Equal("perm.capability_denied", refusal!.Code);

        w.Decisions.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(w.Decisions.Grant(request));
        var owner = await RunAsync(Owner(w), w, invocation, context);
        Assert.Equal(OutcomeKind.Failure, owner.Kind);
        Assert.Equal(0, w.Log.Count("owner-op"));
        Assert.Equal(DecisionStep.CapabilityPermission, Assert.Single(w.Decisions.Audit.Records).FailedStep);
    }

    [Fact]
    public async Task ACapabilityKeyThatIsNotTheRegisteredOneIsRefusedWithoutConsultingTheHost()
    {
        var w = new EnforcementWorld();
        var invocation = w.Invocation();
        invocation.Capability = EnforcementWorld.ListSessionsKey;

        var outcome = await AuthorizeAsync(w, invocation, Context(w));

        Assert.True(outcome.TryGetFailure(out var failure));
        Assert.Equal("validation.invalid_request", failure!.Code);
        Assert.Equal(0, w.Evidence.Calls);

        var unset = w.Invocation();
        unset.ClearCapability();
        Assert.Equal("validation.invalid_request", Code(await AuthorizeAsync(w, unset, Context(w))));
        Assert.Equal(0, w.Evidence.Calls);
    }

    [Fact]
    public async Task MalformedIdentitiesInTheInvocationAreRefusedWithoutRunningAnyDecisionStep()
    {
        var w = new EnforcementWorld();
        var shortCommand = w.Invocation();
        shortCommand.CommandId = new Id { Value = ByteString.CopyFrom(1, 2, 3) };
        Assert.Equal("validation.invalid_request", Code(await AuthorizeAsync(w, shortCommand, Context(w))));

        var emptyLease = w.Invocation();
        emptyLease.LeaseId = new Id { Value = ByteString.CopyFrom(new byte[16]) };
        Assert.Equal("validation.invalid_request", Code(await AuthorizeAsync(w, emptyLease, Context(w))));

        var badApproval = w.Invocation();
        badApproval.ApprovalId = new Id { Value = ByteString.CopyFrom(9) };
        Assert.Equal("validation.invalid_request", Code(await AuthorizeAsync(w, badApproval, Context(w))));

        Assert.Empty(w.Decisions.Audit.Records);
        Assert.DoesNotContain("policy", w.Log.Entries);
    }

    [Fact]
    public async Task TheEffectDigestIsStableForTheSameRequestAndChangesWithWhatIsAsked()
    {
        var w = new EnforcementWorld();
        var digests = new List<string>();
        w.Decisions.Permissions.Behavior = (request, _) =>
        {
            digests.Add(request.EffectSha256);
            return ValueTask.FromResult<PermissionGrantRecord?>(w.Decisions.Grant(request));
        };
        var command = Guid.NewGuid();
        var baseline = w.Invocation(command: command);
        var retried = baseline.Clone();
        retried.InvocationId = ArcForges.Foundation.Execution.InvocationId.New().ToWire();
        retried.Context = new SdkContext { ProfileVersion = "profile.8" };
        var other = w.Invocation("other argument", command: command);
        var precondition = baseline.Clone();
        precondition.ExpectedRev = new Revision { Value = 8 };

        foreach (var invocation in new[] { baseline, retried, other, precondition })
        {
            _ = await AuthorizeAsync(w, invocation, Context(w));
        }

        Assert.Equal(digests[0], digests[1]);
        Assert.NotEqual(digests[0], digests[2]);
        Assert.NotEqual(digests[0], digests[3]);
        Assert.All(digests, digest => Assert.Matches("^[0-9A-F]{64}$", digest));

        var elsewhere = new EnforcementWorld();
        var elsewhereDigests = new List<string>();
        elsewhere.Decisions.Permissions.Behavior = (request, _) =>
        {
            elsewhereDigests.Add(request.EffectSha256);
            return ValueTask.FromResult<PermissionGrantRecord?>(elsewhere.Decisions.Grant(request));
        };
        _ = await AuthorizeAsync(elsewhere, elsewhere.Invocation(command: command), Context(elsewhere));
        Assert.NotEqual(digests[0], elsewhereDigests[0]);
    }

    [Fact]
    public async Task TheEffectDigestNamesTheExactTargetInstanceAndEpoch()
    {
        var command = Guid.NewGuid();
        var baseline = new EnforcementWorld();
        var same = new EnforcementWorld(identity: baseline.Identity);
        var nextEpoch = new EnforcementWorld(identity: new InstanceIdentity(baseline.Identity.Installation, baseline.Identity.InstanceId, 2));
        var otherInstance = new EnforcementWorld(identity: new InstanceIdentity(baseline.Identity.Installation, new InstanceId(Guid.NewGuid()), 1));
        var installation = baseline.Identity.Installation;
        var otherInstallation = new EnforcementWorld(identity: new InstanceIdentity(
            new InstallationIdentity(installation.App, installation.DeviceId, new InstallationId(Guid.NewGuid())),
            baseline.Identity.InstanceId,
            1));
        var otherDevice = new EnforcementWorld(identity: new InstanceIdentity(
            new InstallationIdentity(installation.App, new DeviceId(Guid.NewGuid()), installation.InstallationId),
            baseline.Identity.InstanceId,
            1));

        var digest = await DigestAsync(baseline, command);

        Assert.Equal(digest, await DigestAsync(same, command));
        Assert.NotEqual(digest, await DigestAsync(nextEpoch, command));
        Assert.NotEqual(digest, await DigestAsync(otherInstance, command));
        Assert.NotEqual(digest, await DigestAsync(otherInstallation, command));
        Assert.NotEqual(digest, await DigestAsync(otherDevice, command));
    }

    [Fact]
    public async Task TheEffectDigestDoesNotChangeWithTheLeaseOrTheApprovalThatAreClaimedAlongsideIt()
    {
        var w = new EnforcementWorld();
        var command = Guid.NewGuid();
        var digests = new List<string>();
        w.Decisions.Permissions.Behavior = (request, _) =>
        {
            digests.Add(request.EffectSha256);
            return ValueTask.FromResult<PermissionGrantRecord?>(w.Decisions.Grant(request));
        };

        foreach (var invocation in new[]
        {
            w.Invocation(command: command),
            w.Invocation(command: command, lease: CapabilityLeaseId.New()),
            w.Invocation(command: command, approval: Guid.NewGuid()),
        })
        {
            _ = await AuthorizeAsync(w, invocation, Context(w));
        }

        Assert.Equal(3, digests.Count);
        Assert.Single(digests.Distinct());
    }

    private static async Task<string> DigestAsync(EnforcementWorld w, Guid command)
    {
        string? digest = null;
        w.Decisions.Permissions.Behavior = (request, _) =>
        {
            digest = request.EffectSha256;
            return ValueTask.FromResult<PermissionGrantRecord?>(w.Decisions.Grant(request));
        };
        _ = await AuthorizeAsync(w, w.Invocation(command: command), Context(w));
        return digest!;
    }

    [Fact]
    public async Task TheCommandApprovalAndLeaseOfTheDecisionComeFromTheInvocationNotFromTheHost()
    {
        var w = new EnforcementWorld();
        DecisionRequest? seen = null;
        w.Decisions.Permissions.Behavior = (request, _) =>
        {
            seen = request;
            return ValueTask.FromResult<PermissionGrantRecord?>(w.Decisions.Grant(request));
        };
        w.Evidence.Behavior = (_, _, _) => ValueTask.FromResult<CapabilityEvidence?>(w.DefaultEvidence(w.AgentChain()));
        var lease = CapabilityLeaseId.New();
        var approval = Guid.NewGuid();
        var command = Guid.NewGuid();
        var invocation = w.Invocation(lease: lease, approval: approval, command: command);

        _ = await AuthorizeAsync(w, invocation, Context(w));

        Assert.NotNull(seen);
        Assert.Equal(new CommandId(command), seen!.CommandId);
        Assert.Equal(approval, seen.ApprovalId);
        Assert.Equal(lease, seen.Lease);
        Assert.Equal(EnforcementWorld.GetSession, seen.CapabilityKey);
    }

    [Fact]
    public async Task TheHostIsHandedACopyOfTheInvocationSoItCannotChangeWhatIsAuthorized()
    {
        var w = new EnforcementWorld();
        var digests = new List<string>();
        w.Decisions.Permissions.Behavior = (request, _) =>
        {
            digests.Add(request.EffectSha256);
            return ValueTask.FromResult<PermissionGrantRecord?>(w.Decisions.Grant(request));
        };
        var command = Guid.NewGuid();
        var invocation = w.Invocation(command: command);
        var untouched = invocation.Clone();
        w.Evidence.Behavior = (_, seen, _) =>
        {
            seen.Arguments.Value.Text = "rewritten by the host";
            return ValueTask.FromResult<CapabilityEvidence?>(w.DefaultEvidence());
        };

        _ = await AuthorizeAsync(w, invocation, Context(w));
        w.Evidence.Behavior = (_, _, _) => ValueTask.FromResult<CapabilityEvidence?>(w.DefaultEvidence());
        _ = await AuthorizeAsync(w, untouched, Context(w));

        Assert.Equal("argument", invocation.Arguments.Value.Text);
        Assert.Equal(digests[0], digests[1]);
    }

    [Fact]
    public async Task ConcurrentInvocationsEachSpendOnlyTheirOwnAdmission()
    {
        var w = new EnforcementWorld();
        var invocations = Enumerable.Range(0, 16).Select(index => w.Invocation($"argument-{index}")).ToArray();

        var outcomes = await Task.WhenAll(invocations.Select(invocation => w.InvokeAsync(invocation, cancellationToken: Token).AsTask()));

        Assert.All(outcomes, outcome => Assert.Equal(OutcomeKind.Success, outcome.Kind));
        Assert.Equal(16, w.OwnerRuns);
        Assert.Equal(16, w.Decisions.Audit.Records.Count);
        Assert.Equal(16, w.Decisions.Audit.Records.Select(record => record.Correlation).Distinct().Count());
        Assert.Equal(16, w.Decisions.Recorder.Records.Count);
    }

    [Fact]
    public void OnlyTheGateAndTheTicketBoundDelegateLeadToAnOwnerOperation()
    {
        var methods = typeof(CapabilityEnforcementGate)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(method => method.Name)
            .Order()
            .ToArray();
        Assert.Equal([nameof(CapabilityEnforcementGate.AuthorizeAsync), nameof(CapabilityEnforcementGate.Enforce)], methods);

        Assert.Empty(typeof(AuthorizedExecution).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(
            typeof(AuthorizedExecution).GetMethods(BindingFlags.Public | BindingFlags.Static),
            method => method.ReturnType == typeof(AuthorizedExecution));
        var invoke = typeof(EnforcedOwnerOperation<string, string>).GetMethod("Invoke")!;
        Assert.Equal(typeof(AuthorizedExecution), invoke.GetParameters()[0].ParameterType);
    }

    [Fact]
    public void ConstructorsAndEntryPointsRefuseMissingParts()
    {
        var w = new EnforcementWorld();
        Assert.Throws<ArgumentNullException>(() => new CapabilityEnforcementGate(null!, w.Evidence));
        Assert.Throws<ArgumentNullException>(() => new CapabilityEnforcementGate(w.DecisionPipeline, null!));
        Assert.Throws<ArgumentNullException>(() => w.Gate.Enforce<string, string>(null!));
        Assert.Throws<ArgumentNullException>(() => new RegistryCapabilityCatalogue(null!));

        var chain = w.DirectChain();
        var scope = w.Leases.Scope;
        var resource = new ResourceReference("resource/1", "revision:1");
        Assert.Throws<ArgumentNullException>(() => new CapabilityEvidence(null!, scope, resource, DecisionOrigin.Local, w.Decisions.Transport));
        Assert.Throws<ArgumentNullException>(() => new CapabilityEvidence(chain, null!, resource, DecisionOrigin.Local, w.Decisions.Transport));
        Assert.Throws<ArgumentNullException>(() => new CapabilityEvidence(chain, scope, null!, DecisionOrigin.Local, w.Decisions.Transport));
        Assert.Throws<ArgumentNullException>(() => new CapabilityEvidence(chain, scope, resource, DecisionOrigin.Local, null!));
        var evidence = new CapabilityEvidence(chain, scope, resource, DecisionOrigin.Remote, w.Decisions.Transport, egressDestination: "https://a.example");
        Assert.Equal(DecisionOrigin.Remote, evidence.Origin);
        Assert.Equal("https://a.example", evidence.EgressDestination);
        Assert.Null(evidence.DeclaredFacts);
        Assert.Null(evidence.SecretUseKey);
        Assert.Null(evidence.StepUpProof);
        Assert.Equal(SensitiveOperation.None, evidence.SensitiveOperation);
    }

    [Fact]
    public async Task TheRegistryCatalogueAnswersOnlyWithTheRegisteredDescriptorOfAnExactKey()
    {
        var registry = CapabilityRegistry.CreateInitial();
        var catalogue = new RegistryCapabilityCatalogue(registry);

        foreach (var registration in registry.Registrations)
        {
            var found = await catalogue.FindAsync(registration.Key, Token);
            Assert.Equal(registration.Descriptor, found);
        }

        var descriptor = await catalogue.FindAsync(EnforcementWorld.GetSession, Token);
        descriptor!.Risk = "R0";
        Assert.Equal("R1", (await catalogue.FindAsync(EnforcementWorld.GetSession, Token))!.Risk);

        Assert.Null(await catalogue.FindAsync("IScopeOperations.Missing", Token));
        Assert.Null(await catalogue.FindAsync("iscopeoperations.getsession", Token));
        Assert.Null(await catalogue.FindAsync(" ", Token));
        Assert.Null(await catalogue.FindAsync(string.Empty, Token));
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        await Assert.ThrowsAsync<OperationCanceledException>(async () => await catalogue.FindAsync(EnforcementWorld.GetSession, cancelled.Token));
    }

    [Fact]
    public async Task ACapabilityTheRegistryDoesNotHoldIsUnknownToTheDecisionPipeline()
    {
        var w = new EnforcementWorld();
        var request = new DecisionRequest(
            w.DirectChain(), "IScopeOperations.Missing", w.Leases.Scope, new CommandId(Guid.NewGuid()),
            new ResourceReference("resource/1", "revision:1"), DecisionHarness.Sha(), DecisionOrigin.Local, w.Decisions.Transport);

        var decision = await w.DecisionPipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, request, Token);

        Assert.Equal(DecisionReason.S01CapabilityUnknown, decision.Reason);
        Assert.Equal("validation.invalid_request", decision.RegisteredCode);
    }

    private static string? Code<T>(Outcome<T> outcome) => outcome.TryGetFailure(out var failure) ? failure!.Code : null;
}
