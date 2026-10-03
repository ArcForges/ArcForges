// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Execution;
using ArcForges.Security.Decisions;
using ArcForges.Security.Leases;
using Xunit;
using Instant = ArcForges.Foundation.Instant;

namespace ArcForges.Security.Tests;

public sealed class LeaseModelTests
{
    private static readonly Instant Start = new(1_790_000_000, 0);

    [Fact]
    public void ALeaseIdentityIsGuidBackedNonEmptyAndNeverDefault()
    {
        var guid = Guid.NewGuid();
        var id = new CapabilityLeaseId(guid);

        Assert.Equal(guid, id.Value);
        Assert.True(id.IsValid);
        Assert.False(default(CapabilityLeaseId).IsValid);
        Assert.Equal(id, new CapabilityLeaseId(guid));
        Assert.NotEqual(id, new CapabilityLeaseId(Guid.NewGuid()));
        _ = Assert.Throws<ArgumentException>(() => new CapabilityLeaseId(Guid.Empty));
        var created = CapabilityLeaseId.New();
        Assert.True(created.IsValid);
        Assert.NotEqual(created, CapabilityLeaseId.New());
    }

    [Theory]
    [InlineData(ActorKind.Agent, true)]
    [InlineData(ActorKind.Extension, true)]
    [InlineData(ActorKind.Automation, false)]
    [InlineData(ActorKind.InternalService, false)]
    public void OnlyAnAgentOrAnExtensionCanHoldALease(ActorKind kind, bool canHold)
    {
        var holder = new LeaseHolder(kind, Guid.NewGuid());

        Assert.Equal(canHold, holder.CanHoldLease);
    }

    [Fact]
    public void AHolderNamesADefinedKindAndAnExactIdentity()
    {
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new LeaseHolder(ActorKind.None, Guid.NewGuid()));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new LeaseHolder((ActorKind)77, Guid.NewGuid()));
        _ = Assert.Throws<ArgumentException>(() => new LeaseHolder(ActorKind.Agent, Guid.Empty));
        var actor = Guid.NewGuid();
        Assert.Equal(new LeaseHolder(ActorKind.Agent, actor), new LeaseHolder(ActorKind.Agent, actor));
        Assert.NotEqual(new LeaseHolder(ActorKind.Agent, actor), new LeaseHolder(ActorKind.Extension, actor));
        Assert.NotEqual(new LeaseHolder(ActorKind.Agent, actor), new LeaseHolder(ActorKind.Agent, Guid.NewGuid()));
    }

    [Fact]
    public void ALeaseUseRequiresEveryFieldAndAValidLease()
    {
        var h = new LeaseHarness();
        var holder = LeaseHarness.HolderOf(h.Extension);
        var id = CapabilityLeaseId.New();

        _ = Assert.Throws<ArgumentException>(() => new LeaseUse(default, h.Owner, h.Scope, holder, "c", "r"));
        _ = Assert.Throws<ArgumentNullException>(() => new LeaseUse(id, null!, h.Scope, holder, "c", "r"));
        _ = Assert.Throws<ArgumentNullException>(() => new LeaseUse(id, h.Owner, null!, holder, "c", "r"));
        _ = Assert.Throws<ArgumentNullException>(() => new LeaseUse(id, h.Owner, h.Scope, null!, "c", "r"));
        _ = Assert.Throws<ArgumentException>(() => new LeaseUse(id, h.Owner, h.Scope, holder, " ", "r"));
        _ = Assert.Throws<ArgumentException>(() => new LeaseUse(id, h.Owner, h.Scope, holder, "c", ""));
        _ = Assert.Throws<ArgumentException>(() => new LeaseUse(id, h.Owner, h.Scope, holder, new string('c', 257), "r"));
        _ = Assert.Throws<ArgumentException>(() => new LeaseUse(id, h.Owner, h.Scope, holder, "c", new string('r', 513)));
        var use = new LeaseUse(id, h.Owner, h.Scope, holder, new string('c', 256), new string('r', 512));
        Assert.Equal(id, use.Lease);
    }

    [Fact]
    public void ARequestValidatesItsFieldsAndNamesAFreshIdentity()
    {
        var h = new LeaseHarness();
        var holder = LeaseHarness.HolderOf(h.Extension);
        var chain = h.DirectChain();
        string[] resources = ["a"];

        LeaseRequest Make(
            ActorChain? issuedBy = null,
            DecisionScope? scope = null,
            TaskId? task = null,
            LeaseHolder? leaseHolder = null,
            string capability = "c",
            IEnumerable<string>? resourceIds = null,
            RiskLevel risk = RiskLevel.R1,
            DecisionOrigin origin = DecisionOrigin.Local,
            LeaseIssueBasis basis = LeaseIssueBasis.PolicyAllowed) =>
            new(issuedBy ?? chain, scope ?? h.Scope, task ?? h.Task, leaseHolder ?? holder, capability, resourceIds ?? resources, risk, origin, basis, TimeSpan.FromMinutes(1));

        var first = Make();
        var second = Make();
        Assert.True(first.Id.IsValid);
        Assert.NotEqual(first.Id, second.Id);
        _ = Assert.Throws<ArgumentNullException>(() => new LeaseRequest(null!, h.Scope, h.Task, holder, "c", resources, RiskLevel.R1, DecisionOrigin.Local, LeaseIssueBasis.PolicyAllowed, TimeSpan.FromMinutes(1)));
        _ = Assert.Throws<ArgumentNullException>(() => new LeaseRequest(chain, null!, h.Task, holder, "c", resources, RiskLevel.R1, DecisionOrigin.Local, LeaseIssueBasis.PolicyAllowed, TimeSpan.FromMinutes(1)));
        _ = Assert.Throws<ArgumentNullException>(() => new LeaseRequest(chain, h.Scope, h.Task, null!, "c", resources, RiskLevel.R1, DecisionOrigin.Local, LeaseIssueBasis.PolicyAllowed, TimeSpan.FromMinutes(1)));
        _ = Assert.Throws<ArgumentNullException>(() => new LeaseRequest(chain, h.Scope, h.Task, holder, "c", null!, RiskLevel.R1, DecisionOrigin.Local, LeaseIssueBasis.PolicyAllowed, TimeSpan.FromMinutes(1)));
        _ = Assert.Throws<ArgumentException>(() => Make(task: default(TaskId)));
        _ = Assert.Throws<ArgumentException>(() => Make(capability: ""));
        _ = Assert.Throws<ArgumentException>(() => Make(resourceIds: []));
        _ = Assert.Throws<ArgumentException>(() => Make(resourceIds: ["a", "a"]));
        _ = Assert.Throws<ArgumentException>(() => Make(resourceIds: [""]));
        _ = Assert.Throws<ArgumentException>(() => Make(resourceIds: Enumerable.Range(0, CapabilityLease.MaximumResources + 1).Select(index => $"r{index}")));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => Make(risk: (RiskLevel)9));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => Make(origin: DecisionOrigin.None));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => Make(origin: (DecisionOrigin)8));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => Make(basis: LeaseIssueBasis.None));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => Make(basis: (LeaseIssueBasis)8));
        Assert.Equal(CapabilityLease.MaximumResources, Make(resourceIds: Enumerable.Range(0, CapabilityLease.MaximumResources).Select(index => $"r{index}")).ResourceIds.Count);
    }

    [Fact]
    public void AResourceSetIsSortedUniqueAndImmuneToLaterChangesOfItsSource()
    {
        var h = new LeaseHarness();
        var source = new List<string> { "b/2", "a/1", "c/3" };
        var request = h.Request(resources: source);
        source.Add("d/4");
        source[0] = "changed";

        Assert.Equal(["a/1", "b/2", "c/3"], request.ResourceIds);
        var lease = new CapabilityLease(
            CapabilityLeaseId.New(), h.Owner, h.Scope, h.Task, LeaseHarness.HolderOf(h.Extension), "c", request.ResourceIds, RiskLevel.R1,
            DecisionOrigin.Local, LeaseIssueBasis.UserApproved, h.DirectChain(), Start, At(1), LeaseState.Active, 1);
        Assert.Equal(["a/1", "b/2", "c/3"], lease.ResourceIds);
        Assert.Throws<NotSupportedException>(() => ((IList<string>)lease.ResourceIds).Add("x"));
    }

    [Fact]
    public void ALeaseLivesForAPositiveTimeOfAtMostTwentyFourHoursToTheNanosecond()
    {
        var h = new LeaseHarness();
        CapabilityLease Make(Instant expires) => new(
            CapabilityLeaseId.New(), h.Owner, h.Scope, h.Task, LeaseHarness.HolderOf(h.Extension), "c", ["r"], RiskLevel.R1,
            DecisionOrigin.Local, LeaseIssueBasis.UserApproved, h.DirectChain(), Start, expires, LeaseState.Active, 1);

        Assert.Equal(TimeSpan.FromHours(24), CapabilityLease.AbsoluteMaximumLifetime);
        _ = Make(new Instant(Start.UnixSeconds + (24 * 3600), 0));
        _ = Make(new Instant(Start.UnixSeconds, 1));
        _ = Assert.Throws<ArgumentException>(() => Make(new Instant(Start.UnixSeconds + (24 * 3600), 1)));
        _ = Assert.Throws<ArgumentException>(() => Make(Start));
        _ = Assert.Throws<ArgumentException>(() => Make(new Instant(Start.UnixSeconds - 1, 0)));
    }

    [Fact]
    public void ALeaseIsBoundToTheDelegatorsRealmAndAHolderThatCanHoldOne()
    {
        var h = new LeaseHarness();
        CapabilityLease Make(HumanPrincipal? owner = null, DecisionScope? scope = null, LeaseHolder? holder = null, ActorChain? issuedBy = null) => new(
            CapabilityLeaseId.New(), owner ?? h.Owner, scope ?? h.Scope, h.Task, holder ?? LeaseHarness.HolderOf(h.Extension), "c", ["r"],
            RiskLevel.R1, DecisionOrigin.Local, LeaseIssueBasis.UserApproved, issuedBy ?? h.DirectChain(), Start, At(1), LeaseState.Active, 1);

        var other = new HumanPrincipal(h.Owner.Realm, new UserId(Guid.NewGuid()), HumanIdentityKind.CloudUser);
        _ = Assert.Throws<ArgumentException>(() => Make(owner: other));
        _ = Assert.Throws<ArgumentException>(() => Make(scope: new DecisionScope(new RealmId(Guid.NewGuid()), null)));
        _ = Assert.Throws<ArgumentException>(() => Make(holder: new LeaseHolder(ActorKind.Automation, Guid.NewGuid())));
        _ = Assert.Throws<ArgumentException>(() => Make(holder: new LeaseHolder(ActorKind.InternalService, Guid.NewGuid())));
        _ = Make(holder: new LeaseHolder(ActorKind.Agent, Guid.NewGuid()));
        _ = Make(scope: new DecisionScope(h.Owner.Realm, null));
    }

    [Fact]
    public void ALeasesEndMatchesItsStateAndIsRecordedOnlyOnceEnded()
    {
        var h = new LeaseHarness();
        CapabilityLease Make(LeaseState state, Instant? ended = null, LeaseRevocationReason reason = LeaseRevocationReason.None, bool recorded = false, long version = 1) => new(
            CapabilityLeaseId.New(), h.Owner, h.Scope, h.Task, LeaseHarness.HolderOf(h.Extension), "c", ["r"], RiskLevel.R1,
            DecisionOrigin.Local, LeaseIssueBasis.UserApproved, h.DirectChain(), Start, At(60), state, version, ended, reason, recorded);
        var during = At(30);

        _ = Make(LeaseState.Active);
        _ = Make(LeaseState.Revoked, during, LeaseRevocationReason.OwnerRevoked);
        _ = Make(LeaseState.Expired, At(60));
        _ = Make(LeaseState.TaskEnded, during, recorded: true);
        _ = Assert.Throws<ArgumentException>(() => Make(LeaseState.Active, during));
        _ = Assert.Throws<ArgumentException>(() => Make(LeaseState.Active, recorded: true));
        _ = Assert.Throws<ArgumentException>(() => Make(LeaseState.Revoked, during));
        _ = Assert.Throws<ArgumentException>(() => Make(LeaseState.Expired, during, LeaseRevocationReason.OwnerRevoked));
        _ = Assert.Throws<ArgumentException>(() => Make(LeaseState.TaskEnded, during, LeaseRevocationReason.PolicyDenied));
        _ = Assert.Throws<ArgumentException>(() => Make(LeaseState.Expired));
        _ = Assert.Throws<ArgumentException>(() => Make(LeaseState.Revoked, new Instant(Start.UnixSeconds - 1, 0), LeaseRevocationReason.OwnerRevoked));
        _ = Assert.Throws<ArgumentException>(() => Make(LeaseState.None));
        _ = Assert.Throws<ArgumentException>(() => Make((LeaseState)9));
        _ = Assert.Throws<ArgumentException>(() => Make(LeaseState.Active, version: 0));
        _ = Assert.Throws<ArgumentException>(() => Make(LeaseState.Revoked, during, (LeaseRevocationReason)9));
    }

    [Fact]
    public void ALeaseRefusesAnEmptyIdentityTaskAndUndefinedEnumerations()
    {
        var h = new LeaseHarness();
        CapabilityLease Make(
            CapabilityLeaseId? id = null,
            TaskId? task = null,
            RiskLevel risk = RiskLevel.R1,
            DecisionOrigin origin = DecisionOrigin.Local,
            LeaseIssueBasis basis = LeaseIssueBasis.UserApproved,
            string capability = "c") => new(
            id ?? CapabilityLeaseId.New(), h.Owner, h.Scope, task ?? h.Task, LeaseHarness.HolderOf(h.Extension), capability, ["r"], risk, origin, basis,
            h.DirectChain(), Start, At(1), LeaseState.Active, 1);

        _ = Make();
        _ = Assert.Throws<ArgumentException>(() => Make(id: default(CapabilityLeaseId)));
        _ = Assert.Throws<ArgumentException>(() => Make(task: default(TaskId)));
        _ = Assert.Throws<ArgumentException>(() => Make(risk: (RiskLevel)9));
        _ = Assert.Throws<ArgumentException>(() => Make(origin: DecisionOrigin.None));
        _ = Assert.Throws<ArgumentException>(() => Make(basis: LeaseIssueBasis.None));
        _ = Assert.Throws<ArgumentException>(() => Make(capability: ""));
        _ = Assert.Throws<ArgumentNullException>(() => new CapabilityLease(
            CapabilityLeaseId.New(), null!, h.Scope, h.Task, LeaseHarness.HolderOf(h.Extension), "c", ["r"], RiskLevel.R1, DecisionOrigin.Local,
            LeaseIssueBasis.UserApproved, h.DirectChain(), Start, At(1), LeaseState.Active, 1));
        _ = Assert.Throws<ArgumentNullException>(() => new CapabilityLease(
            CapabilityLeaseId.New(), h.Owner, h.Scope, h.Task, LeaseHarness.HolderOf(h.Extension), "c", ["r"], RiskLevel.R1, DecisionOrigin.Local,
            LeaseIssueBasis.UserApproved, null!, Start, At(1), LeaseState.Active, 1));
    }

    [Fact]
    public void ALifecycleFactMustMatchTheStateOfItsLease()
    {
        var h = new LeaseHarness();
        CapabilityLease Make(LeaseState state, LeaseRevocationReason reason = LeaseRevocationReason.None) => new(
            CapabilityLeaseId.New(), h.Owner, h.Scope, h.Task, LeaseHarness.HolderOf(h.Extension), "c", ["r"], RiskLevel.R1,
            DecisionOrigin.Local, LeaseIssueBasis.UserApproved, h.DirectChain(), Start, At(60), state, 2,
            state == LeaseState.Active ? null : At(30), reason);

        var active = Make(LeaseState.Active);
        var revoked = Make(LeaseState.Revoked, LeaseRevocationReason.OwnerRevoked);
        var expired = Make(LeaseState.Expired);
        var taskEnded = Make(LeaseState.TaskEnded);
        Assert.Equal(active.Id, new CapabilityLeaseEvent(LeaseEventKind.Issued, active, Start).LeaseId);
        Assert.Equal(LeaseEventKind.Revoked, new CapabilityLeaseEvent(LeaseEventKind.Revoked, revoked, At(30)).Kind);
        Assert.Equal(LeaseEventKind.Expired, new CapabilityLeaseEvent(LeaseEventKind.Expired, expired, At(30)).Kind);
        Assert.Equal(LeaseEventKind.TaskEnded, new CapabilityLeaseEvent(LeaseEventKind.TaskEnded, taskEnded, At(30)).Kind);
        _ = Assert.Throws<ArgumentException>(() => new CapabilityLeaseEvent(LeaseEventKind.None, active, Start));
        _ = Assert.Throws<ArgumentException>(() => new CapabilityLeaseEvent(LeaseEventKind.Revoked, active, Start));
        _ = Assert.Throws<ArgumentException>(() => new CapabilityLeaseEvent(LeaseEventKind.Issued, revoked, Start));
        _ = Assert.Throws<ArgumentException>(() => new CapabilityLeaseEvent(LeaseEventKind.Expired, revoked, Start));
        _ = Assert.Throws<ArgumentException>(() => new CapabilityLeaseEvent(LeaseEventKind.TaskEnded, expired, Start));
        _ = Assert.Throws<ArgumentException>(() => new CapabilityLeaseEvent((LeaseEventKind)9, active, Start));
        _ = Assert.Throws<ArgumentNullException>(() => new CapabilityLeaseEvent(LeaseEventKind.Issued, null!, Start));
    }

    private static Instant At(int seconds) => new(Start.UnixSeconds + seconds, 0);
}
