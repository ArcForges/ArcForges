// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Capabilities;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Errors;
using ArcForges.Security.CapabilityEnforcement;
using ArcForges.Security.Decisions;
using Google.Protobuf;
using Xunit;
using SdkInvocation = ArcForges.Sdk.Contracts.V1.Invocation;

namespace ArcForges.Security.Tests;

/// <summary>Compatibility vectors and actual approval composition for the shared readonly effect binding.</summary>
public sealed class CapabilityApprovalBindingTests
{
    private static CancellationToken Token => TestContext.Current.CancellationToken;

    private static InstanceIdentity Identity() => new(
        new InstallationIdentity(AppIdentity.ArcScope,
            new DeviceId(Guid.Parse("10000000-0000-0000-0000-000000000001")),
            new InstallationId(Guid.Parse("20000000-0000-0000-0000-000000000002"))),
        new InstanceId(Guid.Parse("30000000-0000-0000-0000-000000000003")), 1);

    private static string Digest(SdkInvocation invocation, CapabilityTarget target) =>
        CapabilityEnforcementGate.ComputeEffectSha256(invocation.Capability, invocation, target);

    [Fact]
    public void AcceptedByteRepresentationHasAFixedCompatibilityVector()
    {
        var world = new EnforcementWorld(identity: Identity());
        var invocation = new SdkInvocation
        {
            CommandId = UuidBoundary.ToWire(Guid.Parse("40000000-0000-0000-0000-000000000004")),
            Capability = EnforcementWorld.GetSession,
        };

        // Fixed protobuf bytes plus the accepted BinaryWriter framing, UUID order and little-endian epoch/length.
        Assert.Equal("12120A10400000000000000000000000000000041A1B4953636F70654F7065726174696F6E732E47657453657373696F6E",
            Convert.ToHexString(invocation.ToByteArray()));
        Assert.Equal("CEF47AA1708B2B90421E57493F6ABF6EB071C8FD141409DA3392C5150C4DA361", Digest(invocation, world.Target));
    }

    [Theory]
    [InlineData("product")]
    [InlineData("device")]
    [InlineData("installation")]
    [InlineData("instance")]
    [InlineData("epoch")]
    public void EveryExactTargetIdentityComponentChangesTheBinding(string changed)
    {
        var identity = Identity();
        var world = new EnforcementWorld(identity: identity);
        var installation = new InstallationIdentity(
            changed == "product" ? AppIdentity.Companion : identity.Installation.App,
            changed == "device" ? new DeviceId(Guid.NewGuid()) : identity.Installation.DeviceId,
            changed == "installation" ? new InstallationId(Guid.NewGuid()) : identity.Installation.InstallationId);
        var other = new CapabilityTarget(new InstanceIdentity(installation,
            changed == "instance" ? new InstanceId(Guid.NewGuid()) : identity.InstanceId,
            changed == "epoch" ? 2UL : identity.Epoch), world.Registration.Descriptor, InstanceHealth.Ready, true);
        var invocation = world.Invocation();

        Assert.NotEqual(Digest(invocation, world.Target), Digest(invocation, other));
    }

    [Theory]
    [InlineData("capability")]
    [InlineData("command")]
    [InlineData("arguments")]
    [InlineData("revision")]
    [InlineData("native-precondition")]
    [InlineData("unknown")]
    public void EveryEffectComponentIncludingUnknownWireFieldsChangesTheBinding(string changed)
    {
        var world = new EnforcementWorld();
        var invocation = world.Invocation();
        var other = invocation.Clone();
        switch (changed)
        {
            case "capability": other.Capability = EnforcementWorld.ListSessionsKey; break;
            case "command": other.CommandId = UuidBoundary.ToWire(Guid.NewGuid()); break;
            case "arguments": other.Arguments.Value.Text = "another effect"; break;
            case "revision": other.ExpectedRev.Value = 8; break;
            case "native-precondition": other.ExpectedNative = new NativeContentRev { Value = 7 }; break;
            case "unknown": other = SdkInvocation.Parser.ParseFrom([.. other.ToByteArray(), 0xA0, 0x06, 0x01]); break;
            default: throw new ArgumentOutOfRangeException(nameof(changed));
        }

        Assert.NotEqual(Digest(invocation, world.Target), Digest(other, world.Target));
    }

    [Fact]
    public void ExcludedRequestMetadataDoesNotChangeTheBindingOrMutateTheMessage()
    {
        var world = new EnforcementWorld();
        var invocation = world.Invocation();
        var original = invocation.ToByteArray();
        var digest = Digest(invocation, world.Target);
        var other = invocation.Clone();
        other.InvocationId = UuidBoundary.ToWire(Guid.NewGuid());
        other.Context.ProfileVersion = "another profile";
        other.Context.PermissionsVersion = "another permission snapshot";
        other.ApprovalId = UuidBoundary.ToWire(Guid.NewGuid());
        other.LeaseId = UuidBoundary.ToWire(Guid.NewGuid());
        var otherOriginal = other.ToByteArray();

        Assert.Equal(digest, Digest(other, world.Target));
        Assert.Equal(original, invocation.ToByteArray());
        Assert.Equal(otherOriginal, other.ToByteArray());
        other.InvocationId = null;
        other.Context = null;
        other.ApprovalId = null;
        other.LeaseId = null;
        Assert.Equal(digest, Digest(other, world.Target));
    }

    [Fact]
    public void InvalidInputsCannotProduceAnApprovalBinding()
    {
        var world = new EnforcementWorld();
        var invocation = world.Invocation();
        Assert.Throws<ArgumentNullException>(() => CapabilityEnforcementGate.ComputeEffectSha256(null!, invocation, world.Target));
        Assert.Throws<ArgumentNullException>(() => CapabilityEnforcementGate.ComputeEffectSha256(invocation.Capability, null!, world.Target));
        Assert.Throws<ArgumentNullException>(() => CapabilityEnforcementGate.ComputeEffectSha256(invocation.Capability, invocation, null!));
        Assert.Throws<ArgumentException>(() => CapabilityEnforcementGate.ComputeEffectSha256(" ", invocation, world.Target));
        Assert.Throws<ArgumentException>(() => CapabilityEnforcementGate.ComputeEffectSha256(EnforcementWorld.ListSessionsKey, invocation, world.Target));
        var unset = invocation.Clone();
        unset.ClearCapability();
        Assert.Throws<ArgumentException>(() => CapabilityEnforcementGate.ComputeEffectSha256(invocation.Capability, unset, world.Target));

        foreach (var length in new[] { 0, 1, 15, 16, 17 })
        {
            var malformed = invocation.Clone();
            malformed.CommandId = new Id { Value = ByteString.CopyFrom(new byte[length]) };
            Assert.Throws<ArgumentException>(() => Digest(malformed, world.Target));
        }
        var missing = invocation.Clone();
        missing.CommandId = null;
        Assert.Throws<ArgumentNullException>(() => Digest(missing, world.Target));
    }

    [Fact]
    public async Task PrecomputedBindingRequiresARealApprovalAndTheGateRejectsChangedEffects()
    {
        var world = new EnforcementWorld(EnforcementWorld.StartCapture);
        var invocation = world.Invocation();
        var digest = Digest(invocation, world.Target);
        DecisionRequest? actual = null;
        world.Decisions.Permissions.Behavior = (request, _) =>
        {
            actual = request;
            return ValueTask.FromResult<PermissionGrantRecord?>(world.Decisions.Grant(request));
        };

        var unapproved = await world.InvokeAsync(invocation, cancellationToken: Token);
        Assert.Equal("perm.approval_required", unapproved.Failure!.Code);
        Assert.Equal(0, world.OwnerRuns);
        Assert.NotNull(actual);
        Assert.Equal(digest, actual.EffectSha256);
        var approval = await world.Decisions.ApproveAsync(actual, RiskLevel.R3);
        invocation.ApprovalId = UuidBoundary.ToWire(approval);
        Assert.Equal(digest, Digest(invocation, world.Target));
        var changed = invocation.Clone();
        changed.Arguments.Value.Text = "different authorized effect";
        var refused = await world.InvokeAsync(changed, cancellationToken: Token);
        Assert.Equal("perm.approval_required", refused.Failure!.Code);
        Assert.Equal("decision.s10.approval_mismatch", world.Decisions.Audit.Records[^1].ReasonCode);
        Assert.Equal(0, world.OwnerRuns);
        var allowed = await world.InvokeAsync(invocation, cancellationToken: Token);
        Assert.Equal(OutcomeKind.Success, allowed.Kind);
        Assert.Equal(1, world.OwnerRuns);
    }

    [Fact]
    public async Task MalformedOwnerReplayRefusesWithoutSpendingTheOriginalAdmission()
    {
        var world = new EnforcementWorld();
        var invocation = world.Invocation();
        var context = FrozenContextSnapshot.Freeze(world.Identity, [], ContextSnapshotBudget.Default);
        var owner = world.Gate.Enforce<string, EnforcedOwnerResult>((_, _, _, _, _, _) =>
            ValueTask.FromResult(world.OwnerBehavior()));
        Assert.Equal(OutcomeKind.Success, (await world.Gate.AuthorizeAsync(world.Registration, invocation, world.Target, context, Token)).Kind);
        var malformed = invocation.Clone();
        malformed.CommandId = new Id { Value = ByteString.CopyFrom(1, 2, 3) };
        var refused = await owner(world.Target, malformed, "argument", context, Token);
        Assert.True(refused.TryGetFailure(out var refusal));
        Assert.Equal("perm.capability_denied", refusal.Code);
        Assert.Equal(OutcomeKind.Success, (await owner(world.Target, invocation, "argument", context, Token)).Kind);
    }
}
