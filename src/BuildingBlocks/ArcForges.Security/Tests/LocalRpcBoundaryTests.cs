// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.LocalRpc;
using ArcForges.Security.Decisions;
using ArcForges.Security.LocalRpcBoundary;
using Xunit;

namespace ArcForges.Security.Tests;

/// <summary>
/// The transport boundary over the real parent-owned launch identity: real launch authorities and launches (offline, no child
/// process), with the claim, the one-use secret proof, revocation, supersession and expiry deciding what the pipeline sees.
/// </summary>
public sealed class LocalRpcBoundaryTests : IAsyncLifetime
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "arcforges-plt38-" + Guid.NewGuid().ToString("N"));
    private readonly List<LocalRpcLaunchAuthority> _authorities = [];

    public ValueTask InitializeAsync()
    {
        _ = Directory.CreateDirectory(_root);
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var authority in _authorities)
        {
            await authority.DisposeAsync();
        }

        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
            // Best effort: the launch directories are owner-only temporary state.
        }
    }

    private static LocalRpcLaunchIdentity Identity(string build = "build-1", uint protocol = 1) => new(
        LocalRpcChildKind.Connector, build, new byte[LocalRpcLaunchIdentity.DigestLength], protocol, new byte[LocalRpcLaunchIdentity.DigestLength]);

    private (LocalRpcLaunchAuthority Authority, LocalRpcLaunch Launch, LocalRpcLaunchClaim Claim) NewLaunch(
        string slot = "connector-1", TimeSpan? window = null)
    {
        var authority = LocalRpcLaunchAuthority.Create(Path.Combine(_root, "r" + _authorities.Count), window);
        _authorities.Add(authority);
        var launch = authority.Launch(slot, Identity(), LocalRpcLaunchTransport.SuppliedStreams);
        return (authority, launch, launch.Descriptor.ToClaim());
    }

    private static bool Accept(int _, ReadOnlySpan<byte> secret) => secret.Length == LocalRpcLaunchDescriptor.SecretLength;

    [Fact]
    public async Task AVerifiedClaimWithAnAcceptedProofEstablishesASessionTheDecisionCanSee()
    {
        var (authority, launch, claim) = NewLaunch();
        var secretSeen = new byte[LocalRpcLaunchDescriptor.SecretLength];
        var bootstrap = launch.HandoffBootstrapResource();
        var instance = new InstanceId(Guid.NewGuid());

        var result = LocalRpcTransportSession.Establish(authority, launch, claim, secretSeen, (state, secret) =>
        {
            secret.CopyTo(state);
            return true;
        }, instance);

        Assert.Equal(TransportRefusal.None, result.Refusal);
        var session = result.Session!;
        Assert.Equal(TransportKind.LocalRpcChild, session.Kind);
        Assert.Equal(bootstrap[^LocalRpcLaunchDescriptor.SecretLength..], secretSeen);
        var verdict = await session.VerifyCurrentAsync(TestContext.Current.CancellationToken);
        Assert.Equal(TransportRefusal.None, verdict.Refusal);
        var binding = verdict.Binding!;
        Assert.Equal(TransportKind.LocalRpcChild, binding.Kind);
        Assert.Equal(TransportAssurance.LaunchClaimWithSecretProof, binding.Assurance);
        Assert.Equal(launch.Descriptor.LaunchId, binding.LaunchId);
        Assert.Equal("connector-1", binding.Slot);
        Assert.Equal(1UL, binding.Epoch);
        Assert.Equal("Connector", binding.ChildKind);
        Assert.Equal("build-1", binding.BuildId);
        Assert.Equal(instance, binding.BoundCallerInstance);
        Assert.Equal(LocalRpcLaunchRefusal.None, launch.Status());
    }

    [Fact]
    public async Task ASessionWithoutABoundInstanceRecordsNone()
    {
        var (authority, launch, claim) = NewLaunch();

        var result = LocalRpcTransportSession.Establish(authority, launch, claim, 0, Accept);

        var verdict = await result.Session!.VerifyCurrentAsync(TestContext.Current.CancellationToken);
        Assert.Null(verdict.Binding!.BoundCallerInstance);
    }

    [Fact]
    public void ARejectedProofRevokesTheLaunchBecauseTheSecretIsSpent()
    {
        var (authority, launch, claim) = NewLaunch();

        var result = LocalRpcTransportSession.Establish(authority, launch, claim, 0, (_, _) => false);

        Assert.Null(result.Session);
        Assert.Equal(TransportRefusal.ProofRejected, result.Refusal);
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, launch.Status());
        Assert.True(launch.Revoked.IsCancellationRequested);
    }

    [Fact]
    public void AProofCheckThatThrowsRevokesTheLaunchAndRefuses()
    {
        var (authority, launch, claim) = NewLaunch();

        var result = LocalRpcTransportSession.Establish<int>(authority, launch, claim, 0, (_, _) => throw new InvalidOperationException("proof backend failed"));

        Assert.Null(result.Session);
        Assert.Equal(TransportRefusal.Unavailable, result.Refusal);
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, launch.Status());
    }

    [Fact]
    public void AClaimThatDoesNotVerifySpendsNothingSoALaterLegitimateEstablishmentSucceeds()
    {
        var (authority, launch, claim) = NewLaunch();
        var forged = new LocalRpcLaunchClaim(claim.LaunchId, claim.Slot, claim.Epoch, new byte[LocalRpcLaunchDescriptor.NonceLength], claim.Identity);
        var proofRan = false;

        var refused = LocalRpcTransportSession.Establish(authority, launch, forged, 0, (_, _) =>
        {
            proofRan = true;
            return true;
        });
        var legitimate = LocalRpcTransportSession.Establish(authority, launch, claim, 0, Accept);

        Assert.Equal(TransportRefusal.IdentityMismatch, refused.Refusal);
        Assert.False(proofRan);
        Assert.Equal(LocalRpcLaunchRefusal.None, launch.Status());
        Assert.NotNull(legitimate.Session);
    }

    [Fact]
    public void AClaimWithAnotherBuildOrProtocolIsRefusedBeforeTheSecretIsConsumed()
    {
        var (authority, launch, claim) = NewLaunch();
        var otherBuild = new LocalRpcLaunchClaim(claim.LaunchId, claim.Slot, claim.Epoch, claim.Nonce.Span, Identity(build: "build-2"));
        var otherProtocol = new LocalRpcLaunchClaim(claim.LaunchId, claim.Slot, claim.Epoch, claim.Nonce.Span, Identity(protocol: 2));
        var proofRan = false;
        bool Proof(int _, ReadOnlySpan<byte> __)
        {
            proofRan = true;
            return true;
        }

        Assert.Equal(TransportRefusal.IdentityMismatch, LocalRpcTransportSession.Establish(authority, launch, otherBuild, 0, Proof).Refusal);
        Assert.Equal(TransportRefusal.IdentityMismatch, LocalRpcTransportSession.Establish(authority, launch, otherProtocol, 0, Proof).Refusal);
        Assert.False(proofRan);
        Assert.NotNull(LocalRpcTransportSession.Establish(authority, launch, claim, 0, Accept).Session);
    }

    [Fact]
    public void AClaimThatDoesNotNameThisLaunchIsRefusedWithoutAskingTheAuthority()
    {
        var (authority, launch, claim) = NewLaunch();
        var other = authority.Launch("connector-2", Identity(), LocalRpcLaunchTransport.SuppliedStreams);
        var otherClaim = other.Descriptor.ToClaim();
        var wrongId = new LocalRpcLaunchClaim(Guid.NewGuid(), claim.Slot, claim.Epoch, claim.Nonce.Span, claim.Identity);
        var wrongEpoch = new LocalRpcLaunchClaim(claim.LaunchId, claim.Slot, claim.Epoch + 1, claim.Nonce.Span, claim.Identity);
        var wrongSlot = new LocalRpcLaunchClaim(claim.LaunchId, "connector-9", claim.Epoch, claim.Nonce.Span, claim.Identity);

        Assert.Equal(TransportRefusal.IdentityMismatch, LocalRpcTransportSession.Establish(authority, launch, otherClaim, 0, Accept).Refusal);
        Assert.Equal(TransportRefusal.IdentityMismatch, LocalRpcTransportSession.Establish(authority, launch, wrongId, 0, Accept).Refusal);
        Assert.Equal(TransportRefusal.IdentityMismatch, LocalRpcTransportSession.Establish(authority, launch, wrongEpoch, 0, Accept).Refusal);
        Assert.Equal(TransportRefusal.IdentityMismatch, LocalRpcTransportSession.Establish(authority, launch, wrongSlot, 0, Accept).Refusal);
        Assert.Equal(LocalRpcLaunchRefusal.None, launch.Status());
    }

    [Fact]
    public async Task ASecondEstablishmentCannotReuseTheSpentSecretAndDoesNotRevokeTheFirstSession()
    {
        var (authority, launch, claim) = NewLaunch();
        var first = LocalRpcTransportSession.Establish(authority, launch, claim, 0, Accept);

        var second = LocalRpcTransportSession.Establish(authority, launch, claim, 0, Accept);

        Assert.Null(second.Session);
        Assert.Equal(TransportRefusal.NotEstablished, second.Refusal);
        Assert.Equal(LocalRpcLaunchRefusal.None, launch.Status());
        Assert.Equal(TransportRefusal.None, (await first.Session!.VerifyCurrentAsync(TestContext.Current.CancellationToken)).Refusal);
    }

    [Fact]
    public async Task ARevokedLaunchStopsVouchingAtTheNextBoundary()
    {
        var (authority, launch, claim) = NewLaunch();
        var session = LocalRpcTransportSession.Establish(authority, launch, claim, 0, Accept).Session!;

        launch.Revoke();

        var verdict = await session.VerifyCurrentAsync(TestContext.Current.CancellationToken);
        Assert.Equal(TransportRefusal.Revoked, verdict.Refusal);
        Assert.Null(verdict.Binding);
    }

    [Fact]
    public async Task ARelaunchOfTheSlotSupersedesTheSessionOfTheOlderEpoch()
    {
        var (authority, launch, claim) = NewLaunch();
        var session = LocalRpcTransportSession.Establish(authority, launch, claim, 0, Accept).Session!;

        _ = authority.Launch("connector-1", Identity(), LocalRpcLaunchTransport.SuppliedStreams);

        var verdict = await session.VerifyCurrentAsync(TestContext.Current.CancellationToken);
        Assert.Contains(verdict.Refusal, new[] { TransportRefusal.Revoked, TransportRefusal.Superseded });
        Assert.Null(verdict.Binding);
        var late = LocalRpcTransportSession.Establish(authority, launch, claim, 0, Accept);
        Assert.Null(late.Session);
    }

    [Fact]
    public async Task DisposingTheAuthorityEndsEverySession()
    {
        var (authority, launch, claim) = NewLaunch();
        var session = LocalRpcTransportSession.Establish(authority, launch, claim, 0, Accept).Session!;

        await authority.DisposeAsync();

        Assert.Equal(TransportRefusal.Revoked, (await session.VerifyCurrentAsync(TestContext.Current.CancellationToken)).Refusal);
    }

    [Fact]
    public async Task AnUnbootstrappedLaunchExpiresOnTheRealClockAndCannotBeEstablished()
    {
        var (authority, launch, claim) = NewLaunch(window: TimeSpan.FromSeconds(1));
        var deadline = DateTimeOffset.UtcNow.AddSeconds(30);
        while (launch.Status() != LocalRpcLaunchRefusal.Expired && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(50, TestContext.Current.CancellationToken);
        }

        var result = LocalRpcTransportSession.Establish(authority, launch, claim, 0, Accept);

        Assert.Equal(TransportRefusal.Expired, result.Refusal);
        Assert.Null(result.Session);
    }

    [Fact]
    public async Task AnEstablishedSessionKeepsVouchingAfterTheBootstrapWindowWouldHavePassed()
    {
        var (authority, launch, claim) = NewLaunch(window: TimeSpan.FromSeconds(1));
        var session = LocalRpcTransportSession.Establish(authority, launch, claim, 0, Accept).Session!;

        await Task.Delay(TimeSpan.FromMilliseconds(1500), TestContext.Current.CancellationToken);

        Assert.Equal(TransportRefusal.None, (await session.VerifyCurrentAsync(TestContext.Current.CancellationToken)).Refusal);
    }

    [Fact]
    public async Task TheVerificationHonoursCancellation()
    {
        var (authority, launch, claim) = NewLaunch();
        var session = LocalRpcTransportSession.Establish(authority, launch, claim, 0, Accept).Session!;
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await session.VerifyCurrentAsync(cancelled.Token));
    }

    [Theory]
    [InlineData(LocalRpcLaunchRefusal.Revoked, TransportRefusal.Revoked)]
    [InlineData(LocalRpcLaunchRefusal.Expired, TransportRefusal.Expired)]
    [InlineData(LocalRpcLaunchRefusal.StaleEpoch, TransportRefusal.Superseded)]
    [InlineData(LocalRpcLaunchRefusal.ParentMismatch, TransportRefusal.PeerGone)]
    [InlineData(LocalRpcLaunchRefusal.ChildGone, TransportRefusal.PeerGone)]
    [InlineData(LocalRpcLaunchRefusal.UnknownSlot, TransportRefusal.IdentityMismatch)]
    [InlineData(LocalRpcLaunchRefusal.UnknownLaunch, TransportRefusal.IdentityMismatch)]
    [InlineData(LocalRpcLaunchRefusal.NonceMismatch, TransportRefusal.IdentityMismatch)]
    [InlineData(LocalRpcLaunchRefusal.BuildMismatch, TransportRefusal.IdentityMismatch)]
    [InlineData(LocalRpcLaunchRefusal.ProtocolMismatch, TransportRefusal.IdentityMismatch)]
    [InlineData(LocalRpcLaunchRefusal.None, TransportRefusal.Unavailable)]
    [InlineData((LocalRpcLaunchRefusal)99, TransportRefusal.Unavailable)]
    public void EveryRefusalOfTheLaunchAuthorityMapsToOneTransportRefusalAndNeverToSuccess(LocalRpcLaunchRefusal refusal, TransportRefusal expected)
    {
        Assert.Equal(expected, LocalRpcTransportSession.Map(refusal));
        Assert.NotEqual(TransportRefusal.None, LocalRpcTransportSession.Map(refusal));
    }

    [Fact]
    public void TheMappingCoversEveryDefinedRefusalOfTheLaunchAuthority()
    {
        foreach (var refusal in Enum.GetValues<LocalRpcLaunchRefusal>().Where(value => value != LocalRpcLaunchRefusal.None))
        {
            Assert.NotEqual(TransportRefusal.Unavailable, LocalRpcTransportSession.Map(refusal));
        }
    }

    [Fact]
    public void EstablishmentRefusesMissingParts()
    {
        var (authority, launch, claim) = NewLaunch();
        _ = Assert.Throws<ArgumentNullException>(() => LocalRpcTransportSession.Establish(null!, launch, claim, 0, Accept));
        _ = Assert.Throws<ArgumentNullException>(() => LocalRpcTransportSession.Establish(authority, null!, claim, 0, Accept));
        _ = Assert.Throws<ArgumentNullException>(() => LocalRpcTransportSession.Establish(authority, launch, null!, 0, Accept));
        _ = Assert.Throws<ArgumentNullException>(() => LocalRpcTransportSession.Establish<int>(authority, launch, claim, 0, null!));
        Assert.Equal(LocalRpcLaunchRefusal.None, launch.Status());
    }

    [Fact]
    public async Task ThePipelineAcceptsTheRealSessionAndRecordsItsBinding()
    {
        var (authority, launch, claim) = NewLaunch();
        var harness = new DecisionHarness();
        var instance = new InstanceId(Guid.NewGuid());
        var session = LocalRpcTransportSession.Establish(authority, launch, claim, 0, Accept, instance).Session!;
        var builder = harness.Request();
        builder.Transport = session;
        builder.Actors = new ActorChain(
            builder.Actors.Owner, builder.Actors.Device, builder.Actors.Installation, builder.Actors.Session, instance, builder.Actors.Actors);

        var decision = await harness.Pipeline().EvaluateAsync(EnforcementPoint.TransportBoundary, builder.Build(), TestContext.Current.CancellationToken);

        Assert.True(decision.Allowed);
        Assert.Equal(TransportAssurance.LaunchClaimWithSecretProof, decision.Transport!.Assurance);
        Assert.Same(decision.Transport, harness.Trust.LastBinding);
        Assert.Equal("connector-1", harness.Trust.LastBinding!.Slot);
        Assert.Equal(instance, decision.Transport.BoundCallerInstance);
    }

    [Fact]
    public async Task ThePipelineRefusesARequestWhoseChainNamesAnotherCallerInstanceThanTheSessionBound()
    {
        var (authority, launch, claim) = NewLaunch();
        var harness = new DecisionHarness();
        var session = LocalRpcTransportSession.Establish(authority, launch, claim, 0, Accept, new InstanceId(Guid.NewGuid())).Session!;
        var builder = harness.Request();
        builder.Transport = session;

        var decision = await harness.Pipeline().EvaluateAsync(EnforcementPoint.TransportBoundary, builder.Build(), TestContext.Current.CancellationToken);

        Assert.False(decision.Allowed);
        Assert.Equal(DecisionReason.S03CallerInstanceMismatch, decision.Reason);
        Assert.Equal(0, harness.Log.Count("identity"));
    }

    [Fact]
    public async Task ARevokedOrSupersededLaunchIsRefusedByThePipelineAtTheTransportBoundaryAndStopsTheExecution()
    {
        var (authority, launch, claim) = NewLaunch();
        var harness = new DecisionHarness();
        var session = LocalRpcTransportSession.Establish(authority, launch, claim, 0, Accept).Session!;
        var builder = harness.Request();
        builder.Transport = session;
        var pipeline = harness.Pipeline();

        var before = await pipeline.ExecuteAsync(builder.Build(), harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);
        Assert.Equal(ExecutionStatus.Succeeded, before.Status);
        Assert.Equal(TransportAssurance.LaunchClaimWithSecretProof, before.Decision.Transport!.Assurance);

        launch.Revoke();
        var after = await pipeline.ExecuteAsync(builder.Build(), harness.OwnerOperation.Operation, TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionStatus.Refused, after.Status);
        Assert.Equal(DecisionReason.S03TransportRefused, after.Decision.Reason);
        Assert.Equal(DecisionStep.ActorIdentity, after.Decision.FailedStep);
        Assert.Equal("auth.unauthenticated", after.Decision.RegisteredCode);
        Assert.Equal(1, harness.OwnerOperation.Calls);
    }
}
