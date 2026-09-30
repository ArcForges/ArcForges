// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using ArcForges.Security.Approvals;
using Xunit;

namespace ArcForges.Security.Tests;

public sealed class ApprovalGuardrailTests
{
    [Fact]
    public async Task SteeringChangesOnlyTheRunningOperationDirectionAndLeavesApprovalPending()
    {
        var clock = new TestClock();
        var store = new ApprovalCoordinatorTests.MemoryApprovalStore();
        var approvals = new ApprovalCoordinator(clock.Clock, store);
        var owner = Principal();
        var intent = new ApprovalIntent(Guid.NewGuid(), new CommandId(Guid.NewGuid()), owner,
            "workspace.export", "workspace/primary", "revision:9", new string('B', 64), RiskLevel.R3);
        _ = Value(await approvals.RequestAsync(intent, TimeSpan.FromMinutes(2), TestContext.Current.CancellationToken));
        var steerer = new RecordingSteerer();
        var steering = new SteeringCoordinator(steerer);
        var request = new SteeringRequest(Guid.NewGuid(), intent.CommandId, owner,
            "Change the execution order, but do not add any new target or effect.");

        Assert.True(Value(await steering.ApplyAsync(request, TestContext.Current.CancellationToken)));
        Assert.Same(request, steerer.LastRequest);
        Assert.Equal(ApprovalState.Pending, (await store.ReadAsync(intent.ApprovalId,
            TestContext.Current.CancellationToken))!.State);
    }

    [Fact]
    public async Task BiometricApplicationUnlockCannotSatisfyFreshStepUpEvenWithLocalPresence()
    {
        var clock = new TestClock();
        var authenticator = new RecordingAuthenticator(clock.Clock)
        {
            Method = StepUpAuthenticationMethod.BiometricApplicationUnlock,
        };
        var presence = new RecordingPresence { IsConfirmed = true };
        var coordinator = new StepUpCoordinator(clock.Clock, authenticator, presence);
        var owner = Principal();
        var commandId = new CommandId(Guid.NewGuid());
        var assessment = Assessment(RiskLevel.R4);
        var challenge = coordinator.CreateChallenge(owner, commandId, SensitiveOperation.DeleteAccount,
            assessment, TimeSpan.FromMinutes(1));

        Assert.Equal("auth.step_up_required", Failure(await coordinator.CompleteAsync(challenge,
            TestContext.Current.CancellationToken)));
        Assert.Equal(0, presence.Calls);

        authenticator.Method = StepUpAuthenticationMethod.FreshPasskey;
        var proof = Value(await coordinator.CompleteAsync(challenge, TestContext.Current.CancellationToken));
        Assert.Equal(StepUpAuthenticationMethod.FreshPasskey, proof.AuthenticationMethod);
        Assert.True(proof.LocalPresenceConfirmed);
        Assert.Equal(challenge.Id, proof.ChallengeId);
        Assert.Equal(commandId, proof.CommandId);
        Assert.False(coordinator.TryConsume(proof, owner, new CommandId(Guid.NewGuid()), SensitiveOperation.DeleteAccount, assessment));
        Assert.True(coordinator.TryConsume(proof, owner, commandId, SensitiveOperation.DeleteAccount, assessment));
        Assert.False(coordinator.TryConsume(proof, owner, commandId, SensitiveOperation.DeleteAccount, assessment));
        Assert.Equal("auth.step_up_required", Failure(await coordinator.CompleteAsync(challenge,
            TestContext.Current.CancellationToken)));
        Assert.Equal(1, presence.Calls);
    }

    [Fact]
    public async Task HighestRiskRequiresSeparateDeviceLocalPresenceAfterFreshIdentityStepUp()
    {
        var clock = new TestClock();
        var authenticator = new RecordingAuthenticator(clock.Clock)
        {
            Method = StepUpAuthenticationMethod.FreshOneTimeCode,
        };
        var presence = new RecordingPresence { IsConfirmed = false };
        var coordinator = new StepUpCoordinator(clock.Clock, authenticator, presence);
        var commandId = new CommandId(Guid.NewGuid());
        var assessment = Assessment(RiskLevel.R4);
        var challenge = coordinator.CreateChallenge(Principal(), commandId,
            SensitiveOperation.ChangeOwnerSecurityOrRecoveryCredentials,
            assessment, TimeSpan.FromMinutes(1));

        Assert.Equal("auth.local_presence_required", Failure(await coordinator.CompleteAsync(challenge,
            TestContext.Current.CancellationToken)));
        Assert.Equal(1, presence.Calls);

        presence.IsConfirmed = true;
        var proof = Value(await coordinator.CompleteAsync(challenge, TestContext.Current.CancellationToken));
        Assert.True(proof.LocalPresenceConfirmed);
        Assert.Equal(SensitiveOperation.ChangeOwnerSecurityOrRecoveryCredentials, proof.Operation);
        Assert.True(coordinator.TryConsume(proof, challenge.Subject, commandId, challenge.Operation, assessment));
    }

    [Fact]
    public async Task LowerRiskChallengeCannotBeConsumedForCurrentHigherRiskAssessment()
    {
        var clock = new TestClock();
        var authenticator = new RecordingAuthenticator(clock.Clock);
        var presence = new RecordingPresence();
        var coordinator = new StepUpCoordinator(clock.Clock, authenticator, presence);
        var owner = Principal();
        var commandId = new CommandId(Guid.NewGuid());
        var challengeAssessment = Assessment(RiskLevel.R1);
        var useAssessment = Assessment(RiskLevel.R4);
        var challenge = coordinator.CreateChallenge(owner, commandId, SensitiveOperation.DeleteAccount,
            challengeAssessment, TimeSpan.FromMinutes(1));

        var proof = Value(await coordinator.CompleteAsync(challenge, TestContext.Current.CancellationToken));

        Assert.Equal(0, presence.Calls);
        Assert.False(coordinator.TryConsume(proof, owner, commandId, SensitiveOperation.DeleteAccount, useAssessment));
        Assert.True(coordinator.TryConsume(proof, owner, commandId, SensitiveOperation.DeleteAccount, challengeAssessment));
        Assert.Equal(0, presence.Calls);
    }

    [Fact]
    public async Task StepUpChallengeExpiresAtBoundaryAndRejectsWrongIdentity()
    {
        var clock = new TestClock();
        var authenticator = new RecordingAuthenticator(clock.Clock)
        {
            SubjectOverride = Principal(),
            Method = StepUpAuthenticationMethod.FreshPasskey,
        };
        var coordinator = new StepUpCoordinator(clock.Clock, authenticator, new RecordingPresence { IsConfirmed = true });
        var assessment = Assessment(RiskLevel.R2);
        var challenge = coordinator.CreateChallenge(Principal(), new CommandId(Guid.NewGuid()), SensitiveOperation.ChangeEmail,
            assessment, TimeSpan.FromSeconds(30));

        Assert.Equal("auth.step_up_required", Failure(await coordinator.CompleteAsync(challenge,
            TestContext.Current.CancellationToken)));
        clock.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal("auth.step_up_required", Failure(await coordinator.CompleteAsync(challenge,
            TestContext.Current.CancellationToken)));
    }

    [Fact]
    public async Task StepUpDurationIsBoundedAndNonSensitiveValuesAreRejected()
    {
        var clock = new TestClock();
        var coordinator = new StepUpCoordinator(clock.Clock,
            new RecordingAuthenticator(clock.Clock), new RecordingPresence());

        var commandId = new CommandId(Guid.NewGuid());
        var assessment = Assessment(RiskLevel.R1);
        Assert.Throws<ArgumentOutOfRangeException>(() => coordinator.CreateChallenge(Principal(), commandId, (SensitiveOperation)999,
            assessment, TimeSpan.FromSeconds(1)));
        Assert.Throws<ArgumentOutOfRangeException>(() => coordinator.CreateChallenge(Principal(), commandId, SensitiveOperation.ChangeEmail,
            assessment, StepUpCoordinator.MaximumChallengeLifetime + TimeSpan.FromTicks(1)));
        Assert.Throws<ArgumentNullException>(() => coordinator.CreateChallenge(Principal(), commandId, SensitiveOperation.ChangeEmail,
            null!, TimeSpan.FromSeconds(1)));
    }

    private static RiskAssessment Assessment(RiskLevel baseline) => RiskModel.Assess(
        new CapabilityDescriptor { Risk = baseline.ToString() },
        new RiskContext(RiskScope.SingleOperation, RiskTarget.Ordinary, RiskReversibility.Reversible,
            RiskEgress.None, ActorKind.None, IsRemoteOrigin: false, IsPackageVerified: true, IsLargeDataVolume: false));

    private static HumanPrincipal Principal() => new(new RealmId(Guid.NewGuid()),
        new UserId(Guid.NewGuid()), HumanIdentityKind.LocalHuman);

    private static T Value<T>(Outcome<T> outcome)
    {
        Assert.True(outcome.TryGetValue(out var value), outcome.TryGetFailure(out var failure) ? failure!.Code : "Expected a successful outcome.");
        return value!;
    }

    private static string Failure<T>(Outcome<T> outcome)
    {
        Assert.True(outcome.TryGetFailure(out var failure), "Expected a refusal outcome.");
        return failure!.Code;
    }

    private sealed class RecordingSteerer : IRunningOperationSteerer
    {
        public SteeringRequest? LastRequest { get; private set; }

        public ValueTask<bool> TryApplyAsync(SteeringRequest request, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastRequest = request;
            return ValueTask.FromResult(true);
        }
    }

    private sealed class RecordingAuthenticator(Clock clock) : IStepUpAuthenticator
    {
        public HumanPrincipal? SubjectOverride { get; set; }
        public StepUpAuthenticationMethod Method { get; set; } = StepUpAuthenticationMethod.FreshPasskey;

        public ValueTask<StepUpAuthentication?> AuthenticateAsync(StepUpChallenge challenge,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<StepUpAuthentication?>(new StepUpAuthentication(
                SubjectOverride ?? challenge.Subject, Method, clock.GetCurrentInstant()));
        }
    }

    private sealed class RecordingPresence : ILocalPresenceVerifier
    {
        public bool IsConfirmed { get; set; }
        public int Calls { get; private set; }

        public ValueTask<bool> ConfirmLocalPresenceAsync(StepUpChallenge challenge,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return ValueTask.FromResult(IsConfirmed);
        }
    }

    private sealed class TestClock
    {
        private readonly ManualTimeProvider provider = new();

        internal TestClock() => Clock = new Clock(provider);

        internal Clock Clock { get; }
        internal void Advance(TimeSpan duration) => provider.Advance(duration);
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset now = new(2026, 9, 30, 12, 0, 0, TimeSpan.Zero);
        private long timestamp;

        public override DateTimeOffset GetUtcNow() => now;
        public override long GetTimestamp() => timestamp;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        internal void Advance(TimeSpan duration)
        {
            now += duration;
            timestamp = checked(timestamp + duration.Ticks);
        }
    }
}
