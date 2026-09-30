// SPDX-License-Identifier: AGPL-3.0-only
using System.Threading;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;

namespace ArcForges.Security.Approvals;

/// <summary>The closed set of operations that require a fresh identity step-up.</summary>
public enum SensitiveOperation
{
    None = 0,
    ChangeEmail = 1,
    RemoveAllPasskeys = 2,
    GenerateRecoveryCodes = 3,
    DeleteAccount = 4,
    AddOrRevokeExternalConnectorAuthorization = 5,
    RevealOrReplaceSensitiveSecret = 6,
    EnableRemoteAgent = 7,
    RevokeTrustedDevices = 8,
    CreateHighPrivilegeApiToken = 9,
    ChangeOwnerSecurityOrRecoveryCredentials = 10,
}

public enum StepUpAuthenticationMethod
{
    None = 0,
    FreshPasskey = 1,
    FreshOneTimeCode = 2,
    BiometricApplicationUnlock = 3,
}

/// <summary>Fresh authentication asserted by the configured trusted identity adapter.</summary>
public sealed record StepUpAuthentication
{
    public StepUpAuthentication(HumanPrincipal subject, StepUpAuthenticationMethod method, Instant verifiedAt)
    {
        ArgumentNullException.ThrowIfNull(subject);
        if (!Enum.IsDefined(method) || method == StepUpAuthenticationMethod.None)
        {
            throw new ArgumentOutOfRangeException(nameof(method));
        }

        Subject = subject;
        Method = method;
        VerifiedAt = verifiedAt;
    }

    public HumanPrincipal Subject { get; }
    public StepUpAuthenticationMethod Method { get; }
    public Instant VerifiedAt { get; }
}

/// <summary>
/// Trusted identity adapter. Implementations must perform fresh passkey/OTP verification bound to
/// the supplied challenge; application-unlock biometrics are reported distinctly and are rejected.
/// </summary>
public interface IStepUpAuthenticator
{
    ValueTask<StepUpAuthentication?> AuthenticateAsync(StepUpChallenge challenge,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Trusted device boundary for an explicit local-presence interaction. This must not be backed by
/// a caller-supplied boolean, remote assertion, or biometric application-unlock result.
/// </summary>
public interface ILocalPresenceVerifier
{
    ValueTask<bool> ConfirmLocalPresenceAsync(StepUpChallenge challenge,
        CancellationToken cancellationToken = default);
}

/// <summary>In-process challenge issued by a single StepUpCoordinator; it is not a credential.</summary>
public sealed class StepUpChallenge
{
    private readonly object issuer;
    private int state;

    internal StepUpChallenge(object issuer, Guid id, HumanPrincipal subject, CommandId commandId,
        SensitiveOperation operation, RiskLevel effectiveRisk, Instant issuedAt, Instant expiresAt)
    {
        _ = commandId.ToWire();
        this.issuer = issuer;
        Id = id;
        Subject = subject;
        CommandId = commandId;
        Operation = operation;
        EffectiveRisk = effectiveRisk;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
    }

    public Guid Id { get; }
    public HumanPrincipal Subject { get; }
    public CommandId CommandId { get; }
    public SensitiveOperation Operation { get; }
    public RiskLevel EffectiveRisk { get; }
    public Instant IssuedAt { get; }
    public Instant ExpiresAt { get; }

    internal bool TryBegin(object expectedIssuer) => ReferenceEquals(issuer, expectedIssuer) &&
        Interlocked.CompareExchange(ref state, 1, 0) == 0;

    internal void Finish(bool consumed) => Interlocked.Exchange(ref state, consumed ? 2 : 0);
}

/// <summary>Short-lived result that records identity proof only and conveys no operation permission.</summary>
public sealed class StepUpProof
{
    private readonly object issuer;
    private int consumed;

    internal StepUpProof(object issuer, StepUpChallenge challenge, StepUpAuthentication authentication,
        bool localPresenceConfirmed)
    {
        this.issuer = issuer;
        ChallengeId = challenge.Id;
        Subject = challenge.Subject;
        CommandId = challenge.CommandId;
        Operation = challenge.Operation;
        AuthenticationMethod = authentication.Method;
        VerifiedAt = authentication.VerifiedAt;
        ExpiresAt = challenge.ExpiresAt;
        EffectiveRisk = challenge.EffectiveRisk;
        LocalPresenceConfirmed = localPresenceConfirmed;
    }

    public Guid ChallengeId { get; }
    public HumanPrincipal Subject { get; }
    public CommandId CommandId { get; }
    public SensitiveOperation Operation { get; }
    public StepUpAuthenticationMethod AuthenticationMethod { get; }
    public Instant VerifiedAt { get; }
    public Instant ExpiresAt { get; }
    public bool LocalPresenceConfirmed { get; }

    internal bool TryConsume(object expectedIssuer, HumanPrincipal subject, CommandId commandId,
        SensitiveOperation operation, RiskLevel currentEffectiveRisk, Instant currentInstant)
    {
        if (!ReferenceEquals(issuer, expectedIssuer) || Subject != subject || CommandId != commandId ||
            Operation != operation || EffectiveRisk != currentEffectiveRisk ||
            currentInstant >= ExpiresAt || (EffectiveRisk == RiskLevel.R4 && !LocalPresenceConfirmed))
        {
            return false;
        }

        return Interlocked.CompareExchange(ref consumed, 1, 0) == 0;
    }

    public RiskLevel EffectiveRisk { get; }
}

/// <summary>
/// Issues one-use, short-lived step-up challenges for enumerated actions. R4 additionally requires
/// device-verified local presence; a biometric app unlock never satisfies fresh identity step-up.
/// </summary>
public sealed class StepUpCoordinator
{
    public static TimeSpan MaximumChallengeLifetime { get; } = TimeSpan.FromMinutes(5);

    private readonly object issuer = new();
    private readonly IClock clock;
    private readonly IStepUpAuthenticator authenticator;
    private readonly ILocalPresenceVerifier localPresence;

    public StepUpCoordinator(IClock clock, IStepUpAuthenticator authenticator, ILocalPresenceVerifier localPresence)
    {
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(authenticator);
        ArgumentNullException.ThrowIfNull(localPresence);
        this.clock = clock;
        this.authenticator = authenticator;
        this.localPresence = localPresence;
    }

    public StepUpChallenge CreateChallenge(HumanPrincipal subject, CommandId commandId,
        SensitiveOperation operation, RiskAssessment assessment, TimeSpan lifetime)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(assessment);
        if (!Enum.IsDefined(operation) || operation == SensitiveOperation.None)
        {
            throw new ArgumentOutOfRangeException(nameof(operation));
        }

        if (lifetime <= TimeSpan.Zero || lifetime > MaximumChallengeLifetime)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime));
        }

        var issuedAt = clock.GetCurrentInstant();
        var expiresAt = Add(issuedAt, lifetime);
        return new StepUpChallenge(issuer, Guid.NewGuid(), subject, commandId, operation, assessment.EffectiveRisk,
            issuedAt, expiresAt);
    }

    public async ValueTask<Outcome<StepUpProof>> CompleteAsync(StepUpChallenge challenge,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        if (!challenge.TryBegin(issuer))
        {
            return Failure<StepUpProof>("auth.step_up_required");
        }

        var consumed = false;
        try
        {
            if (clock.GetCurrentInstant() >= challenge.ExpiresAt)
            {
                consumed = true;
                return Failure<StepUpProof>("auth.step_up_required");
            }

            var authentication = await authenticator.AuthenticateAsync(challenge, cancellationToken).ConfigureAwait(false);
            var authenticatedAt = clock.GetCurrentInstant();
            if (authentication is null || authentication.Subject != challenge.Subject ||
                authentication.Method is not (StepUpAuthenticationMethod.FreshPasskey or StepUpAuthenticationMethod.FreshOneTimeCode) ||
                authentication.VerifiedAt < challenge.IssuedAt || authentication.VerifiedAt > authenticatedAt ||
                authentication.VerifiedAt >= challenge.ExpiresAt || authenticatedAt >= challenge.ExpiresAt)
            {
                return Failure<StepUpProof>("auth.step_up_required");
            }

            var presenceConfirmed = false;
            if (challenge.EffectiveRisk == RiskLevel.R4)
            {
                presenceConfirmed = await localPresence.ConfirmLocalPresenceAsync(challenge, cancellationToken).ConfigureAwait(false);
                if (!presenceConfirmed)
                {
                    return Failure<StepUpProof>("auth.local_presence_required");
                }
            }

            if (clock.GetCurrentInstant() >= challenge.ExpiresAt)
            {
                consumed = true;
                return Failure<StepUpProof>("auth.step_up_required");
            }

            consumed = true;
            return Outcome.Success(new StepUpProof(issuer, challenge, authentication, presenceConfirmed));
        }
        finally
        {
            challenge.Finish(consumed);
        }
    }

    /// <summary>Consumes matching, unexpired identity evidence once; it does not authorize execution.</summary>
    public bool TryConsume(StepUpProof proof, HumanPrincipal subject, CommandId commandId,
        SensitiveOperation operation, RiskAssessment currentAssessment)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(currentAssessment);
        if (!Enum.IsDefined(operation) || operation == SensitiveOperation.None)
        {
            return false;
        }

        return proof.TryConsume(issuer, subject, commandId, operation, currentAssessment.EffectiveRisk,
            clock.GetCurrentInstant());
    }

    private static Instant Add(Instant instant, TimeSpan duration)
    {
        var wholeSeconds = duration.Ticks / TimeSpan.TicksPerSecond;
        var remainingTicks = duration.Ticks % TimeSpan.TicksPerSecond;
        var seconds = checked(instant.UnixSeconds + wholeSeconds);
        var nanoseconds = instant.Nanoseconds + checked((uint)(remainingTicks * 100));
        if (nanoseconds >= 1_000_000_000U)
        {
            seconds = checked(seconds + 1);
            nanoseconds -= 1_000_000_000U;
        }

        return new Instant(seconds, nanoseconds);
    }

    private static Outcome<T> Failure<T>(string code) => Outcome.Failure<T>(TypedFailure.Create(code));
}
