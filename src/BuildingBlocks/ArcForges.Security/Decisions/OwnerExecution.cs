// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;

namespace ArcForges.Security.Decisions;

/// <summary>
/// Proof that the pipeline decided every step up to the owner's final validation for exactly one request. It has no public
/// constructor or factory: only the pipeline's execution route creates one, immediately before it calls the owner's operation, so an
/// owner operation that requires this type as its parameter cannot be reached without the pipeline. It is a per-call value, not a
/// credential: it is not serializable, carries no secret and authorizes nothing outside the one call it was created for.
/// </summary>
public sealed class AuthorizedExecution
{
    internal AuthorizedExecution(SecurityDecision decision, DecisionRequest request, RiskAssessment risk)
    {
        Decision = decision;
        Request = request;
        Risk = risk;
    }

    /// <summary>The complete decision with every step from capability existence to the owner's validation.</summary>
    public SecurityDecision Decision { get; }

    public ActorChain Actors => Request.Actors;

    public string CapabilityKey => Request.CapabilityKey;

    public ResourceReference Resource => Request.Resource;

    public RiskAssessment Risk { get; }

    internal DecisionRequest Request { get; }
}

/// <summary>The owner's operation. It receives the ticket and performs the effect, or reports a typed failure or cancellation.</summary>
public delegate ValueTask<Outcome<TResult>> OwnerOperation<TResult>(AuthorizedExecution ticket, CancellationToken cancellationToken);

public enum ExecutionStatus
{
    None = 0,

    /// <summary>A step refused; the owner operation did not run.</summary>
    Refused = 1,

    Succeeded = 2,

    /// <summary>The owner ran and returned or threw a failure.</summary>
    OwnerFailed = 3,

    /// <summary>The owner ran and was cancelled; its effect is as the owner reported.</summary>
    OwnerCancelled = 4,

    /// <summary>The owner ran but the result record or the audit event could not be written; the effect certainty says what happened.</summary>
    BookkeepingFailed = 5,
}

/// <summary>The complete result of an execution through the pipeline.</summary>
public sealed class SecurityExecution<TResult>
{
    internal SecurityExecution(
        SecurityDecision decision,
        ExecutionStatus status,
        Outcome<TResult> result,
        Outcome<TResult>? ownerResult,
        EffectCertainty effect)
    {
        Decision = decision;
        Status = status;
        Result = result;
        OwnerResult = ownerResult;
        Effect = effect;
    }

    /// <summary>The final decision: every decision step, then the execution, record and audit steps that ran.</summary>
    public SecurityDecision Decision { get; }

    public ExecutionStatus Status { get; }

    /// <summary>What the caller sees: the owner's value on success, otherwise a typed failure with a registered code.</summary>
    public Outcome<TResult> Result { get; }

    /// <summary>The owner's own outcome, present only when the owner operation ran.</summary>
    public Outcome<TResult>? OwnerResult { get; }

    public EffectCertainty Effect { get; }
}
