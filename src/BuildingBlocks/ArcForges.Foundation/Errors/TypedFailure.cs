// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.Foundation.Errors;

/// <summary>An immutable application adapter over the published error schema, never a new wire DTO.</summary>
public sealed class TypedFailure
{
    private readonly ArcError _wire;

    private TypedFailure(ArcError wire, bool known)
    {
        _wire = wire.Clone();
        IsKnownCode = known;
    }

    public string Code => _wire.Code;
    public ErrorCategory Category => _wire.Category;
    public string MessageKey => _wire.MessageKey;
    public EffectCertainty Effect => _wire.Effect;
    public RetryMode Retry => _wire.Retry.Mode;
    public bool IsKnownCode { get; }
    public Id? CorrelationId => _wire.CorrelationId?.Clone();
    public RetryAdvice RetryAdvice => _wire.Retry.Clone();
    public ErrorDetails? Details => _wire.Details?.Clone();

    /// <summary>Only registered producers may emit errors. Missing retry prerequisites disable retry.</summary>
    public static TypedFailure Create(string code, Id? correlationId = null, RetryAdvice? retry = null,
        EffectCertainty? effect = null, ErrorDetails? details = null)
    {
        var reason = ReasonCodes.Get(code);
        var certainty = effect ?? reason.Effect;
        ValidateEffect(certainty);
        if (reason.Effect == EffectCertainty.DidNotHappen && certainty != reason.Effect)
        {
            throw new ArgumentException("This registered refusal occurs before effects.", nameof(effect));
        }

        var advice = retry?.Clone() ?? new RetryAdvice { Mode = RetryMode.Never };
        ValidateRetry(reason, advice, certainty);
        return new TypedFailure(new ArcError
        {
            Code = reason.Code,
            Category = reason.Category,
            MessageKey = reason.MessageKey,
            Effect = certainty,
            CorrelationId = correlationId?.Clone(),
            Retry = advice,
            Details = details?.Clone(),
        }, true);
    }

    /// <summary>Unknown or malformed future metadata is a generic non-retryable failure, never success.</summary>
    public static TypedFailure FromWire(ArcError wire)
    {
        ArgumentNullException.ThrowIfNull(wire);
        var copy = wire.Clone();
        bool known = copy.HasCode && ReasonCodes.TryGet(copy.Code, out _);
        var reason = known ? ReasonCodes.Get(copy.Code) : ReasonCodes.Get("internal.unexpected");
        bool metadataValid = copy.HasCategory && copy.Category == reason.Category &&
            copy.HasEffect && IsKnownEffect(copy.Effect) &&
            (reason.Effect != EffectCertainty.DidNotHappen || copy.Effect == EffectCertainty.DidNotHappen);
        copy.Category = !known && copy.HasCategory && copy.Category != ErrorCategory.Unspecified && Enum.IsDefined(copy.Category)
            ? copy.Category : reason.Category;
        copy.MessageKey = known ? reason.MessageKey : "error.generic";
        if (!copy.HasEffect || !IsKnownEffect(copy.Effect))
        {
            copy.Effect = EffectCertainty.Unknown;
        }

        // A reader never infers retry authority from a future code or unrecognised metadata.
        var retry = copy.Retry;
        bool retryValid = known && metadataValid && retry is not null;
        if (retryValid)
        {
            try
            {
                ValidateRetry(reason, retry!, copy.Effect);
            }
            catch (ArgumentException)
            {
                retryValid = false;
            }
        }

        if (!retryValid)
        {
            copy.Retry = new RetryAdvice { Mode = RetryMode.Never };
        }

        if (!known)
        {
            copy.Details = null;
        }

        return new TypedFailure(copy, known);
    }

    /// <summary>Returns an owned copy. Forwarding a reader's unknown code requires a producer registration.</summary>
    public ArcError ToWire()
    {
        if (!IsKnownCode)
        {
            throw new InvalidOperationException("An unknown reader code cannot become a producer code.");
        }

        var reason = ReasonCodes.Get(Code);
        if (reason.Effect == EffectCertainty.DidNotHappen && Effect != reason.Effect)
        {
            throw new InvalidOperationException("A reader cannot emit contradictory before-effect metadata.");
        }

        return _wire.Clone();
    }

    internal static bool IsKnownEffect(EffectCertainty effect) => effect is
        EffectCertainty.DidNotHappen or EffectCertainty.Happened or EffectCertainty.Unknown;

    internal static void ValidateEffect(EffectCertainty effect)
    {
        if (!IsKnownEffect(effect))
        {
            throw new ArgumentOutOfRangeException(nameof(effect), "Effect certainty must be explicit.");
        }
    }

    private static void ValidateRetry(ReasonCode reason, RetryAdvice advice, EffectCertainty effect)
    {
        if (!advice.HasMode || advice.Mode is RetryMode.Unspecified || !Enum.IsDefined(advice.Mode))
        {
            throw new ArgumentException("Retry mode must be known and explicit.", nameof(advice));
        }

        if (advice.Mode == RetryMode.Never)
        {
            if (advice.RetryAt is not null || advice.HasReconciliationOperation)
            {
                throw new ArgumentException("Never-retry advice cannot carry retry authority.", nameof(advice));
            }

            return;
        }

        if (advice.Mode != reason.Retry)
        {
            throw new ArgumentException("Retry advice is not registered for this reason.", nameof(advice));
        }

        if (advice.Mode is RetryMode.SameCommand or RetryMode.AfterTime && effect != EffectCertainty.DidNotHappen)
        {
            throw new ArgumentException("An uncertain effect requires reconciliation, not automatic retry.", nameof(advice));
        }

        if (advice.Mode == RetryMode.AfterTime)
        {
            if (advice.RetryAt is not { HasUnixSeconds: true, HasNanos: true } at || at.Nanos >= 1_000_000_000 || advice.HasReconciliationOperation)
            {
                throw new ArgumentException("Timed retry requires a canonical server recovery instant only.", nameof(advice));
            }
        }
        else if (advice.Mode == RetryMode.Reconcile)
        {
            if (!advice.HasReconciliationOperation || string.IsNullOrWhiteSpace(advice.ReconciliationOperation) || advice.RetryAt is not null)
            {
                throw new ArgumentException("Reconciliation requires an owner operation, not an automatic retry time.", nameof(advice));
            }
        }
        else if (advice.RetryAt is not null || advice.HasReconciliationOperation)
        {
            throw new ArgumentException("Same-command retry cannot contain unrelated advice.", nameof(advice));
        }
    }
}
