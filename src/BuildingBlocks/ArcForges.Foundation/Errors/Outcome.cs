// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.Foundation.Errors;

public enum OutcomeKind
{
    Success,
    Failure,
    Cancelled,
}

/// <summary>Storage-free result algebra. No default struct can silently represent success.</summary>
public sealed class Outcome<T>
{
    private readonly T? _value;
    private readonly TypedFailure? _failure;
    private readonly EffectCertainty _cancellationEffect;

    internal Outcome(OutcomeKind kind, T? value, TypedFailure? failure, EffectCertainty cancellationEffect)
    {
        Kind = kind;
        _value = value;
        _failure = failure;
        _cancellationEffect = cancellationEffect;
    }

    public OutcomeKind Kind { get; }
    public EffectCertainty CancellationEffect => Kind == OutcomeKind.Cancelled
        ? _cancellationEffect
        : throw new InvalidOperationException("This result is not cancellation.");

    public bool TryGetValue([MaybeNullWhen(false)] out T value)
    {
        value = _value!;
        return Kind == OutcomeKind.Success;
    }

    public bool TryGetFailure([NotNullWhen(true)] out TypedFailure? failure)
    {
        failure = _failure;
        return Kind == OutcomeKind.Failure;
    }

    public Outcome<TResult> Map<TResult>(Func<T, TResult> map)
    {
        ArgumentNullException.ThrowIfNull(map);
        return Kind switch
        {
            OutcomeKind.Success => Outcome.Success(map(_value!)),
            OutcomeKind.Failure => Outcome.Failure<TResult>(_failure!),
            OutcomeKind.Cancelled => Outcome.Cancelled<TResult>(_cancellationEffect),
            _ => throw new InvalidOperationException("Invalid outcome kind."),
        };
    }
}

/// <summary>Type-inferred factories for the immutable outcome algebra.</summary>
public static class Outcome
{
    public static Outcome<T> Success<T>(T value) => new(OutcomeKind.Success, value, null, EffectCertainty.Unspecified);

    public static Outcome<T> Failure<T>(TypedFailure failure)
    {
        ArgumentNullException.ThrowIfNull(failure);
        return new Outcome<T>(OutcomeKind.Failure, default, failure, EffectCertainty.Unspecified);
    }

    public static Outcome<T> Cancelled<T>(EffectCertainty effect)
    {
        TypedFailure.ValidateEffect(effect);
        return new Outcome<T>(OutcomeKind.Cancelled, default, null, effect);
    }

}
