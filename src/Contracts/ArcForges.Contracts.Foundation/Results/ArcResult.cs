// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Contracts.Foundation;

/// <summary>
/// The outcome of an operation that returns a value (architecture §5.2).
/// </summary>
/// <typeparam name="T">The value produced on success.</typeparam>
/// <remarks>
/// An expected business failure is returned here rather than thrown. Exceptions are reserved for
/// cancellation, defects and infrastructure faults, which keeps a predictable refusal distinguishable from a
/// genuine fault.
/// </remarks>
public sealed partial record ArcResult<T>
{
    /// <summary>True when the operation succeeded.</summary>
    public bool Ok { get; init; }

    /// <summary>The value, present only when <see cref="Ok"/> is true.</summary>
    public T? Value { get; init; }

    /// <summary>The failure, present only when <see cref="Ok"/> is false.</summary>
    public ArcError? Error { get; init; }

    /// <summary>The revision a write produced. <see cref="Revision.None"/> for reads and failures.</summary>
    public Revision NewRevision { get; init; }

    public static ArcResult<T> Success(T value, Revision newRevision) =>
        new() { Ok = true, Value = value, NewRevision = newRevision };

    public static ArcResult<T> Failure(ArcError error) =>
        new() { Ok = false, Error = error };
}

/// <summary>The outcome of an operation that returns no value.</summary>
public sealed partial record ArcResult
{
    /// <summary>True when the operation succeeded.</summary>
    public bool Ok { get; init; }

    /// <summary>The failure, present only when <see cref="Ok"/> is false.</summary>
    public ArcError? Error { get; init; }

    /// <summary>The revision a write produced. <see cref="Revision.None"/> for reads and failures.</summary>
    public Revision NewRevision { get; init; }

    public static ArcResult Success(Revision newRevision) =>
        new() { Ok = true, NewRevision = newRevision };

    public static ArcResult Failure(ArcError error) =>
        new() { Ok = false, Error = error };
}
