// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Contracts.Foundation;

/// <summary>
/// A business failure crossing a contract boundary (architecture §5.2).
/// </summary>
/// <remarks>
/// <para>
/// Callers branch on <see cref="Code"/> and never on human text. <see cref="MessageKey"/> is a localisation
/// key; the wording lives in resource files, so a copy change cannot alter behaviour (architecture §5.3).
/// </para>
/// <para>
/// A security refusal must not leak whether a resource exists. <see cref="Detail"/> therefore carries no
/// resource id, path, owner identity or anything else that would let a caller enumerate what it cannot see:
/// "absent" and "not yours" have to look identical from outside. The stable literals themselves are frozen by
/// Step 02.06.
/// </para>
/// <para>
/// This type is one of three separate error shapes. A connection or protocol failure and a remote invocation
/// failure are exceptions owned by the runtime (Step 03); only a business failure is an
/// <see cref="ArcError"/> carried inside an <see cref="ArcResult{T}"/>.
/// </para>
/// </remarks>
public sealed partial record ArcError
{
    /// <summary>
    /// The stable machine code. Once published a literal never changes, because callers branch on it and
    /// stored records keep it.
    /// </summary>
    public required string Code { get; init; }

    /// <summary>The localisation key for the human message. Never the message itself.</summary>
    public required string MessageKey { get; init; }

    /// <summary>Optional non-sensitive structured detail. Never anything that identifies a hidden resource.</summary>
    public string? Detail { get; init; }

    /// <summary>Correlates this failure with its originating operation across boundaries and logs.</summary>
    public Guid CorrelationId { get; init; }
}
