// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Observability;

/// <summary>Why a type must have no logging representation.</summary>
public enum SensitiveContentKind
{
    /// <summary>A secret-bearing type such as a secret reference or a credential grant (observability RD-03).</summary>
    Secret = 0,

    /// <summary>A domain content type such as a message body, note, report text, capture buffer or attachment (RD-04).</summary>
    UserContent = 1,
}

/// <summary>
/// Declares that a type holds secret or user content and therefore must have no logging representation. The
/// declaration is checked structurally by a test over the declaring assembly (the audit in this project's tests is
/// the reference check); it is not a runtime filter.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct, AllowMultiple = false, Inherited = false)]
public sealed class SensitiveContentAttribute(SensitiveContentKind kind) : Attribute
{
    public SensitiveContentKind Kind { get; } = kind;
}
