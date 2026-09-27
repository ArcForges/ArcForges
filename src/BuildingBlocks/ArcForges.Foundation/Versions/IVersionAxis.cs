// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Foundation.Versions;

/// <summary>A closed version axis. Generic ranges cannot accept a value from another axis.</summary>
public interface IVersionAxis<TSelf> : IComparable<TSelf> where TSelf : struct, IVersionAxis<TSelf>
{
    /// <summary>Whether a version was explicitly supplied; default values are absent.</summary>
    bool IsValid { get; }

    /// <summary>Parses the axis value without deriving it from another axis.</summary>
    static abstract TSelf Parse(string text);
}
