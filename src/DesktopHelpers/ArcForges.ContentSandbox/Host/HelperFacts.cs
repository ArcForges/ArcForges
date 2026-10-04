// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.ContentSandbox.Contracts;

namespace ArcForges.ContentSandbox.Host;

/// <summary>
/// What the launch frame fixed about this process, kept for self-checks and for the test-only hostile fixture: the operating-system values
/// of the resources the helper inherited. A parser has no use for them; a test that attacks the descriptor allowlist needs to know which
/// values are the legitimate ones.
/// </summary>
internal static class HelperFacts
{
    /// <summary>The inherited resource values of the closed inventory.</summary>
    internal static IReadOnlySet<ulong> InheritedValues { get; private set; } = new HashSet<ulong>();

    /// <summary>The inherited input mapping, when the frame lists it.</summary>
    internal static ulong? InputHandle { get; private set; }

    /// <summary>The value of the inherited input mapping.</summary>
    internal static bool TryGetInputHandle(out ulong handle)
    {
        handle = InputHandle ?? 0;
        return InputHandle is not null;
    }

    /// <summary>Records the inventory of a frame.</summary>
    internal static void Record(ContentSandboxLaunchFrame frame)
    {
        ArgumentNullException.ThrowIfNull(frame);
        InheritedValues = frame.Handles.Select(entry => entry.Value).ToHashSet();
        InputHandle = frame.TryGetHandle(ContentSandboxHandleRole.Input, out var input) ? input : null;
    }
}
