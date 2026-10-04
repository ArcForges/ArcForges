// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.LocalRpc.Sandbox.V1;

namespace ArcForges.ContentSandbox.Contracts;

/// <summary>
/// The parser budget of one invocation. A launch fixes it before any parser runs; the helper refuses a session request that asks
/// for more, and nothing raises it afterwards. Every value is positive and at most the profile maximum.
/// </summary>
public sealed record ContentSandboxLimits
{
    /// <summary>The profile maximum input (256 MiB).</summary>
    public const ulong ProfileMaxInputBytes = 256UL * 1024 * 1024;

    /// <summary>The profile maximum helper memory (1 GiB), also the Job Object memory limit.</summary>
    public const ulong ProfileMaxMemoryBytes = 1UL * 1024 * 1024 * 1024;

    /// <summary>The profile maximum output (three 64 MiB slots).</summary>
    public const ulong ProfileMaxOutputBytes = 3UL * 64 * 1024 * 1024;

    /// <summary>The profile maximum image or page dimension.</summary>
    public const uint ProfileMaxDimension = 65535;

    /// <summary>The profile maximum number of items (text boxes, channels, tags) a result carries.</summary>
    public const uint ProfileMaxItems = 1024;

    /// <summary>The profile maximum parser deadline of one call (30 s).</summary>
    public const uint ProfileMaxTimeoutMs = 30_000;

    /// <summary>The most input bytes the helper may map.</summary>
    public ulong MaxInputBytes { get; init; } = 64UL * 1024 * 1024;

    /// <summary>The most memory the whole helper process may commit.</summary>
    public ulong MaxMemoryBytes { get; init; } = 512UL * 1024 * 1024;

    /// <summary>The most output bytes one invocation may seal.</summary>
    public ulong MaxOutputBytes { get; init; } = ProfileMaxOutputBytes;

    /// <summary>The widest image or page.</summary>
    public uint MaxWidth { get; init; } = 16384;

    /// <summary>The tallest image or page.</summary>
    public uint MaxHeight { get; init; } = 16384;

    /// <summary>The most items one result carries.</summary>
    public uint MaxItems { get; init; } = ProfileMaxItems;

    /// <summary>The longest one parser call may run, in milliseconds.</summary>
    public uint TimeoutMs { get; init; } = 10_000;

    /// <summary>True when every value is positive and within the profile maximum.</summary>
    public bool IsWithinProfile() =>
        MaxInputBytes is > 0 and <= ProfileMaxInputBytes
        && MaxMemoryBytes is > 0 and <= ProfileMaxMemoryBytes
        && MaxOutputBytes is > 0 and <= ProfileMaxOutputBytes
        && MaxWidth is > 0 and <= ProfileMaxDimension
        && MaxHeight is > 0 and <= ProfileMaxDimension
        && MaxItems is > 0 and <= ProfileMaxItems
        && TimeoutMs is > 0 and <= ProfileMaxTimeoutMs;

    internal SandboxLimits ToWire() => new()
    {
        MaxInputBytes = MaxInputBytes,
        MaxMemoryBytes = MaxMemoryBytes,
        MaxOutputBytes = MaxOutputBytes,
        MaxWidth = MaxWidth,
        MaxHeight = MaxHeight,
        MaxItems = MaxItems,
        TimeoutMs = TimeoutMs,
    };

    /// <summary>Reads wire limits; a missing value, or one not positive and within the profile, is refused.</summary>
    internal static bool TryFromWire(SandboxLimits? wire, out ContentSandboxLimits limits)
    {
        limits = new ContentSandboxLimits();
        if (wire is null
            || !wire.HasMaxInputBytes || !wire.HasMaxMemoryBytes || !wire.HasMaxOutputBytes
            || !wire.HasMaxWidth || !wire.HasMaxHeight || !wire.HasMaxItems || !wire.HasTimeoutMs)
        {
            return false;
        }

        var candidate = new ContentSandboxLimits
        {
            MaxInputBytes = wire.MaxInputBytes,
            MaxMemoryBytes = wire.MaxMemoryBytes,
            MaxOutputBytes = wire.MaxOutputBytes,
            MaxWidth = wire.MaxWidth,
            MaxHeight = wire.MaxHeight,
            MaxItems = wire.MaxItems,
            TimeoutMs = wire.TimeoutMs,
        };
        if (!candidate.IsWithinProfile())
        {
            return false;
        }

        limits = candidate;
        return true;
    }

    /// <summary>True when no value exceeds the corresponding value of <paramref name="budget"/>: a request may lower a budget, never raise it.</summary>
    internal bool FitsWithin(ContentSandboxLimits budget) =>
        MaxInputBytes <= budget.MaxInputBytes && MaxMemoryBytes <= budget.MaxMemoryBytes
        && MaxOutputBytes <= budget.MaxOutputBytes && MaxWidth <= budget.MaxWidth
        && MaxHeight <= budget.MaxHeight && MaxItems <= budget.MaxItems && TimeoutMs <= budget.TimeoutMs;
}
