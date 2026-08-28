// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcChat.Desktop;

/// <summary>
/// The values the composition root needs before any service is registered. Step 02 replaces the
/// string identifiers with the stable <c>ProductId</c>/<c>InstanceId</c> contract types.
/// </summary>
internal sealed record DesktopHostOptions
{
    /// <summary>Stable product identifier from `implementation-repository-layout.md` §14.1.</summary>
    public required string ProductId { get; init; }

    /// <summary>Identifier of this desktop instance; the runtime endpoint is derived from it.</summary>
    public required string InstanceId { get; init; }

    /// <summary>True when the host was started with <c>--smoke</c> and must not open a window.</summary>
    public bool SmokeMode { get; init; }
}
