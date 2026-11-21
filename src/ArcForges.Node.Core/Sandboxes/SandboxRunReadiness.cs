// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Sandbox.V2;

namespace ArcForges.Node.Core.Sandboxes;

/// <summary>The latest default Run profile observation made by the V2 Handshake.</summary>
internal sealed record SandboxRunReadiness(CapabilityState State, string? Reason = null, string? EvidenceId = null)
{
    internal const string ProfileKey = "mxc.profile";

    internal static SandboxRunReadiness NotObserved { get; } = new(CapabilityState.Unverified, "run_profile_not_observed");

    internal static SandboxRunReadiness NoAuthority { get; } = new(CapabilityState.Disabled, "sandbox_authority_unavailable");

    internal bool Qualified => State == CapabilityState.Available && !string.IsNullOrEmpty(EvidenceId);

    internal static SandboxRunReadiness Observe(IReadOnlyList<Capability> capabilities, bool launcherConfigured)
    {
        var profile = capabilities.FirstOrDefault(item => item.Key == ProfileKey);
        if (profile is null)
            return NotObserved;
        if (profile.State != CapabilityState.Available)
            return new(profile.State, profile.Reason);
        if (string.IsNullOrEmpty(profile.EvidenceId))
            return new(CapabilityState.Unverified, "qualification_receipt_missing");

        return launcherConfigured ? new(CapabilityState.Available, EvidenceId: profile.EvidenceId)
            : new(CapabilityState.Disabled, "run_launcher_unavailable");
    }
}
