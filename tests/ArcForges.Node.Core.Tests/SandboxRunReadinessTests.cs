// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Sandboxes;

namespace ArcForges.Node.Core.Tests;

public sealed class SandboxRunReadinessTests
{
    [Fact]
    public void RequiredProfileEvidenceAndALauncherAreNeededForReadiness()
    {
        const string Evidence = "sha256:fixture";
        Capability profile = new()
        {
            Key = SandboxRunReadiness.ProfileKey,
            State = CapabilityState.Available,
            EvidenceId = Evidence,
        };
        Capability unverifiedOptional = new()
        {
            Key = "mxc.network.selected_egress.observation",
            State = CapabilityState.Unverified,
        };
        Capability unsupportedOptional = new()
        {
            Key = "mxc.network.ingress",
            State = CapabilityState.Unsupported,
        };

        var current = SandboxRunReadiness.Observe([profile, unverifiedOptional, unsupportedOptional], launcherConfigured: true);
        Assert.True(current.Qualified);
        Assert.Equal(Evidence, current.EvidenceId);

        var unavailable = SandboxRunReadiness.Observe([profile], launcherConfigured: false);
        Assert.False(unavailable.Qualified);
        Assert.Equal(CapabilityState.Disabled, unavailable.State);
        Assert.Equal("run_launcher_unavailable", unavailable.Reason);

        profile.ClearEvidenceId();
        var unevidenced = SandboxRunReadiness.Observe([profile], launcherConfigured: true);
        Assert.False(unevidenced.Qualified);
        Assert.Equal("qualification_receipt_missing", unevidenced.Reason);
        Assert.False(SandboxRunReadiness.Observe([unverifiedOptional], launcherConfigured: true).Qualified);
    }

    [Theory]
    [InlineData(CapabilityState.Unsupported, "operating_system_not_supported")]
    [InlineData(CapabilityState.Unverified, "installed_profile_outside_qualification")]
    [InlineData(CapabilityState.Unverified, "required_host_prerequisite_missing")]
    public void TheOriginalProfileDecisionAndReasonArePreserved(CapabilityState state, string reason)
    {
        var observation = SandboxRunReadiness.Observe(
            [new Capability { Key = SandboxRunReadiness.ProfileKey, State = state, Reason = reason }],
            launcherConfigured: false);

        Assert.False(observation.Qualified);
        Assert.Equal(state, observation.State);
        Assert.Equal(reason, observation.Reason);
    }

    [Fact]
    public void MissingInstallationRemainsUnverifiedInTheV2Diagnostic()
    {
        var absent = Path.Combine(Path.GetTempPath(), "arcforges-missing-mxc-" + Guid.NewGuid().ToString("N"));
        var capabilities = SandboxPolicyAdmission.HandshakeCapabilities(Path.GetTempPath(), absent);
        var readiness = SandboxRunReadiness.Observe(capabilities, launcherConfigured: true);

        Assert.False(readiness.Qualified);
        if (OperatingSystem.IsWindows() || OperatingSystem.IsLinux())
        {
            Assert.Equal(CapabilityState.Unverified, readiness.State);
            Assert.Equal("official_mxc_installation_missing", readiness.Reason);
        }
        else
        {
            Assert.Equal(CapabilityState.Unsupported, readiness.State);
            Assert.Equal("operating_system_not_supported", readiness.Reason);
        }
    }
}
