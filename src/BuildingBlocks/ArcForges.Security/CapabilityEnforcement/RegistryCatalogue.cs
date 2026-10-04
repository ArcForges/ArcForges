// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Capabilities;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Security.Decisions;

namespace ArcForges.Security.CapabilityEnforcement;

/// <summary>
/// Step 1 of the decision pipeline over the real first-party capability registry: the capability exists only when the registry holds
/// that exact key, and its descriptor (risk, approval and egress posture) is the registered one, never one a caller supplies.
/// </summary>
public sealed class RegistryCapabilityCatalogue : ICapabilityCatalogue
{
    private readonly CapabilityRegistry _registry;

    public RegistryCapabilityCatalogue(CapabilityRegistry registry)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
    }

    public ValueTask<CapabilityDescriptor?> FindAsync(string capabilityKey, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var registration = string.IsNullOrWhiteSpace(capabilityKey) ? null : _registry.Find(capabilityKey);
        return ValueTask.FromResult(registration?.Descriptor);
    }
}
