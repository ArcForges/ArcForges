// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Capabilities;

/// <summary>
/// Closed aspect keys for capability health probes. These name probe dimensions only; they carry
/// no observed value and do not replace installation, presence, health, readiness or compatibility axes.
/// </summary>
public enum HealthDimension
{
    Reachable = 1,
    Ready = 2,
    Healthy = 3,
    Degraded = 4,
    Capacity = 5,
}
