// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Capabilities;

/// <summary>
/// Closed aspect keys for capability health probes. These name probe dimensions only; they carry
/// no observed value and do not replace installation, presence, health, readiness or compatibility axes.
/// </summary>
public enum HealthDimension
{
    Reachable = 0,
    Ready = 1,
    Healthy = 2,
    Degraded = 3,
    Capacity = 4,
}
