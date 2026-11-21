// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Execution;

/// <summary>Thresholds for classifying observed host memory pressure.</summary>
public sealed record PressureLimits(double Tight, double Pressure, double Critical, double MemoryPsi)
{
    internal static PressureLimits FromPolicy(PressureThresholds? pressure)
    {
        pressure ??= new PressureThresholds();
        return new(Fraction(pressure.TightAvailableFraction, 0.10),
            Fraction(pressure.PressureAvailableFraction, 0.05), Fraction(pressure.CriticalAvailableFraction, 0.02),
            pressure.HasMemoryPsiSomeAvg10 ? pressure.MemoryPsiSomeAvg10 : 20);
    }

    private static double Fraction(double value, double fallback) => value is > 0 and <= 1 ? value : fallback;
}
