// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Execution;

namespace ArcForges.Node.Core.Resources;

/// <summary>
/// The asymmetric smoothing of 03 section 2: <c>x_t = x_{t-1} + alpha * (sample - x_{t-1})</c> with <c>alpha_up</c> when the sample
/// rises and <c>alpha_down</c> when it falls, so the user's own load is respected quickly and released slowly. The first sample is
/// taken as it is.
/// </summary>
public sealed class AsymmetricSmoother
{
    /// <summary>The smoothed value, or <see langword="null"/> before the first sample.</summary>
    public double? Value { get; private set; }

    /// <summary>Adds a sample and returns the smoothed value.</summary>
    public double Update(double sample, double alphaUp, double alphaDown)
    {
        if (Value is not { } previous)
        {
            Value = sample;
            return sample;
        }

        var alpha = sample > previous ? alphaUp : alphaDown;
        Value = previous + (alpha * (sample - previous));
        return Value.Value;
    }
}

/// <summary>What one pressure evaluation reads (03 section 7).</summary>
/// <param name="AvailableBytes">Available memory now.</param>
/// <param name="CapacityBytes"><c>C_mem</c>.</param>
/// <param name="CapacityCpu"><c>C_cpu</c> in millicores.</param>
/// <param name="UnmanagedCpu">The smoothed <c>U_cpu</c>.</param>
/// <param name="MemoryPsi">Linux <c>memory some avg10</c>, or <see langword="null"/> (Windows, or no PSI).</param>
/// <param name="OomKills">OOM kills machine-wide so far (Linux), 0 on Windows.</param>
public sealed record PressureInputs(long AvailableBytes, long CapacityBytes, long CapacityCpu, double UnmanagedCpu, double? MemoryPsi, long OomKills);

/// <summary>
/// The pressure levels of 03 section 7, evaluated every second with 5 s persistence: a level is entered once its condition held at every
/// evaluation for 5 s (six consecutive evaluations), and left once the lower level's condition held for 5 s, so unmanaged growth is detected within 1 s of sampling plus
/// 5 s of persistence and acted on at once (03 section 5.4; R-RES-014). An OOM kill seen machine-wide holds the Critical condition for
/// <see cref="OomHold"/>, so it persists like any other condition. Pure: the caller supplies the time and the samples.
/// </summary>
public sealed class PressureEvaluator
{
    /// <summary>How long a condition must hold before its level changes.</summary>
    public static readonly TimeSpan Persistence = TimeSpan.FromSeconds(5);

    /// <summary>
    /// The scheduling tolerance of the persistence: evaluations run every second but never exactly a second apart, so a condition true at
    /// six consecutive evaluations (5 s apart within half an interval) has persisted.
    /// </summary>
    public static readonly TimeSpan Tolerance = TimeSpan.FromMilliseconds(500);

    /// <summary>The window of the Tight CPU condition (<c>U_cpu</c> rose by more than 20% of <c>C_cpu</c> within 10 s).</summary>
    public static readonly TimeSpan CpuRiseWindow = TimeSpan.FromSeconds(10);

    /// <summary>How long an observed OOM kill holds the Critical condition.</summary>
    public static readonly TimeSpan OomHold = TimeSpan.FromSeconds(10);

    private readonly TimeSpan?[] _atLeastSince = new TimeSpan?[5];
    private readonly TimeSpan?[] _atMostSince = new TimeSpan?[5];
    private readonly Queue<(TimeSpan At, double Cpu)> _cpu = new();
    private long? _oomKills;
    private TimeSpan _oomUntil = TimeSpan.MinValue;

    /// <summary>The level in force.</summary>
    public PressureLevel Level { get; private set; } = PressureLevel.Normal;

    /// <summary>The level whose condition holds at the last evaluation, before persistence.</summary>
    public PressureLevel Raw { get; private set; } = PressureLevel.Normal;

    /// <summary>Why the raw level holds (the conditions that are true), for the journal and the findings.</summary>
    public string Trigger { get; private set; } = "available memory above every threshold";

    /// <summary>Evaluates one sample at <paramref name="now"/> (monotonic) and returns the level in force.</summary>
    public PressureLevel Evaluate(TimeSpan now, PressureInputs inputs, PressureLimits limits)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        ArgumentNullException.ThrowIfNull(limits);
        var capacity = (double)Math.Max(1, inputs.CapacityBytes);
        var available = inputs.AvailableBytes / capacity;

        if (_oomKills is { } previousKills && inputs.OomKills > previousKills)
        {
            _oomUntil = now + OomHold;
        }

        _oomKills = inputs.OomKills;
        _cpu.Enqueue((now, inputs.UnmanagedCpu));
        while (_cpu.Count > 0 && now - _cpu.Peek().At > CpuRiseWindow)
        {
            _cpu.Dequeue();
        }

        var rise = inputs.UnmanagedCpu - _cpu.Min(item => item.Cpu);
        var reasons = new List<string>();
        var raw = PressureLevel.Normal;
        if (available < limits.Critical || now < _oomUntil)
        {
            raw = PressureLevel.Critical;
            reasons.Add(now < _oomUntil ? "an OOM kill was observed" : Below(available, limits.Critical));
        }
        else if (available < limits.Pressure || inputs.MemoryPsi > limits.MemoryPsi)
        {
            raw = PressureLevel.Pressure;
            reasons.Add(available < limits.Pressure ? Below(available, limits.Pressure)
                : string.Create(CultureInfo.InvariantCulture, $"memory some avg10 {inputs.MemoryPsi:0.##} > {limits.MemoryPsi:0.##}"));
        }
        else if (available < limits.Tight || rise > 0.2 * inputs.CapacityCpu)
        {
            raw = PressureLevel.Tight;
            reasons.Add(available < limits.Tight ? Below(available, limits.Tight)
                : string.Create(CultureInfo.InvariantCulture, $"unmanaged CPU rose by {rise:0} millicores within 10 s (> 20% of {inputs.CapacityCpu})"));
        }

        Raw = raw;
        Trigger = reasons.Count == 0 ? "available memory above every threshold" : string.Join("; ", reasons);
        for (var level = (int)PressureLevel.Normal; level <= (int)PressureLevel.Critical; level++)
        {
            _atLeastSince[level] = (int)raw >= level ? _atLeastSince[level] ?? now : null;
            _atMostSince[level] = (int)raw <= level ? _atMostSince[level] ?? now : null;
        }

        if (raw > Level)
        {
            for (var level = (int)PressureLevel.Critical; level > (int)Level; level--)
            {
                if (_atLeastSince[level] is { } since && now - since >= Persistence - Tolerance)
                {
                    Level = (PressureLevel)level;
                    break;
                }
            }
        }
        else if (raw < Level)
        {
            for (var level = (int)PressureLevel.Normal; level < (int)Level; level++)
            {
                if (_atMostSince[level] is { } since && now - since >= Persistence - Tolerance)
                {
                    Level = (PressureLevel)level;
                    break;
                }
            }
        }

        return Level;
    }

    private static string Below(double available, double threshold) =>
        string.Create(CultureInfo.InvariantCulture, $"available memory {available:P1} of capacity < {threshold:P1}");
}
