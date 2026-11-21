// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.Node.Core.Execution;

/// <summary>
/// Controlled faults for fault-injection tests (16 section 1), honoured only with <c>--test-mode</c> (02 section 4: test hooks), from
/// <c>ARCFORGES_TEST_FAULT</c>: a comma-separated list of <c>name=seconds</c>. Each fault fires once per data root (a marker file in
/// <c>run/</c> records it), so a node restarted by its supervisor runs normally:
/// <list type="bullet">
/// <item><c>slow-startup=N</c>: startup waits N seconds before opening the store (a long store migration).</item>
/// <item><c>slow-ready=N</c>: startup waits N seconds after the API listener started, before the node is READY (a slow recovery tail:
/// the node answers hellos in RECOVERING meanwhile).</item>
/// <item>Named Sandbox Run and data-transfer checkpoints hold the operation until released by the fixture or the delay elapses.</item>
/// </list>
/// </summary>
public sealed class ExecutionFaults
{
    /// <summary>The environment variable.</summary>
    public const string Variable = "ARCFORGES_TEST_FAULT";

    private readonly Dictionary<string, TimeSpan> _faults;
    private readonly string _runDirectory;

    private ExecutionFaults(Dictionary<string, TimeSpan> faults, string runDirectory)
    {
        _faults = faults;
        _runDirectory = runDirectory;
    }

    /// <summary>No faults.</summary>
    public static ExecutionFaults None { get; } = new([], string.Empty);

    /// <summary>The faults of this process (test mode only).</summary>
    public static ExecutionFaults FromEnvironment(bool testMode, string dataRoot)
    {
        ArgumentNullException.ThrowIfNull(dataRoot);
        if (!testMode || Environment.GetEnvironmentVariable(Variable) is not { Length: > 0 } text)
        {
            return None;
        }

        var faults = new Dictionary<string, TimeSpan>(StringComparer.Ordinal);
        foreach (var item in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = item.Split('=', 2);
            if (parts.Length == 2 && double.TryParse(parts[1], NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds))
            {
                faults[parts[0]] = TimeSpan.FromSeconds(seconds);
            }
        }

        return new ExecutionFaults(faults, Path.Combine(dataRoot, "run"));
    }

    /// <summary>Holds a test-mode fault up to its bound, or until its fixture writes the named release file in this data root.</summary>
    public void Hold(string name, TimeSpan maximum)
    {
        var release = Path.Combine(_runDirectory, "fault-" + name + ".release");
        var elapsed = System.Diagnostics.Stopwatch.StartNew();
        while (elapsed.Elapsed < maximum && !File.Exists(release))
        {
            Thread.Sleep(20);
        }
    }

    /// <summary>The delay of a fault that has not fired yet, marking it fired; <see langword="null"/> when absent or fired.</summary>
    public TimeSpan? Take(string name)
    {
        if (!_faults.TryGetValue(name, out var value))
        {
            return null;
        }

        var marker = Path.Combine(_runDirectory, "fault-" + name + ".done");
        if (File.Exists(marker))
        {
            return null;
        }

        Directory.CreateDirectory(_runDirectory);
        File.WriteAllText(marker, DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        return value;
    }
}
