// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Platform;

namespace ArcForges.Node.Core.Execution;

/// <summary>
/// Supplies an attempt's launch and end steps (04 section 3). Toolchain adapters implement it (the per-attempt compiler servers of
/// AF-TOOL-02); without a provider an attempt has no steps.
/// </summary>
public interface ILaunchStepProvider
{
    /// <summary>The launch and end steps of an attempt of <paramref name="spec"/>.</summary>
    (IReadOnlyList<StepSpec> Launch, IReadOnlyList<StepSpec> End) StepsFor(TaskSpec spec, AttemptFiles files);
}

/// <summary>
/// Controlled faults for fault-injection tests (16 section 1), honoured only with <c>--test-mode</c> (02 section 4: test hooks), from
/// <c>ARCFORGES_TEST_FAULT</c>: a comma-separated list of <c>name=seconds</c>. Each fault fires once per data root (a marker file in
/// <c>run/</c> records it), so a node restarted by its supervisor runs normally:
/// <list type="bullet">
/// <item><c>slow-startup=N</c>: startup waits N seconds before opening the store (a long store migration).</item>
/// <item><c>slow-ready=N</c>: startup waits N seconds after the API listener started, before the node is READY (a slow recovery tail:
/// the node answers hellos in RECOVERING meanwhile).</item>
/// <item><c>hang-tailer-after=N</c>: the enforcement loop hangs N seconds after it started (a hung monitor).</item>
/// <item><c>hang-probe-after=N</c>: a heartbeat probe stops answering N seconds after it started (a hung cache store).</item>
/// <item><c>kill-before-ack=N</c>: the node kills itself N seconds after it recorded a finished attempt, before it acknowledges the exit
/// record (a crash between the commit and the acknowledgement).</item>
/// <item><c>hold-preempt-before-stop=N</c>: holds the first preemption before its platform stop for N seconds, so a test can kill the
/// node after STOPPING committed while its command is still running (MR-100).</item>
/// <item><c>hold-stop-before-stop=N</c>: holds a non-pressure stop after STOPPING commits, before platform action (MR-99).</item>
/// <item><c>hold-finalizing=N</c>: holds finalization after FINALIZING commits, before final output/accounting/result work (MR-99).</item>
/// <item><c>finalize-throw=0</c>: the first finalization throws an exception no handler expects (NotSupportedException) before it
/// records.</item>
/// <item><c>escaped-record-queue-full=0</c>: the first write of escaped-process records finds the command queue full, as
/// <see cref="CommandProcessor.ExecuteAsync{T}"/> reports it (the scan keeps the processes and writes them again).</item>
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

/// <summary>The heartbeat probe of the <c>hang-probe-after</c> fault: it answers until its delay passed, then never.</summary>
internal sealed class FaultProbe(TimeSpan hangAfter, TimeProvider clock) : IHeartbeatProbe
{
    private readonly long _started = clock.GetTimestamp();

    public string Name => "fault-probe";

    public Task ProbeAsync(CancellationToken cancellationToken) =>
        clock.GetElapsedTime(_started) < hangAfter ? Task.CompletedTask : Task.Delay(Timeout.Infinite, cancellationToken);
}
