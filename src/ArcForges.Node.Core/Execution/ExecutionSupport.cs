// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Policy;

namespace ArcForges.Node.Core.Execution;

[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(List<string>))]
internal sealed partial class ExecutionJsonContext : JsonSerializerContext;

/// <summary>An awaitable signal that wakes every waiter each time it is pulsed (output appended, a state changed).</summary>
public sealed class AsyncPulse
{
    private TaskCompletionSource _current = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Wakes the current waiters.</summary>
    public void Pulse() => Interlocked.Exchange(ref _current, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)).TrySetResult();

    /// <summary>Waits for the next pulse, at most <paramref name="timeout"/>; true when pulsed.</summary>
    public async Task<bool> WaitAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        var task = Volatile.Read(ref _current).Task;
        var finished = await Task.WhenAny(task, Task.Delay(timeout, cancellationToken)).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return finished == task;
    }

    /// <summary>The task completed by the next pulse.</summary>
    public Task Next => Volatile.Read(ref _current).Task;
}

/// <summary>
/// The execution settings in force, read from the current policy (policy.proto <c>ResourcePolicy</c>, <c>StoragePolicy</c>) and the
/// machine's capacity (03 section 2): the interim global running limit, the root and attempt limits, and the runtime disk limits.
/// </summary>
public sealed class ExecutionSettings
{
    private const long GiB = 1024L * 1024 * 1024;
    private const long MiB = 1024L * 1024;

    /// <summary>Builds the settings.</summary>
    public ExecutionSettings(PolicyDocument policy, int logicalProcessors, long physicalMemory)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var resources = policy.Resources ?? new ResourcePolicy();
        var storage = policy.Storage ?? new StoragePolicy();
        CapacityCpu = Math.Max(1, logicalProcessors) * 1000L;
        CapacityMemory = Math.Max(1, physicalMemory);
        ReserveCpu = (long)((resources.HasReserveCpuFixedMillicores ? resources.ReserveCpuFixedMillicores : 1000)
            + ((resources.HasReserveCpuFraction ? resources.ReserveCpuFraction : 0.10) * CapacityCpu));
        ReserveMemory = (long)((resources.HasReserveMemFixedBytes ? (long)resources.ReserveMemFixedBytes : 2 * GiB)
            + ((resources.HasReserveMemFraction ? resources.ReserveMemFraction : 0.10) * CapacityMemory));
        var minManaged = resources.HasMinManagedCpuMillicores ? resources.MinManagedCpuMillicores : 1000;
        MinManagedCpu = minManaged;
        AlphaUp = resources.HasSmoothingAlphaUp && resources.SmoothingAlphaUp is >= 0.05 and <= 1 ? resources.SmoothingAlphaUp : 0.5;
        AlphaDown = resources.HasSmoothingAlphaDown && resources.SmoothingAlphaDown is >= 0.01 and <= 1 ? resources.SmoothingAlphaDown : 0.1;
        var pressure = resources.Pressure ?? new PressureThresholds();
        Pressure = new PressureLimits(
            Fraction(pressure.HasTightAvailableFraction, pressure.TightAvailableFraction, 0.10),
            Fraction(pressure.HasPressureAvailableFraction, pressure.PressureAvailableFraction, 0.05),
            Fraction(pressure.HasCriticalAvailableFraction, pressure.CriticalAvailableFraction, 0.02),
            pressure.HasMemoryPsiSomeAvg10 ? pressure.MemoryPsiSomeAvg10 : 20,
            !pressure.HasFreezeOnPressure || pressure.FreezeOnPressure,
            !pressure.HasCancelOnCritical || pressure.CancelOnCritical);

        // The root limits stay at U = 0 until the root follows the measured budget (AF-SCHED-01): B_cpu = max(min_managed, C - R),
        // B_mem = max(0, C - R). The measured budgets of 03 section 2 are the resource monitor's (ResourceMonitor).
        BudgetCpu = Math.Max(minManaged, CapacityCpu - ReserveCpu);
        ManagedMemory = Math.Max(256 * MiB, CapacityMemory - ReserveMemory);
        CommitFactor = resources.HasCommitFactor && resources.CommitFactor is >= 1.0 and <= 4.0 ? resources.CommitFactor : 1.5;
        MaxTaskMemory = resources.HasMaxTaskMemoryBytes && resources.MaxTaskMemoryBytes > 0 ? (long)resources.MaxTaskMemoryBytes : ManagedMemory;
        GlobalMaxRunning = resources.HasGlobalMaxRunning && resources.GlobalMaxRunning > 0
            ? (int)resources.GlobalMaxRunning
            : (int)Math.Min(64, 2 * CapacityCpu / 1000);
        MaxOutputBytes = storage.HasMaxAttemptOutputBytes ? (long)storage.MaxAttemptOutputBytes : 2 * GiB;
        MaxTmpBytes = storage.HasMaxAttemptTmpBytes ? (long)storage.MaxAttemptTmpBytes : 20 * GiB;
        MaxTmpEntries = storage.HasMaxAttemptTmpEntries ? (long)storage.MaxAttemptTmpEntries : 1_000_000;
        CriticalFreeBytes = storage.HasCriticalFreeBytes ? (long)storage.CriticalFreeBytes : 512 * MiB;
        MinFreeBytes = storage.HasMinFreeBytes ? (long)storage.MinFreeBytes : GiB;
        LowFreeCapBytes = storage.HasLowFreeCapBytes ? (long)storage.LowFreeCapBytes : 20 * GiB;
        DiskLimitAction = storage.HasDiskLimitAction && storage.DiskLimitAction == Contracts.Node.V1.DiskLimitAction.Notify ? "NOTIFY" : "TERMINATE";
        GuardTakeoverMs = storage.HasGuardTakeoverMs ? (int)Math.Clamp(storage.GuardTakeoverMs, 2000u, 60_000u) : 5000;
        SecretRetention = TimeSpan.FromHours(storage.HasSecretRetentionHours ? storage.SecretRetentionHours : 24);
        KeepFailedTmp = !storage.HasKeepFailedTmp || storage.KeepFailedTmp;
        KeepFailedTmpHours = storage.HasKeepFailedTmpHours ? (int)storage.KeepFailedTmpHours : 24;
        SwapAllowance = resources.HasSwapAllowanceBytes ? (long)Math.Min(resources.SwapAllowanceBytes, long.MaxValue) : 0;
        AllowUnenforced = resources.HasAllowUnenforced ? resources.AllowUnenforced : null;
        SecretNames = new SecretNameMatcher(policy.Privacy?.SecretNamePatterns.Count > 0 ? policy.Privacy.SecretNamePatterns : DefaultPolicy.SecretNamePatterns);
        Pools = policy.Pools.Count > 0 ? [.. policy.Pools.Select(pool => pool.Name)] : [.. DefaultPolicy.BuiltInPools];
        AcceptAgentAssertions = policy.RetrySafety?.AcceptAgentAssertions ?? false;
    }

    private static double Fraction(bool present, double value, double fallback) => present && value is > 0 and < 1 ? value : fallback;

    /// <summary><c>C_cpu</c> in millicores.</summary>
    public long CapacityCpu { get; }

    /// <summary><c>C_mem</c>.</summary>
    public long CapacityMemory { get; }

    /// <summary><c>R_cpu</c>.</summary>
    public long ReserveCpu { get; }

    /// <summary><c>R_mem</c>.</summary>
    public long ReserveMemory { get; }

    /// <summary><c>B_cpu</c> with no unmanaged load (the root's CPU cap until AF-SCHED-01).</summary>
    public long BudgetCpu { get; }

    /// <summary><c>min_managed_cpu</c> (default 1,000 millicores).</summary>
    public long MinManagedCpu { get; }

    /// <summary><c>smoothing_alpha_up</c> (default 0.5).</summary>
    public double AlphaUp { get; }

    /// <summary><c>smoothing_alpha_down</c> (default 0.1).</summary>
    public double AlphaDown { get; }

    /// <summary>The pressure thresholds and actions of 03 section 7 (<c>resources.pressure</c>).</summary>
    public PressureLimits Pressure { get; }

    /// <summary><c>C_mem - R_mem</c> (the managed share; the interim <c>B_mem</c>).</summary>
    public long ManagedMemory { get; }

    /// <summary><c>commit_factor</c>.</summary>
    public double CommitFactor { get; }

    /// <summary><c>max_task_memory</c>.</summary>
    public long MaxTaskMemory { get; }

    /// <summary>The interim global running limit (<c>global_max_running</c>; 0 = <c>min(64, 2 x C_cpu/1000)</c>).</summary>
    public int GlobalMaxRunning { get; }

    /// <summary><c>storage.max_attempt_output_bytes</c>.</summary>
    public long MaxOutputBytes { get; }

    /// <summary><c>storage.max_attempt_tmp_bytes</c>.</summary>
    public long MaxTmpBytes { get; }

    /// <summary><c>storage.max_attempt_tmp_entries</c>.</summary>
    public long MaxTmpEntries { get; }

    /// <summary><c>storage.critical_free_bytes</c>.</summary>
    public long CriticalFreeBytes { get; }

    /// <summary><c>storage.min_free_bytes</c> (default 1 GiB).</summary>
    public long MinFreeBytes { get; }

    /// <summary><c>storage.low_free_cap_bytes</c> (default 20 GiB).</summary>
    public long LowFreeCapBytes { get; }

    /// <summary>
    /// The disk pressure level of a volume (06 section 5): <c>CRITICAL</c> below <c>critical_free_bytes</c>, <c>LOW</c> below
    /// <c>max(min_free_bytes, min(5% of the volume, low_free_cap_bytes))</c>.
    /// </summary>
    public DiskPressureLevel DiskLevel(long totalBytes, long freeBytes) =>
        freeBytes < CriticalFreeBytes ? DiskPressureLevel.Critical
        : freeBytes < Math.Max(MinFreeBytes, Math.Min(totalBytes / 20, LowFreeCapBytes)) ? DiskPressureLevel.Low
        : DiskPressureLevel.Normal;

    /// <summary><c>TERMINATE</c> or <c>NOTIFY</c>.</summary>
    public string DiskLimitAction { get; }

    /// <summary><c>storage.guard_takeover_ms</c>.</summary>
    public int GuardTakeoverMs { get; }

    /// <summary><c>storage.secret_retention_hours</c>.</summary>
    public TimeSpan SecretRetention { get; }

    /// <summary><c>storage.keep_failed_tmp</c>.</summary>
    public bool KeepFailedTmp { get; }

    /// <summary><c>storage.keep_failed_tmp_hours</c>.</summary>
    public int KeepFailedTmpHours { get; }

    /// <summary><c>privacy.secret_name_patterns</c>.</summary>
    public SecretNameMatcher SecretNames { get; }

    /// <summary>The pool names.</summary>
    public IReadOnlyList<string> Pools { get; }

    /// <summary><c>retry_safety.accept_agent_assertions</c>.</summary>
    public bool AcceptAgentAssertions { get; }

    /// <summary><c>resources.swap_allowance_bytes</c> (default 0): Linux <c>MemorySwapMax</c> of the slice and of each attempt (03 section 5.4).</summary>
    public long SwapAllowance { get; }

    /// <summary>
    /// <c>resources.allow_unenforced</c>, or null when the policy does not set it (03 section 8: then true on an observe-only node, so tasks
    /// run with <c>unenforced=true</c>; false refuses every task while enforcement is missing).
    /// </summary>
    public bool? AllowUnenforced { get; }

    /// <summary>
    /// The root container's limits (03 section 5.1): Windows a CPU rate, a commit limit of <c>commit_factor x (C_mem - R_mem)</c> and a
    /// notification limit at <c>B_mem</c>; Linux <c>CPUQuota</c> from the same rate, <c>MemoryHigh = B_mem</c>, the hard bound
    /// <c>MemoryMax = C_mem - R_mem</c> and <c>MemorySwapMax = swap_allowance</c>.
    /// </summary>
    public ArcForges.Node.Platform.RootLimits RootLimits() => new(
        (int)Math.Clamp(Math.Round((double)BudgetCpu / CapacityCpu * 10_000), 100, 10_000),
        (long)(CommitFactor * ManagedMemory),
        ManagedMemory)
    {
        HardMemoryBytes = ManagedMemory,
        SwapAllowanceBytes = SwapAllowance,
    };

    /// <summary>
    /// The measured budgets of 03 section 2 for smoothed unmanaged use <paramref name="unmanagedCpu"/> and <paramref name="unmanagedMemory"/>:
    /// <c>B_cpu = max(min_managed_cpu, C_cpu - R_cpu - U_cpu)</c> and <c>B_mem = max(0, C_mem - R_mem - U_mem)</c>.
    /// </summary>
    public (long Cpu, long Memory) Budgets(long unmanagedCpu, long unmanagedMemory) =>
        (Math.Max(MinManagedCpu, CapacityCpu - ReserveCpu - Math.Max(0, unmanagedCpu)), Math.Max(0, CapacityMemory - ReserveMemory - Math.Max(0, unmanagedMemory)));

    /// <summary>The CPU weight of a priority (03 section 5.2).</summary>
    public static int Weight(Priority priority) => priority switch
    {
        Priority.Interactive => 9,
        Priority.High => 7,
        Priority.Low => 3,
        Priority.Background => 1,
        _ => 5,
    };

    /// <summary>An attempt's request (03 section 3: the hint, or the generic default), with its ceiling.</summary>
    public (long Cpu, long Expected, long Ceiling, EstimateSource Source) Request(ResourceDemand? hint)
    {
        if (hint is { } demand && (demand.HasCpuMillicores || demand.HasMemExpectedBytes || demand.HasMemCeilingBytes))
        {
            var expected = demand.HasMemExpectedBytes ? (long)demand.MemExpectedBytes : 512 * MiB;
            var ceiling = demand.HasMemCeilingBytes
                ? (long)demand.MemCeilingBytes
                : Math.Min(MaxTaskMemory, Math.Max(2 * expected, expected + GiB));
            return (demand.HasCpuMillicores ? demand.CpuMillicores : 1000, expected, Math.Max(expected, ceiling), EstimateSource.Hint);
        }

        return (1000, 512 * MiB, Math.Max(512 * MiB, Math.Min(MaxTaskMemory, ManagedMemory / 2)), EstimateSource.Default);
    }
}

/// <summary>The pressure thresholds and actions in force (03 section 7; policy.proto <c>PressureThresholds</c>).</summary>
/// <param name="Tight">Tight below this fraction of <c>C_mem</c> available (default 0.10).</param>
/// <param name="Pressure">Pressure below this fraction (default 0.05).</param>
/// <param name="Critical">Critical below this fraction (default 0.02).</param>
/// <param name="MemoryPsi">Pressure when Linux <c>memory some avg10</c> exceeds this (default 20).</param>
/// <param name="FreezeOnPressure">Freeze pausable attempts at Pressure (default true).</param>
/// <param name="CancelOnCritical">Stop preemptible attempts at Critical (default true).</param>
public sealed record PressureLimits(double Tight, double Pressure, double Critical, double MemoryPsi, bool FreezeOnPressure, bool CancelOnCritical);

/// <summary>Summaries, fingerprints and digests of commands (node-store.md <c>task</c>).</summary>
public static class CommandText
{
    /// <summary>The longest title and summary.</summary>
    public const int MaxSummary = 200;

    /// <summary>A redacted one-line summary: secret-shaped <c>NAME=value</c> arguments show only the name.</summary>
    public static string Summary(CommandSpec command, SecretNameMatcher secrets)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(secrets);
        string text;
        if (command.FormCase == CommandSpec.FormOneofCase.Argv)
        {
            text = string.Join(' ', command.Argv.Argv.Select(argument => Redact(argument, secrets)).Select(argument =>
                argument.Contains(' ', StringComparison.Ordinal) ? "\"" + argument + "\"" : argument));
        }
        else
        {
            var script = command.Shell.Script.ReplaceLineEndings(" ");
            text = command.Shell.Kind.ToString().ToLowerInvariant() + ": " + script;
        }

        text = text.ReplaceLineEndings(" ");
        return text.Length <= MaxSummary ? text : string.Concat(text.AsSpan(0, MaxSummary - 3), "...");
    }

    /// <summary>The command fingerprint: the program's file name, lower case, and its first non-option argument.</summary>
    public static string Fingerprint(CommandSpec command)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (command.FormCase != CommandSpec.FormOneofCase.Argv)
        {
            return "shell:" + command.Shell.Kind.ToString().ToLowerInvariant();
        }

        var argv = command.Argv.Argv;
        var program = Path.GetFileNameWithoutExtension(argv[0].Replace('\\', '/').Split('/')[^1]).ToLowerInvariant();
        var verb = argv.Skip(1).FirstOrDefault(argument => !argument.StartsWith('-') && !argument.StartsWith('/'));
        return verb is null ? program : program + " " + verb.ToLowerInvariant();
    }

    /// <summary>
    /// The <c>join_existing</c> identity (tasks.proto): SHA-256 over the program and arguments (or the shell string), the working
    /// directory, the environment digest and the stdin.
    /// </summary>
    public static byte[] Digest(TaskSpec spec, ReadOnlySpan<byte> environmentDigest)
    {
        ArgumentNullException.ThrowIfNull(spec);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        void Add(string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            hash.AppendData(BitConverter.GetBytes(bytes.Length));
            hash.AppendData(bytes);
        }

        Add("arcforges.command-digest.v1");
        if (spec.Command.FormCase == CommandSpec.FormOneofCase.Argv)
        {
            Add("argv");
            foreach (var argument in spec.Command.Argv.Argv)
            {
                Add(argument);
            }
        }
        else
        {
            Add("shell:" + ((int)spec.Command.Shell.Kind).ToString(CultureInfo.InvariantCulture));
            Add(spec.Command.Shell.Script);
        }

        Add(spec.WorkingDirectory);
        hash.AppendData(environmentDigest);
        Add(((int)(spec.Stdin?.Mode ?? StdinMode.None)).ToString(CultureInfo.InvariantCulture));
        if (spec.Stdin is { } stdin)
        {
            hash.AppendData(stdin.Data.Span);
            Add(stdin.FilePath);
        }

        return hash.GetHashAndReset();
    }

    private static string Redact(string argument, SecretNameMatcher secrets)
    {
        var equals = argument.IndexOf('=', StringComparison.Ordinal);
        if (equals <= 0)
        {
            return argument;
        }

        var name = argument[..equals].TrimStart('-');
        return name.Length > 0 && secrets.IsSecret(name) ? argument[..(equals + 1)] + "<redacted>" : argument;
    }
}
