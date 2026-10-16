// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArcForges.Node.Platform;

/// <summary>
/// <c>logs/&lt;attempt&gt;/exit.json</c>, schema 1 (architecture 04 section 3): written by the attempt's holder on Windows (by
/// <c>exit-record</c> on Linux) once the root process exited, the end steps ran and the leftovers were terminated, with the job
/// accounting. The record is durable while the node is down; the node finalizes the attempt from it. Additive changes only.
/// </summary>
public sealed class ExitRecord
{
    /// <summary>The format version.</summary>
    public int Schema { get; set; } = 1;

    /// <summary>The attempt ID (base32).</summary>
    public string AttemptId { get; set; } = string.Empty;

    /// <summary><c>exited</c>, <c>killed</c> or <c>dumped</c> (Windows: <c>exited</c>; the exit code carries any termination).</summary>
    public string ExitCodeKind { get; set; } = "exited";

    /// <summary>The exit code (Windows: the 32-bit exit code as a signed integer), or the signal number.</summary>
    public int ExitStatus { get; set; }

    /// <summary><c>success</c>, <c>exit-code</c>, <c>signal</c>, <c>oom-kill</c> or <c>timeout</c>.</summary>
    public string ServiceResult { get; set; } = "success";

    /// <summary>When the record was written (RFC 3339 UTC).</summary>
    public string RecordedAt { get; set; } = string.Empty;

    /// <summary>User-mode CPU time of the container.</summary>
    public long CpuUserMs { get; set; }

    /// <summary>Kernel-mode CPU time of the container.</summary>
    public long CpuKernelMs { get; set; }

    /// <summary>Peak memory (Windows: peak job commit).</summary>
    public long MemPeakBytes { get; set; }

    /// <summary>Bytes read.</summary>
    public long IoReadBytes { get; set; }

    /// <summary>Bytes written.</summary>
    public long IoWriteBytes { get; set; }

    /// <summary>OOM kills (Linux; Windows has none).</summary>
    public long OomKills { get; set; }

    /// <summary>Limits the container exceeded, for example <c>job_memory</c>, <c>cpu_time</c>, <c>active_process</c>.</summary>
    public List<string> LimitViolations { get; set; } = [];

    /// <summary>Image names of the processes terminated after the root exited (one entry per process).</summary>
    public List<string> LeftoversTerminated { get; set; } = [];

    /// <summary>The peak swap use of the container (Linux <c>memory.swap.peak</c>); absent where the platform has none.</summary>
    public long? SwapPeakBytes { get; set; }

    /// <summary>
    /// Who wrote the record (additive, schema 1): <c>exit-record</c> (the unit's <c>ExecStopPost</c>), <c>unit</c> (the node, from the
    /// properties of a failed unit whose <c>ExecStopPost</c> systemd skipped), <c>node</c> (an attempt the node ran itself), or absent
    /// (the Windows holder).
    /// </summary>
    public string? RecordedBy { get; set; }

    /// <summary>Serializes the record (one JSON object).</summary>
    public string ToJson() => JsonSerializer.Serialize(this, HelperJsonContext.Default.ExitRecord);

    /// <summary>Parses a record.</summary>
    /// <exception cref="JsonException">The text is not an exit record.</exception>
    public static ExitRecord Parse(string json) => JsonSerializer.Deserialize(json, HelperJsonContext.Default.ExitRecord)
        ?? throw new JsonException("exit.json is empty.");

    /// <summary>Reads <paramref name="path"/>, or <see langword="null"/> when it does not exist or is not complete yet.</summary>
    public static ExitRecord? TryRead(string path) => HelperFiles.TryRead(path, Parse);
}

/// <summary>
/// <c>logs/&lt;attempt&gt;/launch.json</c>, schema 1 (04 section 3): a launch step or the command itself could not start. The node
/// records the attempt as <c>SPAWN_FAILED</c> (effect DID_NOT_HAPPEN) with the step's error.
/// </summary>
public sealed class LaunchRecord
{
    /// <summary>The format version.</summary>
    public int Schema { get; set; } = 1;

    /// <summary>The attempt ID (base32).</summary>
    public string AttemptId { get; set; } = string.Empty;

    /// <summary>The failed step's name, or <c>command</c> when the command itself could not be started.</summary>
    public string Step { get; set; } = string.Empty;

    /// <summary>What failed, in words (no environment values).</summary>
    public string Error { get; set; } = string.Empty;

    /// <summary>The step's exit code when it ran and failed.</summary>
    public int? ExitCode { get; set; }

    /// <summary>The operating-system error code when the start failed.</summary>
    public int? OsError { get; set; }

    /// <summary>When the record was written (RFC 3339 UTC).</summary>
    public string RecordedAt { get; set; } = string.Empty;

    /// <summary>Serializes the record.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, HelperJsonContext.Default.LaunchRecord);

    /// <summary>Parses a record.</summary>
    public static LaunchRecord Parse(string json) => JsonSerializer.Deserialize(json, HelperJsonContext.Default.LaunchRecord)
        ?? throw new JsonException("launch.json is empty.");

    /// <summary>Reads <paramref name="path"/>, or <see langword="null"/>.</summary>
    public static LaunchRecord? TryRead(string path) => HelperFiles.TryRead(path, Parse);
}

/// <summary>
/// <c>logs/&lt;attempt&gt;/guard.json</c>, schema 1 (06 section 5): written by the node before the attempt starts, so the attempt's guard
/// knows what to enforce while the node is down: the output files, the temporary directory, the volumes it writes to, the limits and
/// actions in force, and whether the attempt is preemptible and pausable.
/// </summary>
public sealed class GuardSpec
{
    /// <summary>The format version.</summary>
    public int Schema { get; set; } = 1;

    /// <summary>The attempt ID (base32).</summary>
    public string AttemptId { get; set; } = string.Empty;

    /// <summary>The captured output files (stdout and stderr); their sizes count against <see cref="MaxOutputBytes"/>.</summary>
    public List<string> OutputFiles { get; set; } = [];

    /// <summary>The attempt's temporary directory.</summary>
    public string TempDirectory { get; set; } = string.Empty;

    /// <summary>Volumes the attempt writes to (working directory, temporary directory, output root).</summary>
    public List<string> Volumes { get; set; } = [];

    /// <summary><c>storage.max_attempt_output_bytes</c> (0 = no limit).</summary>
    public long MaxOutputBytes { get; set; }

    /// <summary><c>storage.max_attempt_tmp_bytes</c>.</summary>
    public long MaxTmpBytes { get; set; }

    /// <summary><c>storage.max_attempt_tmp_entries</c>.</summary>
    public long MaxTmpEntries { get; set; }

    /// <summary><c>storage.critical_free_bytes</c>.</summary>
    public long CriticalFreeBytes { get; set; }

    /// <summary><c>storage.disk_limit_action</c>: <c>TERMINATE</c> or <c>NOTIFY</c>.</summary>
    public string DiskLimitAction { get; set; } = "TERMINATE";

    /// <summary><c>storage.guard_takeover_ms</c>.</summary>
    public int TakeoverMs { get; set; } = 5000;

    /// <summary>The node heartbeat file the guard watches.</summary>
    public string HeartbeatPath { get; set; } = string.Empty;

    /// <summary>Whether the attempt is preemptible.</summary>
    public bool Preemptible { get; set; }

    /// <summary>Whether the attempt is pausable.</summary>
    public bool Pausable { get; set; }

    /// <summary>Serializes the spec.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, HelperJsonContext.Default.GuardSpec);

    /// <summary>Parses a spec.</summary>
    public static GuardSpec Parse(string json) => JsonSerializer.Deserialize(json, HelperJsonContext.Default.GuardSpec)
        ?? throw new JsonException("guard.json is empty.");

    /// <summary>Reads <paramref name="path"/>, or <see langword="null"/>.</summary>
    public static GuardSpec? TryRead(string path) => HelperFiles.TryRead(path, Parse);
}

/// <summary>The kinds of <c>guard-events.jsonl</c> lines.</summary>
public static class GuardEventKinds
{
    /// <summary>The heartbeat went stale for <c>guard_takeover_ms</c>; the guard enforces the limits.</summary>
    public const string Takeover = "takeover";

    /// <summary>The heartbeat is fresh again; the guard stopped checking.</summary>
    public const string StandDown = "stand_down";

    /// <summary>The guard stopped the attempt at once (TERMINATE).</summary>
    public const string Terminate = "terminate";

    /// <summary>The guard recorded a limit crossing and left the attempt running (NOTIFY).</summary>
    public const string Notify = "notify";
}

/// <summary>
/// One line of <c>logs/&lt;attempt&gt;/guard-events.jsonl</c>, schema 1 (06 section 5): a guard action with its evidence. The node ingests
/// the lines when it returns and records the stops with <c>limit_enforced_by=GUARD</c>. <c>takeover</c> and <c>stand_down</c> lines record
/// when the guard was in charge.
/// </summary>
public sealed class GuardEvent
{
    /// <summary>The format version.</summary>
    public int Schema { get; set; } = 1;

    /// <summary>The attempt ID (base32).</summary>
    public string AttemptId { get; set; } = string.Empty;

    /// <summary>When (RFC 3339 UTC).</summary>
    public string At { get; set; } = string.Empty;

    /// <summary>One of <see cref="GuardEventKinds"/>.</summary>
    public string Event { get; set; } = string.Empty;

    /// <summary>For terminate and notify: <c>OUTPUT_LIMIT</c> (and later <c>DISK_LIMIT</c>).</summary>
    public string? Reason { get; set; }

    /// <summary>The captured output size the guard measured.</summary>
    public long? OutputBytes { get; set; }

    /// <summary>The limit in force.</summary>
    public long? LimitBytes { get; set; }

    /// <summary>How long the heartbeat had not changed, on the guard's monotonic clock.</summary>
    public long? HeartbeatAgeMs { get; set; }

    /// <summary>The heartbeat instance the guard saw last (empty when none).</summary>
    public string? HeartbeatInstance { get; set; }

    /// <summary>Serializes the event as one line (no line break).</summary>
    public string ToJson() => JsonSerializer.Serialize(this, HelperJsonContext.Default.GuardEvent);

    /// <summary>Reads every complete line of <paramref name="path"/>; a torn last line is skipped.</summary>
    public static List<GuardEvent> ReadAll(string path)
    {
        var events = new List<GuardEvent>();
        string text;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream, Encoding.UTF8);
            text = reader.ReadToEnd();
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            return events;
        }

        foreach (var line in text.Split('\n'))
        {
            if (line.Length == 0)
            {
                continue;
            }

            try
            {
                if (JsonSerializer.Deserialize(line, HelperJsonContext.Default.GuardEvent) is { } item)
                {
                    events.Add(item);
                }
            }
            catch (JsonException)
            {
                // A line torn by a crash during the append.
            }
        }

        return events;
    }

    /// <summary>Appends the event as one line.</summary>
    public void Append(string path)
    {
        var bytes = Encoding.UTF8.GetBytes(ToJson() + "\n");
        using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
    }
}

/// <summary>
/// The node heartbeat <c>run/node-heartbeat</c>, schema 1 (02 section 2, 06 section 5): renewed every second from the node's enforcement
/// loop with the node instance's ID and an increasing sequence number. Guards and the Windows supervisor judge staleness on their own
/// monotonic clocks by whether <c>(instance, seq)</c> changed; the wall-clock time is informational.
/// </summary>
public sealed class NodeHeartbeat
{
    /// <summary>The format version.</summary>
    public int Schema { get; set; } = 1;

    /// <summary>The node instance (a new random ID per node process).</summary>
    public string Instance { get; set; } = string.Empty;

    /// <summary>The renewal number within the instance, starting at 1.</summary>
    public long Seq { get; set; }

    /// <summary>The node's process ID.</summary>
    public int Pid { get; set; }

    /// <summary>When it was written (RFC 3339 UTC; informational).</summary>
    public string At { get; set; } = string.Empty;

    /// <summary>The identity guards compare.</summary>
    public string Token => Instance + ":" + Seq.ToString(CultureInfo.InvariantCulture);

    /// <summary>Writes the heartbeat atomically (a temporary file renamed over the old one).</summary>
    public void Write(string path)
    {
        var temporary = path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(this, HelperJsonContext.Default.NodeHeartbeat));
        File.Move(temporary, path, overwrite: true);
    }

    /// <summary>Reads the heartbeat, or <see langword="null"/> when it is absent, being replaced, or malformed.</summary>
    public static NodeHeartbeat? TryRead(string path) =>
        HelperFiles.TryRead(path, json => JsonSerializer.Deserialize(json, HelperJsonContext.Default.NodeHeartbeat));
}

/// <summary>
/// A launch or end step of an attempt (04 section 3): an adapter's command run by the holder inside the attempt's jobs, before the
/// root process is resumed (launch) or after it exited and before leftover termination (end). Steps inherit the attempt's environment
/// and working directory unless they name their own.
/// </summary>
public sealed class StepSpec
{
    /// <summary>The step's name (for records).</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>The executable (absolute path).</summary>
    public string Application { get; set; } = string.Empty;

    /// <summary>The complete command line (Windows) as the program receives it.</summary>
    public string CommandLine { get; set; } = string.Empty;

    /// <summary>The argument vector (Linux; <c>Argv[0]</c> as the program receives it, <see cref="Application"/> is the file executed).</summary>
    public List<string> Argv { get; set; } = [];

    /// <summary>The working directory, or empty for the attempt's.</summary>
    public string WorkingDirectory { get; set; } = string.Empty;

    /// <summary>
    /// How long the step may run until it exits (end steps also share the 10 s end-step budget). A step that starts a background
    /// process (for example a compiler server) returns once the server runs; the server stays in the attempt's jobs.
    /// </summary>
    public int TimeoutMs { get; set; } = 30_000;
}

/// <summary>
/// What the node tells an attempt's holder (<c>arcforges node exec-wrap</c>) on its standard input, schema 1: the command to start, its
/// environment and steps, and where the attempt's records go. It travels over a pipe, never through a file, because the environment
/// can carry sealed secret values (04 section 2). Additive changes only.
/// </summary>
public sealed class HolderSpec
{
    /// <summary>The format version.</summary>
    public int Schema { get; set; } = 1;

    /// <summary>The attempt ID (base32).</summary>
    public string AttemptId { get; set; } = string.Empty;

    /// <summary>The resolved executable.</summary>
    public string Application { get; set; } = string.Empty;

    /// <summary>The complete command line.</summary>
    public string CommandLine { get; set; } = string.Empty;

    /// <summary>The working directory.</summary>
    public string WorkingDirectory { get; set; } = string.Empty;

    /// <summary>The exact environment, as <c>NAME=value</c> entries.</summary>
    public List<string> Environment { get; set; } = [];

    /// <summary>Launch steps, in order.</summary>
    public List<StepSpec> LaunchSteps { get; set; } = [];

    /// <summary>End steps, in order.</summary>
    public List<StepSpec> EndSteps { get; set; } = [];

    /// <summary>The end-step budget (04 section 3: 10 s).</summary>
    public int EndStepBudgetMs { get; set; } = 10_000;

    /// <summary><c>leftover_grace</c> (04 section 3: default 5 s).</summary>
    public int LeftoverGraceMs { get; set; } = 5_000;

    /// <summary>The attempt's directory (<c>logs/&lt;attempt&gt;</c>).</summary>
    public string AttemptDirectory { get; set; } = string.Empty;

    /// <summary>Serializes the spec.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, HelperJsonContext.Default.HolderSpec);

    /// <summary>Parses a spec.</summary>
    public static HolderSpec Parse(string json) => JsonSerializer.Deserialize(json, HelperJsonContext.Default.HolderSpec)
        ?? throw new JsonException("The holder spec is empty.");
}

/// <summary>
/// <c>logs/&lt;attempt&gt;/steps.json</c>, schema 1 (Linux; 04 section 3): the attempt's launch and end steps, written by the node before
/// it starts the unit. <c>arcforges node exec-launch</c> runs the launch steps inside the unit's cgroup before it replaces itself with the
/// command; <c>arcforges node exec-stop</c> (the unit's <c>ExecStop</c>) runs the end steps. Steps carry no environment: they inherit the
/// unit's exact environment (<see cref="EnvironmentNames"/>). Additive changes only.
/// </summary>
public sealed class StepsFile
{
    /// <summary>The format version.</summary>
    public int Schema { get; set; } = 1;

    /// <summary>The attempt ID (base32).</summary>
    public string AttemptId { get; set; } = string.Empty;

    /// <summary>Launch steps, in order.</summary>
    public List<StepSpec> LaunchSteps { get; set; } = [];

    /// <summary>End steps, in order.</summary>
    public List<StepSpec> EndSteps { get; set; } = [];

    /// <summary>The end-step budget (04 section 3: 10 s).</summary>
    public int EndStepBudgetMs { get; set; } = 10_000;

    /// <summary><c>leftover_grace</c> (04 section 3: default 5 s).</summary>
    public int LeftoverGraceMs { get; set; } = 5_000;

    /// <summary>
    /// The names (never the values) of the attempt's resolved environment: <c>exec-launch</c> passes exactly these to the command and the
    /// steps and drops every other variable its process received (from the user manager or systemd itself), so the environment is exact
    /// whatever the manager adds. Null in files written before it existed.
    /// </summary>
    public List<string>? EnvironmentNames { get; set; }

    /// <summary>Serializes the file.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, HelperJsonContext.Default.StepsFile);

    /// <summary>Parses the file.</summary>
    public static StepsFile Parse(string json) => JsonSerializer.Deserialize(json, HelperJsonContext.Default.StepsFile)
        ?? throw new JsonException("steps.json is empty.");

    /// <summary>Reads <paramref name="path"/>, or <see langword="null"/>.</summary>
    public static StepsFile? TryRead(string path) => HelperFiles.TryRead(path, Parse);
}

/// <summary>What one end step did (<c>stop.json</c>).</summary>
public sealed class StepOutcome
{
    /// <summary>The step's name.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary><c>exited</c>, <c>failed</c>, <c>timed_out</c>, <c>not_started</c> or <c>skipped</c> (the budget was spent).</summary>
    public string Outcome { get; set; } = string.Empty;

    /// <summary>The step's exit code when it exited.</summary>
    public int? ExitCode { get; set; }

    /// <summary>How long it ran.</summary>
    public long ElapsedMs { get; set; }
}

/// <summary>
/// <c>logs/&lt;attempt&gt;/stop.json</c>, schema 1 (Linux): written by <c>arcforges node exec-stop</c> after the end steps ran and
/// <c>leftover_grace</c> passed, while the unit's remaining processes still run; <c>exit-record</c> copies the leftovers into
/// <c>exit.json</c> after systemd stopped them. Additive changes only.
/// </summary>
public sealed class StopRecord
{
    /// <summary>The format version.</summary>
    public int Schema { get; set; } = 1;

    /// <summary>The attempt ID (base32).</summary>
    public string AttemptId { get; set; } = string.Empty;

    /// <summary>The end steps and what they did.</summary>
    public List<StepOutcome> EndSteps { get; set; } = [];

    /// <summary>Image names of the processes still in the unit after <c>leftover_grace</c> (systemd stops them next).</summary>
    public List<string> Leftovers { get; set; } = [];

    /// <summary>When it was written (RFC 3339 UTC).</summary>
    public string RecordedAt { get; set; } = string.Empty;

    /// <summary>Serializes the record.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, HelperJsonContext.Default.StopRecord);

    /// <summary>Parses a record.</summary>
    public static StopRecord Parse(string json) => JsonSerializer.Deserialize(json, HelperJsonContext.Default.StopRecord)
        ?? throw new JsonException("stop.json is empty.");

    /// <summary>Reads <paramref name="path"/>, or <see langword="null"/>.</summary>
    public static StopRecord? TryRead(string path) => HelperFiles.TryRead(path, Parse);
}

/// <summary>A line the holder writes to the node on its standard output while the node listens.</summary>
public sealed class HolderReport
{
    /// <summary><c>started</c>, <c>spawn_failed</c>, <c>exited</c> (the root exited) or <c>recorded</c> (exit.json written).</summary>
    public string Event { get; set; } = string.Empty;

    /// <summary>The root process ID (started).</summary>
    public int Pid { get; set; }

    /// <summary>The root process creation time, Windows FILETIME (started).</summary>
    public long StartFileTime { get; set; }

    /// <summary>The root exit code (exited).</summary>
    public int ExitCode { get; set; }

    /// <summary>What failed (spawn_failed).</summary>
    public string? Error { get; set; }

    /// <summary>Serializes the report as one line.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, HelperJsonContext.Default.HolderReport);

    /// <summary>Parses one line, or <see langword="null"/>.</summary>
    public static HolderReport? TryParse(string line)
    {
        try
        {
            return JsonSerializer.Deserialize(line, HelperJsonContext.Default.HolderReport);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

/// <summary>Atomic writes and tolerant reads of the helper files.</summary>
public static class HelperFiles
{
    /// <summary>RFC 3339 UTC text with milliseconds.</summary>
    public static string Now(TimeProvider? clock = null) =>
        (clock ?? TimeProvider.System).GetUtcNow().UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    /// <summary>Writes <paramref name="text"/> to <paramref name="path"/> through a flushed temporary file and a rename.</summary>
    public static void WriteAtomically(string path, string text)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var temporary = path + ".tmp";
        using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            stream.Write(Encoding.UTF8.GetBytes(text));
            stream.Flush(flushToDisk: true);
        }

        File.Move(temporary, path, overwrite: true);
    }

    /// <summary>Reads and parses <paramref name="path"/>; <see langword="null"/> when it is absent, locked by a rename, or malformed.</summary>
    public static T? TryRead<T>(string path, Func<string, T?> parse)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(parse);
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream, Encoding.UTF8);
            var text = reader.ReadToEnd();
            return text.Length == 0 ? null : parse(text);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(ExitRecord))]
[JsonSerializable(typeof(LaunchRecord))]
[JsonSerializable(typeof(GuardSpec))]
[JsonSerializable(typeof(GuardEvent))]
[JsonSerializable(typeof(NodeHeartbeat))]
[JsonSerializable(typeof(HolderSpec))]
[JsonSerializable(typeof(HolderReport))]
[JsonSerializable(typeof(StepsFile))]
[JsonSerializable(typeof(StopRecord))]
internal sealed partial class HelperJsonContext : JsonSerializerContext;
