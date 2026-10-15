// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Platform;

/// <summary>
/// The files of one attempt under the node data root (architecture 04 sections 3-4, 06 sections 1 and 5): <c>logs/&lt;attempt&gt;/</c>
/// holds the output (<c>stdout.bin</c>, <c>stderr.bin</c>), the node's output index (<c>index.bin</c>), the durable exit record
/// (<c>exit.json</c>), a failed launch step (<c>launch.json</c>), what the attempt's guard enforces (<c>guard.json</c>) and the guard's
/// actions (<c>guard-events.jsonl</c>); <c>tmp/&lt;attempt&gt;/</c> is the attempt's temporary directory. The attempt directory name is
/// the attempt ID's base32 text.
/// </summary>
public sealed class AttemptFiles
{
    /// <summary>The file names.</summary>
    public const string Stdout = "stdout.bin";

    /// <summary>The standard error file.</summary>
    public const string Stderr = "stderr.bin";

    /// <summary>The output index.</summary>
    public const string Index = "index.bin";

    /// <summary>The durable exit record.</summary>
    public const string Exit = "exit.json";

    /// <summary>The record of a failed launch step.</summary>
    public const string Launch = "launch.json";

    /// <summary>What the guard enforces.</summary>
    public const string Guard = "guard.json";

    /// <summary>The guard's actions, one JSON object per line.</summary>
    public const string GuardEvents = "guard-events.jsonl";

    /// <summary>Creates the layout of <paramref name="attemptName"/> under <paramref name="dataRoot"/>.</summary>
    public AttemptFiles(string dataRoot, string attemptName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(attemptName);
        if (attemptName.IndexOfAny([.. Path.GetInvalidFileNameChars(), '.']) >= 0)
        {
            throw new ArgumentException("An attempt name is a plain file name.", nameof(attemptName));
        }

        DataRoot = dataRoot;
        AttemptName = attemptName;
        Directory = Path.Combine(dataRoot, "logs", attemptName);
        TempDirectory = Path.Combine(dataRoot, "tmp", attemptName);
    }

    /// <summary>The node data root.</summary>
    public string DataRoot { get; }

    /// <summary>The attempt's directory name (the attempt ID's base32 text).</summary>
    public string AttemptName { get; }

    /// <summary><c>logs/&lt;attempt&gt;/</c>.</summary>
    public string Directory { get; }

    /// <summary><c>tmp/&lt;attempt&gt;/</c>: TMP, TEMP and TMPDIR of the attempt (06 section 4).</summary>
    public string TempDirectory { get; }

    /// <summary><c>stdout.bin</c>.</summary>
    public string StdoutPath => Path.Combine(Directory, Stdout);

    /// <summary><c>stderr.bin</c>.</summary>
    public string StderrPath => Path.Combine(Directory, Stderr);

    /// <summary><c>index.bin</c>.</summary>
    public string IndexPath => Path.Combine(Directory, Index);

    /// <summary><c>exit.json</c>.</summary>
    public string ExitPath => Path.Combine(Directory, Exit);

    /// <summary><c>launch.json</c>.</summary>
    public string LaunchPath => Path.Combine(Directory, Launch);

    /// <summary><c>guard.json</c>.</summary>
    public string GuardPath => Path.Combine(Directory, Guard);

    /// <summary><c>guard-events.jsonl</c>.</summary>
    public string GuardEventsPath => Path.Combine(Directory, GuardEvents);

    /// <summary><c>run/node-heartbeat</c> of a data root (06 section 5).</summary>
    public static string HeartbeatPath(string dataRoot) => Path.Combine(dataRoot, "run", "node-heartbeat");

    /// <summary>The path of a stream's file.</summary>
    public string OutputPath(OutputStreamKind stream) => stream == OutputStreamKind.Stdout ? StdoutPath : StderrPath;
}

/// <summary>The two captured streams; the numbers are the <c>stream</c> byte of index records (and <c>OutputStream</c> values).</summary>
public enum OutputStreamKind : byte
{
    /// <summary>Standard output.</summary>
    Stdout = 1,

    /// <summary>Standard error.</summary>
    Stderr = 2,
}
