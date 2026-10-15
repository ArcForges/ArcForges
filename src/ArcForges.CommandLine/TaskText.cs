// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;

namespace ArcForges.CommandLine;

/// <summary>Shared pieces of <c>run</c> and <c>tasks</c>: words, exit codes, ID resolution and output mirroring.</summary>
internal static class TaskText
{
    public static readonly TimeSpan Unary = TimeSpan.FromSeconds(5);

    /// <summary><c>run</c> only: not started (validation, permission, approval or queue refusal).</summary>
    public const int NotStarted = 125;

    /// <summary><c>run</c> only: the program could not be executed.</summary>
    public const int SpawnFailed = 126;

    /// <summary><c>run</c> only: the program was not found.</summary>
    public const int ProgramNotFound = 127;

    /// <summary><c>tasks wait</c>: the wait ended without reaching the target state.</summary>
    public const int WaitNotReached = 9;

    /// <summary><c>run --client-timeout</c>: handed off before the client's timeout; the task continues.</summary>
    public const int HandedOff = 124;

    public static readonly Dictionary<string, TaskState> States = new(StringComparer.OrdinalIgnoreCase)
    {
        ["queued"] = TaskState.Queued,
        ["running"] = TaskState.Running,
        ["succeeded"] = TaskState.Succeeded,
        ["failed"] = TaskState.Failed,
        ["cancelled"] = TaskState.Cancelled,
        ["lost"] = TaskState.Lost,
    };

    public static string Word(TaskState state) => state switch
    {
        TaskState.Queued => "QUEUED",
        TaskState.WaitingDependency => "WAITING_DEPENDENCY",
        TaskState.Placing => "PLACING",
        TaskState.Running => "RUNNING",
        TaskState.Paused => "PAUSED",
        TaskState.RetryWait => "RETRY_WAIT",
        TaskState.Succeeded => "SUCCEEDED",
        TaskState.Failed => "FAILED",
        TaskState.Cancelled => "CANCELLED",
        TaskState.Lost => "LOST",
        _ => "UNKNOWN",
    };

    public static string Word(TerminationReason reason) =>
        string.Concat(reason.ToString().Select((character, index) => index > 0 && char.IsUpper(character) ? "_" + character : character.ToString())).ToUpperInvariant();

    public static bool IsTerminal(TaskState state) => state is TaskState.Succeeded or TaskState.Failed or TaskState.Cancelled or TaskState.Lost;

    /// <summary>
    /// The exit code of a finished attempt (cli.md section 3; 04 section 5): the task's exit code; 126 when it could not be spawned; a
    /// signal maps to 128 + n on Linux; any other termination on Windows exits 1 with a message on stderr.
    /// </summary>
    public static int ExitCode(AttemptResult? result, CliOutput output)
    {
        if (result is null)
        {
            output.Error.WriteLine("arcforges: the task ended without a result");
            return ExitCodes.Failed;
        }

        switch (result.TerminationReason)
        {
            case TerminationReason.Exited:
                return result.ExitCode;
            case TerminationReason.SpawnFailed:
                output.Error.WriteLine("arcforges: the program could not be executed" + (result.HasDetail ? ": " + result.Detail : string.Empty));
                return SpawnFailed;
        }

        output.Error.WriteLine($"arcforges: the task ended: {Word(result.TerminationReason)}" + (result.HasDetail && result.Detail.Length > 0 ? $" ({result.Detail})" : string.Empty));
        if (!OperatingSystem.IsWindows() && result.HasSignal && result.Signal > 0)
        {
            return 128 + result.Signal;
        }

        return ExitCodes.Failed;
    }

    /// <summary>The exit code of a submission refusal (cli.md section 3, <c>run</c>: 127, 125).</summary>
    public static int Refused(ArcError error, Id? correlation, CliOutput output)
    {
        output.Fail(error, correlation);
        return error.Code == "program_not_found" ? ProgramNotFound : NotStarted;
    }

    /// <summary>Resolves a full task ID or a unique prefix of at least 6 characters (exit 2, 4 or 1 otherwise).</summary>
    public static async Task<(Id? Id, int Exit)> ResolveAsync(Cli cli, NodeSession session, string text, CancellationToken cancellationToken)
    {
        if (IdText.TryParse(text, out var full))
        {
            return (new Id { Value = ByteString.CopyFrom(full) }, ExitCodes.Success);
        }

        if (text.Length < 6 || !IdText.TryNormalizePrefix(text, out var prefix))
        {
            return (null, cli.Output.Usage($"'{text}' is not a task ID or an ID prefix of at least 6 characters."));
        }

        var matches = new List<Id>();
        var page = new PageRequest { Limit = 500 };
        for (var pages = 0; pages < 20; pages++)
        {
            var request = new TaskServiceListTasksRequest { Meta = Cli.Meta(), Page = page };
            var response = await cli.CallAsync("ListTasks", request.Meta, () => session.Channel.Tasks.ListTasksAsync(request,
                deadline: cli.Deadline(Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return (null, cli.Output.Fail(error, request.Meta.CorrelationId));
            }

            matches.AddRange(response.Value.Tasks.Where(task => IdText.Format(task.TaskId).StartsWith(prefix, StringComparison.Ordinal)).Select(task => task.TaskId));
            if (!response.Value.Page.HasMore)
            {
                break;
            }

            page = new PageRequest { Limit = 500, Cursor = response.Value.Page.NextCursor };
        }

        switch (matches.Count)
        {
            case 1:
                return (matches[0], ExitCodes.Success);
            case 0:
                cli.Output.Error.WriteLine($"error: no task matches '{text}' (STATE/not_found)");
                return (null, ExitCodes.NotFound);
            default:
                return (null, cli.Output.Usage($"'{text}' matches {matches.Count} tasks; give more characters."));
        }
    }

    /// <summary>Writes output chunks byte-exactly to the CLI's own stdout and stderr (cli.md section 2, <c>run</c> attached).</summary>
    public sealed class Mirror : IDisposable
    {
        private readonly Stream _stdout = Console.OpenStandardOutput();
        private readonly Stream _stderr = Console.OpenStandardError();

        public long StdoutBytes { get; private set; }

        public long StderrBytes { get; private set; }

        public void Write(OutputStream stream, ReadOnlySpan<byte> data)
        {
            if (stream == OutputStream.Stderr)
            {
                _stderr.Write(data);
                _stderr.Flush();
                StderrBytes += data.Length;
            }
            else
            {
                _stdout.Write(data);
                _stdout.Flush();
                StdoutBytes += data.Length;
            }
        }

        public void Dispose()
        {
            _stdout.Dispose();
            _stderr.Dispose();
        }
    }

    public static string Bytes(ulong value) => value switch
    {
        < 1024 => value.ToString(CultureInfo.InvariantCulture) + " B",
        < 1024 * 1024 => (value / 1024.0).ToString("0.#", CultureInfo.InvariantCulture) + " KiB",
        < 1024UL * 1024 * 1024 => (value / (1024.0 * 1024)).ToString("0.#", CultureInfo.InvariantCulture) + " MiB",
        _ => (value / (1024.0 * 1024 * 1024)).ToString("0.##", CultureInfo.InvariantCulture) + " GiB",
    };
}
