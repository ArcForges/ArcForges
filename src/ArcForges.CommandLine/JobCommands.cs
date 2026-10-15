// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;

namespace ArcForges.CommandLine;

/// <summary>
/// <c>arcforges jobs list|show|cancel</c> (experience/cli.md C-08): node jobs through <c>ListJobs</c>, <c>GetJob</c> and <c>CancelJob</c>.
/// IDs accept the full base32 ID or a unique prefix of at least 6 characters (section 1).
/// </summary>
internal static class JobCommands
{
    private static readonly TimeSpan Unary = TimeSpan.FromSeconds(5);

    private static readonly Dictionary<string, JobState> States = new(StringComparer.OrdinalIgnoreCase)
    {
        ["pending"] = JobState.Pending,
        ["running"] = JobState.Running,
        ["succeeded"] = JobState.Succeeded,
        ["failed"] = JobState.Failed,
        ["cancelled"] = JobState.Cancelled,
    };

    public static Command Build(Func<ParseResult, Cli> factory)
    {
        var jobs = new Command("jobs", "List, show and cancel node jobs");
        jobs.Subcommands.Add(List(factory));
        jobs.Subcommands.Add(Show(factory));
        jobs.Subcommands.Add(Cancel(factory));
        return jobs;
    }

    private static Command List(Func<ParseResult, Cli> factory)
    {
        var state = new Option<string[]>("--state") { Description = "Only jobs in this state (repeatable)", HelpName = "s" };
        state.AcceptOnlyFromAmong([.. States.Keys]);
        var limit = new Option<int?>("--limit") { Description = "At most this many jobs (1..500; default 100)", HelpName = "n" };
        var command = new Command("list", "List recent and running node jobs") { state, limit };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var request = new NodeServiceListJobsRequest { Meta = Cli.Meta() };
            request.States.Add((result.GetValue(state) ?? []).Select(name => States[name]).Distinct());
            if (result.GetValue(limit) is { } count)
            {
                request.Page = new PageRequest { Limit = count };
            }

            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var response = await cli.CallAsync("ListJobs", request.Meta, () => session.Channel.Node.ListJobsAsync(request,
                deadline: cli.Deadline(Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
                return ExitCodes.Success;
            }

            if (response.Value.Jobs.Count == 0)
            {
                cli.Output.Line("No jobs.");
                return ExitCodes.Success;
            }

            cli.Output.Table(["ID", "KIND", "STATE", "PROGRESS", "CREATED"],
                [.. response.Value.Jobs.Select(job => (IReadOnlyList<string>)[IdText.Format(job.JobId), Kind(job.Kind), Word(job.State),
                    job.ProgressPercent + "%", CliOutput.When(job.CreatedAt)])]);
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Show(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("id") { Description = "The job ID or a unique prefix (at least 6 characters)" };
        var command = new Command("show", "Show one node job") { id };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (jobId, exit) = await ResolveAsync(cli, session, result.GetValue(id)!, cancellationToken).ConfigureAwait(false);
            if (jobId is null)
            {
                return exit;
            }

            var request = new NodeServiceGetJobRequest { Meta = Cli.Meta(), JobId = jobId };
            var response = await cli.CallAsync("GetJob", request.Meta, () => session.Channel.Node.GetJobAsync(request,
                deadline: cli.Deadline(Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            Print(cli, response.Value.Job, response.Value);
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Cancel(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("id") { Description = "The job ID or a unique prefix (at least 6 characters)" };
        var command = new Command("cancel", "Cancel a pending or running node job") { id };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (jobId, exit) = await ResolveAsync(cli, session, result.GetValue(id)!, cancellationToken).ConfigureAwait(false);
            if (jobId is null)
            {
                return exit;
            }

            var request = new NodeServiceCancelJobRequest { Meta = Cli.Meta(), JobId = jobId };
            var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
            var response = await cli.MutateAsync("CancelJob", request.Meta.CommandId, action, r => session.Channel.Node.CancelJobAsync(r,
                deadline: cli.Deadline(TimeSpan.FromSeconds(10)), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            Print(cli, response.Value.Job, response.Value);
            return ExitCodes.Success;
        });
        return command;
    }

    /// <summary>Resolves a full ID or a unique prefix of at least 6 characters to an ID (exit 2, 4 or 1 otherwise).</summary>
    private static async Task<(Id? Id, int Exit)> ResolveAsync(Cli cli, NodeSession session, string text, CancellationToken cancellationToken)
    {
        if (IdText.TryParse(text, out var full))
        {
            return (new Id { Value = ByteString.CopyFrom(full) }, ExitCodes.Success);
        }

        if (text.Length < 6 || !IdText.TryNormalizePrefix(text, out var prefix))
        {
            return (null, cli.Output.Usage($"'{text}' is not a job ID or an ID prefix of at least 6 characters."));
        }

        var matches = new List<Id>();
        var page = new PageRequest { Limit = 500 };
        for (var pages = 0; pages < 20; pages++)
        {
            var request = new NodeServiceListJobsRequest { Meta = Cli.Meta(), Page = page };
            var response = await cli.CallAsync("ListJobs", request.Meta, () => session.Channel.Node.ListJobsAsync(request,
                deadline: cli.Deadline(Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return (null, cli.Output.Fail(error, request.Meta.CorrelationId));
            }

            matches.AddRange(response.Value.Jobs.Where(job => IdText.Format(job.JobId).StartsWith(prefix, StringComparison.Ordinal)).Select(job => job.JobId));
            if (!response.Value.Page.HasMore)
            {
                break;
            }

            page = new PageRequest { Limit = 500, Cursor = response.Value.Page.NextCursor };
        }

        return matches.Count switch
        {
            1 => (matches[0], ExitCodes.Success),
            0 => (null, NotFound(cli, text)),
            _ => (null, cli.Output.Usage($"'{text}' matches {matches.Count} jobs; give more characters.")),
        };
    }

    private static int NotFound(Cli cli, string text)
    {
        cli.Output.Error.WriteLine($"error: no job matches '{text}' (STATE/not_found)");
        return ExitCodes.NotFound;
    }

    private static void Print(Cli cli, JobView job, IMessage value)
    {
        if (cli.Output.Json)
        {
            cli.Output.Document(value);
            return;
        }

        var rows = new List<(string Key, string Value)>
        {
            ("job", IdText.Format(job.JobId)),
            ("kind", Kind(job.Kind)),
            ("state", Word(job.State)),
            ("progress", job.ProgressPercent + "%" + (job.HasProgressText ? " " + job.ProgressText : string.Empty)),
            ("requested by", job.RequestedBy?.Origin.ToString().ToUpperInvariant() ?? "-"),
            ("created", CliOutput.When(job.CreatedAt)),
            ("finished", CliOutput.When(job.FinishedAt)),
        };
        if (job.Error is { } error)
        {
            rows.Add(("error", $"{error.Category.ToString().ToUpperInvariant()}/{error.Code}"));
        }

        cli.Output.KeyValues(rows);
    }

    private static string Word(JobState state) => state.ToString().ToUpperInvariant();

    private static string Kind(JobKind kind) =>
        string.Concat(kind.ToString().Select((character, index) => index > 0 && char.IsUpper(character) ? "_" + character : character.ToString())).ToLowerInvariant();
}
