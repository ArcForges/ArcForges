// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;

namespace ArcForges.CommandLine;

/// <summary>
/// <c>arcforges approvals list|show|approve|deny|withdraw</c> (experience/cli.md C-07; approvals.proto): the approvals the permission matrix
/// raised, pending first. Only a HUMAN caller (an interactive CLI or the Desktop) approves or denies (11 section 1); the requester or a HUMAN
/// withdraws. An approved request runs at once under its original command ID, so the requester's retry receives the executed outcome.
/// IDs accept the full base32 ID or a unique prefix of at least 6 characters.
/// </summary>
internal static class ApprovalCommands
{
    private static readonly TimeSpan Unary = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan Decide = TimeSpan.FromSeconds(10);

    private static readonly Dictionary<string, ApprovalState> States = new Dictionary<string, ApprovalState>(StringComparer.OrdinalIgnoreCase)
    {
        ["pending"] = ApprovalState.Pending,
        ["approved"] = ApprovalState.Approved,
        ["denied"] = ApprovalState.Denied,
        ["expired"] = ApprovalState.Expired,
        ["cancelled"] = ApprovalState.Cancelled,
        ["executed"] = ApprovalState.Executed,
        ["failed"] = ApprovalState.Failed,
    };

    public static Command Build(Func<ParseResult, Cli> factory)
    {
        var approvals = new Command("approvals", "List, show, approve, deny and withdraw approval requests");
        approvals.Subcommands.Add(List(factory));
        approvals.Subcommands.Add(Show(factory));
        approvals.Subcommands.Add(Decision(factory, "approve", ApprovalDecisionKind.Approve, "Approve a request; it runs at once under its original command ID"));
        approvals.Subcommands.Add(Decision(factory, "deny", ApprovalDecisionKind.Deny, "Deny a request"));
        approvals.Subcommands.Add(Withdraw(factory));
        return approvals;
    }

    private static Command List(Func<ParseResult, Cli> factory)
    {
        var state = new Option<string[]>("--state")
        {
            Description = "States to show (comma-separated or repeated): pending, approved, denied, expired, cancelled, executed, failed",
            AllowMultipleArgumentsPerToken = true,
        };
        var limit = new Option<int?>("--limit") { Description = "At most this many (1..500; default 50)", HelpName = "n" };
        var command = new Command("list", "List approvals, pending first") { state, limit };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var request = new ApprovalServiceListApprovalsRequest { Meta = Cli.Meta(), Page = new PageRequest { Limit = result.GetValue(limit) ?? 50 } };
            foreach (var name in (result.GetValue(state) ?? []).SelectMany(value => value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)))
            {
                request.States.Add(States.TryGetValue(name, out var parsed) ? parsed : throw new UsageException($"--state: '{name}' is not an approval state."));
            }

            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var response = await cli.CallAsync("ListApprovals", request.Meta, () => session.Channel.Approvals.ListApprovalsAsync(request, deadline: cli.Deadline(Unary),
                cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
                return ExitCodes.Success;
            }

            cli.Output.Table(["ID", "STATE", "OPERATION", "REQUESTER", "SUMMARY"], response.Value.Approvals.Select(approval => (IReadOnlyList<string>)
                [IdText.Format(approval.ApprovalId), Word(approval.State), approval.Operation, Requester(approval.Requester), approval.Summary]).ToList());
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Show(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("id") { Description = "The approval ID or a unique prefix (at least 6 characters)" };
        var command = new Command("show", "Show an approval with its outcome") { id };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (approvalId, exit) = await ResolveAsync(cli, session, result.GetValue(id)!, cancellationToken).ConfigureAwait(false);
            if (approvalId is null)
            {
                return exit;
            }

            var request = new ApprovalServiceGetApprovalRequest { Meta = Cli.Meta(), ApprovalId = approvalId };
            var response = await cli.CallAsync("GetApproval", request.Meta, () => session.Channel.Approvals.GetApprovalAsync(request, deadline: cli.Deadline(Unary),
                cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            Print(cli, response.Value.Approval);
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Decision(Func<ParseResult, Cli> factory, string name, ApprovalDecisionKind decision, string description)
    {
        var id = new Argument<string>("id") { Description = "The approval ID or a unique prefix (at least 6 characters)" };
        var comment = new Option<string?>("--comment") { Description = "A comment for the record (<= 500 characters)", HelpName = "c" };
        var command = new Command(name, description) { id, comment };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (approvalId, exit) = await ResolveAsync(cli, session, result.GetValue(id)!, cancellationToken).ConfigureAwait(false);
            if (approvalId is null)
            {
                return exit;
            }

            var request = new ApprovalServiceDecideApprovalRequest { Meta = Cli.Meta(), ApprovalId = approvalId, Decision = decision };
            if (result.GetValue(comment) is { } text)
            {
                request.Comment = text;
            }

            var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
            var response = await cli.MutateAsync("DecideApproval", request.Meta.CommandId, action, r => session.Channel.Approvals.DecideApprovalAsync(r,
                deadline: cli.Deadline(Decide), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            Print(cli, response.Value.Approval);
            return response.Value.Approval.State == ApprovalState.Failed ? ExitCodes.Failed : ExitCodes.Success;
        });
        return command;
    }

    private static Command Withdraw(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("id") { Description = "The approval ID or a unique prefix (at least 6 characters)" };
        var command = new Command("withdraw", "Withdraw a pending approval request (the requester or a HUMAN caller)") { id };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (approvalId, exit) = await ResolveAsync(cli, session, result.GetValue(id)!, cancellationToken).ConfigureAwait(false);
            if (approvalId is null)
            {
                return exit;
            }

            var request = new ApprovalServiceCancelApprovalRequest { Meta = Cli.Meta(), ApprovalId = approvalId };
            var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
            var response = await cli.MutateAsync("CancelApproval", request.Meta.CommandId, action, r => session.Channel.Approvals.CancelApprovalAsync(r,
                deadline: cli.Deadline(Unary), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            Print(cli, response.Value.Approval);
            return ExitCodes.Success;
        });
        return command;
    }

    private static void Print(Cli cli, Approval approval)
    {
        if (cli.Output.Json)
        {
            cli.Output.Document(approval);
            return;
        }

        cli.Output.Line($"approval {IdText.Format(approval.ApprovalId)}: {Word(approval.State)}");
        cli.Output.Line($"  operation: {approval.Operation}");
        cli.Output.Line($"  summary:   {approval.Summary}");
        cli.Output.Line($"  requester: {Requester(approval.Requester)}");
        cli.Output.Line($"  risk:      {approval.Risk.ToString().ToUpperInvariant()}");
        if (approval.DecidedBy is { } decider)
        {
            cli.Output.Line($"  decided by {Requester(decider)}" + (approval.HasComment ? $": {approval.Comment}" : string.Empty));
        }

        if (approval.OutcomeError is { } error)
        {
            cli.Output.Line($"  outcome:   failed: {Messages.For(error)} ({error.Category.ToString().ToUpperInvariant()}/{error.Code})");
        }
        else if (approval.State == ApprovalState.Executed)
        {
            cli.Output.Line("  outcome:   executed under the original command ID");
        }
    }

    private static string Word(ApprovalState state) => state.ToString().ToUpperInvariant();

    private static string Requester(ActorRef? actor) => actor is null ? "-" : actor.Origin.ToString().ToUpperInvariant()
        + (actor.ClientKind is not ClientKind.Unspecified ? " (" + actor.ClientKind.ToString().ToLowerInvariant() + ")" : string.Empty);

    /// <summary>The approval named by a full ID or a unique prefix of at least 6 characters (cli.md section 1).</summary>
    private static async Task<(Id? Id, int Exit)> ResolveAsync(Cli cli, NodeSession session, string text, CancellationToken cancellationToken)
    {
        if (IdText.TryParse(text, out var full))
        {
            return (new Id { Value = ByteString.CopyFrom(full) }, ExitCodes.Success);
        }

        if (text.Length < 6 || !IdText.TryNormalizePrefix(text, out var prefix))
        {
            return (null, cli.Output.Usage($"'{text}' is not an approval ID or an ID prefix of at least 6 characters."));
        }

        var request = new ApprovalServiceListApprovalsRequest { Meta = Cli.Meta(), Page = new PageRequest { Limit = 500 } };
        var response = await cli.CallAsync("ListApprovals", request.Meta, () => session.Channel.Approvals.ListApprovalsAsync(request, deadline: cli.Deadline(Unary),
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (response.Error is { } error)
        {
            return (null, cli.Output.Fail(error, request.Meta.CorrelationId));
        }

        var matches = response.Value.Approvals.Where(approval => IdText.Format(approval.ApprovalId).StartsWith(prefix, StringComparison.Ordinal)).ToList();
        switch (matches.Count)
        {
            case 1:
                return (matches[0].ApprovalId, ExitCodes.Success);
            case 0:
                cli.Output.Error.WriteLine($"error: no approval matches '{text}' (STATE/not_found)");
                return (null, ExitCodes.NotFound);
            default:
                cli.Output.Error.WriteLine($"error: '{text}' matches {matches.Count} approvals; give more characters");
                return (null, ExitCodes.Usage);
        }
    }
}
