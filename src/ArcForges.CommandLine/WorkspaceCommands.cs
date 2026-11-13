// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;

namespace ArcForges.CommandLine;

/// <summary>The center-routed registered-workspace commands (06a section 1 and CLI C-05).</summary>
internal static class WorkspaceCommands
{
    internal static Command Build(Func<ParseResult, Cli> factory)
    {
        var workspace = new Command("workspace", "Manage registered workspaces through the center");
        workspace.Subcommands.Add(Register(factory));
        workspace.Subcommands.Add(Unregister(factory));
        workspace.Subcommands.Add(List(factory));
        workspace.Subcommands.Add(Show(factory));
        return workspace;
    }

    private static Option<string?> NodeOption() => new("--node") { Description = "Target node UUID or exact name (default: this node)", HelpName = "name-or-id" };

    private static Command Register(Func<ParseResult, Cli> factory)
    {
        var path = new Argument<string>("path") { Description = "Absolute existing directory on the target node" };
        var name = new Option<string?>("--name") { Description = "Workspace name", HelpName = "name" };
        var node = NodeOption();
        var command = new Command("register", "Register an existing directory (HUMAN only)") { path, name, node };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (route, exit) = await TaskRoute.ResolveAsync(cli, session, result.GetValue(node), local: false, cancellationToken).ConfigureAwait(false);
            if (route is null) return exit;
            var request = new WorkspaceServiceRegisterWorkspaceRequest { Meta = Cli.Meta(), Path = result.GetValue(path)! };
            if (result.GetValue(name) is { } selected) request.Name = selected;
            var action = CommandIds.Begin(request, item => item.Meta, (item, meta) => item.Meta = meta);
            var response = await route.RegisterWorkspaceAsync(action.RequestForAttempt(), cancellationToken).ConfigureAwait(false);
            if (response.Error is { } error) return TaskRoute.Fail(cli, error, request.Meta.CorrelationId, request.Meta.CommandId, workspace: true);
            if (response.Value?.Workspace is not { WorkspaceId.Value.Length: 16 } created)
                return TaskRoute.Fail(cli, TaskRoute.MalformedResponse(), request.Meta.CorrelationId, request.Meta.CommandId, workspace: true);
            Render(cli, created);
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Unregister(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("id") { Description = "Registered workspace ID or unique prefix" };
        var node = NodeOption();
        var command = new Command("unregister", "Forget a registration without deleting files (HUMAN only)") { id, node };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (route, exit) = await TaskRoute.ResolveAsync(cli, session, result.GetValue(node), local: false, cancellationToken).ConfigureAwait(false);
            if (route is null) return exit;
            var (workspace, lookupExit) = await ResolveAsync(cli, route, result.GetValue(id)!, allowPath: false, cancellationToken).ConfigureAwait(false);
            if (workspace is null) return lookupExit;
            var request = new WorkspaceServiceUnregisterWorkspaceRequest { Meta = Cli.Meta(), WorkspaceId = workspace };
            var action = CommandIds.Begin(request, item => item.Meta, (item, meta) => item.Meta = meta);
            var response = await route.UnregisterWorkspaceAsync(action.RequestForAttempt(), cancellationToken).ConfigureAwait(false);
            if (response.Error is { } error) return TaskRoute.Fail(cli, error, request.Meta.CorrelationId, request.Meta.CommandId, workspace: true);
            if (response.Value?.Receipt is not { HasEffect: true, Effect: EffectCertainty.Happened, CommandId: { } receiptCommand } ||
                !receiptCommand.Equals(request.Meta.CommandId))
                return TaskRoute.Fail(cli, TaskRoute.MalformedResponse(), request.Meta.CorrelationId, request.Meta.CommandId, workspace: true);
            if (cli.Output.Json) cli.Output.Document(response.Value);
            else cli.Output.Line("Unregistered " + IdText.Format(workspace));
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command List(Func<ParseResult, Cli> factory)
    {
        var limit = new Option<int?>("--limit") { Description = "Workspaces per page (1..500; default 100)", HelpName = "n" };
        var cursor = new Option<string?>("--cursor") { Description = "Continue a previous page", HelpName = "cursor" };
        var node = NodeOption();
        var command = new Command("list", "List a page of workspaces") { node, limit, cursor };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (route, exit) = await TaskRoute.ResolveAsync(cli, session, result.GetValue(node), local: false, cancellationToken).ConfigureAwait(false);
            if (route is null) return exit;
            var request = new WorkspaceServiceListWorkspacesRequest { Meta = Cli.Meta() };
            if (result.GetValue(limit) is not null || result.GetValue(cursor) is not null)
            {
                request.Page = new PageRequest();
                if (result.GetValue(limit) is { } selected) request.Page.Limit = selected;
                if (result.GetValue(cursor) is { } continuation) request.Page.Cursor = continuation;
            }

            var response = await route.ListWorkspacesAsync(request, cancellationToken).ConfigureAwait(false);
            if (response.Error is { } error) return TaskRoute.Fail(cli, error, request.Meta.CorrelationId, workspace: true);
            if (response.Value is not { } value || !ValidPage(value.Page) || value.Workspaces.Any(item => item.WorkspaceId?.Value.Length != 16))
                return TaskRoute.Fail(cli, TaskRoute.MalformedResponse(), request.Meta.CorrelationId, workspace: true);
            if (cli.Output.Json)
            {
                cli.Output.Document(value);
            }
            else
            {
                foreach (var item in value.Workspaces) RenderText(cli, item);
                if (value.Page is { HasMore: true, HasNextCursor: true })
                    cli.Output.Line("Next cursor: " + value.Page.NextCursor + " (use with the same --node)");
            }

            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Show(Func<ParseResult, Cli> factory)
    {
        var selector = new Argument<string>("id-or-path") { Description = "Workspace ID, unique ID prefix, or exact registered root path" };
        var node = NodeOption();
        var command = new Command("show", "Show a registered workspace") { selector, node };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (route, exit) = await TaskRoute.ResolveAsync(cli, session, result.GetValue(node), local: false, cancellationToken).ConfigureAwait(false);
            if (route is null) return exit;
            var (id, lookupExit) = await ResolveAsync(cli, route, result.GetValue(selector)!, allowPath: true, cancellationToken).ConfigureAwait(false);
            if (id is null) return lookupExit;
            var request = new WorkspaceServiceGetWorkspaceRequest { Meta = Cli.Meta(), WorkspaceId = id };
            var response = await route.GetWorkspaceAsync(request, cancellationToken).ConfigureAwait(false);
            if (response.Error is { } error) return TaskRoute.Fail(cli, error, request.Meta.CorrelationId, workspace: true);
            if (response.Value?.Workspace is not { WorkspaceId.Value.Length: 16 } found || !found.WorkspaceId.Equals(id))
                return TaskRoute.Fail(cli, TaskRoute.MalformedResponse(), request.Meta.CorrelationId, workspace: true);
            Render(cli, found);
            return ExitCodes.Success;
        });
        return command;
    }

    private static async Task<(Id? Id, int Exit)> ResolveAsync(Cli cli, TaskRoute route, string selection, bool allowPath, CancellationToken cancellationToken)
    {
        if (IdText.TryParse(selection, out var bytes))
            return (new Id { Value = ByteString.CopyFrom(bytes) }, ExitCodes.Success);
        if (Guid.TryParseExact(selection, "D", out var guid) && guid != Guid.Empty)
            return (new Id { Value = ByteString.CopyFrom(guid.ToByteArray(bigEndian: true)) }, ExitCodes.Success);

        var path = allowPath && (selection.StartsWith('/') || selection.Length >= 3 && char.IsAsciiLetter(selection[0]) && selection[1] == ':' &&
            (selection[2] is '/' or '\\'));
        if (!path && (!IdText.TryNormalizePrefix(selection, out _) || selection.Length < 6))
            return (null, cli.Output.Usage("workspace ID: give a full ID or a prefix of at least six characters."));
        _ = IdText.TryNormalizePrefix(selection, out var prefix);

        var matches = new List<Id>();
        string? cursor = null;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var page = 0; page < 100; page++)
        {
            var request = new WorkspaceServiceListWorkspacesRequest { Meta = Cli.Meta(), Page = new PageRequest { Limit = 500 } };
            if (cursor is not null) request.Page.Cursor = cursor;
            var response = await route.ListWorkspacesAsync(request, cancellationToken).ConfigureAwait(false);
            if (response.Error is { } error) return (null, TaskRoute.Fail(cli, error, request.Meta.CorrelationId, workspace: true));
            if (response.Value is not { } value || !ValidPage(value.Page))
                return (null, TaskRoute.Fail(cli, TaskRoute.MalformedResponse(), request.Meta.CorrelationId, workspace: true));
            foreach (var workspace in value.Workspaces)
            {
                if (workspace.WorkspaceId?.Value.Length != 16) return (null, TaskRoute.Fail(cli, TaskRoute.MalformedResponse(), request.Meta.CorrelationId, workspace: true));
                var matchesSelection = path ? string.Equals(workspace.RootPath, selection, StringComparison.Ordinal) :
                    IdText.Format(workspace.WorkspaceId).StartsWith(prefix, StringComparison.Ordinal);
                if (matchesSelection) matches.Add(workspace.WorkspaceId.Clone());
            }

            if (matches.Count > 1) return (null, cli.Output.Usage("Workspace selection is ambiguous; use the full ID."));
            if (value.Page is not { HasMore: true }) return matches.Count == 1
                ? (matches[0], ExitCodes.Success)
                : (null, cli.Output.Usage(path ? "No workspace has that exact registered root path." : "No workspace has that ID prefix."));
            if (!value.Page.HasNextCursor || string.IsNullOrEmpty(value.Page.NextCursor) || !seen.Add(value.Page.NextCursor))
                return (null, TaskRoute.Fail(cli, TaskRoute.MalformedResponse(), request.Meta.CorrelationId, workspace: true));
            cursor = value.Page.NextCursor;
        }

        return (null, cli.Output.Usage("Workspace lookup exceeded its bounded page limit; use the full ID."));
    }

    private static bool ValidPage(PageState? page) => page is { HasHasMore: true } &&
        (page.HasMore ? page.HasNextCursor && page.NextCursor.Length > 0 : !page.HasNextCursor);

    private static void Render(Cli cli, Workspace workspace)
    {
        if (cli.Output.Json) cli.Output.Document(workspace);
        else RenderText(cli, workspace);
    }

    private static void RenderText(Cli cli, Workspace workspace)
    {
        var git = workspace.Git switch
        {
            null => "non-git",
            { HasQuality: true, Quality: GitStatusQuality.Complete } complete =>
                (complete.Dirty ? "dirty" : "clean") + " (modified " + complete.ModifiedFiles + ", untracked " + complete.UntrackedFiles + ")",
            { HasQuality: true } quality => quality.Quality.ToString().ToLowerInvariant(),
            _ => "unknown",
        };
        cli.Output.Line(IdText.Format(workspace.WorkspaceId) + "  " + Messages.Plain(workspace.Name) + "  " +
            Messages.Plain(workspace.RootPath) + "  git:" + git);
    }
}
