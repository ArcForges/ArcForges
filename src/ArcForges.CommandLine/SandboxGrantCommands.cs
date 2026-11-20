// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using Grpc.Core;

namespace ArcForges.CommandLine;

internal static class SandboxGrantCommands
{
    private static readonly TimeSpan UnaryDeadline = TimeSpan.FromSeconds(10);

    internal static Command Build(Func<ParseResult, Cli> factory)
    {
        var group = new Command("grant", "Manage local authorization grants for an existing Center enrollment");
        group.Subcommands.Add(SetGrant(factory));
        group.Subcommands.Add(ListGrants(factory));
        group.Subcommands.Add(RevokeGrant(factory));
        return group;
    }

    private static Command SetGrant(Func<ParseResult, Cli> factory)
    {
        var file = new Option<string>("--file") { Required = true, Description = "V2 remote grant JSON file", HelpName = "grant" };
        var revision = new Option<long?>("--expected-revision") { Description = "Current grant revision for an edit" };
        var command = new Command("set", "Create or replace an explicit remote grant") { file, revision };
        var mutation = new V2MutationOptions();
        mutation.AddTo(command);
        V2Cli.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var expected = result.GetValue(revision);
            ValidateGrantRevision(expected);
            var grant = await V2Cli.ReadJsonAsync(result.GetValue(file)!, RemoteGrant.Parser, cancellationToken).ConfigureAwait(false);
            if (expected is not null && grant.GrantId is null)
            {
                throw new UsageException("A grant update requires grantId in the JSON file.");
            }

            if (grant.ParentGrantId is not null || grant.HasState && grant.State != GrantState.Active)
            {
                throw new UsageException("Set accepts locally issued active grants with no parent grant.");
            }

            if (grant.Revision is { } supplied && supplied.Value != (expected ?? 1))
            {
                throw new UsageException("The grant file revision must match --expected-revision, or be 1 for creation.");
            }

            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            using var pin = session.PinConnection();
            DateTime deadline = cli.Deadline(UnaryDeadline);
            var identity = await mutation.BeginAsync(result, session, deadline, cancellationToken).ConfigureAwait(false);
            if (expected is long previous)
            {
                identity.Meta.ExpectedRev = new Revision { Value = previous };
            }

            var request = new NodeServiceSetRemoteGrantRequest { Meta = identity.Meta, OwnerEpoch = identity.OwnerEpoch, Grant = grant };
            var response = await V2Cli.SendAsync(cli, "NodeService.SetRemoteGrant", identity,
                () => session.Node.SetRemoteGrantAsync(request, deadline: deadline, cancellationToken: cancellationToken)).ConfigureAwait(false);
            return V2Cli.Print(cli, V2Cli.Require(response.Value, response.Error, identity), identity);
        });
        return command;
    }

    private static Command ListGrants(Func<ParseResult, Cli> factory)
    {
        var sandbox = new Option<string?>("--sandbox") { Description = "Filter grants by Sandbox ID" };
        var command = new Command("list", "List visible grants and expiration") { sandbox };
        V2Cli.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var filter = result.GetValue(sandbox) is { } specified ? V2Cli.ReadId(specified, "--sandbox") : null;
            var all = new NodeServiceListRemoteGrantsValue();
            var cursors = new HashSet<string>(StringComparer.Ordinal);
            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            using var pin = session.PinConnection();
            DateTime deadline = cli.Deadline(UnaryDeadline);
            string cursor = string.Empty;
            do
            {
                var request = new NodeServiceListRemoteGrantsRequest { Meta = Cli.Meta(), SandboxId = filter, Limit = 200 };
                if (cursor.Length != 0)
                {
                    request.Cursor = cursor;
                }

                var response = await cli.CallAsync("NodeService.ListRemoteGrants", request.Meta, () => session.Node.ListRemoteGrantsAsync(
                    request, deadline: deadline, cancellationToken: cancellationToken)).ConfigureAwait(false);
                var page = V2Cli.Require(response.Value, response.Error);
                all.Grants.AddRange(page.Grants);
                all.Page = V2Cli.Require(page.Page, null);
                cursor = all.Page.NextCursor;
                if (cursor.Length != 0 && !cursors.Add(cursor))
                {
                    throw new RpcException(new Status(StatusCode.Internal, "The grant list repeated a continuation cursor."));
                }
            }
            while (cursor.Length != 0);

            return V2Cli.Print(cli, all);
        });
        return command;
    }

    private static Command RevokeGrant(Func<ParseResult, Cli> factory)
    {
        var grant = new Argument<string>("grant-id") { Description = "Original grant ID" };
        var revision = new Option<long>("--expected-revision") { Required = true, Description = "Current grant revision" };
        var command = new Command("revoke", "Revoke a grant and fence future remote use") { grant, revision };
        var mutation = new V2MutationOptions();
        mutation.AddTo(command);
        V2Cli.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var id = V2Cli.ReadId(result.GetValue(grant), "grant-id");
            long expected = result.GetValue(revision);
            ValidateGrantRevision(expected);
            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            using var pin = session.PinConnection();
            DateTime deadline = cli.Deadline(UnaryDeadline);
            var identity = await mutation.BeginAsync(result, session, deadline, cancellationToken).ConfigureAwait(false);
            identity.Meta.ExpectedRev = new Revision { Value = expected };
            var request = new NodeServiceRevokeRemoteGrantRequest { Meta = identity.Meta, OwnerEpoch = identity.OwnerEpoch, GrantId = id };
            var response = await V2Cli.SendAsync(cli, "NodeService.RevokeRemoteGrant", identity,
                () => session.Node.RevokeRemoteGrantAsync(request, deadline: deadline, cancellationToken: cancellationToken)).ConfigureAwait(false);
            return V2Cli.Print(cli, V2Cli.Require(response.Value, response.Error, identity), identity);
        });
        return command;
    }

    private static void ValidateGrantRevision(long? revision)
    {
        if (revision is <= 0 or long.MaxValue)
        {
            throw new UsageException("--expected-revision requires a positive revision below the maximum revision.");
        }
    }
}
