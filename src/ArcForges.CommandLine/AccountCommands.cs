// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.CommandLine;

/// <summary>
/// <c>arcforges logout [--local]</c> and <c>arcforges account status</c> (AF-CTR-04 CTR4-NODE-15 as amended; Q18), with the hidden aliases
/// <c>account login</c> and <c>account logout</c> of experience/cli.md C-09.
/// </summary>
internal static class AccountCommands
{
    private static readonly TimeSpan StatusDeadline = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan SignOutDeadline = TimeSpan.FromSeconds(15);

    /// <summary>The stranded states <c>logout --local</c> abandons after a confirmation (N2 decision R-3).</summary>
    private static readonly string[] Abandonable = ["credential_backend_changed", "credential_for_other_node"];

    /// <summary>The <c>account</c> group: <c>status</c>, and the hidden <c>login</c>/<c>logout</c> aliases.</summary>
    public static Command Account(Func<ParseResult, Cli> factory)
    {
        var account = new Command("account", "The node's account link");
        account.Subcommands.Add(Status(factory));
        account.Subcommands.Add(LoginCommands.Build(factory, "login", alias: true));
        account.Subcommands.Add(Logout(factory, alias: true));
        return account;
    }

    /// <summary>The <c>logout</c> command (also the hidden <c>account logout</c>).</summary>
    public static Command Logout(Func<ParseResult, Cli> factory, bool alias = false)
    {
        var local = new Option<bool>("--local") { Description = "Forget the credential on this node only (the center keeps it until it expires or is revoked on the web)" };
        var command = new Command("logout", "Sign this node out of its center") { local };
        command.Hidden = alias;
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var localOnly = result.GetValue(local);
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            if (localOnly && !cli.Yes && (cli.Output.Json || !Console.IsInputRedirected))
            {
                var status = await ReadStatusAsync(cli, session, cancellationToken).ConfigureAwait(false);
                if (status?.Warnings.FirstOrDefault(warning => Abandonable.Contains(warning, StringComparer.Ordinal)) is not null)
                {
                    if (cli.Output.Json)
                    {
                        // Only --yes skips the abandon confirmation (N2 review sec N-6): --json never answers it.
                        return cli.Output.Usage("logout --local would forget a credential this node cannot use; confirm it with --yes.");
                    }

                    cli.Output.Error.Write("Forget a credential this node cannot use? It may remain in the previous secret store and stay live at "
                        + (status.CenterUrl is { Length: > 0 } center ? center : "its center") + " until you revoke this device on the web or it expires. [y/N] ");
                    var answer = Console.In.ReadLine();
                    if (answer is not ("y" or "Y" or "yes"))
                    {
                        cli.Output.Error.WriteLine("Nothing was changed.");
                        return ExitCodes.Failed;
                    }
                }
            }

            var request = new AccountServiceSignOutRequest { Meta = Cli.Meta(), RevokeRemote = !localOnly };
            var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
            var response = await cli.MutateAsync("SignOut", request.Meta.CommandId, action, r => session.Channel.Account.SignOutAsync(r,
                deadline: cli.Deadline(SignOutDeadline), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            var warnings = response.Meta?.Warnings.ToList() ?? [];
            if (response.Error is { } error)
            {
                if (!cli.Output.Json && error.Code == "invalid_state" && error.Details?.State?.Reason == "credential_store_unavailable")
                {
                    // N2 review FX-3: refused while the store cannot be read; nothing changed (both forms).
                    cli.Output.Error.WriteLine("error: " + LoginCommands.StoreUnavailableText("nothing was changed") + " (STATE/invalid_state)");
                    return ExitCodes.Failed;
                }

                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            if (cli.Output.Json)
            {
                var document = new JsonObject { ["value"] = CliOutput.ToJsonNode(response.Value), ["warnings"] = new JsonArray([.. warnings.Select(warning => (JsonNode?)warning)]) };
                cli.Output.Document(document);
                return ExitCodes.Success;
            }

            if (warnings.Contains("stranded_credential_abandoned"))
            {
                cli.Output.Line("The node forgot the credential it could not use. It may remain in the previous secret store and stay live at its center until you revoke this device on the web or it expires.");
            }
            else if (warnings.Contains("remote_sign_out_unconfirmed"))
            {
                cli.Output.Line(localOnly
                    ? "Signed out on this node. The center keeps the credential until it expires or you revoke this device on the web."
                    : "Signed out on this node. The center could not confirm the revocation: the credential may stay live until it expires or you revoke this device on the web.");
            }
            else
            {
                cli.Output.Line("Signed out.");
            }

            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Status(Func<ParseResult, Cli> factory)
    {
        var command = new Command("status", "Show the node's account link");
        Actions.Set(command, factory, async (cli, _, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var meta = Cli.Meta();
            var response = await cli.CallAsync("GetAccountStatus", meta, () => session.Channel.Account.GetAccountStatusAsync(
                new AccountServiceGetAccountStatusRequest { Meta = meta }, deadline: cli.Deadline(StatusDeadline), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, meta.CorrelationId);
            }

            var status = response.Value.Status;
            if (cli.Output.Json)
            {
                cli.Output.Document(status);
                return ExitCodes.Success;
            }

            var rows = StatusRows(status);
            cli.Output.KeyValues(rows);
            return ExitCodes.Success;
        });
        return command;
    }

    /// <summary>
    /// The rows of <c>account status</c>. The account's name and e-mail come from the center: they reach the terminal only as plain text
    /// (SEC-24; N2 confirmation C1-1), and so does every other value of the status.
    /// </summary>
    internal static List<(string, string)> StatusRows(AccountStatus status)
    {
        ArgumentNullException.ThrowIfNull(status);
        var rows = new List<(string, string)>
        {
            ("signed in", status.SignedIn ? "yes" : "no"),
            ("center", Messages.Plain(status.CenterUrl)),
        };
        if (status.SignedIn)
        {
            rows.Add(("account", Messages.Plain(status.AccountDisplayName) + (status.HasAccountEmailMasked ? " (" + Messages.Plain(status.AccountEmailMasked) + ")" : string.Empty)));
            rows.Add(("credential in OS store", status.CredentialInOsStore ? "yes" : "no"));
            rows.Add(("credential ends", CliOutput.When(status.CredentialExpiresAt)));
        }

        if (status.HasNodeKeyFingerprint)
        {
            rows.Add(("key fingerprint", Messages.Plain(status.NodeKeyFingerprint)));
        }

        if (status.HasCloudReachable)
        {
            rows.Add(("center reachable", status.CloudReachable ? "yes" : "no"));
        }

        if (status.Warnings.Count > 0)
        {
            rows.Add(("warnings", Messages.Plain(string.Join(", ", status.Warnings))));
        }

        return rows;
    }

    /// <summary>The account status, or <see langword="null"/> (a read failure is not this command's error).</summary>
    internal static async Task<AccountStatus?> ReadStatusAsync(Cli cli, NodeSession session, CancellationToken cancellationToken)
    {
        var meta = Cli.Meta();
        var response = await cli.CallAsync("GetAccountStatus", meta, () => session.Channel.Account.GetAccountStatusAsync(
            new AccountServiceGetAccountStatusRequest { Meta = meta }, deadline: cli.Deadline(StatusDeadline), cancellationToken: cancellationToken)).ConfigureAwait(false);
        return response.Error is null ? response.Value.Status : null;
    }
}
