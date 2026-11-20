// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;
using Grpc.Core;
using V2 = ArcForges.Contracts.Sandbox.V2;

namespace ArcForges.CommandLine;

/// <summary>The local CenterControl commands and the carried V1 settings commands.</summary>
internal static class CenterCommands
{
    private static readonly TimeSpan Unary = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ControlDeadline = TimeSpan.FromSeconds(10);

    /// <summary>The <c>center</c> group.</summary>
    public static Command Build(Func<ParseResult, Cli> factory)
    {
        var center = new Command("center", "Manage the local Node's Center connection and sign-in");
        center.Subcommands.Add(Status(factory));
        center.Subcommands.Add(Connect(factory));
        center.Subcommands.Add(Flow(factory));
        center.Subcommands.Add(Cancel(factory));
        center.Subcommands.Add(Disconnect(factory));
        center.Subcommands.Add(SignOut(factory));
        center.Subcommands.Add(Show(factory));
        center.Subcommands.Add(Set(factory));
        return center;
    }

    private static Command Status(Func<ParseResult, Cli> factory)
    {
        var command = new Command("status", "Inspect the local Center link and observed channel");
        V2Cli.Set(command, factory, async (cli, _, ct) =>
        {
            await using var session = await V2CliSession.OpenAsync(cli, ct).ConfigureAwait(false);
            using var pin = session.PinConnection();
            var request = new V2.CenterControlServiceGetStatusRequest { Meta = Cli.Meta() };
            var response = await cli.CallAsync("CenterControlService.GetStatus", request.Meta, () => session.CenterControl.GetStatusAsync(
                request, deadline: cli.Deadline(ControlDeadline), cancellationToken: ct)).ConfigureAwait(false);
            var status = V2Cli.Require(response.Value, response.Error);
            V2Cli.Require(status.Connection, null);
            return V2Cli.Print(cli, status);
        });
        return command;
    }

    private static Command Connect(Func<ParseResult, Cli> factory)
    {
        const string Method = "CenterControlService.BeginConnect";
        var origin = new Argument<string>("origin") { Description = "Exact Center HTTPS origin" };
        var mode = new Option<string>("--mode") { Required = true, Description = "Select the service mode" };
        mode.AcceptOnlyFromAmong("official", "self_hosted");
        var flow = new Option<string?>("--flow") { Description = "Select the sign-in flow for a new enrollment" };
        flow.AcceptOnlyFromAmong("browser", "device_code");
        var command = new Command("connect", "Enable an existing enrollment or begin a bounded sign-in") { origin, mode, flow };
        var mutation = new V2MutationOptions();
        mutation.AddTo(command);
        V2Cli.Set(command, factory, async (cli, result, ct) =>
        {
            var request = new V2.CenterControlServiceBeginConnectRequest
            {
                CenterOrigin = result.GetValue(origin)!,
                ServiceMode = result.GetValue(mode)!,
            };
            if (result.GetValue(flow) is { } flowKind)
            {
                request.FlowKind = flowKind;
            }

            await using var session = await V2CliSession.OpenAsync(cli, ct).ConfigureAwait(false);
            using var pin = session.PinConnection();
            var deadline = cli.Deadline(ControlDeadline);
            var identity = await mutation.BeginAsync(result, session, deadline, ct).ConfigureAwait(false);
            request.Meta = identity.Meta;
            request.OwnerEpoch = identity.OwnerEpoch;
            var response = await V2Cli.SendAsync(cli, Method, identity, () => session.CenterControl.BeginConnectAsync(
                request, deadline: deadline, cancellationToken: ct)).ConfigureAwait(false);
            var value = V2Cli.Require(response.Value, response.Error, identity);
            if (MutationFailure(value.Operation, Method, identity) is { } failure)
            {
                return V2Cli.Fail(cli, failure, identity, value);
            }

            var document = (JsonObject)CliOutput.ToJsonNode(value);
            if (value.FlowId is { } flowId)
            {
                await ObserveFlowAsync(document, cli, session, flowId, deadline, ct).ConfigureAwait(false);
            }

            return V2Cli.Print(cli, document, identity);
        });
        return command;
    }

    private static Command Flow(Func<ParseResult, Cli> factory)
    {
        var flowId = new Argument<string>("flow-id") { Description = "Owner-visible sign-in flow ID" };
        var command = new Command("flow", "Read an existing sign-in flow") { flowId };
        V2Cli.Set(command, factory, async (cli, result, ct) =>
        {
            var id = V2Cli.ReadId(result.GetValue(flowId), "flow-id");
            await using var session = await V2CliSession.OpenAsync(cli, ct).ConfigureAwait(false);
            using var pin = session.PinConnection();
            var response = await ReadFlowAsync(cli, session, id, cli.Deadline(ControlDeadline), ct).ConfigureAwait(false);
            var value = V2Cli.Require(response.Value, response.Error);
            if (!id.Equals(value.Flow?.FlowId))
            {
                return V2Cli.Fail(cli, V2Cli.Error(ErrorCategory.State, "node_unavailable", "flow_response_identity_mismatch"));
            }

            return V2Cli.Print(cli, value);
        });
        return command;
    }

    private static Command Cancel(Func<ParseResult, Cli> factory)
    {
        const string Method = "CenterControlService.CancelConnect";
        var flowId = new Argument<string>("flow-id") { Description = "Owner-visible sign-in flow ID" };
        var command = new Command("cancel", "Cancel an existing pending sign-in") { flowId };
        var mutation = new V2MutationOptions();
        mutation.AddTo(command);
        V2Cli.Set(command, factory, async (cli, result, ct) =>
        {
            var id = V2Cli.ReadId(result.GetValue(flowId), "flow-id");
            await using var session = await V2CliSession.OpenAsync(cli, ct).ConfigureAwait(false);
            using var pin = session.PinConnection();
            var deadline = cli.Deadline(ControlDeadline);
            var identity = await mutation.BeginAsync(result, session, deadline, ct).ConfigureAwait(false);
            var request = new V2.CenterControlServiceCancelConnectRequest { Meta = identity.Meta, OwnerEpoch = identity.OwnerEpoch, FlowId = id };
            var response = await V2Cli.SendAsync(cli, Method, identity, () => session.CenterControl.CancelConnectAsync(
                request, deadline: deadline, cancellationToken: ct)).ConfigureAwait(false);
            var value = V2Cli.Require(response.Value, response.Error, identity);
            return PrintMutation(cli, value, value.Operation, Method, identity);
        });
        return command;
    }

    private static Command Disconnect(Func<ParseResult, Cli> factory)
    {
        const string Method = "CenterControlService.Disconnect";
        var command = new Command("disconnect", "Disable the Center link and retain the protected credential");
        var mutation = new V2MutationOptions();
        mutation.AddTo(command);
        V2Cli.Set(command, factory, async (cli, result, ct) =>
        {
            await using var session = await V2CliSession.OpenAsync(cli, ct).ConfigureAwait(false);
            using var pin = session.PinConnection();
            var deadline = cli.Deadline(ControlDeadline);
            var identity = await mutation.BeginAsync(result, session, deadline, ct).ConfigureAwait(false);
            var request = new V2.CenterControlServiceDisconnectRequest { Meta = identity.Meta, OwnerEpoch = identity.OwnerEpoch };
            var response = await V2Cli.SendAsync(cli, Method, identity, () => session.CenterControl.DisconnectAsync(
                request, deadline: deadline, cancellationToken: ct)).ConfigureAwait(false);
            var value = V2Cli.Require(response.Value, response.Error, identity);
            return PrintMutation(cli, value, value.Operation, Method, identity);
        });
        return command;
    }

    private static Command SignOut(Func<ParseResult, Cli> factory)
    {
        const string Method = "CenterControlService.SignOut";
        var command = new Command("signout", "End local Center credentials and request remote revocation");
        var mutation = new V2MutationOptions();
        mutation.AddTo(command);
        V2Cli.Set(command, factory, async (cli, result, ct) =>
        {
            await using var session = await V2CliSession.OpenAsync(cli, ct).ConfigureAwait(false);
            using var pin = session.PinConnection();
            var deadline = cli.Deadline(ControlDeadline);
            var identity = await mutation.BeginAsync(result, session, deadline, ct).ConfigureAwait(false);
            var request = new V2.CenterControlServiceSignOutRequest { Meta = identity.Meta, OwnerEpoch = identity.OwnerEpoch };
            var response = await V2Cli.SendAsync(cli, Method, identity, () => session.CenterControl.SignOutAsync(
                request, deadline: deadline, cancellationToken: ct)).ConfigureAwait(false);
            var value = V2Cli.Require(response.Value, response.Error, identity);
            return PrintMutation(cli, value, value.Operation, Method, identity);
        });
        return command;
    }

    private static Task<V2.CenterControlServiceGetConnectFlowResponse> ReadFlowAsync(
        Cli cli, V2CliSession session, Id flowId, DateTime deadline, CancellationToken ct)
    {
        var request = new V2.CenterControlServiceGetConnectFlowRequest { Meta = Cli.Meta(), FlowId = flowId };
        return cli.CallAsync("CenterControlService.GetConnectFlow", request.Meta, () => session.CenterControl.GetConnectFlowAsync(
            request, deadline: deadline, cancellationToken: ct));
    }

    private static async Task ObserveFlowAsync(JsonObject document, Cli cli, V2CliSession session, Id flowId, DateTime deadline,
        CancellationToken ct)
    {
        try
        {
            var response = await ReadFlowAsync(cli, session, flowId, deadline, ct).ConfigureAwait(false);
            if (response.Error is null && response.Value?.Flow is { } flow && flowId.Equals(flow.FlowId))
            {
                document["flow"] = CliOutput.ToJsonNode(flow);
                return;
            }
        }
        catch (Exception exception) when (exception is RpcException or OperationCanceledException)
        {
            // The observed acceptance is still valid if the separate, transient flow read fails.
        }

        document["flowObservation"] = "unavailable";
    }

    private static int PrintMutation(Cli cli, IMessage value, V2.Operation? operation, string method, V2CommandIdentity identity) =>
        MutationFailure(operation, method, identity) is { } failure
            ? V2Cli.Fail(cli, failure, identity, value)
            : V2Cli.Print(cli, value, identity);

    private static ArcError? MutationFailure(V2.Operation? operation, string method, V2CommandIdentity identity)
    {
        if (operation is null || operation.Method != method || !identity.CommandId.Equals(operation.CommandId)
            || !identity.OwnerEpoch.Equals(operation.OwnerEpoch))
        {
            throw new V2CommandException(V2Cli.UnknownEffect("center_control_receipt_identity_mismatch", identity.Meta.CorrelationId), identity);
        }

        if (operation.State is (V2.OperationState.Failed or V2.OperationState.Unknown) && operation.Error is { } failure)
        {
            return failure;
        }

        if (operation.Error is null && operation.State is (V2.OperationState.Accepted or V2.OperationState.Succeeded))
        {
            return null;
        }

        return V2Cli.UnknownEffect("center_control_receipt_state_unconfirmed", identity.Meta.CorrelationId);
    }

    private static Command Show(Func<ParseResult, Cli> factory)
    {
        var command = new Command("show", "Print the configured center");
        Actions.Set(command, factory, async (cli, _, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var meta = Cli.Meta();
            var settings = await cli.CallAsync("GetNodeSettings", meta, () => session.Channel.Node.GetNodeSettingsAsync(
                new NodeServiceGetNodeSettingsRequest { Meta = meta }, deadline: cli.Deadline(Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (settings.Error is { } error)
            {
                return cli.Output.Fail(error, meta.CorrelationId);
            }

            var configured = settings.Value.Settings.HasCenterUrl ? settings.Value.Settings.CenterUrl : null;
            var status = await AccountCommands.ReadStatusAsync(cli, session, cancellationToken).ConfigureAwait(false);
            var credential = status is { SignedIn: true, HasCenterUrl: true } ? status.CenterUrl : null;
            if (cli.Output.Json)
            {
                var document = new JsonObject { ["centerUrl"] = configured };
                if (credential is not null)
                {
                    document["credentialCenterUrl"] = credential;
                }

                cli.Output.Document(document);
                return ExitCodes.Success;
            }

            cli.Output.Line("Center: " + (configured ?? "none (set one with 'arcforges center set <url>')"));
            if (credential is not null && credential != configured)
            {
                cli.Output.Line("Signed in at: " + credential);
            }

            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Set(Func<ParseResult, Cli> factory)
    {
        var url = new Argument<string?>("url") { Description = "The center's URL (https; http only for localhost, 127.0.0.1 or [::1])", Arity = ArgumentArity.ZeroOrOne };
        var reset = new Option<bool>("--default") { Description = "Use the official center again" };
        var command = new Command("set", "Change the center (sign out first)") { url, reset };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var value = result.GetValue(url);
            var official = result.GetValue(reset);
            if ((value is null) == !official)
            {
                throw new UsageException("give either a URL or --default.");
            }

            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            for (var attempt = 0; ; attempt++)
            {
                var readMeta = Cli.Meta();
                var current = await cli.CallAsync("GetNodeSettings", readMeta, () => session.Channel.Node.GetNodeSettingsAsync(
                    new NodeServiceGetNodeSettingsRequest { Meta = readMeta }, deadline: cli.Deadline(Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
                if (current.Error is { } readError)
                {
                    return cli.Output.Fail(readError, readMeta.CorrelationId);
                }

                var request = new NodeServiceUpdateNodeSettingsRequest { Meta = Cli.Meta(), CenterUrl = official ? string.Empty : value! };
                request.Meta.ExpectedRev = current.Value.Settings.Revision;
                var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
                var response = await cli.MutateAsync("UpdateNodeSettings", request.Meta.CommandId, action, r => session.Channel.Node.UpdateNodeSettingsAsync(r,
                    deadline: cli.Deadline(Unary), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
                if (response.Error is { Code: "revision_conflict" } && attempt == 0)
                {
                    continue;
                }

                if (response.Error is { } error)
                {
                    if (!cli.Output.Json && error.Code == "invalid_state" && error.Details?.State is { } state)
                    {
                        cli.Output.Error.WriteLine("error: " + (state.State switch
                        {
                            "signed_in" => "the node is signed in; run 'arcforges logout' first",
                            "signing_in" => "a sign-in is in progress; finish or cancel it first",
                            _ => "the center cannot be changed now (" + state.Reason + ")",
                        }) + " (STATE/invalid_state)");
                        return ExitCodes.Failed;
                    }

                    return cli.Output.Fail(error, request.Meta.CorrelationId);
                }

                if (cli.Output.Json)
                {
                    cli.Output.Document(response.Value);
                }
                else
                {
                    cli.Output.Line("Center: " + response.Value.Settings.CenterUrl);
                    foreach (var warning in response.Meta.Warnings)
                    {
                        cli.Output.Note(warning);
                    }
                }

                return ExitCodes.Success;
            }
        });
        return command;
    }
}
