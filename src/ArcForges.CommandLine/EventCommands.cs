// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using ArcForges.Contracts.Node.V1;
using Grpc.Core;

namespace ArcForges.CommandLine;

/// <summary>
/// <c>arcforges events [--topic t...] [--since cursor]</c> (experience/cli.md C-08): <c>NodeEventService.Subscribe</c> printed as JSON
/// Lines, one frame per line (snapshot events, snapshot completion, resets and events; heartbeats only with <c>--verbose</c>). With
/// <c>--since</c> the stream resumes after that cursor (a cursor from another generation or beyond retention gets a reset and a
/// snapshot). It runs until interrupted or until the node ends the stream.
/// </summary>
internal static class EventCommands
{
    /// <summary>The topic names of <c>--topic</c> (EventTopic without its prefix, lower case).</summary>
    internal static readonly IReadOnlyDictionary<string, EventTopic> Topics = new Dictionary<string, EventTopic>(StringComparer.OrdinalIgnoreCase)
    {
        ["node"] = EventTopic.Node,
        ["tasks"] = EventTopic.Tasks,
        ["queue"] = EventTopic.Queue,
        ["resources"] = EventTopic.Resources,
        ["findings"] = EventTopic.Findings,
        ["approvals"] = EventTopic.Approvals,
        ["sessions"] = EventTopic.Sessions,
        ["workspaces"] = EventTopic.Workspaces,
        ["jobs"] = EventTopic.Jobs,
        ["peers"] = EventTopic.Peers,
        ["guests"] = EventTopic.Guests,
        ["policy"] = EventTopic.Policy,
        ["updates"] = EventTopic.Updates,
        ["account"] = EventTopic.Account,
        ["integrations"] = EventTopic.Integrations,
        ["storage"] = EventTopic.Storage,
        ["support"] = EventTopic.Support,
        ["notifications"] = EventTopic.Notifications,
    };

    public static Command Build(Func<ParseResult, Cli> factory)
    {
        var topic = new Option<string[]>("--topic") { Description = "A topic to subscribe to (repeatable; default all)", HelpName = "t" };
        topic.AcceptOnlyFromAmong([.. Topics.Keys]);
        var since = new Option<string?>("--since") { Description = "Resume after this cursor", HelpName = "cursor" };
        var command = new Command("events", "Stream node events as JSON Lines") { topic, since };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var request = new NodeEventServiceSubscribeRequest();
            var names = result.GetValue(topic) ?? [];
            request.Topics.Add(names.Length == 0 ? Topics.Values : names.Select(name => Topics[name]).Distinct());
            if (result.GetValue(since) is { Length: > 0 } cursor)
            {
                request.Cursor = cursor;
            }

            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            using var call = session.Channel.Events.Subscribe(request, cancellationToken: cancellationToken);
            try
            {
                await foreach (var frame in call.ResponseStream.ReadAllAsync(cancellationToken).ConfigureAwait(false))
                {
                    if (frame.FrameCase == NodeEventServiceSubscribeFrame.FrameOneofCase.Heartbeat && !cli.Output.Verbose)
                    {
                        continue;
                    }

                    cli.Output.JsonLine(frame);
                    await cli.Output.Out.FlushAsync(cancellationToken).ConfigureAwait(false);
                    if (frame.FrameCase == NodeEventServiceSubscribeFrame.FrameOneofCase.Error)
                    {
                        return ExitCodes.For(frame.Error);
                    }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return ExitCodes.Success;
            }
            catch (RpcException exception) when (exception.StatusCode == StatusCode.Cancelled && cancellationToken.IsCancellationRequested)
            {
                return ExitCodes.Success;
            }

            cli.Output.Error.WriteLine("arcforges: the node ended the stream");
            return ExitCodes.NodeUnreachable;
        });
        return command;
    }
}
