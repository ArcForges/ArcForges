// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Core;

namespace ArcForges.Node.Api;

/// <summary>
/// The node's API listener (architecture 02 section 2 step 7): a DesktopPlatform LocalRpc server in service-endpoint mode on the
/// per-user pipe or socket. LocalRpc creates the endpoint same-user-only (pipe DACL with <c>PIPE_REJECT_REMOTE_CLIENTS</c>; socket
/// directory 0700, socket 0600) and resolves every connection's peer before HTTP/2 reads a byte, refusing other users and peers it
/// cannot identify (11 section 2; R-SEC-001). Method deadlines follow node.proto and events.proto; <c>Subscribe</c> runs in the
/// stream lane with 15 s heartbeats and a 2,048-event buffer; <c>GetHealth</c> runs in a reserved control slot.
/// </summary>
public static class NodeApiServer
{
    private const string Node = "arcforges.node.v1.NodeService";
    private const string Events = "arcforges.node.v1.NodeEventService";
    private const string Tasks = "arcforges.node.v1.TaskService";
    private const string Resources = "arcforges.node.v1.ResourceService";
    private const string Approvals = "arcforges.node.v1.ApprovalService";

    /// <summary>Builds the server (not started).</summary>
    /// <param name="endpoint">The node's endpoint.</param>
    /// <param name="node">The running node.</param>
    /// <param name="sessions">The client sessions.</param>
    /// <param name="streamBuffer">The per-subscriber buffer (default 2,048, 02 section 1).</param>
    /// <param name="images">The executables that verify each client kind (default: the node's own, <see cref="ClientImages.ForNode"/>).</param>
    public static LocalRpcServer Build(LocalRpcEndpoint endpoint, NodeRuntime node, ClientSessions sessions, int streamBuffer = 2048, ClientImages? images = null)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(node);
        ArgumentNullException.ThrowIfNull(sessions);
        var builder = LocalRpcServer.CreateBuilder(endpoint);
        builder.Options = new LocalRpcServerOptions { Mode = LocalRpcServerMode.Service };

        // Each approval-gated service registers how its captured requests execute once a HUMAN approved them (11 section 1).
        var executors = new ApprovalExecutors();
        var approvals = new ApprovalServiceHandler(node, sessions, executors);
        builder.AddService(new NodeServiceHandler(node, sessions, executors, images ?? ClientImages.ForNode(testMode: false)));
        builder.AddService(new NodeEventServiceHandler(node, streamBuffer));
        builder.AddService(new TaskServiceHandler(node, sessions, executors));
        builder.AddService(new ResourceServiceHandler(node, sessions, executors));
        builder.AddService(new QueueServiceHandler(node, sessions, executors));
        builder.AddService(new PolicyServiceHandler(node, sessions, executors));
        builder.AddService(approvals);
        node.ResumeApprovals = approvals.ResumeAsync;
        builder.AuthorizeConnections(connection =>
        {
            // Reached only by same-user peers that LocalRpc identified (other users, exited and unresolvable peers are dropped
            // before this decision). Every same-user peer is admitted; its hello assigns the origin the permission matrix decides by.
            node.Log.Debug("api.connection", new LogField("sequence", connection.Sequence), new LogField("pid", connection.Peer?.ProcessId ?? 0));
            return connection.Peer is not null;
        });
        builder.RegisterControl(LocalRpcControlOperation.Health, Node, "GetHealth");
        Profile(builder, "Hello", 5);
        Profile(builder, "GetNodeInfo", 5);
        Profile(builder, "GetCapabilities", 30);
        Profile(builder, "RenameNode", 5);
        Profile(builder, "GetNodeSettings", 5);
        Profile(builder, "UpdateNodeSettings", 5);
        Profile(builder, "StopNode", 10);
        Profile(builder, "GetJob", 5);
        Profile(builder, "ListJobs", 5);
        Profile(builder, "CancelJob", 10);
        Profile(builder, "ListNotifications", 5);
        Profile(builder, "MarkNotificationsRead", 5);
        builder.RegisterMethod(Events, "ListEvents", new LocalRpcCallProfile(TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(30)));

        // TaskService deadlines (tasks.proto): WaitTask holds up to wait_ms (55 s) + 5 s.
        foreach (var (method, seconds) in (ReadOnlySpan<(string, int)>)[("SubmitTask", 10), ("GetTask", 5), ("ListTasks", 5), ("WriteTaskInput", 5),
            ("CloseTaskInput", 5), ("ReleaseCallerBinding", 5), ("CancelTask", 10), ("RetryTask", 5), ("PinTask", 5), ("PurgeTaskRecord", 30),
            ("ReadTaskOutput", 10), ("GetAttempt", 5), ("ListAttempts", 5)])
        {
            builder.RegisterMethod(Tasks, method, new LocalRpcCallProfile(TimeSpan.FromSeconds(seconds), TimeSpan.FromSeconds(Math.Max(seconds, 30))));
        }

        builder.RegisterMethod(Tasks, "WaitTask", new LocalRpcCallProfile(TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60)));
        foreach (var method in (ReadOnlySpan<string>)["AttachTask", "WatchTaskOutput"])
        {
            builder.RegisterStream(Tasks, method, new LocalRpcStreamProfile
            {
                HeartbeatInterval = NodeEventServiceHandler.HeartbeatInterval,
                MaxBufferedMessages = streamBuffer,
            });
        }

        // ResourceService deadlines (resources.proto): snapshot and process list 5 s, samples 10 s, adoption and termination 10 s; WatchResources
        // streams with 15 s heartbeats.
        foreach (var (method, seconds) in (ReadOnlySpan<(string, int)>)[("GetResourceSnapshot", 5), ("ListProcesses", 5), ("GetSamples", 10), ("AdoptProcess", 10),
            ("TerminateProcess", 10)])
        {
            builder.RegisterMethod(Resources, method, new LocalRpcCallProfile(TimeSpan.FromSeconds(seconds), TimeSpan.FromSeconds(30)));
        }

        // ApprovalService deadlines (approvals.proto): list, get and withdraw 5 s; a decision 10 s (it runs the approved request).
        foreach (var (method, seconds) in (ReadOnlySpan<(string, int)>)[("ListApprovals", 5), ("GetApproval", 5), ("DecideApproval", 10), ("CancelApproval", 5)])
        {
            builder.RegisterMethod(Approvals, method, new LocalRpcCallProfile(TimeSpan.FromSeconds(seconds), TimeSpan.FromSeconds(30)));
        }

        builder.RegisterStream(Resources, "WatchResources", new LocalRpcStreamProfile
        {
            HeartbeatInterval = NodeEventServiceHandler.HeartbeatInterval,
            MaxBufferedMessages = streamBuffer,
        });
        builder.RegisterStream(Events, "Subscribe", new LocalRpcStreamProfile
        {
            HeartbeatInterval = NodeEventServiceHandler.HeartbeatInterval,
            MaxBufferedMessages = streamBuffer,
        });
        var server = builder.Build();
        node.ServerMetrics = () =>
        {
            var service = server.GetServiceSnapshot();
            var metrics = new List<HealthMetric>
            {
                new() { Name = "rpc.streams_active", Kind = MetricKind.Gauge, Value = service.StreamsActive },
                new() { Name = "rpc.peers_admitted", Kind = MetricKind.Counter, Value = service.PeersAdmitted },
            };
            foreach (var (reason, count) in service.PeersDenied)
            {
                var metric = new HealthMetric { Name = "rpc.peers_denied", Kind = MetricKind.Counter, Value = count };
                metric.Labels["reason"] = reason.ToString();
                metrics.Add(metric);
            }

            foreach (var (reason, count) in service.StreamsEnded)
            {
                var metric = new HealthMetric { Name = "rpc.streams_ended", Kind = MetricKind.Counter, Value = count };
                metric.Labels["reason"] = reason.ToString();
                metrics.Add(metric);
            }

            return metrics;
        };
        return server;
    }

    private static void Profile(LocalRpcServerBuilder builder, string method, int seconds) =>
        builder.RegisterMethod(Node, method, new LocalRpcCallProfile(TimeSpan.FromSeconds(seconds), TimeSpan.FromSeconds(Math.Max(seconds, 30))));
}
