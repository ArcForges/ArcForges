// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Text.RegularExpressions;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Events;
using Google.Protobuf.Collections;

namespace ArcForges.Node.Api;

/// <summary>The <c>validate:</c> rules of the node.proto and events.proto request fields this API serves.</summary>
internal static partial class Validation
{
    /// <summary>How far a hello's process start time may differ from the peer's (the two are read through different OS calls).</summary>
    private static readonly TimeSpan StartTolerance = TimeSpan.FromSeconds(1);

    /// <summary><c>meta.command_id</c>: required on mutations, a 16-byte UUIDv7.</summary>
    public static ArcError? CommandId(RequestMeta? meta) =>
        meta?.CommandId?.Value is { Length: 16 } ? null : NodeErrors.InvalidArgument("meta.command_id: required; a 16-byte UUIDv7");

    /// <summary>A required 16-byte ID field.</summary>
    public static ArcError? RequiredId(Id? id, string field) =>
        id?.Value is { Length: 16 } ? null : NodeErrors.InvalidArgument($"{field}: required; a 16-byte ID");

    /// <summary>
    /// The client hello (node.proto <c>ClientHello</c>): kind and contract major required, version SemVer, at most 64 features, the
    /// process required and equal to the connection's peer process, the parent verified when present, MCP fields only from the MCP
    /// adapter. A contract major other than 1 is <c>VALIDATION/incompatible_version</c>.
    /// </summary>
    public static ArcError? Hello(ClientHello? hello, LocalRpcPeer? peer)
    {
        if (hello is null)
        {
            return NodeErrors.InvalidArgument("hello: required");
        }

        if (!hello.HasClientKind || hello.ClientKind == ClientKind.Unspecified || !Enum.IsDefined(hello.ClientKind))
        {
            return NodeErrors.InvalidArgument("hello.client_kind: required");
        }

        if (!hello.HasContractMajor)
        {
            return NodeErrors.InvalidArgument("hello.contract_major: required");
        }

        if (hello.HasClientVersion && !SemVer().IsMatch(hello.ClientVersion))
        {
            return NodeErrors.InvalidArgument("hello.client_version: SemVer");
        }

        if (hello.Features.Count > 64)
        {
            return NodeErrors.InvalidArgument("hello.features: at most 64");
        }

        if (hello.HasMcpClientName && hello.ClientKind != ClientKind.McpAdapter)
        {
            return NodeErrors.InvalidArgument("hello.mcp_client_name: MCP adapter only");
        }

        if (hello.Process is not { HasPid: true, Pid: > 0 } process || ProtoTime.ToDateTimeOffset(process.StartTime) is not { } start)
        {
            return NodeErrors.InvalidArgument("hello.process: required (pid > 0 and start_time)");
        }

        if (peer is null || process.Pid != (uint)peer.ProcessId || (start - peer.ProcessStartTime).Duration() > StartTolerance)
        {
            return NodeErrors.InvalidArgument("hello.process: must be the connection's peer process");
        }

        if (hello.ParentProcess is { } parent && !ProcessMatches(parent))
        {
            return NodeErrors.InvalidArgument("hello.parent_process: no running process with this pid and start time");
        }

        if (hello.ContractMajor != NodeContract.Major)
        {
            return NodeErrors.IncompatibleVersion(NodeContract.Major + ".0", hello.ContractMajor + "." + hello.ContractMinor);
        }

        return null;
    }

    /// <summary>A page limit in <c>1..max</c> (absent = <paramref name="defaultLimit"/>), and a cursor this node issued.</summary>
    public static ArcError? Page(PageRequest? page, int max, int defaultLimit, out int limit, out PageCursor? cursor)
    {
        limit = defaultLimit;
        cursor = null;
        if (page is null)
        {
            return null;
        }

        if (page.HasLimit)
        {
            if (page.Limit < 1 || page.Limit > max)
            {
                return NodeErrors.InvalidArgument($"page.limit: 1..{max}");
            }

            limit = page.Limit;
        }

        if (page.HasCursor && page.Cursor.Length > 0)
        {
            if (!PageCursor.TryParse(page.Cursor, out var parsed))
            {
                return NodeErrors.InvalidCursor();
            }

            cursor = parsed;
        }

        return null;
    }

    /// <summary>Event topics: non-empty, unique and known (events.proto <c>topics</c>).</summary>
    public static ArcError? Topics(RepeatedField<EventTopic> topics, bool unique, out HashSet<EventTopic> set)
    {
        set = [.. topics];
        if (topics.Count == 0)
        {
            return NodeErrors.InvalidArgument("topics: non-empty");
        }

        if (unique && set.Count != topics.Count)
        {
            return NodeErrors.InvalidArgument("topics: unique");
        }

        if (set.Any(topic => topic == EventTopic.Unspecified || !Enum.IsDefined(topic)))
        {
            return NodeErrors.InvalidArgument("topics: known topics only");
        }

        return null;
    }

    /// <summary>A stream cursor: absent, or one this node wrote.</summary>
    public static ArcError? Cursor(bool present, string text, out EventCursor? cursor)
    {
        cursor = null;
        if (!present || text.Length == 0)
        {
            return null;
        }

        if (!EventCursor.TryParse(text, out var parsed))
        {
            return NodeErrors.InvalidCursor();
        }

        cursor = parsed;
        return null;
    }

    private static bool ProcessMatches(ProcessIdentity identity)
    {
        if (!identity.HasPid || ProtoTime.ToDateTimeOffset(identity.StartTime) is not { } start)
        {
            return false;
        }

        try
        {
            using var process = Process.GetProcessById((int)identity.Pid);
            return (new DateTimeOffset(process.StartTime.ToUniversalTime()) - start).Duration() <= StartTolerance;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    [GeneratedRegex(@"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$")]
    private static partial Regex SemVer();
}
