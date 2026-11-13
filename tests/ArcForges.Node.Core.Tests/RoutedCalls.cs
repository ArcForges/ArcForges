// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.CloudLink;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// The routed test seam of part N2b (decisions Q7): hands a call to a real node's <see cref="RoutedDispatcher"/> as N1's channel does after
/// its verification (the pending <c>routed_call_log</c> row first, the final decision after the answer), without the channel or signatures,
/// which the CloudLink tests cover with a mocked center. Callers are built as the center signs them into a call header.
/// </summary>
internal sealed class RoutedCalls(InProcessNode node)
{
    /// <summary>The account of the test node's link.</summary>
    public static readonly Id Account = new() { Value = ByteString.CopyFrom(Enumerable.Repeat((byte)0xac, 16).ToArray()) };

    private RoutedCallLog Log { get; } = new(new ProcessorRoutedCallStore(node.Runtime.Processor), node.Runtime.Clock);

    /// <summary>The most recently constructed verified call ID, for response-correlation checks.</summary>
    public Id? LastCallId { get; private set; }

    /// <summary>The link the calls arrive on (a test flips it).</summary>
    public TestLink Link { get; } = new();

    public RoutedDispatcher Dispatcher => (RoutedDispatcher)node.Runtime.RoutedDispatcher!;

    /// <summary>A node-relayed caller: from this node, or from another node of the account.</summary>
    public CenterCaller Relay(Origin origin, bool ownNode = true, Id? relaying = null) => new()
    {
        Kind = CenterCallerKind.NodeRelay,
        AccountId = Account.Clone(),
        RelayingNodeId = relaying ?? (ownNode ? new Id { Value = ByteString.CopyFrom(node.Runtime.NodeId.Span) } : CommandIds.New()),
        LocalOrigin = origin,
        LocalSessionId = CommandIds.New(),
    };

    /// <summary>An account-session caller (Web, Android).</summary>
    public static CenterCaller Session(Id? session = null) => new()
    {
        Kind = CenterCallerKind.AccountSession,
        AccountId = Account.Clone(),
        UserId = new Id { Value = ByteString.CopyFrom(Enumerable.Repeat((byte)0x55, 16).ToArray()) },
        SessionId = session ?? CommandIds.New(),
    };

    /// <summary>
    /// Dispatches <paramref name="payload"/> as <paramref name="method"/> for <paramref name="caller"/>; <paramref name="record"/> false skips
    /// the log rows (a test that holds the writer). <paramref name="expires"/> defaults to a minute from now.
    /// </summary>
    public async Task<(RoutedAnswer? Answer, long LogId)> CallAsync(CenterCaller caller, RoutedMethod method, byte[] payload, Id? commandId = null,
        DateTimeOffset? expires = null, bool record = true, CancellationToken? cancellationToken = null)
    {
        var now = node.Runtime.Clock.GetUtcNow();
        var header = new CallHeader
        {
            CallId = CommandIds.New(),
            Kid = "routed-test-key",
            CenterUrlSha256 = ByteString.CopyFrom(new byte[32]),
            AccountId = Account.Clone(),
            TargetNodeId = new Id { Value = ByteString.CopyFrom(node.Runtime.NodeId.Span) },
            Caller = caller,
            Method = method,
            RequestSha256 = ByteString.CopyFrom(SHA256.HashData(payload)),
            RequestSize = (uint)payload.Length,
            IssuedAt = ProtoTime.ToInstant(now.AddSeconds(-1)),
            ExpiresAt = ProtoTime.ToInstant(expires ?? now.AddSeconds(60)),
            Deadline = ProtoTime.ToInstant((expires ?? now.AddSeconds(60)) < now.AddSeconds(10) ? (expires ?? now) : now.AddSeconds(10)),
        };
        LastCallId = header.CallId.Clone();
        if (commandId is not null)
        {
            header.CommandId = commandId;
        }

        long logId = 0;
        if (record)
        {
            logId = await Log.RecordVerifiedAsync(new VerifiedCallRow
            {
                FrameSha256 = SHA256.HashData(header.ToByteArray()),
                CallId = header.CallId.Value.ToByteArray(),
                Kid = header.Kid,
                Method = (int)method,
                Caller = caller.ToByteArray(),
                CommandId = commandId?.Value.ToByteArray(),
                RequestSha256 = header.RequestSha256.ToByteArray(),
                RequestSize = payload.Length,
            }) ?? throw new InvalidOperationException("a fresh call ID");
        }

        var answer = await Dispatcher.DispatchAsync(new VerifiedCall(header, ByteString.CopyFrom(payload), logId), Link, cancellationToken ?? TestContext.Current.CancellationToken);
        if (record && answer is not null)
        {
            var decision = answer.Outcome switch
            {
                RoutedOutcome.Executed => RoutedCallDecision.Executed,
                RoutedOutcome.Expired => RoutedCallDecision.Expired,
                _ => RoutedCallDecision.RefusedByPolicy,
            };
            var code = answer.Error is { } error ? error.Category.ToString().ToUpperInvariant() + "/" + error.Code : answer.HandlerCode;
            await Log.CompleteAsync(logId, decision, code, answer.TaskId, answer.Risk,
                answer.Response is { } response ? SHA256.HashData(response.Span) : null, answer.Response?.Length,
                fileWorkspace: (int)method is >= 9 and <= 20, workspaceId: answer.WorkspaceId);
        }

        return (answer, logId);
    }

    /// <summary>A routed SubmitTask of <paramref name="request"/> (its exact bytes, or <paramref name="raw"/>).</summary>
    public async Task<(RoutedAnswer? Answer, TaskServiceSubmitTaskResponse? Response)> SubmitAsync(CenterCaller caller, TaskServiceSubmitTaskRequest request,
        byte[]? raw = null, DateTimeOffset? expires = null, bool record = true)
    {
        var (answer, _) = await CallAsync(caller, RoutedMethod.SubmitNodeTask, raw ?? request.ToByteArray(), request.Meta.CommandId, expires, record);
        return (answer, answer?.Response is { } bytes ? TaskServiceSubmitTaskResponse.Parser.ParseFrom(bytes) : null);
    }

    /// <summary>A routed CancelTask of <paramref name="task"/>.</summary>
    public async Task<(RoutedAnswer? Answer, TaskServiceCancelTaskResponse? Response)> CancelAsync(CenterCaller caller, Id task, RequestMeta? meta = null)
    {
        var request = new TaskServiceCancelTaskRequest { Meta = meta ?? Tasks.Meta(), TaskId = task };
        var (answer, _) = await CallAsync(caller, RoutedMethod.CancelNodeTask, request.ToByteArray(), request.Meta.CommandId);
        return (answer, answer?.Response is { } bytes ? TaskServiceCancelTaskResponse.Parser.ParseFrom(bytes) : null);
    }

    /// <summary>A routed read; the response parsed with <paramref name="parser"/>.</summary>
    public async Task<(RoutedAnswer? Answer, T? Response)> ReadAsync<T>(CenterCaller caller, RoutedMethod method, IMessage request, MessageParser<T> parser)
        where T : class, IMessage<T>
    {
        var (answer, _) = await CallAsync(caller, method, request.ToByteArray());
        return (answer, answer?.Response is { } bytes ? parser.ParseFrom(bytes) : null);
    }

    /// <summary>
    /// The digest the center compares a replayed outcome with (Cloud <c>fleetapi.OutcomeDigest</c>, decisions Q-5): the response's fields in
    /// wire order without <c>ResponseMeta</c> (field 1) and, inside the error (field 3), without <c>correlation_id</c> (6) and
    /// <c>retry.retry_at</c> (4.2).
    /// </summary>
    public static byte[] OutcomeDigest(ReadOnlySpan<byte> response) => SHA256.HashData(Rewrite(response.ToArray(), (number, value) => number switch
    {
        1 => null,
        3 => Rewrite(value, (inner, field) => inner switch
        {
            6 => null,
            4 => Rewrite(field, (retry, part) => retry == 2 ? null : part),
            _ => field,
        }),
        _ => value,
    }));

    private static byte[] Rewrite(byte[] message, Func<int, byte[], byte[]?> edit)
    {
        var output = new MemoryStream();
        var input = new CodedInputStream(message);
        while (true)
        {
            var start = (int)input.Position;
            var tag = input.ReadTag();
            if (tag == 0)
            {
                break;
            }

            var number = WireFormat.GetTagFieldNumber(tag);
            if (WireFormat.GetTagWireType(tag) == WireFormat.WireType.LengthDelimited)
            {
                var bytes = input.ReadBytes().ToByteArray();
                if (edit(number, bytes) is { } kept)
                {
                    var writer = new CodedOutputStream(output, leaveOpen: true);
                    writer.WriteTag(tag);
                    writer.WriteBytes(ByteString.CopyFrom(kept));
                    writer.Flush();
                }
            }
            else
            {
                input.SkipLastField();
                output.Write(message, start, (int)input.Position - start);
            }
        }

        return output.ToArray();
    }

    /// <summary>
    /// A link a test flips (decisions B-3): usable for its first <see cref="UsableFor"/> reads and not stopping for its first
    /// <see cref="NotStoppingFor"/> reads. The dispatcher reads each once on entry and once immediately before the effect.
    /// </summary>
    internal sealed class TestLink : IRoutedLink
    {
        private int _usableReads;
        private int _stoppingReads;

        public int UsableFor { get; set; } = int.MaxValue;

        public int NotStoppingFor { get; set; } = int.MaxValue;

        public bool Usable => Interlocked.Increment(ref _usableReads) <= UsableFor;

        public bool Stopping => Interlocked.Increment(ref _stoppingReads) > NotStoppingFor;

        public void Reset(int usableFor = int.MaxValue, int notStoppingFor = int.MaxValue)
        {
            _usableReads = 0;
            _stoppingReads = 0;
            UsableFor = usableFor;
            NotStoppingFor = notStoppingFor;
        }
    }
}
