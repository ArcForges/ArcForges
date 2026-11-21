// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;
using ProtoDecimal = ArcForges.Contracts.Foundation.V1.Decimal;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>Real Node, signed WebSocket and SQLite with a fixture Center and prior removal records.</summary>
public sealed class RoutedRemovalPlanChannelTests
{
    [Fact(Timeout = 120_000)]
    public async Task SignedRetainedPlanUsesExactCallerAndRawRequestWithoutRemovingFiles()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        var connection = await RoutedRemovalPlanFixture.ConnectAsync(center, node);
        var caller = RoutedRemovalPlanFixture.Caller(node, connection, Origin.Human);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "signed-removal-plan-root")).FullName;
        var tree = Directory.CreateDirectory(Path.Combine(root, "tree")).FullName;
        var marker = Path.Combine(tree, "marker");
        var body = "signed-plan-only-private-body"u8.ToArray();
        File.WriteAllBytes(marker, body);

        var request = RoutedRemovalPlanFixture.Request(node, root, "tree", ct);
        var raw = request.ToByteArray();
        var plan = RoutedRemovalPlanFixture.PriorPlan(node, request, requiresApproval: true,
            RoutedRemovalPlanFixture.Item("tree", FileEntryKind.Directory, 0, ownerVerified: false),
            RoutedRemovalPlanFixture.Item("tree/marker", FileEntryKind.File, (ulong)body.Length, ownerVerified: false));
        var receipt = RoutedRemovalPlanFixture.OriginalBytes(new FileServicePlanRemovalResponse
        {
            Meta = RoutedRemovalPlanFixture.ReplyMeta(request),
            Value = new FileServicePlanRemovalValue { Plan = plan },
        });
        node.Runtime.Store.Write(tx =>
        {
            RoutedRemovalPlanFixture.SeedReceipt(tx, request, raw, caller, receipt);
            RoutedRemovalPlanFixture.SeedPlan(tx, request, raw, caller, root, plan);
            return 0;
        }, CommitDurability.Full);

        Task<ByteString> Invoke(CenterCaller source, byte[] payload) =>
            RoutedRemovalPlanFixture.InvokeAsync(center, connection, request.Meta.CommandId, source, payload, ct);

        var first = await Invoke(caller, raw);
        Assert.Equal(ByteString.CopyFrom(receipt), first);
        var response = FileServicePlanRemovalResponse.Parser.ParseFrom(first);
        Assert.True(NodeShapes.IsValid(response));
        Assert.Null(response.Error);
        Assert.Equal(2, response.Value.Plan.Items.Count);
        Assert.True(response.Value.Plan.RequiresApproval);
        Assert.True(response.Value.Plan.QuarantineAvailable);
        Assert.Equal(first, await Invoke(caller, raw));

        var foreign = caller.Clone();
        foreign.LocalSessionId = CommandIds.New();
        var changed = request.Clone();
        changed.Meta.CorrelationId = CommandIds.New();
        foreach (var refused in new[] { await Invoke(foreign, raw), await Invoke(caller, changed.ToByteArray()) })
        {
            var error = FileServicePlanRemovalResponse.Parser.ParseFrom(refused).Error;
            Assert.Equal("command_id_reused", error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);
        }

        Assert.Equal(body, File.ReadAllBytes(marker));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(SHA256.HashData(raw), node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT request_sha256 FROM file_removal_plan WHERE command_id = $id;", ("$id", request.Meta.CommandId.Value.ToByteArray()))));
        Assert.Empty(connection.UnverifiedResults);
    }

    // The fresh 985-entry producer proof remains at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
    [Fact(Timeout = 120_000)]
    public async Task SignedRetainedSizeRefusalReplaysOriginalBytesWithoutCreatingPlan()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        var connection = await RoutedRemovalPlanFixture.ConnectAsync(center, node);
        var caller = RoutedRemovalPlanFixture.Caller(node, connection, Origin.Human);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "signed-budget-root")).FullName;
        var request = RoutedRemovalPlanFixture.Request(node, root, "tree", ct);
        var raw = request.ToByteArray();
        var receipt = RoutedRemovalPlanFixture.OriginalBytes(new FileServicePlanRemovalResponse
        {
            Meta = RoutedRemovalPlanFixture.ReplyMeta(request),
            Error = new ArcError
            {
                Category = ErrorCategory.Resource,
                Code = "too_large",
                MessageKey = "error.resource.too_large",
                CorrelationId = request.Meta.CorrelationId.Clone(),
                Effect = EffectCertainty.DidNotHappen,
                Retry = new RetryAdvice { Mode = RetryMode.Never },
                Details = new ErrorDetails
                {
                    Limit = new LimitFailure
                    {
                        LimitName = "removal_plan_response_bytes",
                        Maximum = new ProtoDecimal { Value = "1040384" },
                    },
                },
            },
        });
        node.Runtime.Store.Write(tx =>
        {
            RoutedRemovalPlanFixture.SeedReceipt(tx, request, raw, caller, receipt);
            return 0;
        }, CommitDurability.Full);

        var first = await RoutedRemovalPlanFixture.InvokeAsync(center, connection, request.Meta.CommandId, caller, raw, ct);
        Assert.Equal(ByteString.CopyFrom(receipt), first);
        var refusal = FileServicePlanRemovalResponse.Parser.ParseFrom(first);
        Assert.True(NodeShapes.IsValid(refusal));
        Assert.Equal(ErrorCategory.Resource, refusal.Error.Category);
        Assert.Equal("too_large", refusal.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, refusal.Error.Effect);
        Assert.Equal(RetryMode.Never, refusal.Error.Retry.Mode);
        Assert.Equal("removal_plan_response_bytes", refusal.Error.Details.Limit.LimitName);
        Assert.Equal("1040384", refusal.Error.Details.Limit.Maximum.Value);
        Assert.Null(refusal.Value);
        var tree = Directory.CreateDirectory(Path.Combine(root, "tree")).FullName;
        var marker = Path.Combine(tree, "marker");
        File.WriteAllText(marker, "created after the retained refusal");
        Assert.Equal(first, await RoutedRemovalPlanFixture.InvokeAsync(center, connection, request.Meta.CommandId, caller, raw, ct));
        Assert.Equal("created after the retained refusal", File.ReadAllText(marker));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM cleanup_plan;")));
        Assert.Equal(SHA256.HashData(raw), node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT payload_digest FROM command_dedup WHERE command_id = $id;", ("$id", request.Meta.CommandId.Value.ToByteArray()))));
        Assert.Empty(connection.UnverifiedResults);
    }
}

internal static class RoutedRemovalPlanFixture
{
    internal static async Task<FakeChannelConnection> ConnectAsync(FakeCenter center, CloudNode node)
    {
        var nodeId = node.Runtime.NodeId.ToArray();
        var credentials = center.Issue(nodeId);
        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Load(nodeId, center.Endpoint.Origin)
            ?? NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
            center.CommandKeys.Add(center.Channel.CommandPublicKey);
            center.Channel.RegisterNodeKey(credentials.AccessToken, key.PublicKey);
            await node.Cloud.AdoptAsync(credentials, center.Endpoint);
        }

        return await center.Channel.ProvedAsync();
    }

    internal static CenterCaller Caller(CloudNode node, FakeChannelConnection connection, Origin origin) => new()
    {
        Kind = CenterCallerKind.NodeRelay,
        AccountId = new Id { Value = ByteString.CopyFrom(connection.AccountId) },
        RelayingNodeId = new Id { Value = ByteString.CopyFrom(node.Runtime.NodeId.Span) },
        LocalOrigin = origin,
        LocalSessionId = CommandIds.New(),
    };

    internal static FileServicePlanRemovalRequest Request(CloudNode node, string root, string path, CancellationToken ct)
    {
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        return new()
        {
            Meta = CloudNode.Command(),
            WorkspacePath = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = path },
        };
    }

    internal static ResponseMeta ReplyMeta(FileServicePlanRemovalRequest request) => new() { CorrelationId = request.Meta.CorrelationId.Clone() };

    internal static ActorRef Actor(FileServicePlanRemovalRequest request, CenterCaller caller) => new()
    {
        Origin = Origin.Remote,
        CenterCaller = caller.Clone(),
        RemoteCommandId = request.Meta.CommandId.Clone(),
    };

    internal static FileRemovalPlan PriorPlan(CloudNode node, FileServicePlanRemovalRequest request, bool requiresApproval, params FileRemovalItem[] items)
    {
        var plan = new FileRemovalPlan
        {
            PlanId = CommandIds.New(),
            Digest = ByteString.CopyFrom(SHA256.HashData("historical-plan-digest"u8)),
            WorkspacePath = request.WorkspacePath.Clone(),
            ExpiresAt = ProtoTime.ToInstant(node.Runtime.Clock.GetUtcNow().AddMinutes(5)),
            TotalBytes = (ulong)items.Sum(item => (long)item.SizeBytes),
            RequiresApproval = requiresApproval,
            QuarantineAvailable = true,
            Risk = requiresApproval ? RiskClass.High : RiskClass.Low,
        };
        plan.Items.AddRange(items);
        return plan;
    }

    internal static FileRemovalItem Item(string path, FileEntryKind kind, ulong size, bool ownerVerified) => new()
    {
        Path = path,
        Kind = kind,
        SizeBytes = size,
        IdentitySha256 = ByteString.CopyFrom(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(path))),
        OwnerVerified = ownerVerified,
    };

    // Preserve wire order and the unknown field when sending a stored response.
    internal static byte[] OriginalBytes(IMessage response) => [0x98, 0x06, 1, .. response.ToByteArray()];

    internal static void SeedReceipt(StoreTransaction tx, FileServicePlanRemovalRequest request, byte[] raw, CenterCaller caller, byte[] response)
    {
        var command = request.Meta.CommandId.Value.ToByteArray();
        Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, command, "arcforges.node.v1.FileService/PlanRemoval",
            SHA256.HashData(raw), Origin.Remote).Status);
        tx.Execute("INSERT INTO file_removal_command_owner (command_id, caller) VALUES ($id, $caller);",
            ("$id", command), ("$caller", caller.ToByteArray()));
        CommandDeduplication.Complete(tx, command, response);
    }

    internal static void SeedPlan(StoreTransaction tx, FileServicePlanRemovalRequest request, byte[] raw, CenterCaller caller,
        string rootPath, FileRemovalPlan plan)
    {
        using var root = WorkspacePath.OpenRoot(rootPath);
        var identity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
        var planId = plan.PlanId.Value.ToByteArray();
        var expires = StoreTime.ToMicroseconds(Assert.IsType<DateTimeOffset>(ProtoTime.ToDateTimeOffset(plan.ExpiresAt)));
        tx.Execute("""
            INSERT INTO cleanup_plan (plan_id, state, digest, planned_by, total_bytes, item_count, created_at, expires_at, rev)
            VALUES ($id, 1, $digest, $actor, $total, $count, $now, $expires, 0);
            """, ("$id", planId), ("$digest", plan.Digest.ToByteArray()), ("$actor", Actor(request, caller).ToByteArray()),
            ("$total", (long)plan.TotalBytes), ("$count", plan.Items.Count), ("$now", tx.NowMicroseconds), ("$expires", expires));
        tx.Execute("""
            INSERT INTO file_removal_plan (plan_id, command_id, request_sha256, caller, target_kind, workspace_id, workspace_path,
              root_platform, root_identity, requires_approval, quarantine_available)
            VALUES ($id, $command, $digest, $caller, 1, $workspace, $path, $platform, $root, $approval, 1);
            """, ("$id", planId), ("$command", request.Meta.CommandId.Value.ToByteArray()), ("$digest", SHA256.HashData(raw)),
            ("$caller", caller.ToByteArray()), ("$workspace", request.WorkspacePath.WorkspaceId.Value.ToByteArray()),
            ("$path", request.WorkspacePath.Path), ("$platform", identity.Platform), ("$root", identity.Bytes),
            ("$approval", plan.RequiresApproval ? 1 : 0));
    }

    internal static async Task<ByteString> InvokeAsync(FakeCenter center, FakeChannelConnection connection, Id commandId,
        CenterCaller caller, byte[] raw, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var (call, header) = center.Channel.BuildCall(connection, new FakeCallSpec
        {
            Method = RoutedMethod.PlanNodeRemoval,
            Payload = raw,
            Caller = caller,
            CommandId = commandId,
            Lifetime = TimeSpan.FromSeconds(30),
        });
        Assert.Equal(commandId, header!.CommandId);
        await connection.SendCallAsync(call);
        var frame = await connection.ResultOfAsync(call.CallId);
        await Eventually.TrueAsync(() => connection.VerifiedResults.Any(result => result.Header.CallId.Equals(call.CallId)),
            "verified retained removal plan");
        Assert.Equal(RoutedOutcome.Executed, connection.VerifiedResults.Single(result => result.Header.CallId.Equals(call.CallId)).Header.Outcome);
        return frame.Payload;
    }
}
