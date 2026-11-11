// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>One native named-stage source to guarded Windows target; no approval, journal or routed acceptance.</summary>
public sealed class WorkspaceNamedStageEffectTests
{
    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    public async Task RecoveredExactNamedStageCanSupplyTheGuardedTarget()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows guarded target effect."); return; }
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var caller = new RoutedCalls(node).Relay(Origin.Human);
        var path = Directory.CreateDirectory(Path.Combine(node.Root, "named-effect")).FullName;
        var oldBytes = Encoding.UTF8.GetBytes("prior-owned-target");
        var intendedBytes = Encoding.UTF8.GetBytes("new-owned-target-from-named-stage");
        File.WriteAllBytes(Path.Combine(path, "target"), oldBytes);
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(path, cancellationToken: ct);
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target" },
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(oldBytes)),
            Data = ByteString.CopyFrom(intendedBytes),
        };
        var raw = request.ToByteArray();
        var spec = new PrivateStageSpec(2, Path.Combine(path, "stage"), intendedBytes.Length, SHA256.HashData(intendedBytes));
        var beforeSpec = new PrivateStageSpec(1, Path.Combine(path, "before"), oldBytes.Length, SHA256.HashData(oldBytes));
        Assert.Equal(PrivateStageReservationResult.Reserved, node.Runtime.Store.Write(t => PrivateStageRegistry.Reserve(t,
            new FileStageBudget(), FileOperationKind.Write, request.Meta.CommandId.Value.Span, workspace.Id,
            request.Meta.CorrelationId.Value.Span, caller, raw, [beforeSpec, spec]), CommitDurability.Full));
        using var root = WorkspacePath.OpenRoot(path);
        using (var empty = root.CreateEmptyPrivateNamedStage("stage", ct))
        {
            node.Runtime.Store.Write(t => PrivateStageRegistry.BindEmptyForProtection(t, request.Meta.CommandId.Value.Span,
                2, root, root, "stage", empty.Guard, ct), CommitDurability.Full);
            PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, request.Meta.CommandId.Value.Span, 2, caller, raw, empty, intendedBytes, ct);
        }

        using (var source = node.Runtime.Store.Read(r => PrivateStageRegistry.ReopenReadyStage(r,
            request.Meta.CommandId.Value.Span, 2, caller, SHA256.HashData(raw), ct)))
        using (var target = root.OpenExistingWriteGuard("target"))
        {
            var result = root.ApplyExistingGuardedStage("target", target, source, SHA256.HashData(oldBytes), ct);
            Assert.Equal(intendedBytes.Length, result.Size);
            Assert.Equal(SHA256.HashData(intendedBytes), result.Sha256);
        }
        Assert.Equal(intendedBytes, File.ReadAllBytes(Path.Combine(path, "target")));
        Assert.Equal(intendedBytes, File.ReadAllBytes(Path.Combine(path, "stage")));
    }
}
