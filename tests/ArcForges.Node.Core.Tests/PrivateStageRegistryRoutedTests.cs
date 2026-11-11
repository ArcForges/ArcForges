// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Real SQLite, Node dispatcher and native named-stage producer. The caller is synthetic; this does not establish
/// approval, power-loss durability or a real center.
/// </summary>
public sealed class PrivateStageRegistryRoutedTests
{
    [Fact(Timeout = 120_000)]
    public async Task DurableIdentityBlocksRealFileRoutesAfterRestartRenameAndHardLink()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Human);
        var rootA = Directory.CreateDirectory(Path.Combine(node.Root, "stage-workspace-a")).FullName;
        var rootB = Directory.CreateDirectory(Path.Combine(node.Root, "stage-workspace-b")).FullName;
        var privateDir = Directory.CreateDirectory(Path.Combine(rootA, "private")).FullName;
        var emptyPath = Path.Combine(privateDir, "stage.tmp");
        File.WriteAllText(Path.Combine(rootA, "public.txt"), "ordinary");
        File.WriteAllText(Path.Combine(rootB, "visible.txt"), "public");
        var workspaces = new RegisteredWorkspaces(node.Runtime.Store);
        var workspaceA = workspaces.RegisterFromVerifiedHuman(rootA, cancellationToken: ct);
        var workspaceB = workspaces.RegisterFromVerifiedHuman(rootB, cancellationToken: ct);
        var body = Encoding.UTF8.GetBytes("private-approval-stage-35fb2");
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspaceA.Id) }, Path = "target.txt" },
            ExpectedAbsent = true,
            Data = ByteString.CopyFrom(body),
        };
        var raw = request.ToByteArray();
        var budget = new FileStageBudget();
        using (var workspaceRoot = WorkspacePath.OpenRoot(rootA))
        using (var stageDir = WorkspacePath.OpenRoot(privateDir))
        {
            var spec = new PrivateStageSpec(2, Path.Combine(stageDir.RootPath, "stage.tmp"), body.Length, SHA256.HashData(body));
            PrivateStageReservationResult Reserve(CenterCaller who, byte[] bytes) =>
                node.Runtime.Store.Write(t => PrivateStageRegistry.Reserve(t, budget, FileOperationKind.Write,
                    request.Meta.CommandId.Value.Span, workspaceA.Id,
                    FileServiceWriteFileRequest.Parser.ParseFrom(bytes).Meta.CorrelationId.Value.Span, who, bytes, [spec]), CommitDurability.Full);
            Assert.Equal(PrivateStageReservationResult.Reserved, Reserve(actor, raw));
            Assert.Equal(PrivateStageReservationResult.Existing, Reserve(actor, raw));
            var different = request.Clone();
            different.Meta.CorrelationId = CommandIds.New();
            Assert.Equal(PrivateStageReservationResult.Conflict, Reserve(actor, different.ToByteArray()));
            Assert.Equal(PrivateStageReservationResult.Conflict, Reserve(calls.Relay(Origin.Agent), raw));
            Assert.Equal((1, (long)body.Length), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
            Assert.Empty(node.Runtime.Store.Read(PrivateStageRegistry.LoadIdentities));
            Assert.False(File.Exists(emptyPath));
            using var empty = stageDir.CreateEmptyPrivateNamedStage("stage.tmp", ct);
            Assert.Equal(0, empty.Guard.ObserveLength(ct));
            if (OperatingSystem.IsLinux()) Assert.Equal(NamedStageDurabilityEvidence.LinuxFileAndDirectoryFsync, empty.DurabilityEvidence);
            if (OperatingSystem.IsWindows()) Assert.Equal(NamedStageDurabilityEvidence.WindowsNtfsWriteThroughAndFileFlush, empty.DurabilityEvidence);
            node.Runtime.Store.Write(t => PrivateStageRegistry.BindEmptyForProtection(t, request.Meta.CommandId.Value.Span, 2,
                workspaceRoot, stageDir, "stage.tmp", empty.Guard, ct), CommitDurability.Full);
            Assert.Single(node.Runtime.Store.Read(PrivateStageRegistry.LoadIdentities));
            PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, request.Meta.CommandId.Value.Span, 2, actor, raw, empty, body, ct);
            Assert.Equal(3L, node.Runtime.Store.Read(r => r.Scalar("SELECT phase FROM file_private_stage_object;")));
        }

        Assert.Equal("workspace_in_use",
            Assert.Throws<RegisteredWorkspaceException>(() => workspaces.UnregisterFromVerifiedHuman(workspaceA.Id, ct)).Reason);
        async Task CheckPrivate(RoutedCalls routed, byte[] workspace, string relative, string directory, bool expectVisible)
        {
            var caller = routed.Relay(Origin.Agent);
            var read = new FileServiceReadFileRequest
            {
                Meta = new RequestMeta { CorrelationId = CommandIds.New() },
                Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace) }, Path = relative },
                Offset = 0,
                Length = 128,
            };
            var readCall = await routed.CallAsync(caller, RoutedMethod.ReadNodeFile, read.ToByteArray());
            var readResponse = FileServiceReadFileResponse.Parser.ParseFrom(readCall.Answer!.Response);
            Assert.Null(readResponse.Value);
            Assert.NotNull(readResponse.Error);
            var search = new FileServiceSearchFilesRequest
            {
                Meta = new RequestMeta { CorrelationId = CommandIds.New() },
                Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace) }, Path = "" },
                Pattern = Encoding.UTF8.GetString(body),
                Mode = FileSearchMode.Literal,
            };
            var searchCall = await routed.CallAsync(caller, RoutedMethod.SearchNodeFiles, search.ToByteArray());
            var searchResponse = FileServiceSearchFilesResponse.Parser.ParseFrom(searchCall.Answer!.Response);
            Assert.Null(searchResponse.Error);
            Assert.Empty(searchResponse.Value.Matches);
            var list = new FileServiceListDirectoryRequest
            {
                Meta = new RequestMeta { CorrelationId = CommandIds.New() },
                Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace) }, Path = directory },
            };
            var listCall = await routed.CallAsync(caller, RoutedMethod.ListNodeDirectory, list.ToByteArray());
            var listResponse = FileServiceListDirectoryResponse.Parser.ParseFrom(listCall.Answer!.Response);
            Assert.Null(listResponse.Error);
            Assert.DoesNotContain(listResponse.Value.Entries, item => item.Name is "stage.tmp" or "moved.tmp" or "alias.tmp");
            if (expectVisible) Assert.Contains(listResponse.Value.Entries, item => item.Name == "visible.txt");
        }

        await CheckPrivate(calls, workspaceA.Id, "private/stage.tmp", "private", expectVisible: false);
        var commandId = request.Meta.CommandId.Value.ToByteArray();
        var requestDigest = SHA256.HashData(raw);
        Assert.Throws<InvalidOperationException>(() => node.Runtime.Store.Read(r =>
            PrivateStageRegistry.ReopenReadyStage(r, commandId, 2, calls.Relay(Origin.Agent), requestDigest, ct)));
        Assert.Throws<InvalidOperationException>(() => node.Runtime.Store.Read(r =>
            PrivateStageRegistry.ReopenReadyStage(r, commandId, 2, actor, new byte[32], ct)));
        using (var recovered = node.Runtime.Store.Read(r =>
            PrivateStageRegistry.ReopenReadyStage(r, commandId, 2, actor, requestDigest, ct)))
            Assert.True(recovered.Guard.MatchesExpectedContent(SHA256.HashData(body), body.Length, ct));

        // A pending stage modified while the node is stopped must fail its same-object full rehash after restart.
        Assert.Equal(0, await node.StopAsync());
        var tampered = body.ToArray();
        tampered[0] ^= 1;
        File.WriteAllBytes(emptyPath, tampered);
        await node.StartAsync();
        Assert.Throws<WorkspacePathException>(() => node.Runtime.Store.Read(r =>
            PrivateStageRegistry.ReopenReadyStage(r, commandId, 2, actor, requestDigest, ct)));
        Assert.Equal(tampered, File.ReadAllBytes(emptyPath));
        Assert.Equal(0, await node.StopAsync());
        File.WriteAllBytes(emptyPath, body); // Test-owned restoration for the independent move/hardlink route check.
        var moved = Path.Combine(rootB, "moved.tmp");
        File.Move(emptyPath, moved);
        NativeHardLink(moved, Path.Combine(rootB, "alias.tmp"));
        await node.StartAsync();
        calls = new RoutedCalls(node);
        Assert.Single(node.Runtime.Store.Read(PrivateStageRegistry.LoadIdentities));
        Assert.Throws<WorkspacePathException>(() => node.Runtime.Store.Read(r =>
            PrivateStageRegistry.ReopenReadyStage(r, commandId, 2, actor, requestDigest, ct)));
        await CheckPrivate(calls, workspaceB.Id, "moved.tmp", "", expectVisible: true);
        await CheckPrivate(calls, workspaceB.Id, "alias.tmp", "", expectVisible: true);
        Assert.Equal(body, File.ReadAllBytes(moved));

        foreach (var file in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(file)) continue;
            using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(body));
        }
    }

    private static void NativeHardLink(string source, string destination)
    {
        var windows = OperatingSystem.IsWindows();
        var executable = windows ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe") : "ln";
        string[] args = windows ? ["/d", "/c", "mklink", "/H", destination, source] : [source, destination];
        using var process = Process.Start(new ProcessStartInfo(executable, args)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        })!;
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        Assert.True(process.WaitForExit(10_000) && process.ExitCode == 0, "native hardlink setup failed: " + output);
    }
}
