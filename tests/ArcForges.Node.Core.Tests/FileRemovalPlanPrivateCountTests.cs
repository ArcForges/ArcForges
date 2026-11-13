// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real registered stage identities, native aliases, dispatcher and SQLite; the routed caller is synthetic.</summary>
public sealed class FileRemovalPlanPrivateCountTests
{
    [Theory(Timeout = 120_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PrivateAliasCannotContributeToThePublicDescendantLimit(bool hardLink)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Human);
        var planner = calls.Relay(Origin.Agent);
        var rootPath = Directory.CreateDirectory(Path.Combine(node.Root, "private-count-root")).FullName;
        var tree = Directory.CreateDirectory(Path.Combine(rootPath, "tree")).FullName;
        var privatePath = Directory.CreateDirectory(Path.Combine(rootPath, "private")).FullName;
        File.WriteAllText(Path.Combine(rootPath, "ordinary.txt"), "ordinary");
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(rootPath, cancellationToken: ct);
        FileServicePlanRemovalRequest Request(string path) => new()
        {
            Meta = Tasks.Meta(),
            WorkspacePath = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = path },
        };
        async Task<(FileServicePlanRemovalResponse Response, byte[] Bytes)> Plan(FileServicePlanRemovalRequest request)
        {
            var result = await calls.CallAsync(planner, RoutedMethod.PlanNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
            Assert.NotNull(result.Answer);
            Assert.Equal(RoutedOutcome.Executed, result.Answer.Outcome);
            var bytes = result.Answer.Response!.ToByteArray();
            var response = FileServicePlanRemovalResponse.Parser.ParseFrom(bytes);
            Assert.True(NodeShapes.IsValid(response));
            Assert.Equal(request.Meta.CorrelationId, response.Meta.CorrelationId);
            return (response, bytes);
        }
        for (var index = 0; index < 999; index++)
            File.WriteAllBytes(Path.Combine(tree, "public-" + index.ToString("D4", System.Globalization.CultureInfo.InvariantCulture)), []);

        // With no private registry, the original below/at/above-1000 classification remains observable.
        var below = (await Plan(Request("tree"))).Response;
        Assert.Null(below.Error);
        Assert.Equal(1000, below.Value.Plan.Items.Count);
        File.WriteAllBytes(Path.Combine(tree, "public-0999"), []);
        var exact = (await Plan(Request("tree"))).Response;
        Assert.Null(exact.Error);
        Assert.Equal(1001, exact.Value.Plan.Items.Count);
        File.WriteAllBytes(Path.Combine(tree, "public-1000"), []);
        var publicOverflow = (await Plan(Request("tree"))).Response;
        Assert.Equal("too_large", publicOverflow.Error.Code);
        Assert.Equal("removal_descendants", publicOverflow.Error.Details.Limit.LimitName);
        Assert.Equal("1000", publicOverflow.Error.Details.Limit.Maximum.Value);
        Assert.Equal(2L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_removal_plan;")));
        File.Delete(Path.Combine(tree, "public-1000")); // Only the extra file created by this fixture.

        var body = Encoding.UTF8.GetBytes("private-count-stage-body-9e21");
        var stageRequest = new FileServiceWriteFileRequest
        {
            Meta = Tasks.Meta(),
            ExpectedAbsent = true,
            Data = ByteString.CopyFrom(body),
            Path = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "never-created.txt" },
        };
        var raw = stageRequest.ToByteArray();
        var source = Path.Combine(privatePath, "stage.tmp");
        using (var root = WorkspacePath.OpenRoot(rootPath))
        using (var stageDirectory = WorkspacePath.OpenRoot(privatePath))
        {
            Assert.Equal(PrivateStageReservationResult.Reserved, node.Runtime.Store.Write(tx =>
                PrivateStageRegistry.Reserve(tx, new FileStageBudget(), FileOperationKind.Write,
                    stageRequest.Meta.CommandId.Value.Span, workspace.Id, stageRequest.Meta.CorrelationId.Value.Span,
                    actor, raw, [new PrivateStageSpec(2, source, body.Length, SHA256.HashData(body))]), CommitDurability.Full));
            using var empty = stageDirectory.CreateEmptyPrivateNamedStage("stage.tmp", ct);
            node.Runtime.Store.Write(tx => PrivateStageRegistry.BindEmptyForProtection(tx,
                stageRequest.Meta.CommandId.Value.Span, 2, root, stageDirectory, "stage.tmp", empty.Guard, ct), CommitDurability.Full);
            PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, stageRequest.Meta.CommandId.Value.Span, 2,
                actor, raw, empty, body, ct);
        }
        Assert.Single(node.Runtime.Store.Read(PrivateStageRegistry.LoadIdentities));
        var alias = Path.Combine(tree, "private-alias");
        if (hardLink) NativeHardLink(source, alias);
        else File.Move(source, alias);
        var namesBefore = Directory.GetFileSystemEntries(rootPath, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal).ToArray();
        var request = Request("tree");
        var (denied, refusedBytes) = await Plan(request);

        // The actual bound private alias is the 1001st child. Its name must not produce a public count refusal.
        Assert.Equal("file_access_denied", denied.Error.Code);
        Assert.Equal(ErrorCategory.State, denied.Error.Category);
        Assert.Equal("file_access_denied", denied.Error.Details.State.Reason);
        Assert.Null(denied.Error.Details.Limit);
        Assert.Equal(EffectCertainty.DidNotHappen, denied.Error.Effect);
        Assert.Equal(RetryMode.Never, denied.Error.Retry.Mode);
        Assert.Null(denied.Value);
        Assert.Equal(2L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_operation_journal;")));
        Assert.Equal(refusedBytes, (await Plan(request)).Bytes);
        var id = request.Meta.CommandId.Value.ToByteArray();
        node.Runtime.Store.Read(reader =>
        {
            using var query = reader.CreateCommand("""
                SELECT d.payload_digest, d.outcome, o.caller
                FROM command_dedup d JOIN file_removal_command_owner o ON o.command_id = d.command_id
                WHERE d.command_id = $id;
                """);
            query.Parameters.AddWithValue("$id", id);
            using var row = query.ExecuteReader();
            Assert.True(row.Read());
            Assert.Equal(SHA256.HashData(request.ToByteArray()), (byte[])row.GetValue(0));
            Assert.Equal(refusedBytes, (byte[])row.GetValue(1));
            Assert.Equal(planner, CenterCaller.Parser.ParseFrom((byte[])row.GetValue(2)));
            Assert.False(row.Read());
            return 0;
        });
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM audit_log WHERE remote_command_id = $id
              AND operation = 'cleanup.plan FileService.PlanRemoval' AND outcome_summary = 'refused: file_access_denied';
            """, ("$id", id))));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM audit_log WHERE remote_command_id = $id
              AND operation = 'cleanup.plan FileService.PlanRemoval' AND outcome_summary = 'replayed: file_access_denied';
            """, ("$id", id))));

        // The same genuinely registered identity also protects the indexed lookup path, without claiming a 129-stage run.
        using (var indexed = WorkspacePath.OpenRoot(rootPath))
        {
            indexed.ProtectPrivateStageFiles(identity => node.Runtime.Store.Read(reader => PrivateStageRegistry.ContainsIdentity(reader, identity)));
            Assert.Equal("file_access_denied", Assert.Throws<WorkspaceRemovalPlanException>(() =>
                WorkspaceRemovalPlan.Capture(indexed, "tree", ct)).Reason);
        }
        var ordinary = (await Plan(Request("ordinary.txt"))).Response;
        Assert.Null(ordinary.Error);
        Assert.Single(ordinary.Value.Plan.Items);
        Assert.False(ordinary.Value.Plan.Items[0].OwnerVerified);
        Assert.True(ordinary.Value.Plan.RequiresApproval);
        Assert.False(ordinary.Value.Plan.QuarantineAvailable);
        Assert.Equal(namesBefore, Directory.GetFileSystemEntries(rootPath, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal));
        Assert.Equal(body, File.ReadAllBytes(alias));
        if (hardLink) Assert.Equal(body, File.ReadAllBytes(source));
        Assert.All(Directory.GetFiles(tree, "public-*"), file => Assert.Equal(0, new FileInfo(file).Length));
        Assert.Equal("ordinary", File.ReadAllText(Path.Combine(rootPath, "ordinary.txt")));
        Assert.False(File.Exists(Path.Combine(rootPath, "never-created.txt")));
        Assert.Equal(3L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_operation_journal;")));
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
