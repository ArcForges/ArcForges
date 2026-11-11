// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>Native NTFS stage identity and process-crash recovery with an isolated synthetic caller.</summary>
public sealed class WorkspaceWindowsNamedStageRecoveryTests
{
    private const string ChildVariable = "ARCFORGES_PRIVATE_STAGE_OWNED_TEST_CHILD";
    private static readonly byte[] Body = Encoding.UTF8.GetBytes("owned-private-ntfs-stage-43c23");

    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    [SupportedOSPlatform("windows")]
    public async Task OwnedProducerCrashReopensExactRecordedObjectAndRejectsTampering()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows NTFS named-stage restart."); return; }
        if (Environment.GetEnvironmentVariable(ChildVariable) is { Length: > 0 } ownedChildRoot)
        {
            await RunOwnedChildAsync(ownedChildRoot);
            return;
        }

        var ct = TestContext.Current.CancellationToken;
        using var fixture = new OwnedDirectory();
        var marker = Path.Combine(fixture.Path, "ready.json");
        File.WriteAllText(Path.Combine(fixture.Path, "owned-parent.marker"), "owned fixture");
        var testAssembly = typeof(WorkspaceWindowsNamedStageRecoveryTests).Assembly.Location;
        var executable = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet";
        var info = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        info.ArgumentList.Add(testAssembly);
        info.ArgumentList.Add("-method");
        info.ArgumentList.Add(typeof(WorkspaceWindowsNamedStageRecoveryTests).FullName + "." + nameof(OwnedProducerCrashReopensExactRecordedObjectAndRejectsTampering));
        info.Environment[ChildVariable] = fixture.Path;
        using var child = Process.Start(info) ?? throw new InvalidOperationException("Cannot start the owned stage producer.");
        try
        {
            var until = Stopwatch.StartNew();
            while (!File.Exists(marker) && !child.HasExited && until.Elapsed < TimeSpan.FromSeconds(20))
                await Task.Delay(40, ct);
            Assert.True(File.Exists(marker), "Owned producer did not finish staging.");
            var ready = JsonSerializer.Deserialize<Ready>(await File.ReadAllTextAsync(marker, ct))!;
            var identity = new RegisteredWorkspaces.RootIdentity(ready.Platform, Convert.FromBase64String(ready.Identity));
            var digest = Convert.FromHexString(ready.Sha256);
            using (var root = WorkspacePath.OpenRoot(Path.Combine(fixture.Path, "workspace")))
            {
                // The producer still holds its private no-sharing handle.
                Assert.Throws<WorkspacePathException>(() => root.ReopenWindowsPrivateNamedStage(identity, "stage", Body.Length, digest, ct));
            }

            child.Kill(); // This exact test-owned process handle only; do not terminate a process group.
            await child.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(10), ct);
            Assert.True(child.HasExited);
            TestContext.Current.TestOutputHelper?.WriteLine($"Owned producer PID {child.Id}, start {child.StartTime.ToUniversalTime():O}, exit {child.ExitCode}; retained stage identity SHA-256 {Convert.ToHexString(SHA256.HashData(identity.Bytes))}.");

            using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = Path.Combine(fixture.Path, "data"), BootIdentity = "owned-parent" });
            _ = store.Read(reader =>
            {
                using var query = reader.CreateCommand("""
                    SELECT phase, identity_platform, native_identity, expected_size, expected_sha256
                    FROM file_private_stage_object WHERE command_id = $id AND slot = 2;
                    """);
                query.Parameters.AddWithValue("$id", Convert.FromHexString(ready.CommandId));
                using var row = query.ExecuteReader();
                Assert.True(row.Read());
                Assert.Equal(3, row.GetInt32(0));
                Assert.Equal(identity.Platform, row.GetInt32(1));
                Assert.Equal(identity.Bytes, (byte[])row.GetValue(2));
                Assert.Equal(Body.Length, row.GetInt64(3));
                Assert.Equal(digest, (byte[])row.GetValue(4));
                return true; // The SQLite reader closes before native access.
            });
            using var reopenedRoot = WorkspacePath.OpenRoot(Path.Combine(fixture.Path, "workspace"));
            using (var reopened = reopenedRoot.ReopenWindowsPrivateNamedStage(identity, "stage", Body.Length, digest, ct))
            {
                Assert.True(reopened.MatchesExpectedContent(digest, Body.Length, ct));
                Assert.Throws<IOException>(() => File.OpenHandle(Path.Combine(fixture.Path, "workspace", "stage"),
                    FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete));
            }

            var altered = Body.ToArray();
            altered[0] ^= 1;
            File.WriteAllBytes(Path.Combine(fixture.Path, "workspace", "stage"), altered);
            Assert.Throws<WorkspacePathException>(() => reopenedRoot.ReopenWindowsPrivateNamedStage(identity, "stage", Body.Length, digest, ct));
            Assert.Equal(altered, File.ReadAllBytes(Path.Combine(fixture.Path, "workspace", "stage")));
            var wrongIdentity = identity.Bytes.ToArray();
            wrongIdentity[^1] ^= 1;
            Assert.Throws<WorkspacePathException>(() => reopenedRoot.ReopenWindowsPrivateNamedStage(
                new RegisteredWorkspaces.RootIdentity(identity.Platform, wrongIdentity), "stage", Body.Length,
                SHA256.HashData(altered), ct));
        }
        finally
        {
            if (!child.HasExited)
            {
                child.Kill();
                if (!child.WaitForExit(10_000)) TestContext.Current.TestOutputHelper?.WriteLine("Owned producer did not exit after termination.");
            }
        }
        Assert.True(child.HasExited, "Owned producer cleanup did not complete.");
    }

    private static async Task RunOwnedChildAsync(string root)
    {
        var fullRoot = Path.GetFullPath(root);
        var temporaryRoot = Path.GetFullPath(Path.GetTempPath());
        if (!fullRoot.StartsWith(temporaryRoot, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(fullRoot).StartsWith("arcforges-named-stage-crash-", StringComparison.Ordinal) ||
            !File.Exists(Path.Combine(fullRoot, "owned-parent.marker")))
            throw new InvalidOperationException("The owned fixture directory is unavailable.");
        var workspacePath = Directory.CreateDirectory(Path.Combine(fullRoot, "workspace")).FullName;
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = Path.Combine(root, "data"), BootIdentity = "owned-child" });
        var workspace = new RegisteredWorkspaces(store).RegisterFromVerifiedHuman(workspacePath);
        var caller = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = CommandIds.New(),
            RelayingNodeId = CommandIds.New(),
            LocalOrigin = Origin.Human,
            LocalSessionId = CommandIds.New(),
        };
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target" },
            ExpectedAbsent = true,
            Data = ByteString.CopyFrom(Body),
        };
        var raw = request.ToByteArray();
        var hash = SHA256.HashData(Body);
        var spec = new PrivateStageSpec(2, Path.Combine(workspacePath, "stage"), Body.Length, hash);
        var budget = new FileStageBudget();
        Assert.Equal(PrivateStageReservationResult.Reserved, store.Write(t => PrivateStageRegistry.Reserve(t, budget,
            FileOperationKind.Write, request.Meta.CommandId.Value.Span, workspace.Id, request.Meta.CorrelationId.Value.Span,
            caller, raw, [spec]), CommitDurability.Full));
        using var opened = WorkspacePath.OpenRoot(workspacePath);
        using var stage = opened.CreateEmptyPrivateNamedStage("stage", CancellationToken.None);
        Assert.Equal(NamedStageDurabilityEvidence.WindowsNtfsWriteThroughAndFileFlush, stage.DurabilityEvidence);
        store.Write(t => PrivateStageRegistry.BindEmptyForProtection(t, request.Meta.CommandId.Value.Span,
            2, opened, opened, "stage", stage.Guard, CancellationToken.None), CommitDurability.Full);
        PrivateStageRegistry.WriteBoundStage(store, request.Meta.CommandId.Value.Span, 2, caller, raw, stage, Body, CancellationToken.None);
        var ready = new Ready(stage.Identity.Platform, Convert.ToBase64String(stage.Identity.Bytes),
            Convert.ToHexString(hash), Convert.ToHexString(request.Meta.CommandId.Value.Span));
        using (var stream = new FileStream(Path.Combine(root, "ready.tmp"), FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(stream, ready);
            stream.Flush(flushToDisk: true);
        }
        File.Move(Path.Combine(root, "ready.tmp"), Path.Combine(root, "ready.json"));
        await Task.Delay(Timeout.InfiniteTimeSpan);
    }

    private sealed record Ready(int Platform, string Identity, string Sha256, string CommandId);

    private sealed class OwnedDirectory : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("arcforges-named-stage-crash-");
        public string Path => _directory.FullName;
        public void Dispose() => _directory.Delete(recursive: true);
    }
}
