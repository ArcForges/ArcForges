// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using Google.Protobuf;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    private const string FixtureDataPath = "data/round-trip.bin";
    private const int TransferChunkSize = 1024 * 1024;

    [Fact(Timeout = 145_000, DisableParallelization = true)]
    public async Task InstalledSandboxDataImportsPersistsAndExportsTheExactRetainedSnapshot()
    {
        var token = TestContext.Current.CancellationToken;
        token.ThrowIfCancellationRequested();
        await using var installed = await TerminalCliFixture.StartAsync(retention: 2 * TransferChunkSize);
        await using var control = OpenChannel(installed.Node);
        var node = new NodeService.NodeServiceClient(control.CallInvoker);
        var data = new DataService.DataServiceClient(control.CallInvoker);
        var epoch = (await HandshakeAsync(node)).OwnerEpoch;
        var sandbox = installed.Sandbox;
        var clientFiles = Directory.CreateDirectory(Path.Combine(installed.Node.Root, "client data files")).FullName;
        var source = Path.Combine(clientFiles, "fixture input 四.bin");
        byte[] original = BuildFileBytes(TransferChunkSize + 89, 17);
        byte[] replacement = BuildFileBytes(1389, 91);
        await File.WriteAllBytesAsync(source, original, token);

        var firstUsage = await data.GetUsageAsync(new DataServiceGetUsageRequest { Meta = Query(), SandboxId = sandbox.SandboxId },
            deadline: Deadline, cancellationToken: token);
        var pendingScan = Value(firstUsage.Value, firstUsage.Error).Usage;
        Assert.True(pendingScan.HasPartial && pendingScan.Partial);
        Assert.False(pendingScan.HasOwnedBytes);
        Assert.False(pendingScan.HasFileCount);
        var baseline = await AwaitOwnedUsageAsync(data, sandbox.SandboxId, _ => true, token);
        await RequireOwnedRootListingAsync(data, sandbox.SandboxId, token);
        var imported = await InstalledCliSuccessAsync(installed.Node, "sandbox", "import", installed.SandboxText, source,
            "--to", FixtureDataPath);
        Assert.Equal(epoch, InstalledCliId(imported, "ownerEpoch"));
        var importId = InstalledCliId(imported.GetProperty("transfer"), "transferId");
        var importState = await InspectFileTransferAsync(data, importId, token);
        var importedTransfer = Value(importState.Value, importState.Error).Transfer;
        RequireCompleteFileTransfer(importedTransfer, sandbox, FixtureDataPath, "import", original);
        Assert.NotNull(importedTransfer.ClosedAt);
        var usage = await AwaitOwnedUsageAsync(data, sandbox.SandboxId,
            current => current.OwnedBytes == baseline.OwnedBytes + (ulong)original.Length && current.FileCount == baseline.FileCount + 1, token);
        var cliUsage = (await InstalledCliSuccessAsync(installed.Node, "sandbox", "usage", installed.SandboxText)).GetProperty("usage");
        Assert.Equal(usage.OwnedBytes.ToString(CultureInfo.InvariantCulture), CliScalar(cliUsage.GetProperty("ownedBytes")));
        Assert.Equal(usage.FileCount.ToString(CultureInfo.InvariantCulture), CliScalar(cliUsage.GetProperty("fileCount")));
        Assert.False(cliUsage.GetProperty("partial").GetBoolean());

        var entry = await ReadOwnedFileEntryAsync(data, sandbox, original.Length, token);
        var cliFiles = await InstalledCliSuccessAsync(installed.Node, "sandbox", "files", installed.SandboxText, "data");
        var entryJson = Assert.Single(cliFiles.GetProperty("entries").EnumerateArray(), e =>
            e.GetProperty("relativePath").GetString() == FixtureDataPath);
        Assert.Equal(entry.VersionToken, entryJson.GetProperty("versionToken").GetString());

        var firstRun = await ReadOriginalFromNativeRunAsync(installed, epoch, original, replacementFile: null, token);
        var begin = new DataServiceBeginExportRequest
        {
            Meta = Mutation(sandbox.Revision),
            OwnerEpoch = epoch,
            SandboxId = sandbox.SandboxId,
            RelativePath = FixtureDataPath,
            ExpectedFileVersion = entry.VersionToken,
        };
        var started = await data.BeginExportAsync(begin, deadline: Deadline, cancellationToken: token);
        var exportId = Value(started.Value, started.Error).Transfer.TransferId;
        var snapshot = await AwaitMaterializedExportAsync(data, exportId, token);
        var retained = Value(snapshot.Value, snapshot.Error).Transfer;
        RequireCompleteFileTransfer(retained, sandbox, FixtureDataPath, "export", original);
        Assert.Null(retained.ClosedAt);
        await RequireFileTransferCliInspectionAsync(installed.Node, retained, original);

        var replacementFile = Path.Combine(installed.Working, "replacement.bin");
        await File.WriteAllBytesAsync(replacementFile, replacement, token);
        var secondRun = await ReadOriginalFromNativeRunAsync(installed, epoch, original, replacementFile, token);
        Assert.NotEqual(firstRun.RunId, secondRun.RunId);
        var updated = await File.ReadAllBytesAsync(Path.Combine(sandbox.DataLocation, "data", "round-trip.bin"), token);
        Assert.True(replacement.AsSpan().SequenceEqual(updated));
        await VerifyRetainedExportReplayAsync(installed.Node, data, node, epoch, sandbox, retained, original, token);

        var destination = Path.Combine(clientFiles, "fixture export 四.bin");
        var exported = await InstalledCliSuccessAsync(installed.Node, "sandbox", "export", installed.SandboxText, FixtureDataPath,
            "--to", destination);
        Assert.True(exported.GetProperty("localFilePublished").GetBoolean());
        var cliExport = InstalledCliId(exported.GetProperty("transfer"), "transferId");
        var cliClosed = await InspectFileTransferAsync(data, cliExport, token);
        var closed = Value(cliClosed.Value, cliClosed.Error).Transfer;
        RequireCompleteFileTransfer(closed, sandbox, FixtureDataPath, "export", replacement);
        Assert.NotNull(closed.ClosedAt);
        var written = await File.ReadAllBytesAsync(destination, token);
        var unchanged = await File.ReadAllBytesAsync(source, token);
        Assert.True(replacement.AsSpan().SequenceEqual(written));
        Assert.True(original.AsSpan().SequenceEqual(unchanged));
        await RequireLocalExportNoReplaceAsync(installed.Node, installed.SandboxText, destination, replacement, token);
    }

    [Fact(Timeout = 125_000, DisableParallelization = true)]
    public async Task InstalledSandboxDataRefusesOrdinaryUnsafePathsAndManagedUse()
    {
        var token = TestContext.Current.CancellationToken;
        token.ThrowIfCancellationRequested();
        await using var installed = await TerminalCliFixture.StartAsync();
        await using var control = OpenChannel(installed.Node);
        var node = new NodeService.NodeServiceClient(control.CallInvoker);
        var data = new DataService.DataServiceClient(control.CallInvoker);
        var epoch = (await HandshakeAsync(node)).OwnerEpoch;
        var sandbox = installed.Sandbox;
        var owned = Path.Combine(sandbox.DataLocation, "data");
        var outside = Directory.CreateDirectory(Path.Combine(installed.Node.Root, "foreign file fixture")).FullName;
        var outsideFile = Path.Combine(outside, "sentinel.bin");
        var original = BuildFileBytes(3141, 82);
        var offered = BuildFileBytes(41_021, 183);
        await File.WriteAllBytesAsync(outsideFile, original, token);
        var existing = Path.Combine(owned, "CaseOwner.bin");
        await File.WriteAllBytesAsync(existing, original, token);

        string[] invalid = OperatingSystem.IsWindows()
            ? ["../sentinel.bin", outsideFile, "data/file.bin:stream"]
            : ["../sentinel.bin", outsideFile];
        foreach (var path in invalid)
        {
            var response = await data.BeginImportAsync(BeginFixtureImport(sandbox, epoch, path, offered), deadline: Deadline,
                cancellationToken: token);
            Assert.Null(response.Value);
            Assert.NotNull(response.Error);
            Assert.Equal(ErrorCategory.Validation, response.Error.Category);
            Assert.Equal("invalid_argument", response.Error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        }

        var noReplace = await data.BeginImportAsync(BeginFixtureImport(sandbox, epoch, "data/CaseOwner.bin", offered),
            deadline: Deadline, cancellationToken: token);
        Assert.Null(noReplace.Value);
        RequireDataRefusal(noReplace.Error, ErrorCategory.Conflict, "identity_changed");
        Assert.Equal("import_target_changed", noReplace.Error?.Details?.State?.Reason);
        var wrongCase = await data.BeginImportAsync(BeginFixtureImport(sandbox, epoch, "data/caseowner.bin", offered),
            deadline: Deadline, cancellationToken: token);
        RequireFileDestinationRefused(wrongCase);
        Assert.Equal("CaseOwner.bin", Path.GetFileName(Assert.Single(Directory.EnumerateFiles(owned))));
        await RequireDataLinkRefusalAsync(installed.Node, data, sandbox, epoch, owned, outside, token);
        await RequireApprovedHostGrantExclusionAsync(new SandboxService.SandboxServiceClient(control.CallInvoker), data,
            sandbox.Config, epoch, outside, token);
        await RequireActiveRunDataRefusalAsync(installed, data, epoch, offered, token);
        var retained = await File.ReadAllBytesAsync(existing, token);
        var sentinel = await File.ReadAllBytesAsync(outsideFile, token);
        Assert.True(original.AsSpan().SequenceEqual(retained));
        Assert.True(original.AsSpan().SequenceEqual(sentinel));
    }

    private static DataServiceBeginImportRequest BeginFixtureImport(Sandbox sandbox, Id epoch, string path, byte[] bytes) => new()
    {
        Meta = Mutation(sandbox.Revision),
        OwnerEpoch = epoch,
        SandboxId = sandbox.SandboxId,
        RelativePath = path,
        ByteLength = (ulong)bytes.Length,
        Sha256 = FileDigest(bytes),
        Overwrite = false,
    };

    private static void RequireFileDestinationRefused(DataServiceBeginImportResponse response)
    {
        Assert.Null(response.Value);
        Assert.NotNull(response.Error);
        Assert.True(response.Error.Code is "identity_changed" or "path_rejected" or "invalid_argument");
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
    }

    private static async Task RequireDataLinkRefusalAsync(TestNode fixture, DataService.DataServiceClient data, Sandbox sandbox,
        Id epoch, string owned, string outside, CancellationToken token)
    {
        var link = Path.Combine(owned, "linked-dir");
        if (OperatingSystem.IsWindows())
        {
            using var junction = fixture.Start(Path.Combine(Environment.SystemDirectory, "cmd.exe"), ["/d", "/c", "mklink", "/J", link, outside]);
            await junction.WaitForExitAsync(token).WaitAsync(NativeBound, token);
            Assert.Equal(0, junction.ExitCode);
        }
        else
        {
            Directory.CreateSymbolicLink(link, outside);
        }

        Assert.True((File.GetAttributes(link) & FileAttributes.ReparsePoint) != 0);
        try
        {
            var list = await data.ListEntriesAsync(new DataServiceListEntriesRequest
            {
                Meta = Query(), SandboxId = sandbox.SandboxId, RelativeDirectory = "data/linked-dir",
            }, deadline: Deadline, cancellationToken: token);
            Assert.Null(list.Value);
            RequireDataRefusal(list.Error, ErrorCategory.Validation, "path_rejected");
            var export = await data.BeginExportAsync(new DataServiceBeginExportRequest
            {
                Meta = Mutation(sandbox.Revision), OwnerEpoch = epoch, SandboxId = sandbox.SandboxId,
                RelativePath = "data/linked-dir/sentinel.bin",
            }, deadline: Deadline, cancellationToken: token);
            Assert.Null(export.Value);
            RequireDataRefusal(export.Error, ErrorCategory.Validation, "invalid_argument");
        }
        finally
        {
            Directory.Delete(link, recursive: false);
        }
    }

    private static async Task RequireApprovedHostGrantExclusionAsync(SandboxService.SandboxServiceClient sandboxes,
        DataService.DataServiceClient data, SandboxConfig original, Id epoch, string outside, CancellationToken token)
    {
        var config = original.Clone();
        config.HostGrants.Add(new HostGrant { HostPath = outside, SandboxPath = outside, Writable = false });
        var created = await sandboxes.CreateAsync(new SandboxServiceCreateRequest
        {
            Meta = Mutation(), OwnerEpoch = epoch, DisplayName = "Installed file exclusion fixture", Config = config,
        }, deadline: Deadline, cancellationToken: token);
        var sandbox = Value(created.Value, created.Error).Sandbox;
        var bound = Assert.Single(sandbox.Config.HostGrants);
        Assert.False(string.IsNullOrEmpty(bound.NativeIdentity));
        var current = await AwaitOwnedUsageAsync(data, sandbox.SandboxId, _ => true, token);
        Assert.Equal(bound.HostPath, Assert.Single(current.ExcludedRoots));
        Assert.Equal(0UL, current.OwnedBytes);
        Assert.Equal(0UL, current.FileCount);
    }

    private static void RequireDataRefusal(ArcError? error, ErrorCategory category, string code)
    {
        Assert.NotNull(error);
        Assert.Equal(category, error.Category);
        Assert.Equal(code, error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);
    }

    private static async Task RequireActiveRunDataRefusalAsync(TerminalCliFixture installed, DataService.DataServiceClient data,
        Id epoch, byte[] offered, CancellationToken token)
    {
        var release = Path.Combine(installed.Working, "live-file-run-release");
        var marker = Path.Combine(installed.Working, "live-file-run.log");
        var request = BuildStart(installed.Sandbox, epoch,
            [installed.Payload, "hold", "--hold-ms", "60000", "--until-file", release, "--marker", marker]);
        request.TerminalMode = TerminalMode.Pipes;
        request.TerminalSize = null;
        var reply = await installed.Runs.StartAsync(request, deadline: Deadline, cancellationToken: token);
        var run = Value(reply.Value, reply.Error).Run;
        await WaitForStateAsync(installed.Node, installed.Runs, run.RunId, RunState.Running, token);
        await TestNode.WaitAsync(() => ReadLines(marker).Any(line => line.StartsWith("ready ", StringComparison.Ordinal)),
            NativeBound, "a real active Run with its Sandbox private root");

        var sandbox = installed.Sandbox;
        var import = await data.BeginImportAsync(BeginFixtureImport(sandbox, epoch, "data/live-refused.bin", offered),
            deadline: Deadline, cancellationToken: token);
        Assert.Null(import.Value);
        RequireDataRefusal(import.Error, ErrorCategory.State, "managed_use");
        var export = await data.BeginExportAsync(new DataServiceBeginExportRequest
        {
            Meta = Mutation(sandbox.Revision), OwnerEpoch = epoch, SandboxId = sandbox.SandboxId, RelativePath = "data/CaseOwner.bin",
        }, deadline: Deadline, cancellationToken: token);
        Assert.Null(export.Value);
        RequireDataRefusal(export.Error, ErrorCategory.State, "managed_use");
        Assert.False(File.Exists(Path.Combine(sandbox.DataLocation, "data", "live-refused.bin")));
        await File.WriteAllTextAsync(release, "release", token);
        var settled = await installed.WaitExitedAsync(run.RunId, token);
        Assert.True(settled.Exit.HasRawCode);
        Assert.Equal(0, settled.Exit.RawCode);
    }

    [Fact(Timeout = 125_000, DisableParallelization = true)]
    public async Task InstalledSandboxDataResumesTheSameStagedImportAfterOrderlyNodeRestart()
    {
        var token = TestContext.Current.CancellationToken;
        token.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var fixture = TestNode.Create();
        PrepareInstalledCliFixture(fixture);
        var process = await fixture.StartNodeAsync();
        Id? epoch = null;
        try
        {
            const string path = "data/staged-import.bin";
            const int initialBytes = 16 * 1024;
            byte[] original = BuildFileBytes(41_021, 183);
            string destination;
            Sandbox sandbox;
            string originalNode;
            Id ownerEpoch;
            DataServiceWriteImportRequest first;
            Transfer partial;
            await using (var originalConnection = OpenChannel(fixture))
            {
                var hello = await HandshakeAsync(new NodeService.NodeServiceClient(originalConnection.CallInvoker));
                ownerEpoch = hello.OwnerEpoch;
                epoch = ownerEpoch;
                originalNode = hello.NodeEpoch;
                sandbox = await CreateSandboxAsync(new SandboxService.SandboxServiceClient(originalConnection.CallInvoker), ownerEpoch);
                destination = Path.Combine(sandbox.DataLocation, "data", "staged-import.bin");
                var data = new DataService.DataServiceClient(originalConnection.CallInvoker);
                (first, partial) = await WriteFirstFileChunkAsync(data, sandbox, ownerEpoch, path, destination, original, initialBytes, token);
            }

            await StopInstalledCliNodeAsync(fixture, process);
            Assert.True(process.HasExited);
            var originalProcess = process;
            process = await fixture.StartNodeAsync();
            originalProcess.Dispose();
            await using var recovered = OpenChannel(fixture);
            var node = new NodeService.NodeServiceClient(recovered.CallInvoker);
            var current = await HandshakeAsync(node);
            Assert.Equal(ownerEpoch, current.OwnerEpoch);
            Assert.NotEqual(originalNode, current.NodeEpoch);
            var resumed = new DataService.DataServiceClient(recovered.CallInvoker);
            var checkpoint = await InspectFileTransferAsync(resumed, partial.TransferId, token);
            Assert.Equal(partial, Value(checkpoint.Value, checkpoint.Error).Transfer);
            Assert.False(File.Exists(destination));
            var originalReceipt = await OperationAsync(node, ownerEpoch, first.Meta.CommandId);
            Assert.Equal(first.Meta.CommandId, originalReceipt.CommandId);
            Assert.Equal(partial.TransferId, originalReceipt.AggregateId);
            Assert.Equal(OperationState.Succeeded, originalReceipt.State);
            Assert.Equal(EffectCertainty.Happened, originalReceipt.Effect);

            var replay = await resumed.WriteImportAsync(first, deadline: Deadline, cancellationToken: token);
            Assert.Equal(partial, Value(replay.Value, replay.Error).Transfer);
            var afterReplay = await InspectFileTransferAsync(resumed, partial.TransferId, token);
            Assert.Equal(partial, Value(afterReplay.Value, afterReplay.Error).Transfer);
            Assert.Equal(TransferRevision(checkpoint.Meta), TransferRevision(afterReplay.Meta));
            await RequireFileTransferCliInspectionAsync(fixture, partial, original);
            await FinishResumedFileImportAsync(resumed, node, ownerEpoch, sandbox, path, destination, original, afterReplay, token);
        }
        finally
        {
            await CleanInstalledCliFixtureAsync(fixture, process, epoch, heldRun: null);
        }
    }

    private static async Task<(DataServiceWriteImportRequest First, Transfer Partial)> WriteFirstFileChunkAsync(
        DataService.DataServiceClient data, Sandbox sandbox, Id epoch, string path, string destination, byte[] original,
        int initialBytes, CancellationToken token)
    {
        var opened = await data.BeginImportAsync(BeginFixtureImport(sandbox, epoch, path, original), deadline: Deadline,
            cancellationToken: token);
        var stage = Value(opened.Value, opened.Error).Transfer;
        Assert.Equal("import", stage.Direction);
        Assert.Equal(0UL, stage.VerifiedOffset);
        Assert.Null(stage.ClosedAt);
        Assert.False(File.Exists(destination));
        var first = new DataServiceWriteImportRequest
        {
            Meta = Mutation(TransferRevision(opened.Meta)), OwnerEpoch = epoch, TransferId = stage.TransferId,
            Offset = 0, Chunk = ByteString.CopyFrom(original.AsSpan(0, initialBytes)),
        };
        var written = await data.WriteImportAsync(first, deadline: Deadline, cancellationToken: token);
        var partial = Value(written.Value, written.Error).Transfer;
        Assert.Equal(stage.TransferId, partial.TransferId);
        Assert.Equal((ulong)initialBytes, partial.VerifiedOffset);
        Assert.Null(partial.ClosedAt);
        Assert.False(File.Exists(destination));
        return (first, partial);
    }

    private static async Task FinishResumedFileImportAsync(DataService.DataServiceClient resumed, NodeService.NodeServiceClient node,
        Id epoch, Sandbox sandbox, string path, string destination, byte[] original, DataServiceInspectTransferResponse checkpoint,
        CancellationToken token)
    {
        var progress = Value(checkpoint.Value, checkpoint.Error).Transfer;
        var id = progress.TransferId;
        Assert.InRange(progress.VerifiedOffset, 1UL, (ulong)original.Length - 1);
        var final = new DataServiceWriteImportRequest
        {
            Meta = Mutation(TransferRevision(checkpoint.Meta)), OwnerEpoch = epoch, TransferId = id,
            Offset = progress.VerifiedOffset, Chunk = ByteString.CopyFrom(original.AsSpan(checked((int)progress.VerifiedOffset))),
        };
        var written = await resumed.WriteImportAsync(final, deadline: Deadline, cancellationToken: token);
        var verified = Value(written.Value, written.Error).Transfer;
        Assert.Equal((ulong)original.Length, verified.VerifiedOffset);
        var replay = await resumed.WriteImportAsync(final, deadline: Deadline, cancellationToken: token);
        Assert.Equal(verified, Value(replay.Value, replay.Error).Transfer);
        var changed = final.Clone();
        changed.Chunk = ByteString.CopyFrom(new byte[final.Chunk.Length]);
        var conflict = await resumed.WriteImportAsync(changed, deadline: Deadline, cancellationToken: token);
        Assert.Null(conflict.Value);
        RequireDataRefusal(conflict.Error, ErrorCategory.Conflict, "command_id_reused");
        Assert.False(File.Exists(destination));

        var commit = new DataServiceCommitImportRequest
        {
            Meta = Mutation(TransferRevision(written.Meta)), OwnerEpoch = epoch, TransferId = id,
        };
        var committed = await resumed.CommitImportAsync(commit, deadline: Deadline, cancellationToken: token);
        var receipt = Value(committed.Value, committed.Error).Operation;
        Assert.Equal(commit.Meta.CommandId, receipt.CommandId);
        Assert.Equal(id, receipt.AggregateId);
        Assert.True(receipt.State is OperationState.Accepted or OperationState.Succeeded);
        DataServiceInspectTransferResponse? finalState = null;
        await TestNode.WaitAsync(async () =>
        {
            var observed = await InspectFileTransferAsync(resumed, id, token);
            if (Value(observed.Value, observed.Error).Transfer.State != TransferState.Complete) return false;
            finalState = observed;
            return true;
        }, NativeBound, "the original staged import commit");
        var finished = Assert.IsType<DataServiceInspectTransferResponse>(finalState);
        var committedTransfer = Value(finished.Value, finished.Error).Transfer;
        RequireCompleteFileTransfer(committedTransfer, sandbox, path, "import", original);
        var operation = await OperationAsync(node, epoch, commit.Meta.CommandId);
        Assert.Equal(OperationState.Succeeded, operation.State);
        Assert.Equal(EffectCertainty.Happened, operation.Effect);
        var actual = await File.ReadAllBytesAsync(destination, token);
        Assert.True(original.AsSpan().SequenceEqual(actual));
        var close = await resumed.CloseTransferAsync(new DataServiceCloseTransferRequest
        {
            Meta = Mutation(TransferRevision(finished.Meta)), OwnerEpoch = epoch, TransferId = id,
        }, deadline: Deadline, cancellationToken: token);
        var closed = Value(close.Value, close.Error).Transfer;
        RequireCompleteFileTransfer(closed, sandbox, path, "import", original);
        Assert.NotNull(closed.ClosedAt);
    }

    private static Revision TransferRevision(ResponseMeta meta)
    {
        Assert.NotNull(meta.ResultRev);
        Assert.True(meta.ResultRev.Value > 0);
        return meta.ResultRev;
    }

    private static byte[] BuildFileBytes(int length, int salt)
    {
        var bytes = new byte[length];
        for (int index = 0; index < length; index++) bytes[index] = (byte)((index * 31) ^ (index >> 9) ^ salt);
        return bytes;
    }

    private static string FileDigest(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static async Task<Usage> AwaitOwnedUsageAsync(DataService.DataServiceClient data, Id sandbox,
        Func<Usage, bool> expected, CancellationToken token)
    {
        Usage? completed = null;
        await TestNode.WaitAsync(async () =>
        {
            var response = await data.GetUsageAsync(new DataServiceGetUsageRequest { Meta = Query(), SandboxId = sandbox },
                deadline: Deadline, cancellationToken: token);
            var usage = Value(response.Value, response.Error).Usage;
            if (!(usage.HasPartial && !usage.Partial && usage.HasOwnedBytes && usage.HasFileCount && expected(usage))) return false;
            Assert.NotNull(usage.ObservedAt);
            completed = usage;
            return true;
        }, NativeBound, "the completed private ownership scan");
        return Assert.IsType<Usage>(completed);
    }

    private static async Task RequireOwnedRootListingAsync(DataService.DataServiceClient data, Id sandbox, CancellationToken token)
    {
        var request = new DataServiceListEntriesRequest { Meta = Query(), SandboxId = sandbox, Limit = 2 };
        var first = await data.ListEntriesAsync(request, deadline: Deadline, cancellationToken: token);
        var page = Value(first.Value, first.Error);
        Assert.Equal(["cache", "config"], page.Entries.Select(entry => entry.RelativePath));
        Assert.False(string.IsNullOrEmpty(page.Page.NextCursor));
        var otherDirectory = request.Clone();
        otherDirectory.RelativeDirectory = "data";
        otherDirectory.Cursor = page.Page.NextCursor;
        var refused = await data.ListEntriesAsync(otherDirectory, deadline: Deadline, cancellationToken: token);
        Assert.Null(refused.Value);
        RequireDataRefusal(refused.Error, ErrorCategory.Validation, "invalid_cursor");

        var rest = request.Clone();
        rest.Cursor = page.Page.NextCursor;
        rest.Limit = 4;
        var reply = await data.ListEntriesAsync(rest, deadline: Deadline, cancellationToken: token);
        var terminal = Value(reply.Value, reply.Error);
        Assert.Equal(["data", "home", "tmp", "work"], terminal.Entries.Select(entry => entry.RelativePath));
        Assert.Empty(terminal.Page.NextCursor);
    }

    private static async Task<FileEntry> ReadOwnedFileEntryAsync(DataService.DataServiceClient data, Sandbox sandbox, int length,
        CancellationToken token)
    {
        var listed = await data.ListEntriesAsync(new DataServiceListEntriesRequest
        {
            Meta = Query(), SandboxId = sandbox.SandboxId, RelativeDirectory = "data", Limit = 20,
        }, deadline: Deadline, cancellationToken: token);
        var entry = Assert.Single(Value(listed.Value, listed.Error).Entries, row => row.RelativePath == FixtureDataPath);
        Assert.Equal("regular_file", entry.Kind);
        Assert.True(entry.HasByteLength);
        Assert.Equal((ulong)length, entry.ByteLength);
        Assert.False(string.IsNullOrEmpty(entry.VersionToken));
        return entry;
    }

    private static async Task<Run> ReadOriginalFromNativeRunAsync(TerminalCliFixture installed, Id epoch, byte[] expected,
        string? replacementFile, CancellationToken token)
    {
        var owned = Path.Combine(installed.Sandbox.DataLocation, "data", "round-trip.bin");
        string[] argv;
        if (OperatingSystem.IsLinux())
        {
            argv = replacementFile is null ? ["/usr/bin/cat", "--", owned]
                : ["/usr/bin/dash", "-c", "cat -- \"$1\" && cat -- \"$2\" > \"$1\"", "arcforges-file-fixture", owned, replacementFile];
        }
        else
        {
            const string read = """
                @echo off
                arcforges-testload.exe echo < "..\..\data\round-trip.bin"
                if not "%errorlevel%"=="0" exit /b %errorlevel%
                """;
            const string replace = """
                copy /b /y "replacement.bin" "..\..\data\round-trip.bin" >nul
                exit /b %errorlevel%
                """;
            string batch = replacementFile is null ? read + "\nexit /b 0\n" : read + "\n" + replace;
            await File.WriteAllTextAsync(Path.Combine(installed.Working, "data-round-trip.cmd"), batch.ReplaceLineEndings("\r\n"), token);
            argv = [Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/d", "/c", "data-round-trip.cmd"];
        }

        var request = BuildStart(installed.Sandbox, epoch, argv);
        request.TerminalMode = TerminalMode.Pipes;
        request.TerminalSize = null;
        var started = await installed.Runs.StartAsync(request, deadline: Deadline, cancellationToken: token);
        var run = Value(started.Value, started.Error).Run;
        var final = await installed.WaitExitedAsync(run.RunId, token);
        Assert.True(final.Exit.HasRawCode);
        Assert.Equal(0, final.Exit.RawCode);
        var output = await WatchAsync(installed.Runs, final, StreamKind.Stdout);
        Assert.Null(output.Gap);
        Assert.Equal((ulong)expected.Length, output.Offset);
        Assert.True(expected.AsSpan().SequenceEqual(output.Bytes), "The native Run did not read the exact imported file bytes.");
        return final;
    }

    private static Task<DataServiceInspectTransferResponse> InspectFileTransferAsync(DataService.DataServiceClient data, Id transfer,
        CancellationToken token) => data.InspectTransferAsync(new DataServiceInspectTransferRequest { Meta = Query(), TransferId = transfer },
        deadline: Deadline, cancellationToken: token).ResponseAsync;

    private static async Task<DataServiceInspectTransferResponse> AwaitMaterializedExportAsync(DataService.DataServiceClient data,
        Id transferId, CancellationToken token)
    {
        DataServiceInspectTransferResponse? complete = null;
        await TestNode.WaitAsync(async () =>
        {
            var response = await InspectFileTransferAsync(data, transferId, token);
            var transfer = Value(response.Value, response.Error).Transfer;
            Assert.Equal(transferId, transfer.TransferId);
            Assert.Equal("export", transfer.Direction);
            Assert.Null(transfer.ClosedAt);
            Assert.True(transfer.State is TransferState.Open or TransferState.Streaming or TransferState.Complete);
            if (transfer.State != TransferState.Complete) return false;
            complete = response;
            return true;
        }, NativeBound, "the same verified private export snapshot");
        return Assert.IsType<DataServiceInspectTransferResponse>(complete);
    }

    private static void RequireCompleteFileTransfer(Transfer transfer, Sandbox sandbox, string path, string direction, byte[] bytes)
    {
        Assert.Equal(sandbox.SandboxId, transfer.SandboxId);
        Assert.Equal(path, transfer.RelativePath);
        Assert.Equal(direction, transfer.Direction);
        Assert.Equal(TransferState.Complete, transfer.State);
        Assert.True(transfer.HasByteLength && transfer.HasVerifiedOffset && transfer.HasSha256);
        Assert.Equal((ulong)bytes.Length, transfer.ByteLength);
        Assert.Equal(transfer.ByteLength, transfer.VerifiedOffset);
        Assert.Equal(FileDigest(bytes), transfer.Sha256);
        Assert.NotNull(transfer.ExpiresAt);
    }

    private static async Task RequireFileTransferCliInspectionAsync(TestNode fixture, Transfer transfer, byte[] expected)
    {
        var inspected = await InstalledCliSuccessAsync(fixture, "sandbox", "transfer", "inspect", IdText.Format(transfer.TransferId));
        var result = inspected.GetProperty("transfer");
        Assert.Equal(transfer.TransferId, InstalledCliId(result, "transferId"));
        Assert.Equal(transfer.Direction, result.GetProperty("direction").GetString());
        Assert.Equal(FileDigest(expected), result.GetProperty("sha256").GetString());
        Assert.Equal(transfer.ByteLength.ToString(CultureInfo.InvariantCulture), CliScalar(result.GetProperty("byteLength")));
        Assert.Equal(transfer.VerifiedOffset.ToString(CultureInfo.InvariantCulture), CliScalar(result.GetProperty("verifiedOffset")));
        Assert.Equal(transfer.ClosedAt is not null, result.TryGetProperty("closedAt", out _));
    }

    private static async Task VerifyRetainedExportReplayAsync(TestNode fixture, DataService.DataServiceClient data,
        NodeService.NodeServiceClient node, Id epoch, Sandbox sandbox, Transfer retained, byte[] original, CancellationToken token)
    {
        var initial = new DataServiceReadExportRequest
        {
            Meta = Query(), TransferId = retained.TransferId, Offset = 0, MaxBytes = TransferChunkSize,
        };
        var first = await data.ReadExportAsync(initial, deadline: Deadline, cancellationToken: token);
        var firstChunk = Value(first.Value, first.Error).Chunk;
        Assert.Equal(0UL, firstChunk.Offset);
        Assert.False(firstChunk.Eof);
        Assert.Equal(TransferChunkSize, firstChunk.Data.Length);
        Assert.True(original.AsSpan(0, firstChunk.Data.Length).SequenceEqual(firstChunk.Data.Span));

        var final = new DataServiceReadExportRequest
        {
            Meta = Query(), TransferId = retained.TransferId, Offset = (ulong)firstChunk.Data.Length, MaxBytes = TransferChunkSize,
        };
        await using (var abandoned = OpenChannel(fixture))
        {
            var reader = new DataService.DataServiceClient(abandoned.CallInvoker);
            var discarded = await reader.ReadExportAsync(final, deadline: Deadline, cancellationToken: token);
            // Leave the real response body unconsumed by the fixture, then reconnect without another BeginExport.
            Assert.Null(discarded.Error);
        }

        var repeated = await data.ReadExportAsync(final, deadline: Deadline, cancellationToken: token);
        var replay = Value(repeated.Value, repeated.Error).Chunk;
        Assert.Equal(final.Offset, replay.Offset);
        Assert.True(replay.Eof);
        Assert.Equal((ulong)original.Length, replay.Offset + (ulong)replay.Data.Length);
        Assert.True(original.AsSpan(TransferChunkSize).SequenceEqual(replay.Data.Span));
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(firstChunk.Data.Span);
        hash.AppendData(replay.Data.Span);
        Assert.Equal(retained.Sha256, Convert.ToHexStringLower(hash.GetHashAndReset()));

        var inspected = await InspectFileTransferAsync(data, retained.TransferId, token);
        Assert.Equal(retained, Value(inspected.Value, inspected.Error).Transfer);
        Assert.NotNull(inspected.Meta.ResultRev);
        Assert.True(inspected.Meta.ResultRev.Value > 0);
        var close = new DataServiceCloseTransferRequest
        {
            Meta = Mutation(inspected.Meta.ResultRev), TransferId = retained.TransferId, OwnerEpoch = epoch,
        };
        var response = await data.CloseTransferAsync(close, deadline: Deadline, cancellationToken: token);
        var closed = Value(response.Value, response.Error).Transfer;
        RequireCompleteFileTransfer(closed, sandbox, FixtureDataPath, "export", original);
        Assert.Equal(retained.TransferId, closed.TransferId);
        Assert.NotNull(closed.ClosedAt);
        var again = await data.CloseTransferAsync(close, deadline: Deadline, cancellationToken: token);
        Assert.Equal(closed, Value(again.Value, again.Error).Transfer);
        var operation = await OperationAsync(node, epoch, close.Meta.CommandId);
        Assert.Equal(OperationState.Succeeded, operation.State);
        Assert.Equal(EffectCertainty.Happened, operation.Effect);
        Assert.Equal(closed.TransferId, operation.AggregateId);
        await RequireFileTransferCliInspectionAsync(fixture, closed, original);
        var after = await data.ReadExportAsync(final, deadline: Deadline, cancellationToken: token);
        Assert.Null(after.Value);
        RequireDataRefusal(after.Error, ErrorCategory.State, "managed_use");
        Assert.Equal("transfer_closed", after.Error?.Details?.State?.Reason);
    }

    private static async Task RequireLocalExportNoReplaceAsync(TestNode fixture, string sandbox, string destination, byte[] content,
        CancellationToken token)
    {
        var existing = Path.Combine(Path.GetDirectoryName(destination)!, "leave existing intact.bin");
        var sentinel = BuildFileBytes(79, 202);
        await File.WriteAllBytesAsync(existing, sentinel, token);
        var refusal = await InstalledCliRefusalAsync(fixture, 3, "identity_changed", "sandbox", "export", sandbox,
            FixtureDataPath, "--to", existing);
        var reason = refusal.GetProperty("error").GetProperty("details").GetProperty("state").GetProperty("reason");
        Assert.Equal("local_destination_exists", reason.GetString());
        var transfer = refusal.GetProperty("value");
        var retained = InstalledCliId(transfer, "transferId");
        Assert.Equal(FileDigest(content), transfer.GetProperty("sha256").GetString());
        Assert.False(transfer.TryGetProperty("closedAt", out _));
        var unchanged = await File.ReadAllBytesAsync(existing, token);
        Assert.True(sentinel.AsSpan().SequenceEqual(unchanged));
        var released = await InstalledCliSuccessAsync(fixture, "sandbox", "transfer", "close", IdText.Format(retained));
        var closed = released.GetProperty("transfer");
        Assert.Equal(retained, InstalledCliId(closed, "transferId"));
        Assert.True(closed.TryGetProperty("closedAt", out _));
    }
}
