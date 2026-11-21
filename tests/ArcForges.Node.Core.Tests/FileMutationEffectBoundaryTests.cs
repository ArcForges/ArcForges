// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>Link and cancellation boundaries on retained write requests queued behind the SQLite writer.</summary>
public sealed class FileMutationEffectBoundaryTests
{
    [Theory(Timeout = 120_000)]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public async Task InterruptionBeforeReplayKeepsHistoricalIntentForRecovery(bool expectedAbsent, bool cancel)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Human);
        var fixture = new RetainedFileMutationFixture(node, actor, expectedAbsent, ct);
        fixture.Prepare();

        using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var blocker = node.Runtime.Processor.ExecuteAsync(_ =>
        {
            entered.TrySetResult();
            if (!release.Wait(TimeSpan.FromSeconds(15), ct))
            {
                throw new TimeoutException("The test writer was not released.");
            }

            return 0;
        });
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5), ct);
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var pending = fixture.InvokeAsync(calls, actor, cancellation.Token);
            Assert.False(pending.IsCompleted);
            if (cancel)
            {
                await cancellation.CancelAsync();
            }
            else
            {
                calls.Link.Reset(usableFor: 0);
            }

            release.Set();
            if (cancel)
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
            }
            else
            {
                await Assert.ThrowsAsync<RoutedAbortException>(() => pending);
            }
        }
        finally
        {
            release.Set();
            await blocker.WaitAsync(TimeSpan.FromSeconds(5), ct);
        }

        await node.Runtime.Processor.ExecuteAsync(_ => 0).WaitAsync(TimeSpan.FromSeconds(5), ct);
        var retained = fixture.ReadJournal();
        Assert.Equal(FileOperationState.Prepared, retained.State);
        Assert.True(retained.Held);
        Assert.Equal(SHA256.HashData(fixture.Raw), retained.RequestSha256.ToByteArray());
        fixture.AssertNoEffect();

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        var recovered = fixture.ReadJournal();
        Assert.Equal(FileOperationState.Unknown, recovered.State);
        Assert.True(recovered.Held);
        Assert.Equal("file_outcome_unknown", recovered.Error.Details.State.Reason);
        Assert.Equal(retained.RequestSha256, recovered.RequestSha256);
        fixture.AssertNoEffect();
    }
}

/// <summary>Historical metadata for the journal tests. All fixture bytes live in the test node's temporary root.</summary>
internal sealed class RetainedFileMutationFixture
{
    private readonly InProcessNode _node;
    private readonly string _target;
    private readonly byte[]? _original;
    private readonly CenterCaller _actor;

    public RetainedFileMutationFixture(InProcessNode node, CenterCaller actor, bool expectedAbsent, CancellationToken cancellationToken)
    {
        _node = node;
        _actor = actor;
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "retained-workspace")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: cancellationToken);
        _target = Path.Combine(root, "target.txt");
        if (!expectedAbsent)
        {
            _original = "retained original bytes"u8.ToArray();
            File.WriteAllBytes(_target, _original);
        }

        var meta = InProcessNode.Command();
        var replacement = "historical intended bytes"u8.ToArray();
        var request = new FileServiceWriteFileRequest
        {
            Meta = meta,
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target.txt" },
            Data = ByteString.CopyFrom(replacement),
        };
        var originalHash = _original is null ? null : SHA256.HashData(_original);
        if (originalHash is null)
            request.ExpectedAbsent = true;
        else
            request.ExpectedSha256 = ByteString.CopyFrom(originalHash);

        // The journal validates identity encoding. Replay does not use these synthetic identities to open a path.
        var platform = OperatingSystem.IsWindows() ? 1 : 2;
        byte[] Identity(byte number)
        {
            var value = new byte[platform == 1 ? 33 : 53];
            value[0] = 1;
            value[1] = number;
            return value;
        }

        Intent = new FileJournalIntent(FileOperationKind.Write, meta.CommandId.Value.ToByteArray(), meta.CorrelationId.Value.ToByteArray(),
            actor, workspace.Id, request.Path.Path, platform, Identity(1), Identity(1), expectedAbsent ? null : Identity(2),
            _original?.LongLength, originalHash, expectedAbsent ? null : Identity(3), replacement.LongLength,
            SHA256.HashData(replacement), Identity(4));
        Raw = request.ToByteArray();
    }

    public FileJournalIntent Intent { get; }
    public byte[] Raw { get; }

    public void Prepare() => Assert.Equal(FileJournalPreparation.Prepared, _node.Runtime.Store.Write(
        transaction => FileMutationJournal.Prepare(transaction, Intent, Raw), CommitDurability.Full));

    public FileOperation ReadJournal() => Assert.IsType<FileOperation>(_node.Runtime.Store.Read(reader =>
        FileMutationJournal.GetForCaller(reader, Intent.CommandId, _actor)));

    public Task<byte[]?> InvokeAsync(RoutedCalls calls, CenterCaller actor, CancellationToken cancellationToken)
    {
        var runtime = _node.Runtime;
        var routed = new RoutedContext(calls.Link, runtime.Lifecycle, runtime.Clock.GetUtcNow().AddSeconds(30),
            TimeSpan.FromSeconds(15), runtime.Clock, runtime.Clock.GetTimestamp(), CommandIds.New(), fileWorkspace: true);
        var caller = new Caller(Origin.Remote, ClientKind.Unspecified, null, centerCaller: actor.Clone())
        {
            CellsOrigin = CenterRouting.CellsOrigin(actor, runtime.NodeId.Span),
            RemoteCommandId = new Id { Value = ByteString.CopyFrom(Intent.CommandId) },
            RawRequest = Raw,
            Routed = routed,
        };
        return calls.Dispatcher.FileHandlerForTests!.WriteExistingCandidateAsync(caller, cancellationToken);
    }

    public void AssertNoEffect()
    {
        if (_original is null)
            Assert.False(File.Exists(_target));
        else
            Assert.Equal(_original, File.ReadAllBytes(_target));

        _node.Runtime.Store.Read(reader =>
        {
            Assert.Equal(1L, reader.Scalar("SELECT count(*) FROM file_operation_journal;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_private_stage_reservation;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_stage_worker;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_effect_worker;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM approval;"));
            return 0;
        });
    }
}
