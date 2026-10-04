// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.ContentSandbox.Broker;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.ContentSandbox.Host;
using ArcForges.Contracts.LocalRpc.Sandbox.V1;
using ArcForges.LocalRpc;
using Grpc.Core;
using Xunit;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>
/// The parent, the real helper host and the real generated contract end to end over in-memory streams and arrays: launch frame,
/// registration with the one-use secret, session, grant, seal, private copy, digest on the copy, acknowledgement, cancellation and failure. The
/// helper runs in this process: none of this is operating-system containment, which only the opt-in OS tests observe.
/// </summary>
public sealed class InvocationTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static void AssertPattern(ContentSandboxTile tile)
    {
        var bytes = tile.Bytes.Span;
        var pixelBytes = tile.Format == 1 ? 4 : 16;
        Assert.Equal((int)(((tile.Height - 1) * tile.RowStride) + (tile.Width * (uint)pixelBytes)), bytes.Length);
        for (var row = 0; row < tile.Height; row++)
        {
            for (var column = 0; column < tile.Width; column++)
            {
                var offset = (int)((ulong)row * tile.RowStride) + (column * pixelBytes);
                var x = tile.X + (uint)column;
                var y = tile.Y + (uint)row;
                if (tile.Format == 1)
                {
                    Assert.Equal([(byte)(x & 0xFF), (byte)(y & 0xFF), (byte)((x + y) & 0xFF), (byte)0xFF], bytes.Slice(offset, 4).ToArray());
                }
                else
                {
                    Assert.Equal((float)x / tile.FullWidth, BitConverter.ToSingle(bytes.Slice(offset, 4)));
                    Assert.Equal((float)y / tile.FullHeight, BitConverter.ToSingle(bytes.Slice(offset + 4, 4)));
                }
            }
        }
    }

    [Fact]
    public async Task ATileTravelsThroughAGrantedSlotAndIsVerifiedOnThePrivateCopy()
    {
        var (launcher, helper, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("image 300 200"));
        await using var _ = launcher;
        await using var __ = invocation;
        var image = await invocation.OpenImageAsync(0, 0, 1, Ct);
        Assert.True(image.IsSuccess, image.Failure?.Code);
        var info = await invocation.GetImageInfoAsync(image.Value, Ct);
        Assert.True(info.IsSuccess, info.Failure?.Code);
        Assert.Equal((300u, 200u), (info.Value.Width, info.Value.Height));
        Assert.Equal(["R", "G", "B", "A"], info.Value.Channels.Select(channel => channel.Name));

        // Five tiles through three slots: a slot is reused only after the matching acknowledgement.
        for (uint index = 0; index < 5; index++)
        {
            using var tile = (await invocation.ReadImageTileAsync(image.Value, index * 8, 16, 40, 24, Ct)).Value!;
            Assert.NotNull(tile);
            AssertPattern(tile);
            Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(tile.Bytes.Span)), tile.Sha256);
        }

        var snapshot = invocation.BrokerSession!.GetSnapshot();
        Assert.All(snapshot.Slots, state => Assert.Equal(LocalRpcSlotState.Free, state));
        Assert.True(snapshot.NextSequences.Max() >= 2);
        var closed = await invocation.CloseImageAsync(image.Value, Ct);
        Assert.True(closed.IsSuccess);
        Assert.Equal("state.not_found", (await invocation.CloseImageAsync(image.Value, Ct)).Failure!.Code);
        await invocation.CloseAsync();
        Assert.Equal(ContentSandboxContract.ExitClean, await invocation.WaitForExitAsync(Ct));
        Assert.Single(helper.Started);
    }

    [Fact]
    public async Task AFloatTileUsesTheSixteenByteFormat()
    {
        var (launcher, _, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("image 64 64"));
        await using var _l = launcher;
        await using var _i = invocation;
        var image = (await invocation.OpenImageAsync(0, 0, 2, Ct)).Value;
        using var tile = (await invocation.ReadImageTileAsync(image, 4, 4, 8, 8, Ct)).Value!;
        Assert.Equal(2u, tile.Format);
        Assert.Equal(8UL * 16, tile.RowStride);
        AssertPattern(tile);
    }

    [Fact]
    public async Task InvalidRequestsAreRefusedBeforeAnySlotIsGranted()
    {
        var (launcher, _, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("image 100 100"));
        await using var _l = launcher;
        await using var _i = invocation;
        Assert.Equal("validation.invalid_request", (await invocation.OpenImageAsync(0, 0, 3, Ct)).Failure!.Code);
        var image = (await invocation.OpenImageAsync(0, 0, 1, Ct)).Value;
        Assert.Equal("state.not_found", (await invocation.ReadImageTileAsync(Guid.NewGuid(), 0, 0, 8, 8, Ct)).Failure!.Code);
        Assert.Equal("validation.invalid_request", (await invocation.ReadImageTileAsync(image, 0, 0, 0, 8, Ct)).Failure!.Code);
        Assert.Equal("validation.invalid_request", (await invocation.ReadImageTileAsync(image, 0, 0, 2049, 8, Ct)).Failure!.Code);
        Assert.Equal("validation.invalid_request", (await invocation.ReadImageTileAsync(image, 95, 0, 10, 8, Ct)).Failure!.Code);
        Assert.Equal("validation.invalid_request", (await invocation.ReadImageTileAsync(image, 0, 95, 8, 10, Ct)).Failure!.Code);
        Assert.False(invocation.IsEnded);
        Assert.All(invocation.BrokerSession!.GetSnapshot().Slots, state => Assert.Equal(LocalRpcSlotState.Free, state));
        Assert.Equal("state.not_found", (await invocation.GetImageInfoAsync(Guid.NewGuid(), Ct)).Failure!.Code);
    }

    [Fact]
    public async Task AScriptTheParserCannotReadFailsTheCallAndKeepsTheInvocation()
    {
        var (launcher, _, invocation) = await Fixtures.LaunchAsync("not a script"u8.ToArray());
        await using var _l = launcher;
        await using var _i = invocation;
        var image = await invocation.OpenImageAsync(0, 0, 1, Ct);
        Assert.Equal("resource.parser_failed", image.Failure!.Code);
        Assert.False(invocation.IsEnded);
    }

    [Fact]
    public async Task APdfIsOpenedPagedAndExtractedInBoundedChunksAndRendered()
    {
        var (launcher, _, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("page 612 792 first page of the document", "longpage 90000"));
        await using var _l = launcher;
        await using var _i = invocation;
        var document = await invocation.OpenPdfAsync(Ct);
        Assert.True(document.IsSuccess, document.Failure?.Code);
        var first = await invocation.GetPdfPageAsync(document.Value, 0, Ct);
        Assert.Equal((612d, 792d), (first.Value!.WidthPoints, first.Value.HeightPoints));
        Assert.Equal("state.not_found", (await invocation.GetPdfPageAsync(document.Value, 2, Ct)).Failure!.Code);

        var small = await invocation.ExtractPdfTextAsync(document.Value, 0, 0, Ct);
        Assert.Equal("first page of the document", small.Value!.Text);
        Assert.False(small.Value.HasNext);
        Assert.Equal(5, small.Value.Boxes.Count);

        var total = 0;
        uint start = 0;
        while (true)
        {
            var chunk = (await invocation.ExtractPdfTextAsync(document.Value, 1, start, Ct)).Value!;
            Assert.NotNull(chunk);
            total += chunk.Text.Length;
            if (!chunk.HasNext)
            {
                break;
            }

            start = chunk.Next;
        }

        Assert.Equal(90000, total);
        Assert.Equal("validation.invalid_offset", (await invocation.ExtractPdfTextAsync(document.Value, 1, 7, Ct)).Failure!.Code);

        using var tile = (await invocation.RenderPdfTileAsync(document.Value, first.Value, 600, 780, 8, 8, 32, 16, Ct)).Value!;
        Assert.Equal((32u, 16u), (tile.Width, tile.Height));
        AssertPattern(tile);
        Assert.True((await invocation.ClosePdfAsync(document.Value, Ct)).IsSuccess);
        Assert.Equal("state.not_found", (await invocation.ClosePdfAsync(document.Value, Ct)).Failure!.Code);
    }

    [Fact]
    public async Task APdfRenderMustUseTheGeometryThePageCallReturned()
    {
        var (launcher, _, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("page 612 792 hello"));
        await using var _l = launcher;
        await using var _i = invocation;
        var document = (await invocation.OpenPdfAsync(Ct)).Value;
        var page = (await invocation.GetPdfPageAsync(document, 0, Ct)).Value!;
        var scaled = page.Clone();
        scaled.WidthPoints = 100;
        var refused = await invocation.RenderPdfTileAsync(document, scaled, 600, 780, 0, 0, 8, 8, Ct);
        Assert.False(refused.IsSuccess);
        Assert.Equal("validation.invalid_request", refused.Failure!.Code);
    }

    [Fact]
    public async Task ATileTheParserOverrunsIsRefusedAndTheInvocationEnds()
    {
        var (launcher, _, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("image 64 64", "overflow-on-tile"));
        await using var _l = launcher;
        await using var _i = invocation;
        var image = (await invocation.OpenImageAsync(0, 0, 1, Ct)).Value;
        var tile = await invocation.ReadImageTileAsync(image, 0, 0, 16, 16, Ct);
        Assert.Equal("resource.parser_failed", tile.Failure!.Code);
        Assert.True(invocation.IsEnded);
        Assert.Equal("resource.parser_failed", (await invocation.OpenImageAsync(0, 0, 1, Ct)).Failure!.Code);
    }

    [Fact]
    public async Task AParserThatNeverReturnsEndsTheHelperAtItsDeadlineAndTheParentCarriesOn()
    {
        var limits = new ContentSandboxLimits { TimeoutMs = 600, MaxWidth = 4096, MaxHeight = 4096 };
        var (launcher, _, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("image 64 64", "polite-hang-on-tile"), Fixtures.Options(limits: limits));
        await using var _l = launcher;
        await using var _i = invocation;
        var image = (await invocation.OpenImageAsync(0, 0, 1, Ct)).Value;
        var started = DateTime.UtcNow;
        var tile = await invocation.ReadImageTileAsync(image, 0, 0, 16, 16, Ct);
        Assert.Equal("resource.parser_failed", tile.Failure!.Code);
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(20));
        Assert.True(invocation.IsEnded);
        Assert.Equal(ContentSandboxContract.ExitParserHung, await invocation.WaitForExitAsync(Ct));
    }

    [Fact]
    public async Task CancellationReachesTheHelperThroughTheControlSlotWhileTheDataLaneIsFull()
    {
        var limits = new ContentSandboxLimits { TimeoutMs = 8000, MaxWidth = 4096, MaxHeight = 4096 };
        var (launcher, _, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("slow-on-open 6000"), Fixtures.Options(limits: limits));
        await using var _l = launcher;
        await using var _i = invocation;

        // 80 calls that the helper holds: 16 run (one in the parser, the rest waiting for it) and 64 queue. The data lane is full.
        var held = Enumerable.Range(0, 80).Select(_ => invocation.RawClient.OpenPdfAsync(
            new ContentSandboxServiceOpenPdfRequest
            {
                Meta = Meta(),
                SessionId = SandboxRecords.ToWireId(invocation.SessionId),
                DocumentId = SandboxRecords.ToWireId(Guid.NewGuid()),
            },
            new CallOptions(deadline: DateTime.UtcNow + TimeSpan.FromSeconds(28), cancellationToken: Ct)).ResponseAsync).ToArray();
        await Task.Delay(TimeSpan.FromSeconds(1), Ct);

        var refused = await Assert.ThrowsAsync<RpcException>(async () => await invocation.RawClient.GetImageInfoAsync(
            new ContentSandboxServiceGetImageInfoRequest { Meta = Meta(), SessionId = SandboxRecords.ToWireId(invocation.SessionId), ImageId = SandboxRecords.ToWireId(Guid.NewGuid()) },
            new CallOptions(deadline: DateTime.UtcNow + TimeSpan.FromSeconds(5), cancellationToken: Ct)));
        Assert.Equal(StatusCode.ResourceExhausted, refused.StatusCode);
        Assert.True(LocalRpcRefusal.TryRead(refused, out var refusal) && refusal!.Reason == LocalRpcRefusalReason.DataQueueFull);

        var watch = System.Diagnostics.Stopwatch.StartNew();
        var acknowledged = await invocation.CancelAsync();
        Assert.True(acknowledged);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(4), "the cancel waited behind the data lane: " + watch.Elapsed);
        Assert.Equal(LocalRpcBrokerSessionState.Cancelled, invocation.BrokerSession!.State);
        foreach (var call in held)
        {
            try
            {
                _ = await call;
            }
            catch (RpcException)
            {
                // Refused, cancelled or past its deadline: the lane is released.
            }
        }
    }

    [Fact]
    public async Task ASessionIsOpenedOnceAndRenewedIdempotently()
    {
        var (launcher, _, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("image 8 8"));
        await using var _l = launcher;
        await using var _i = invocation;
        var client = invocation.RawClient;
        var session = SandboxRecords.ToWireId(invocation.SessionId);
        var command = Meta();
        var first = await client.RenewSessionAsync(new ContentSandboxServiceRenewSessionRequest { Meta = command, SessionId = session }, cancellationToken: Ct);
        await Task.Delay(1200, Ct);
        var repeated = await client.RenewSessionAsync(new ContentSandboxServiceRenewSessionRequest { Meta = command, SessionId = session }, cancellationToken: Ct);
        Assert.Equal(first.Value.ExpiresAt, repeated.Value.ExpiresAt);
        var fresh = await client.RenewSessionAsync(new ContentSandboxServiceRenewSessionRequest { Meta = Meta(), SessionId = session }, cancellationToken: Ct);
        Assert.True(SandboxRecords.FromInstant(fresh.Value.ExpiresAt) > SandboxRecords.FromInstant(first.Value.ExpiresAt));

        var wrongSession = await client.RenewSessionAsync(new ContentSandboxServiceRenewSessionRequest { Meta = Meta(), SessionId = SandboxRecords.ToWireId(Guid.NewGuid()) }, cancellationToken: Ct);
        Assert.Equal("state.not_found", wrongSession.Error.Code);

        var again = await client.OpenSessionAsync(
            new ContentSandboxServiceOpenSessionRequest
            {
                Meta = Meta(),
                Input = new SandboxInput { InvocationId = SandboxRecords.ToWireId(Guid.NewGuid()), Generation = 1, InputId = SandboxRecords.ToWireId(Guid.NewGuid()), Length = 1, Sha256 = new string('0', 64) },
                Limits = new ContentSandboxLimits().ToWire(),
            },
            cancellationToken: Ct);
        Assert.Equal("validation.invalid_request", again.Error.Code);
    }

    [Fact]
    public async Task AGrantTheHelperDoesNotRecogniseAndAStaleAcknowledgementAreRefused()
    {
        var (launcher, _, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("image 8 8"));
        await using var _l = launcher;
        await using var _i = invocation;
        var client = invocation.RawClient;
        var session = SandboxRecords.ToWireId(invocation.SessionId);
        var image = (await invocation.OpenImageAsync(0, 0, 1, Ct)).Value;
        var region = new SandboxRegion { X = 0, Y = 0, Width = 4, Height = 4, FirstSample = 0, SampleCount = 0, RowStride = 16 };

        var ungranted = await client.ReadImageTileAsync(
            new ContentSandboxServiceReadImageTileRequest
            {
                Meta = Meta(),
                SessionId = session,
                ImageId = SandboxRecords.ToWireId(image),
                Region = region,
                Grant = new SandboxSlotGrant { SlotId = 0, Sequence = 1, Capacity = 64 },
            },
            cancellationToken: Ct);
        Assert.Equal("validation.invalid_request", ungranted.Error.Code);

        var badSlot = await client.GrantSlotAsync(
            new ContentSandboxServiceGrantSlotRequest { Meta = Meta(), SessionId = session, Grant = new SandboxSlotGrant { SlotId = 9, Sequence = 1, Capacity = 64 } },
            cancellationToken: Ct);
        Assert.NotNull(badSlot.Error);
        var stale = await client.AckBufferAsync(
            new ContentSandboxServiceAckBufferRequest
            {
                Meta = Meta(),
                SessionId = session,
                Ack = SandboxRecords.ToWire(new LocalRpcBufferAck(Guid.NewGuid(), Guid.NewGuid(), 1, 0, 1, LocalRpcDigest.Compute("x"u8))),
            },
            cancellationToken: Ct);
        Assert.NotNull(stale.Error);
    }

    [Fact]
    public async Task AHelperThatDiesEndsTheInvocationWithATypedFailure()
    {
        var (launcher, helper, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("image 8 8"));
        await using var _l = launcher;
        await using var _i = invocation;
        var image = (await invocation.OpenImageAsync(0, 0, 1, Ct)).Value;
        helper.Started[0].Terminate();
        var tile = await invocation.ReadImageTileAsync(image, 0, 0, 4, 4, Ct);
        Assert.Equal("resource.parser_failed", tile.Failure!.Code);
        Assert.True(invocation.IsEnded);
    }

    [Fact]
    public async Task CallerCancellationCancelsTheInvocation()
    {
        var (launcher, _, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("image 64 64", "slow-on-tile 20000"));
        await using var _l = launcher;
        await using var _i = invocation;
        var image = (await invocation.OpenImageAsync(0, 0, 1, Ct)).Value;
        using var source = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var pending = invocation.ReadImageTileAsync(image, 0, 0, 8, 8, source.Token).AsTask();
        await Task.Delay(500, Ct);
        await source.CancelAsync();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await pending);
        Assert.NotEqual(LocalRpcBrokerSessionState.Open, invocation.BrokerSession!.State);
    }

    [Fact]
    public async Task AParserProfileTheHelperDoesNotContainIsRefusedAtTheSession()
    {
        var stand = new InProcessHelperLauncher(ParserProfiles.Production);
        await using var launcher = new ContentSandboxLauncher(Fixtures.Options(parser: "hostile-test-parser"), profileOverride: null, launcherOverride: stand);
        var result = await launcher.LaunchAsync("HOSTILE1\n"u8.ToArray(), Ct);
        Assert.False(result.IsSuccess);
        Assert.Equal("resource.unavailable", result.Failure!.Code);
    }

    [Fact]
    public async Task TheLaunchIdentityBindsTheContractSetAndTheBuild()
    {
        var options = Fixtures.Options();
        var identity = ContentSandboxLauncher.IdentityFor(options);
        Assert.Equal(LocalRpcChildKind.ContentSandbox, identity.ChildKind);
        Assert.True(identity.ContractSetDigest.Span.SequenceEqual(ContentSandboxContract.ContractSetDigest.Span));
        Assert.True(identity.BuildDigest.Span.SequenceEqual(options.HelperSha256.Span));
        Assert.Equal(ContentSandboxContract.ProtocolVersion, identity.ProtocolVersion);
        await Task.CompletedTask;
    }

    private static ArcForges.Contracts.Foundation.V1.RequestMeta Meta() => new()
    {
        CommandId = SandboxRecords.ToWireId(Guid.NewGuid()),
        CorrelationId = SandboxRecords.ToWireId(Guid.NewGuid()),
    };
}
