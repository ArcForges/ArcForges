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
/// A helper that lies. Everything a hostile helper can put on the contract (a wrong digest, a range past its grant, another slot, a stale
/// sequence, other geometry) and everything it can do to the shared memory (rewrite it between the seal and the copy, or during the copy) must
/// end the invocation with a typed integrity failure and never reach the caller as bytes. The helper is a stand-in in this process.
/// </summary>
public sealed class HostileHelperTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    internal enum Lie
    {
        WrongDigest,
        RangePastGrant,
        OtherSlot,
        StaleSequence,
        OtherGeometry,
        OtherInvocation,
    }

    /// <summary>The real service with one lie told in the seal of every tile.</summary>
    private sealed class LyingService(
        Lie lie,
        ContentSandboxLaunchFrame frame,
        HelperResources resources,
        IContentParserProfile? profile,
        TimeProvider clock,
        Action<int> requestExit) : ContentSandboxServiceImpl(frame, resources, profile, clock, requestExit)
    {
        public override async Task<ContentSandboxServiceReadImageTileResponse> ReadImageTile(ContentSandboxServiceReadImageTileRequest request, ServerCallContext context)
        {
            var response = await base.ReadImageTile(request, context);
            var buffer = response.Value?.Buffer;
            if (buffer is null)
            {
                return response;
            }

            switch (lie)
            {
                case Lie.WrongDigest:
                    buffer.Sha256 = Convert.ToHexStringLower(SHA256.HashData("something else"u8));
                    break;
                case Lie.RangePastGrant:
                    buffer.Offset = request.Grant.Capacity;
                    break;
                case Lie.OtherSlot:
                    buffer.SlotId = (buffer.SlotId + 1) % 3;
                    break;
                case Lie.StaleSequence:
                    buffer.Sequence += 5;
                    break;
                case Lie.OtherGeometry:
                    buffer.FullWidth += 1;
                    break;
                case Lie.OtherInvocation:
                    buffer.InvocationId = SandboxRecords.ToWireId(Guid.NewGuid());
                    break;
                default:
                    break;
            }

            return response;
        }
    }

    private static InProcessHelperLauncher LyingLauncher(Lie lie) =>
        new(run => ContentSandboxHost.RunAsync(
            run.Frame,
            run.Bootstrap,
            run.Resources,
            Fixtures.Hostile(),
            TimeProvider.System,
            run.Stop,
            (frame, resources, profile, clock, exit) => new LyingService(lie, frame, resources, profile, clock, exit)));

    [Theory]
    [InlineData("WrongDigest")]
    [InlineData("RangePastGrant")]
    [InlineData("OtherSlot")]
    [InlineData("StaleSequence")]
    [InlineData("OtherGeometry")]
    [InlineData("OtherInvocation")]
    public async Task ATileSealedWithALieEndsTheInvocationAndYieldsNoBytes(string name)
    {
        var lie = Enum.Parse<Lie>(name);
        var (launcher, _, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("image 64 64"), helper: LyingLauncher(lie));
        await using var _l = launcher;
        await using var _i = invocation;
        var image = (await invocation.OpenImageAsync(0, 0, 1, Ct)).Value;
        var tile = await invocation.ReadImageTileAsync(image, 0, 0, 16, 16, Ct);
        Assert.False(tile.IsSuccess);
        Assert.Equal("resource.integrity_failed", tile.Failure!.Code);
        Assert.True(invocation.IsEnded);
        Assert.Null(tile.Value);
    }

    [Theory]
    [InlineData("between-seal-and-copy")]
    [InlineData("during-copy")]
    public async Task MemoryRewrittenAfterTheSealCannotChangeWhatTheCallerReceives(string when)
    {
        var options = Fixtures.Options(slotBytes: 1024 * 1024);
        var (launcher, helper, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("image 512 512"), options);
        await using var _l = launcher;
        await using var _i = invocation;
        var image = (await invocation.OpenImageAsync(0, 0, 1, Ct)).Value;

        // The parent's reads of the slot are the only moment the "child" can race: flip bytes at the first read, or after the first chunk.
        var reads = 0;
        foreach (var view in helper.Started[0].ParentViews)
        {
            var memory = helper.Started[0].Memory[Array.IndexOf(helper.Started[0].ParentViews, view)];
            view.BeforeRead = _ =>
            {
                var count = Interlocked.Increment(ref reads);
                if ((when == "between-seal-and-copy" && count == 1) || (when == "during-copy" && count == 2))
                {
                    memory.Bytes[0] ^= 0xFF;
                    memory.Bytes[^1] ^= 0xFF;
                }
            };
        }

        var tile = await invocation.ReadImageTileAsync(image, 0, 0, 512, 512, Ct);
        Assert.False(tile.IsSuccess);
        Assert.Equal("resource.integrity_failed", tile.Failure!.Code);
        Assert.True(invocation.IsEnded);
    }

    [Fact]
    public async Task AnUntamperedFullSlotTileIsAccepted()
    {
        var (launcher, _, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("image 512 512"), Fixtures.Options(slotBytes: 1024 * 1024));
        await using var _l = launcher;
        await using var _i = invocation;
        var image = (await invocation.OpenImageAsync(0, 0, 1, Ct)).Value;
        using var tile = (await invocation.ReadImageTileAsync(image, 0, 0, 512, 512, Ct)).Value!;
        Assert.Equal(1024 * 1024, tile.Bytes.Length);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(tile.Bytes.Span)), tile.Sha256);
    }

    [Fact]
    public async Task TheBytesOfATileAreAPrivateCopyThatSurvivesLaterWritesAndIsZeroedOnDispose()
    {
        var (launcher, helper, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("image 64 64"));
        await using var _l = launcher;
        await using var _i = invocation;
        var image = (await invocation.OpenImageAsync(0, 0, 1, Ct)).Value;
        var tile = (await invocation.ReadImageTileAsync(image, 0, 0, 16, 16, Ct)).Value!;
        var before = tile.Bytes.ToArray();
        Array.Fill(helper.Started[0].Memory[0].Bytes, (byte)0xAA);
        Assert.Equal(before, tile.Bytes.ToArray());
        tile.Dispose();
        Assert.Throws<ObjectDisposedException>(() => tile.Bytes);
        tile.Dispose();
    }

    [Fact]
    public async Task AHelperThatNeverRegistersFailsTheLaunchAtItsTimeoutAndLeavesNothingRunning()
    {
        var silent = new InProcessHelperLauncher(async run =>
        {
            try
            {
                await Task.Delay(Timeout.Infinite, run.Stop);
            }
            catch (OperationCanceledException)
            {
                // Terminated.
            }

            return ContentSandboxContract.ExitClean;
        });
        var options = Fixtures.Options() with { LaunchTimeout = TimeSpan.FromSeconds(2) };
        var stand = silent;
        await using var launcher = new ContentSandboxLauncher(options, profileOverride: null, launcherOverride: stand);
        var result = await launcher.LaunchAsync("HOSTILE1\n"u8.ToArray(), Ct);
        Assert.False(result.IsSuccess);
        Assert.Equal("resource.unavailable", result.Failure!.Code);
        Assert.True(stand.Started[0].Exited.IsCompleted);
    }

    [Fact]
    public async Task AHelperThatExitsWithTheIsolationCodeIsReportedAsIsolationUnavailable()
    {
        var refusing = new InProcessHelperLauncher(run => Task.FromResult(ContentSandboxContract.ExitIsolationUnavailable));
        await using var launcher = new ContentSandboxLauncher(Fixtures.Options(), profileOverride: null, launcherOverride: refusing);
        var result = await launcher.LaunchAsync("HOSTILE1\n"u8.ToArray(), Ct);
        Assert.Equal("security.isolation_unavailable", result.Failure!.Code);
    }

    [Fact]
    public async Task ASessionTheParentDoesNotRenewExpiresAndTheHelperLeaves()
    {
        var clock = new ManualClock();
        var stand = new InProcessHelperLauncher(Fixtures.Hostile(), clock);
        var (launcher, _, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("image 8 8"), helper: stand);
        await using var _l = launcher;
        await using var _i = invocation;
        clock.Advance(TimeSpan.FromSeconds(31));
        Assert.Equal(ContentSandboxContract.ExitSessionExpired, await stand.Started[0].Exited.WaitAsync(TimeSpan.FromSeconds(15), Ct));
    }

    /// <summary>A time provider the test moves by hand; the helper sees the lease pass without waiting for it.</summary>
    private sealed class ManualClock : TimeProvider
    {
        private long _offsetTicks;

        public override long TimestampFrequency => global::System.Diagnostics.Stopwatch.Frequency;

        public override long GetTimestamp() => global::System.Diagnostics.Stopwatch.GetTimestamp() + (long)(Interlocked.Read(ref _offsetTicks) / (double)TimeSpan.TicksPerSecond * TimestampFrequency);

        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UtcNow + TimeSpan.FromTicks(Interlocked.Read(ref _offsetTicks));

        internal void Advance(TimeSpan by) => Interlocked.Add(ref _offsetTicks, by.Ticks);
    }
}
