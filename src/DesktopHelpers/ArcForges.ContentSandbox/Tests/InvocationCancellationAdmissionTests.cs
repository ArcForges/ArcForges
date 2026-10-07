// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.ContentSandbox.Broker;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.ContentSandbox.Host;
using ArcForges.ContentSandbox.HostileFixture;
using ArcForges.Contracts.LocalRpc.Sandbox.V1;
using ArcForges.LocalRpc;
using Xunit;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>Actual broker/generated controls/helper host over unavailable-OS stream substitutions; no codec or OS proof.</summary>
public sealed class InvocationCancellationAdmissionTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task PreCancelledAdmissionEndsTheInvocationAndPreservesTheCallerToken()
    {
        var (launcher, _, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("image 8 8"));
        await using var ownedLauncher = launcher;
        await using var ownedInvocation = invocation;
        try
        {
            var image = await invocation.OpenImageAsync(0, 0, 1, Ct);
            Assert.True(image.IsSuccess);
            var token = new CancellationToken(canceled: true);
            var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await invocation.GetImageInfoAsync(image.Value, token));
            Assert.Equal(token, error.CancellationToken);
            Assert.Equal(LocalRpcBrokerSessionState.Cancelled, invocation.BrokerSession!.State);
            Assert.False((await invocation.GetImageInfoAsync(image.Value, Ct)).IsSuccess);
        }
        finally { _ = await invocation.CancelAsync(); }
    }

    [Fact]
    public async Task QueuedCallerCancellationEndsTheBorrowedOperationWithoutWaitingForItsDataGate()
    {
        var profile = new WaitingProfile();
        var helper = new InProcessHelperLauncher(new ParserProfiles([profile]));
        var (launcher, _, invocation) = await Fixtures.LaunchAsync(Fixtures.Script("image 8 8"),
            Fixtures.Options(parser: profile.Id, limits: new ContentSandboxLimits { TimeoutMs = 15000 }), helper);
        await using var ownedLauncher = launcher;
        await using var ownedInvocation = invocation;
        try
        {
            var image = await invocation.OpenImageAsync(0, 0, 1, Ct);
            Assert.True(image.IsSuccess);
            var borrowed = invocation.ReadImageTileAsync(image.Value, 0, 0, 1, 1, Ct).AsTask();
            await profile.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5), Ct);
            using var caller = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            var queued = invocation.GetImageInfoAsync(image.Value, caller.Token).AsTask();
            await caller.CancelAsync();
            var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await queued.WaitAsync(TimeSpan.FromSeconds(8), Ct));
            Assert.Equal(caller.Token, error.CancellationToken);
            Assert.Equal(LocalRpcBrokerSessionState.Cancelled, invocation.BrokerSession!.State);
            var ended = await borrowed.WaitAsync(TimeSpan.FromSeconds(8), Ct);
            Assert.False(ended.IsSuccess);
        }
        finally { _ = await invocation.CancelAsync(); }
    }

    private sealed class WaitingProfile : IContentParserProfile
    {
        internal TaskCompletionSource<bool> Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public string Id => "admission-wait-test";

        public IImageParser? CreateImageParser() => new WaitingImage(Entered);

        public IPdfParser? CreatePdfParser() => null;
    }

    private sealed class WaitingImage(TaskCompletionSource<bool> entered) : IImageParser
    {
        private readonly HostileImageParser _fixture = new();

        public SandboxImageInfo Open(ParserInput input, uint subimage, uint mip, uint outputFormat, ParserContext context) =>
            _fixture.Open(input, subimage, mip, outputFormat, context);

        public int ReadTile(SandboxRegion region, uint format, Span<byte> destination, ParserContext context)
        {
            _ = entered.TrySetResult(true);
            _ = context.Cancelled.WaitHandle.WaitOne(TimeSpan.FromSeconds(20));
            context.Cancelled.ThrowIfCancellationRequested();
            return _fixture.ReadTile(region, format, destination, context);
        }

        public void Dispose() => _fixture.Dispose();
    }
}
