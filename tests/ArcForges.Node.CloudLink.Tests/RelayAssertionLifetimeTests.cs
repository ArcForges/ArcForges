// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>The N1 relay assertion API handles a lost session and caller cancellation distinctly.</summary>
public sealed class RelayAssertionLifetimeTests
{
    [Fact(Timeout = 30000)]
    public async Task ClosingTheChannelWhileWaitingForANonceReturnsUnavailable()
    {
        var (link, connection) = await ChannelTests.ConnectedAsync(fixture => fixture.Center.Channel.AnswerNonces = false);
        await using (link)
        {
            var signing = link.Service.SignRelayAssertionAsync(Origin.Script, CommandIds.New(), RoutedMethod.GetNodeTask,
                SHA256.HashData([1, 2, 3]), new Id { Value = ByteString.CopyFrom(link.NodeId) }, null, TestContext.Current.CancellationToken);
            await Eventually.TrueAsync(() => connection.Received.Any(frame => frame.FrameCase == RelayFrame.FrameOneofCase.RelayNonceRequest), "nonce requested");
            Assert.True(await link.Service.SetCloudLinkAsync(false));
            Assert.Null(await signing.WaitAsync(TimeSpan.FromSeconds(15), TestContext.Current.CancellationToken));
        }
    }

    [Fact(Timeout = 30000)]
    public async Task AClosingSessionRefusesBeforeSigningWorkStarts()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var (link, connection) = await ChannelTests.ConnectedAsync(fixture => fixture.StepHook = async step =>
        {
            if (step == "relay.before_register")
            {
                entered.TrySetResult();
                await release.Task;
            }
        });
        await using (link)
        {
            try
            {
                var signing = link.Service.SignRelayAssertionAsync(Origin.Script, CommandIds.New(), RoutedMethod.GetNodeTask,
                    SHA256.HashData([1, 2, 3]), new Id { Value = ByteString.CopyFrom(link.NodeId) }, null, TestContext.Current.CancellationToken);
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
                Assert.True(await link.Service.SetCloudLinkAsync(false));
                await connection.Done.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
                await Eventually.TrueAsync(() => link.Service.Status() is { Relay: RelayState.Disabled, RelayReason: ChannelReasons.LinkDisabled }, "the old session closed");
                release.TrySetResult();
                Assert.Null(await signing.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
                Assert.DoesNotContain(connection.Received, frame => frame.FrameCase == RelayFrame.FrameOneofCase.RelayNonceRequest);
            }
            finally
            {
                release.TrySetResult();
            }
        }
    }

    [Fact(Timeout = 30000)]
    public async Task CallerCancellationWhileWaitingForANonceStillPropagates()
    {
        var (link, connection) = await ChannelTests.ConnectedAsync(fixture => fixture.Center.Channel.AnswerNonces = false);
        await using (link)
        using (var cancelled = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken))
        {
            var signing = link.Service.SignRelayAssertionAsync(Origin.Script, CommandIds.New(), RoutedMethod.GetNodeTask,
                SHA256.HashData([1, 2, 3]), new Id { Value = ByteString.CopyFrom(link.NodeId) }, null, cancelled.Token);
            await Eventually.TrueAsync(() => connection.Received.Any(frame => frame.FrameCase == RelayFrame.FrameOneofCase.RelayNonceRequest), "nonce requested");
            await cancelled.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await signing);
        }
    }
}
