// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// AF-CTR-05 part N2b at the channel (the HARD item of N1 review A C-N1 and B N-12; decisions B-3): after verification, which may wait on a
/// key refresh, and immediately before the dispatch, the link is read again, and a link switched off or a session ending drops the call; the
/// dispatcher is told when the node's stop began; its answers are signed with their closed fields and logged with their codes.
/// </summary>
public sealed class RoutedChannelTests
{
    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("verified")]
    [InlineData("dispatch")]
    public async Task ACallIsNotDispatchedOnceTheLinkIsSwitchedOffBeforeItsDispatch(string step)
    {
        var dispatcher = new Recording();
        LinkFixture? fixture = null;
        var flipped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var (link, connection) = await ChannelTests.ConnectedAsync(configured =>
        {
            fixture = configured;
            configured.Dispatcher = dispatcher;
            configured.StepHook = async at =>
            {
                if (at == step && !flipped.Task.IsCompleted)
                {
                    Assert.True(await fixture!.Service.SetCloudLinkAsync(false));
                    flipped.TrySetResult();
                }
            };
        });
        await using (link)
        {
            var (call, _) = link.Center.Channel.BuildCall(connection, new FakeCallSpec { Method = RoutedMethod.GetNodeTask });
            await connection.SendCallAsync(call);
            await flipped.Task.WaitAsync(TimeSpan.FromSeconds(15), Cancel);
            await connection.Done.WaitAsync(TimeSpan.FromSeconds(10), Cancel);

            // Verified and logged pending, never dispatched, never answered (N1-15's rule: nothing else happens).
            Assert.Equal(0, dispatcher.Calls);
            Assert.Empty(connection.VerifiedResults);
            Assert.Equal((5L, (string?)null, (string?)null, true), Assert.Single(link.RoutedLog()));
        }
    }

    [Fact(Timeout = 30_000)]
    public async Task SessionEndingSignalsFileEffectsBeforeWaitingForTheCloseFrame()
    {
        var ct = TestContext.Current.CancellationToken;
        var dispatcher = new EndingProbe();
        var (link, connection) = await ChannelTests.ConnectedAsync(configured => configured.Dispatcher = dispatcher);
        await using (link)
        {
            var (call, _) = link.Center.Channel.BuildCall(connection, new FakeCallSpec { Method = RoutedMethod.GetNodeTask });
            await connection.SendCallAsync(call);
            await dispatcher.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
            Assert.True(await link.Service.SetCloudLinkAsync(false));
            var observation = await dispatcher.Signaled.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
            Assert.False(observation.Usable);
            Assert.False(observation.SessionCanceled); // Ending signals synchronously before the ordinary close/cancel path.
            await connection.Done.WaitAsync(TimeSpan.FromSeconds(10), ct);
            Assert.Empty(connection.VerifiedResults);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AKeyRefreshInFlightCannotDispatchAfterTheLinkIsSwitchedOff(bool switchOff)
    {
        var dispatcher = new Recording();
        var releaseVerified = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var (link, connection) = await ChannelTests.ConnectedAsync(configured =>
        {
            configured.Dispatcher = dispatcher;
            configured.StepHook = async at =>
            {
                if (switchOff && at == "verified")
                {
                    await releaseVerified.Task;
                }
            };
        });
        await using (link)
        {
            // Sign-in had only the original key. This valid newly named key is delivered by the held refresh, so the
            // control proves that the very same kind of call can really pass verification and reach the dispatcher.
            var rotated = link.Center.Channel.CommandPublicKey;
            rotated.Kid = "cmd-rotated-0002";
            link.Center.CommandKeys.Add(rotated);
            var releaseRefresh = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            link.Center.Script("RefreshNodeSession", new FakeFault.Hold(releaseRefresh));
            try
            {
                var (call, _) = link.Center.Channel.BuildCall(connection, new FakeCallSpec
                {
                    Method = RoutedMethod.GetNodeTask,
                    FrameKid = rotated.Kid,
                    HeaderKid = rotated.Kid,
                });
                await connection.SendCallAsync(call);
                await Eventually.TrueAsync(() => link.Center.CallsOf("RefreshNodeSession").Count == 1, "call verification holds the key refresh");

                // Refresh and SetCloudLink take the same gate: a switch requested while the network refresh is held
                // queues until that refresh finishes. If verification wins that race, pause it at the verified hook.
                Task<bool>? switching = null;
                if (switchOff)
                {
                    switching = link.Service.SetCloudLinkAsync(false);
                    Assert.False(switching.IsCompleted);
                }

                releaseRefresh.TrySetResult();
                if (switchOff)
                {
                    Assert.True(await switching!.WaitAsync(TimeSpan.FromSeconds(15), Cancel));
                    releaseVerified.TrySetResult();
                    await Eventually.TrueAsync(() => link.Service.Status().Relay == RelayState.Disabled, "disabled channel drained its in-flight call");
                    Assert.Equal(0, dispatcher.Calls);
                    Assert.Empty(connection.VerifiedResults);
                }
                else
                {
                    await connection.ResultOfAsync(call.CallId);
                    Assert.Equal(1, dispatcher.Calls);
                }
            }
            finally
            {
                releaseRefresh.TrySetResult();
                releaseVerified.TrySetResult();
            }
        }
    }

    [Fact]
    public async Task AVerificationRefusalIsNotSentAfterTheLinkIsSwitchedOffDuringKeyRefresh()
    {
        var dispatcher = new Recording();
        var refreshed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var refusalAttempts = 0;
        var (link, connection) = await ChannelTests.ConnectedAsync(configured =>
        {
            configured.Dispatcher = dispatcher;
            configured.StepHook = async at =>
            {
                if (at == "refresh.completed")
                {
                    refreshed.TrySetResult();
                    await resume.Task;
                }
                else if (at == "refusal.send")
                {
                    Interlocked.Increment(ref refusalAttempts);
                }
            };
        });
        await using (link)
        {
            var rotated = link.Center.Channel.CommandPublicKey;
            rotated.Kid = "cmd-rotated-0002";
            link.Center.CommandKeys.Add(rotated);
            var releaseRefresh = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            link.Center.Script("RefreshNodeSession", new FakeFault.Hold(releaseRefresh));
            try
            {
                var (call, _) = link.Center.Channel.BuildCall(connection, new FakeCallSpec
                {
                    Method = RoutedMethod.GetNodeTask,
                    FrameKid = rotated.Kid,
                    HeaderKid = rotated.Kid,
                });
                await connection.SendCallAsync(call);
                await Eventually.TrueAsync(() => link.Center.CallsOf("RefreshNodeSession").Count == 1, "the key refresh is held");
                var switching = link.Service.SetCloudLinkAsync(false);
                Assert.False(switching.IsCompleted);
                releaseRefresh.TrySetResult();
                await refreshed.Task.WaitAsync(TimeSpan.FromSeconds(15), Cancel);
                Assert.True(await switching.WaitAsync(TimeSpan.FromSeconds(15), Cancel));
                Assert.Null(((IChannelHost)link.Service).Binding());
                resume.TrySetResult();
                await connection.Done.WaitAsync(TimeSpan.FromSeconds(15), Cancel);

                Assert.Equal(0, dispatcher.Calls);
                Assert.Empty(connection.VerifiedResults);
                Assert.Equal(0, Volatile.Read(ref refusalAttempts));
            }
            finally
            {
                releaseRefresh.TrySetResult();
                resume.TrySetResult();
            }
        }
    }

    [Fact]
    public async Task AVerificationRefusalIsNotSentIfTheLinkIsSwitchedOffImmediatelyBeforeTheSend()
    {
        var dispatcher = new Recording();
        LinkFixture? fixture = null;
        var switched = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var (link, connection) = await ChannelTests.ConnectedAsync(configured =>
        {
            fixture = configured;
            configured.Dispatcher = dispatcher;
            configured.StepHook = async at =>
            {
                if (at == "refusal.send")
                {
                    Assert.True(await fixture!.Service.SetCloudLinkAsync(false));
                    switched.TrySetResult();
                }
            };
        });
        await using (link)
        {
            var (call, _) = link.Center.Channel.BuildCall(connection, new FakeCallSpec
            {
                Method = RoutedMethod.GetNodeTask,
                TargetNodeId = CommandIds.New().Value.ToByteArray(),
            });
            await connection.SendCallAsync(call);
            await switched.Task.WaitAsync(TimeSpan.FromSeconds(15), Cancel);
            await connection.Done.WaitAsync(TimeSpan.FromSeconds(15), Cancel);
            Assert.Equal(0, dispatcher.Calls);
            Assert.Empty(connection.VerifiedResults);
        }
    }

    [Fact]
    public async Task ThereIsNoBindingWhileTheLinkIsOff()
    {
        // N1 review A C-N1: Binding() is null while the cloud link is off (and after a sign-out), so a call in the close window is dropped
        // unverified; the hook tests above show the drop of a call already verified.
        var (link, _) = await ChannelTests.ConnectedAsync(configured => configured.Dispatcher = new Recording());
        await using (link)
        {
            Assert.NotNull(((IChannelHost)link.Service).Binding());
            Assert.True(await link.Service.SetCloudLinkAsync(false));
            Assert.Null(((IChannelHost)link.Service).Binding());
            Assert.True(await link.Service.SetCloudLinkAsync(true));
            Assert.NotNull(((IChannelHost)link.Service).Binding());
            Assert.False(((IChannelHost)link.Service).Stopping);
            link.Service.BeginStop(TimeSpan.FromSeconds(10));
            Assert.True(((IChannelHost)link.Service).Stopping);
        }
    }

    [Fact]
    public async Task TheDispatcherIsToldTheStopBeganAndItsAnswersAreSignedAndLoggedWithTheirCodes()
    {
        var dispatcher = new Recording
        {
            Answer = call => call.Header.Method == RoutedMethod.CancelNodeTask
                ? new RoutedAnswer(RoutedOutcome.RefusedByPolicy, null, RoutedRefusals.ApprovalRequired("task.cancel_others", CommandIds.New(), CommandIds.New()), null, 2)
                : new RoutedAnswer(RoutedOutcome.Executed,
                    new TaskServiceGetTaskResponse { Error = NodeErrorsForTest.InvalidArgument() }.ToByteString(), null, null, 1, "VALIDATION/invalid_argument"),
        };
        var (link, connection) = await ChannelTests.ConnectedAsync(configured => configured.Dispatcher = dispatcher);
        await using (link)
        {
            var (get, _) = link.Center.Channel.BuildCall(connection, new FakeCallSpec { Method = RoutedMethod.GetNodeTask });
            await connection.SendCallAsync(get);
            await connection.ResultOfAsync(get.CallId);
            Assert.False(dispatcher.LastStopping);

            var cancel = new TaskServiceCancelTaskRequest { Meta = new RequestMeta { CommandId = CommandIds.New() }, TaskId = CommandIds.New() };
            var (call, _) = link.Center.Channel.BuildCall(connection, new FakeCallSpec { Method = RoutedMethod.CancelNodeTask, Payload = cancel.ToByteArray() });
            link.Service.BeginStop(TimeSpan.FromSeconds(10));
            await connection.SendCallAsync(call);
            await connection.ResultOfAsync(call.CallId);
            Assert.True(dispatcher.LastStopping);

            await Eventually.TrueAsync(() => connection.VerifiedResults.Count == 2, "both results verified at the peer");
            var refused = connection.VerifiedResults.Single(result => result.Header.Method == RoutedMethod.CancelNodeTask).Header;
            Assert.Equal(("approval_required", "approval"), (refused.Error.Code, refused.Error.Details.State.Resource.Kind));
            Assert.Equal(new List<(long, string?, string?, bool)> { (1L, null, "VALIDATION/invalid_argument", true), (2L, null, "AUTHORIZATION/approval_required", true) },
                link.RoutedLog());
        }
    }

    private sealed class EndingProbe : IRoutedDispatcher
    {
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<(bool Usable, bool SessionCanceled)> Signaled { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<RoutedAnswer?> DispatchAsync(VerifiedCall call, IRoutedLink link, CancellationToken cancellationToken)
        {
            using var registration = link.EffectEnding.Register(() =>
                Signaled.TrySetResult((link.Usable, cancellationToken.IsCancellationRequested)));
            Entered.TrySetResult();
            await Signaled.Task.ConfigureAwait(false);
            return null;
        }
    }

    /// <summary>Records the calls it sees and the link's state at the dispatch.</summary>
    private sealed class Recording : IRoutedDispatcher
    {
        private int _calls;

        public Func<VerifiedCall, RoutedAnswer>? Answer { get; init; }

        public int Calls => Volatile.Read(ref _calls);

        public bool LastStopping { get; private set; }

        public Task<RoutedAnswer?> DispatchAsync(VerifiedCall call, IRoutedLink link, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            LastStopping = link.Stopping;
            return Answer is { } answer
                ? Task.FromResult<RoutedAnswer?>(answer(call))
                : new RefusingDispatcher(TimeProvider.System).DispatchAsync(call, link, cancellationToken);
        }
    }

    private static class NodeErrorsForTest
    {
        public static ArcError InvalidArgument() => ArcForges.Node.Core.NodeErrors.InvalidArgument("request: a test");
    }
}
