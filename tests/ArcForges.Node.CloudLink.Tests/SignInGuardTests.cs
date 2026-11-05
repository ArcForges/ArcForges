// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// N2 interim review fixes FX-1, FX-2, FX-3 and sec N-2/N-4: the guards at the edges of a flow (a cancel or a sign-out racing a key
/// restart or a delivery, a failed adoption, a sign-out while the secret store cannot be read, late credentials while the next flow runs).
/// Each test ports a reviewer's probe and fails on 1483afb. MOCKED center (FakeCenter), MOCKED browser (ScriptedBrowser), MOCKED time
/// (ManualClock), ISOLATED store.
/// </summary>
public sealed class SignInGuardTests
{
    private const string Complete = "CompleteNodeSignIn";
    private const string Poll = "PollDeviceAuthorization";

    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ASignOutDuringACompletingBrowserFlowWhoseKeyIsRefusedCreatesNothing()
    {
        // sec B-1 probe ProbeSignOutDuringCompletingThenKeyRefusedDoesNotReopen.
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await SignInFlowTests.BeginAsync(link, SignInMethod.Browser)).Flow!;
        var key = link.Keys.Recorded()!.Fingerprint;
        var hold = new TaskCompletionSource();
        link.Center.Script(Complete, new FakeFault.Hold(hold));
        link.Center.Script(Complete, new FakeFault.Refusal(SignInFlowTests.Arc(ErrorCategory.Authentication, "credential_revoked")));
        await ScriptedBrowser.GetAsync(link.Center.ApproveFlow());
        await Eventually.TrueAsync(() => link.Center.CallsOf(Complete).Count == 1, "the Complete in flight");
        var worker = link.Service.SignIn.Worker!;

        // What AccountService.SignOut does first.
        link.Service.SignIn.CancelActive();
        hold.SetResult();
        await worker.WaitAsync(TimeSpan.FromSeconds(10), Cancel);
        Assert.Equal(SignInFlowState.Cancelled, link.Service.SignIn.Get(flow.FlowId)!.State);
        Assert.Single(link.Center.CallsOf("BeginNodeSignIn"));
        Assert.Single(link.Browser.Opened);
        Assert.Equal(key, link.Keys.Recorded()!.Fingerprint);
        Assert.False(link.Service.SignIn.Active);
        Assert.Equal(CloudLinkPhase.SignedOut, link.Service.Phase);
    }

    [Fact]
    public async Task ADeviceCancelWithAKeyRefusedPollInFlightStartsNothing()
    {
        // sec B-1 probe ProbeDeviceCancelThenKeyRefusedPollRestartsNothing.
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await SignInFlowTests.BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        var key = link.Keys.Recorded()!.Fingerprint;
        var hold = new TaskCompletionSource();
        link.Center.Script(Poll, new FakeFault.Hold(hold));
        link.Center.Script(Poll, new FakeFault.Refusal(SignInFlowTests.Arc(ErrorCategory.Authentication, "credential_revoked")));
        await SignInFlowTests.Advance(link, TimeSpan.FromSeconds(30), () => link.Center.CallsOf(Poll).Count == 1, "the poll in flight");
        var worker = link.Service.SignIn.Worker!;
        Assert.Equal(SignInFlowState.Cancelled, link.Service.SignIn.Cancel(flow.FlowId).Flow!.State);
        hold.SetResult();
        await worker.WaitAsync(TimeSpan.FromSeconds(10), Cancel);
        Assert.Single(link.Center.CallsOf("StartDeviceAuthorization"));
        Assert.Equal(key, link.Keys.Recorded()!.Fingerprint);
        Assert.Equal(SignInFlowState.Cancelled, link.Service.SignIn.Get(flow.FlowId)!.State);
        Assert.Equal(CloudLinkPhase.SignedOut, link.Service.Phase);
    }

    [Fact]
    public async Task ASignOutDuringCompletingWhoseCompleteSucceedsRevokesTheCredentialsAndStoresNothing()
    {
        // sec B-1 test gap (mutation S4): the sign-out's mark keeps the delivered credentials out, under the link's gate.
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await SignInFlowTests.BeginAsync(link, SignInMethod.Browser)).Flow!;
        var hold = new TaskCompletionSource();
        link.Center.Script(Complete, new FakeFault.Hold(hold));
        await ScriptedBrowser.GetAsync(link.Center.ApproveFlow());
        await Eventually.TrueAsync(() => link.Center.CallsOf(Complete).Count == 1, "the Complete in flight");
        var worker = link.Service.SignIn.Worker!;
        link.Service.SignIn.CancelActive();
        hold.SetResult();
        await worker.WaitAsync(TimeSpan.FromSeconds(10), Cancel);
        var ended = link.Service.SignIn.Get(flow.FlowId)!;
        Assert.Equal(SignInFlowState.Cancelled, ended.State);
        Assert.Null(ended.Error);
        Assert.False(link.Service.AccountLinked);
        Assert.Null(link.StoredRecord());
        Assert.False(File.Exists(link.Storage.LinkPath));
        Assert.Single(link.Center.CallsOf("SignOutNode"));
        Assert.False(link.Center.IsLive(link.Center.LatestDelivered!));
    }

    [Fact]
    public async Task AnUnconfirmedRevocationOfDeliveredCredentialsIsInTheFlowsError()
    {
        // sec N-5: the flow says the delivered session may stay live at the center.
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await SignInFlowTests.BeginAsync(link, SignInMethod.Browser)).Flow!;
        var hold = new TaskCompletionSource();
        link.Center.Script(Complete, new FakeFault.Hold(hold));
        link.Center.Script("SignOutNode", new FakeFault.HttpStatus(503));
        await ScriptedBrowser.GetAsync(link.Center.ApproveFlow());
        await Eventually.TrueAsync(() => link.Center.CallsOf(Complete).Count == 1, "the Complete in flight");
        var worker = link.Service.SignIn.Worker!;
        link.Service.SignIn.CancelActive();
        hold.SetResult();
        await worker.WaitAsync(TimeSpan.FromSeconds(30), Cancel);
        var ended = link.Service.SignIn.Get(flow.FlowId)!;
        Assert.Equal(SignInFlowState.Cancelled, ended.State);
        Assert.Equal("cancelled: revocation_unconfirmed", ended.Error.Details.State.Reason);
        Assert.Null(link.StoredRecord());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AnAdoptionThatFailsAfterItsRecordWasWrittenIsUndoneTwoPhase(bool restart)
    {
        // sec B-2 probe ProbeAnAdoptionThatFailsAfterTheRecordWasWritten: a directory at the key-set path fails the adoption after the
        // committing link and the record were written.
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        Directory.CreateDirectory(link.Storage.KeysPath);
        var flow = (await SignInFlowTests.BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        link.Center.ApproveDevice();
        await SignInFlowTests.Advance(link, TimeSpan.FromSeconds(120),
            () => link.Service.SignIn.Get(flow.FlowId)!.State == SignInFlowState.Failed, "failed");
        Assert.Equal("credential_storage_failed", link.Service.SignIn.Get(flow.FlowId)!.Error.Details.State.Reason);
        Assert.False(link.Center.IsLive(link.Center.LatestDelivered!));
        Assert.False(File.Exists(link.Storage.LinkPath));
        Assert.Empty(link.Secrets.Names());
        Assert.False(link.Service.AccountLinked);
        Assert.Equal(CloudLinkPhase.SignedOut, link.Service.Phase);
        Assert.DoesNotContain("credential_store_unavailable", link.Service.Status().Warnings);
        Directory.Delete(link.Storage.KeysPath);
        if (restart)
        {
            await link.StopAsync();
            await link.StartAsync();
            Assert.False(link.Service.AccountLinked);
            Assert.False(File.Exists(link.Storage.LinkPath));
            Assert.Empty(link.Secrets.Names());
        }

        // A later sign-in works (without a restart too).
        var again = (await SignInFlowTests.BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        link.Center.ApproveDevice();
        await SignInFlowTests.Advance(link, TimeSpan.FromSeconds(120),
            () => link.Service.SignIn.Get(again.FlowId)!.State == SignInFlowState.SignedIn, "signed in");
        Assert.True(link.Service.AccountLinked);
        Assert.Equal(link.Center.LatestDelivered, link.StoredRecord()!.RefreshToken);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ASignOutWhileTheSecretStoreCannotBeReadRefusesAndChangesNothing(bool revokeRemote)
    {
        // sec B-3 probe ProbeSignOutWithALockedSecretStore (R-3: refuses and deletes nothing).
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var issued = await link.SignInAsync();
        using (link.Keys.Create(link.NodeId, link.Center.Endpoint.Origin, link.Clock))
        {
        }

        await link.StopAsync();
        link.Secrets.Unavailable = true;
        await link.StartAsync();
        Assert.Contains("credential_store_unavailable", link.Service.Status().Warnings);
        var linkBytes = PrivateFiles.ReadOrNull(link.Storage.LinkPath)!;
        SignOutResult result;
        using (await link.Service.EnterForSignOutAsync(TimeSpan.FromSeconds(5), Cancel))
        {
            result = await link.Service.SignOutHeldAsync(revokeRemote);
        }

        Assert.Equal(SignOutResult.StoreUnavailable, result);
        Assert.Equal(linkBytes, PrivateFiles.ReadOrNull(link.Storage.LinkPath)!);
        Assert.True(File.Exists(link.Storage.KeysPath));
        Assert.NotNull(link.Keys.Recorded());
        Assert.Empty(link.Center.CallsOf("SignOutNode"));

        // When the store is back, the sign-out can be honest: the credential is revoked at its center.
        link.Secrets.Unavailable = false;
        await link.StopAsync();
        await link.StartAsync();
        Assert.True(link.Service.AccountLinked);
        Assert.Equal(issued.RefreshToken, link.StoredRecord()!.RefreshToken);
        using (await link.Service.EnterForSignOutAsync(TimeSpan.FromSeconds(5), Cancel))
        {
            Assert.Equal(SignOutResult.RemoteConfirmed, await link.Service.SignOutHeldAsync(revokeRemote: true));
        }

        Assert.False(link.Center.IsLive(issued.RefreshToken));
    }

    [Fact]
    public async Task TheSignOutApiRefusesWhileTheSecretStoreCannotBeRead()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        await node.StartAsync();
        var issued = center.Issue(node.Runtime.NodeId.Span);
        await node.Cloud.AdoptAsync(issued, center.Endpoint);
        await node.StopAsync();
        node.Secrets.Unavailable = true;
        await node.StartAsync();
        var linkBytes = PrivateFiles.ReadOrNull(node.Cloud.Storage.LinkPath)!;
        await using var human = await node.ChannelAsync(Origin.Human);
        foreach (var remote in new[] { true, false })
        {
            var response = await human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = CloudNode.Command(), RevokeRemote = remote }, cancellationToken: Cancel);
            Assert.Equal(ErrorCategory.State, response.Error.Category);
            Assert.Equal("invalid_state", response.Error.Code);
            Assert.Equal("signed_out", response.Error.Details.State.State);
            Assert.Equal("credential_store_unavailable", response.Error.Details.State.Reason);
        }

        Assert.Equal(linkBytes, PrivateFiles.ReadOrNull(node.Cloud.Storage.LinkPath)!);
        Assert.Empty(center.CallsOf("SignOutNode"));
        Assert.True(center.IsLive(issued.RefreshToken));
    }

    [Fact]
    public async Task ACenterChangedBeforeCompleteSendsNoComplete()
    {
        // sec N-2 (S7): the re-check before CompleteNodeSignIn, for the browser flow.
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await SignInFlowTests.BeginAsync(link, SignInMethod.Browser)).Flow!;
        Assert.True(CenterEndpoint.TryParse("https://other.example.test/api", out var other, out _));
        link.ConfiguredCenter = other;
        await ScriptedBrowser.GetAsync(link.Center.ApproveFlow());
        await Eventually.TrueAsync(() => link.Service.SignIn.Get(flow.FlowId)!.State == SignInFlowState.Failed, "failed");
        Assert.Equal("center_url", link.Service.SignIn.Get(flow.FlowId)!.Error.Details.State.Reason);
        Assert.Empty(link.Center.CallsOf(Complete));
    }

    [Fact]
    public async Task ACentersRefusalTextBecomesTheNodesOwnErrorOnlyInATokensShape()
    {
        // sec N-1: the node repeats a center's reason or code in BeginSignIn's error only when it has a token's shape.
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var hostile = SignInFlowTests.Arc(ErrorCategory.Validation, "invalid_argument");
        hostile.Details = new ErrorDetails { State = new StateFailure { Reason = "\u001b]0;owned\u0007\nopen https://evil.example" } };
        link.Center.Script("BeginNodeSignIn", new FakeFault.Refusal(hostile));
        var refused = await SignInFlowTests.BeginAsync(link, SignInMethod.Browser);
        Assert.Equal("center_refused", refused.Error!.Details.State.State);
        Assert.Equal("invalid_argument", refused.Error.Details.State.Reason);
        var foreign = SignInFlowTests.Arc(ErrorCategory.Resource, "\u001b[2J");
        link.Center.Script("BeginNodeSignIn", new FakeFault.Refusal(foreign));
        Assert.Equal("resource/refused", (await SignInFlowTests.BeginAsync(link, SignInMethod.Browser)).Error!.Details.State.Reason);
        Assert.Equal("node_key: already_registered", SignInOrchestrator.Token("node_key: already_registered"));
        Assert.Null(SignInOrchestrator.Token("A\u0007"));
    }

    [Fact]
    public async Task ASignOutDuringTheRestartsBeginEndsTheFlowDeletesItsNewKeyAndOpensNothing()
    {
        // N2 confirmation N-1 (probe ProbeSignOutDuringTheRestartsBeginLeavesNoKeyAndOpensNothing): the re-check after the restart's call.
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await SignInFlowTests.BeginAsync(link, SignInMethod.Browser)).Flow!;
        var key = link.Keys.Recorded()!.Fingerprint;
        var hold = new TaskCompletionSource();
        link.Center.Script(Complete, new FakeFault.Refusal(SignInFlowTests.Arc(ErrorCategory.Authentication, "credential_revoked")));
        link.Center.Script("BeginNodeSignIn", new FakeFault.Hold(hold));
        await ScriptedBrowser.GetAsync(link.Center.ApproveFlow());
        await Eventually.TrueAsync(() => link.Center.CallsOf("BeginNodeSignIn").Count == 2, "the restart's Begin in flight");
        var worker = link.Service.SignIn.Worker!;
        Assert.NotEqual(key, link.Keys.Recorded()!.Fingerprint);
        link.Service.SignIn.CancelActive();
        hold.SetResult();
        await worker.WaitAsync(TimeSpan.FromSeconds(10), Cancel);
        Assert.Equal(SignInFlowState.Cancelled, link.Service.SignIn.Get(flow.FlowId)!.State);
        Assert.Single(link.Browser.Opened);
        Assert.Null(link.Keys.Recorded());
        Assert.False(link.Service.SignIn.Active);
        Assert.Equal(CloudLinkPhase.SignedOut, link.Service.Phase);
    }

    [Fact]
    public async Task ADeviceCancelDuringTheRestartsStartDeletesItsNewKeyAndPollsNoMore()
    {
        // N2 confirmation N-1 (probe ProbeDeviceCancelDuringTheRestartsStartLeavesNoKeyAndPollsNoMore) and N-4 (no code of the restart shown).
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await SignInFlowTests.BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        var hold = new TaskCompletionSource();
        link.Center.Script(Poll, new FakeFault.Refusal(SignInFlowTests.Arc(ErrorCategory.Authentication, "credential_revoked")));
        link.Center.Script("StartDeviceAuthorization", new FakeFault.Hold(hold));
        await SignInFlowTests.Advance(link, TimeSpan.FromSeconds(30), () => link.Center.CallsOf("StartDeviceAuthorization").Count == 2, "the restart's Start in flight");
        var worker = link.Service.SignIn.Worker!;
        Assert.Equal(SignInFlowState.Cancelled, link.Service.SignIn.Cancel(flow.FlowId).Flow!.State);
        hold.SetResult();
        await worker.WaitAsync(TimeSpan.FromSeconds(10), Cancel);
        link.Clock.Advance(TimeSpan.FromMinutes(2));
        await Task.Delay(100, Cancel);
        Assert.Single(link.Center.CallsOf(Poll));
        Assert.Null(link.Keys.Recorded());
        var ended = link.Service.SignIn.Get(flow.FlowId)!;
        Assert.Equal(SignInFlowState.Cancelled, ended.State);
        Assert.False(ended.HasUserCode);
    }

    [Fact]
    public async Task AnEndedFlowIsReadBackWithoutItsUrlsOrUserCode()
    {
        // N2 confirmation C1-4 (R-4): the center's flow ID (inside authorize_url) and the user code only while the flow runs.
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var browser = (await SignInFlowTests.BeginAsync(link, SignInMethod.Browser)).Flow!;
        Assert.True(browser.HasAuthorizeUrl);
        var cancelled = link.Service.SignIn.Cancel(browser.FlowId).Flow!;
        foreach (var flow in new[] { cancelled, link.Service.SignIn.Get(browser.FlowId)! })
        {
            Assert.Equal(SignInFlowState.Cancelled, flow.State);
            Assert.False(flow.HasAuthorizeUrl);
            Assert.Equal(browser.NodeKeyFingerprint, flow.NodeKeyFingerprint);
        }

        var device = (await SignInFlowTests.BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        Assert.True(device.HasUserCode);
        link.Center.DenyDevice();
        await SignInFlowTests.Advance(link, TimeSpan.FromSeconds(30), () => link.Service.SignIn.Get(device.FlowId)!.State == SignInFlowState.Denied, "denied");
        var denied = link.Service.SignIn.Get(device.FlowId)!;
        Assert.False(denied.HasUserCode || denied.HasVerificationUri || denied.HasVerificationUriComplete || denied.HasQrPayload);
    }

    [Fact]
    public async Task UnconfirmedRevocationsOfLateOrMisshapenCredentialsAreInTheFlowsError()
    {
        // N2 confirmation C1-4 (N-5 on every path): late credentials of a cancelled device flow, and credentials of the wrong shape.
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var late = (await SignInFlowTests.BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        link.Center.ApproveDevice();
        var hold = new TaskCompletionSource();
        link.Center.Script(Poll, new FakeFault.Hold(hold));
        link.Center.Script("SignOutNode", new FakeFault.HttpStatus(503));
        await SignInFlowTests.Advance(link, TimeSpan.FromSeconds(30), () => link.Center.CallsOf(Poll).Count == 1, "the poll in flight");
        var worker = link.Service.SignIn.Worker!;
        Assert.Null(link.Service.SignIn.Cancel(late.FlowId).Flow!.Error);
        hold.SetResult();
        await worker.WaitAsync(TimeSpan.FromSeconds(30), Cancel);
        var ended = link.Service.SignIn.Get(late.FlowId)!;
        Assert.Equal(SignInFlowState.Cancelled, ended.State);
        Assert.Equal("cancelled: revocation_unconfirmed", ended.Error.Details.State.Reason);

        var misshapen = (await SignInFlowTests.BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        var approved = new NodeEnrollmentServicePollDeviceAuthorizationResponse
        {
            Meta = new ResponseMeta(),
            Value = new NodeEnrollmentServicePollDeviceAuthorizationValue
            {
                State = DeviceAuthorizationState.Approved,
                IntervalMs = 5000,
                Credentials = new NodeCredentials { AccessToken = "afa1.misshapen" },
            },
        };
        link.Center.Script(Poll, new FakeFault.Raw([.. FakeCenter.DataFrame(approved), .. FakeCenter.TrailerFrame(0, null)]));
        link.Center.Script("SignOutNode", new FakeFault.HttpStatus(503));
        await SignInFlowTests.Advance(link, TimeSpan.FromSeconds(30), () => link.Service.SignIn.Get(misshapen.FlowId)!.State == SignInFlowState.Failed, "failed");
        Assert.Equal("credentials: shape: revocation_unconfirmed", link.Service.SignIn.Get(misshapen.FlowId)!.Error.Details.State.Reason);
        Assert.Null(link.StoredRecord());
    }

    [Fact]
    public async Task LateCredentialsWhoseNewerFlowAlreadyEndedDeleteTheKey()
    {
        // N2 confirmation N-3: the key is kept only while a NEWER flow is ACTIVE.
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var first = (await SignInFlowTests.BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        link.Center.ApproveDevice();
        var hold = new TaskCompletionSource();
        link.Center.Script(Poll, new FakeFault.Hold(hold));
        await SignInFlowTests.Advance(link, TimeSpan.FromSeconds(30), () => link.Center.CallsOf(Poll).Count == 1, "the poll in flight");
        var worker = link.Service.SignIn.Worker!;
        link.Service.SignIn.Cancel(first.FlowId);
        var second = (await SignInFlowTests.BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        link.Service.SignIn.Cancel(second.FlowId);
        hold.SetResult();
        await worker.WaitAsync(TimeSpan.FromSeconds(10), Cancel);
        Assert.Single(link.Center.CallsOf("SignOutNode"));
        Assert.Null(link.Keys.Recorded());
    }

    [Fact]
    public async Task WhoeverSeesAFlowEndedSeesTheLinksOwnPhase()
    {
        // The Windows leg's ABrowserFlowExpiresAfterTenMinutes: the flow read EXPIRED while the link still said SigningIn, because the flow's
        // end and the release of the link's reservation were two steps (the receiver's stop between them). A reader spins on the flow while
        // the flow ends; the first time it sees the end, the phase must already be the link's own.
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var seen = new List<CloudLinkPhase>();
        for (var round = 0; round < 50; round++)
        {
            var flow = (await SignInFlowTests.BeginAsync(link, SignInMethod.Browser)).Flow!;
            using var started = new SemaphoreSlim(0);
            var reader = Task.Run(() =>
            {
                started.Release();
                var deadline = System.Diagnostics.Stopwatch.StartNew();
                while (deadline.Elapsed < TimeSpan.FromSeconds(10))
                {
                    if (link.Service.SignIn.Get(flow.FlowId)!.State != SignInFlowState.Pending)
                    {
                        return link.Service.Phase;
                    }
                }

                return (CloudLinkPhase?)null;
            }, Cancel);
            await started.WaitAsync(Cancel);
            link.Service.SignIn.Cancel(flow.FlowId);
            var phase = await reader.WaitAsync(TimeSpan.FromSeconds(20), Cancel);
            Assert.True(phase is not null, "round " + round + ": the reader never saw the flow end within 10 s");
            seen.Add(phase.Value);
        }

        Assert.All(seen, phase => Assert.Equal(CloudLinkPhase.SignedOut, phase));
    }

    [Fact]
    public async Task AFlowBegunRightAfterAnotherEndedKeepsItsReservationAndTheHeldProbePaused()
    {
        // PR #71 review B-1: the ending flow released the reservation a second time after its lock, so a BeginSignIn in that gap lost its
        // reservation (the phase read SignedOut and the probe of a held rejected credential resumed during the new flow; N2 R-2, F-1).
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        link.Center.Script("RefreshNodeSession", new FakeFault.Refusal(SignInFlowTests.Arc(ErrorCategory.Authentication, "unauthenticated")));
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(45),
            () => link.Service.Status().Warnings.Contains("center_rejected_credential"), "the rejection");

        // The held credential's probe is due 50 to 60 minutes after the rejection (at least 49 minutes from here).
        var rejected = link.Clock.GetTimestamp();
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(49),
            () => link.Clock.GetElapsedTime(rejected) >= TimeSpan.FromMinutes(48.5), "48.5 minutes after the rejection");
        var refreshes = link.Center.CallsOf("RefreshNodeSession").Count;

        var first = (await SignInFlowTests.BeginAsync(link, SignInMethod.Browser)).Flow!;
        SignInReply? next = null;
        link.Service.SignIn.AfterEnd = () =>
        {
            // In the gap between the first flow's end and the rest of its ending: the new flow reserves.
            link.Service.SignIn.AfterEnd = null;
            next = SignInFlowTests.BeginAsync(link, SignInMethod.DeviceCode).GetAwaiter().GetResult();
        };
        Assert.Equal(SignInFlowState.Cancelled, link.Service.SignIn.Cancel(first.FlowId).Flow!.State);
        Assert.NotNull(next?.Flow);
        Assert.Equal(SignInFlowState.Pending, next.Flow.State);
        Assert.Equal(CloudLinkPhase.SigningIn, link.Service.Phase);

        // Through the new flow's whole life (its hard stop, past the probe's due time) the probe stays paused; it runs once the flow ended.
        // The count is read before the state, so a count seen with the flow still pending was the count while it was pending.
        var whilePending = refreshes;
        await SignInFlowTests.Advance(link, TimeSpan.FromSeconds(700), () =>
        {
            var count = link.Center.CallsOf("RefreshNodeSession").Count;
            if (link.Service.SignIn.Get(next.Flow.FlowId)!.State == SignInFlowState.Pending)
            {
                whilePending = Math.Max(whilePending, count);
                return false;
            }

            return true;
        }, "the new flow's end");
        Assert.Equal(refreshes, whilePending);
        Assert.Equal(SignInFlowState.Expired, link.Service.SignIn.Get(next.Flow.FlowId)!.State);
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(15),
            () => link.Center.CallsOf("RefreshNodeSession").Count > refreshes, "the probe after the flow");
    }

    [Fact]
    public async Task AnEndedFlowsLateWorkNeverHidesTheNextFlowsClockWait()
    {
        // The Linux leg at 16a663f (the B-1 test above, in the ci run): the first flow's background work started only after it had been
        // cancelled and the next flow had begun; its late, immediately ended wait cleared the one shared record of a clock wait, so the
        // next flow, blocked on the clock, looked as if it were not waiting. Each flow now records its own wait; this holds the first flow's
        // work until the next flow waits.
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var hold = new TaskCompletionSource();
        var works = 0;
        link.Service.SignIn.BeforeWork = _ => Interlocked.Increment(ref works) == 1 ? hold.Task : null;
        var first = (await SignInFlowTests.BeginAsync(link, SignInMethod.Browser)).Flow!;
        var lateWork = link.Service.SignIn.Worker!;
        Assert.Equal(SignInFlowState.Cancelled, link.Service.SignIn.Cancel(first.FlowId).Flow!.State);
        var next = (await SignInFlowTests.BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        await Eventually.TrueAsync(() => link.Service.SignIn.ClockWait.Blocked, "the next flow waits on the clock");

        hold.SetResult();
        await lateWork.WaitAsync(TimeSpan.FromSeconds(10), Cancel);
        Assert.True(link.Service.SignIn.ClockWait.Blocked, "the next flow's wait is hidden");
        Assert.Equal(SignInFlowState.Pending, link.Service.SignIn.Get(next.FlowId)!.State);
        await SignInFlowTests.Advance(link, TimeSpan.FromSeconds(30), () => link.Center.CallsOf(Poll).Count >= 1, "the next flow's first poll");
    }

    [Fact]
    public async Task LateCredentialsOfACancelledFlowKeepTheKeyOfTheNextFlow()
    {
        // sec N-4 probe ProbeLateCredentialsOfACancelledFlowDeleteTheKeyOfTheNextFlow.
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var first = (await SignInFlowTests.BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        link.Center.ApproveDevice();
        var hold = new TaskCompletionSource();
        link.Center.Script(Poll, new FakeFault.Hold(hold));
        await SignInFlowTests.Advance(link, TimeSpan.FromSeconds(30), () => link.Center.CallsOf(Poll).Count == 1, "the poll in flight");
        var worker = link.Service.SignIn.Worker!;
        Assert.Equal(SignInFlowState.Cancelled, link.Service.SignIn.Cancel(first.FlowId).Flow!.State);
        var second = (await SignInFlowTests.BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        Assert.Equal(SignInFlowState.Pending, second.State);
        hold.SetResult();
        await worker.WaitAsync(TimeSpan.FromSeconds(10), Cancel);
        Assert.Single(link.Center.CallsOf("SignOutNode"));
        Assert.False(link.Center.IsLive(link.Center.LatestDelivered!));
        Assert.Equal(second.NodeKeyFingerprint, link.Keys.Recorded()!.Fingerprint);
        Assert.NotNull(link.Keys.Load(link.NodeId, link.Center.Endpoint.Origin));
        Assert.True(link.Service.SignIn.Active);
    }
}
