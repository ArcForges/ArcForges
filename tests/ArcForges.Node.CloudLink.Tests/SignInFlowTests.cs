// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Sockets;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// N2-3, N2-4, N2-5, N2-13: the browser and device-code sign-ins and their orchestration (CTR4-NODE-12/13/14/17 as amended; N2 decisions
/// R-2, F-1..F-21) over the real HTTP seam and the real loopback receiver. MOCKED center (FakeCenter, conformance-tested against the REAL
/// captures), MOCKED browser (ScriptedBrowser, the Plan's allowed fake), MOCKED time (ManualClock), ISOLATED store.
/// </summary>
public sealed class SignInFlowTests
{
    private const string Complete = "CompleteNodeSignIn";
    private const string Poll = "PollDeviceAuthorization";

    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ABrowserSignInSucceedsThroughTheRealReceiver()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var begun = await BeginAsync(link, SignInMethod.Browser);
        var flow = begun.Flow!;
        Assert.Equal(SignInFlowState.Pending, flow.State);
        Assert.Equal(SignInMethod.Browser, flow.Method);
        Assert.Equal(CloudLinkPhase.SigningIn, link.Service.Phase);
        Assert.StartsWith(link.Center.Endpoint.Url + "/connect#flow=", flow.AuthorizeUrl, StringComparison.Ordinal);
        Assert.Equal([flow.AuthorizeUrl], link.Browser.Opened);
        Assert.Equal(CloudIdentity.Fingerprint(link.Keys.Load(link.NodeId, link.Center.Endpoint.Origin)!.PublicKey), flow.NodeKeyFingerprint);

        // The node-local flow ID is not the center's (the center's is only inside authorize_url).
        Assert.DoesNotContain(Convert.ToHexStringLower(flow.FlowId.Value.Span)[..8], flow.AuthorizeUrl, StringComparison.Ordinal);

        Assert.Equal("HTTP/1.1 200 OK", await ScriptedBrowser.GetAsync(link.Center.ApproveFlow()));

        // The flow's own end, not the link's phase (which turns SignedIn a moment before the flow ends: N2 review sec N-8).
        await Eventually.TrueAsync(() => link.Service.SignIn.Get(flow.FlowId)!.State == SignInFlowState.SignedIn, "signed in");
        Assert.True(link.Service.AccountLinked);
        Assert.Single(link.Center.CallsOf(Complete));
        Assert.Equal(link.Center.LatestDelivered, link.StoredRecord()!.RefreshToken);
        Assert.Equal("COMPLETED", link.Center.LatestFlowState);
        Assert.False(link.Service.SignIn.Active);
    }

    [Fact]
    public async Task ADenialEndsTheFlowAndChangesNothing()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.Browser)).Flow!;
        Assert.Equal("HTTP/1.1 200 OK", await ScriptedBrowser.GetAsync(link.Center.DenyFlow()));
        await Eventually.TrueAsync(() => link.Service.SignIn.Get(flow.FlowId)!.State == SignInFlowState.Denied, "denied");
        Assert.Equal(CloudLinkPhase.SignedOut, link.Service.Phase);
        Assert.Empty(link.Center.CallsOf(Complete));
        Assert.Null(link.StoredRecord());
    }

    [Fact]
    public async Task ABrowserFlowExpiresAfterTenMinutes()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.Browser)).Flow!;
        await Eventually.AdvanceUntilAsync(link.Clock, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(12),
            () => link.Service.SignIn.Get(flow.FlowId)!.State == SignInFlowState.Expired, "expired");
        Assert.Equal(CloudLinkPhase.SignedOut, link.Service.Phase);
        await link.Service.SignIn.Receiver!.Closed.WaitAsync(TimeSpan.FromSeconds(5), Cancel);
    }

    [Fact]
    public async Task AFailedBindFallsBackToDeviceCodeOnly()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        link.Service.SignIn.Listen = _ => throw new SocketException(10013);
        var flow = (await BeginAsync(link, SignInMethod.Browser)).Flow!;
        Assert.Equal(SignInMethod.DeviceCode, flow.Method);
        Assert.True(flow.FellBackToDeviceCode);
        Assert.False(flow.HasAuthorizeUrl);
        Assert.Equal(link.Center.LatestUserCode, flow.UserCode);
        Assert.Empty(link.Browser.Opened);
    }

    [Fact]
    public async Task ABrowserThatDoesNotOpenIsAWarningNotAFallback()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        link.Browser.Opens = false;
        var begun = await BeginAsync(link, SignInMethod.Browser);
        Assert.Equal(SignInMethod.Browser, begun.Flow!.Method);
        Assert.Equal(["browser_not_opened"], begun.Warnings);
    }

    [Fact]
    public async Task AForeignAuthorizeUrlFailsTheFlowAndOpensNothing()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        link.Center.AuthorizeUrlOverride = "file:///C:/Windows/System32/calc.exe";
        var begun = await BeginAsync(link, SignInMethod.Browser);
        Assert.Null(begun.Flow);
        Assert.Equal("invalid_argument", begun.Error!.Code);
        Assert.Equal("authorize_url: center_url_mismatch", begun.Error.Details.State.Reason);
        Assert.Empty(link.Browser.Opened);
        Assert.Equal(CloudLinkPhase.SignedOut, link.Service.Phase);
    }

    [Fact]
    public async Task AHostileDeviceReplyFailsTheFlow()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        link.Center.UserCodeOverride = "BCDF\u001b[2";
        var begun = await BeginAsync(link, SignInMethod.DeviceCode);
        Assert.Equal("user_code: pattern", begun.Error!.Details.State.Reason);
        link.Center.UserCodeOverride = null;
        link.Center.VerificationUriOverride = "https://evil.example/api/activate";
        begun = await BeginAsync(link, SignInMethod.DeviceCode);
        Assert.Equal("verification_uri: center_url_mismatch", begun.Error!.Details.State.Reason);
    }

    [Fact]
    public async Task TestALostCompleteReplyNeedsANewSignIn()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.Browser)).Flow!;
        link.Center.Script(Complete, new FakeFault.DropReply());
        await ScriptedBrowser.GetAsync(link.Center.ApproveFlow());
        await Eventually.TrueAsync(() => link.Service.SignIn.Get(flow.FlowId)!.State == SignInFlowState.Failed, "failed");
        var failed = link.Service.SignIn.Get(flow.FlowId)!;
        Assert.Equal("cloud_unreachable", failed.Error.Code);
        Assert.Equal("complete_reply_lost", failed.Error.Details.State.Reason);

        // Never resent: one Complete only; the delivered (and lost) credentials are not the node's.
        Assert.Single(link.Center.CallsOf(Complete));
        Assert.False(link.Service.AccountLinked);
    }

    [Fact]
    public async Task AnOverloadedCompleteIsSentOnceMoreAfterItsReceivedRefusal()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.Browser)).Flow!;
        var overloaded = Arc(ErrorCategory.Resource, "overloaded");
        overloaded.Retry = new RetryAdvice { Mode = RetryMode.AfterTime, RetryAt = ArcForges.Client.ProtoTime.ToInstant(link.Clock.GetUtcNow() + TimeSpan.FromSeconds(2)) };
        link.Center.Script(Complete, new FakeFault.Refusal(overloaded));
        await ScriptedBrowser.GetAsync(link.Center.ApproveFlow());
        await Eventually.TrueAsync(() => link.Center.CallsOf(Complete).Count == 1, "the first Complete");
        await Advance(link, TimeSpan.FromSeconds(120), () => link.Service.SignIn.Get(flow.FlowId)!.State == SignInFlowState.SignedIn, "signed in");
        Assert.Equal(2, link.Center.CallsOf(Complete).Count);
        Assert.True(link.Service.AccountLinked);
    }

    [Theory]
    [InlineData("code_reused", ErrorCategory.Conflict, SignInFlowState.Failed)]
    [InlineData("unauthenticated", ErrorCategory.Authentication, SignInFlowState.Failed)]
    [InlineData("not_found", ErrorCategory.State, SignInFlowState.Failed)]
    [InlineData("quota_exceeded", ErrorCategory.Resource, SignInFlowState.Failed)]
    [InlineData("expired", ErrorCategory.State, SignInFlowState.Expired)]
    public async Task EveryCompleteRefusalEndsTheFlowOnce(string code, ErrorCategory category, SignInFlowState state)
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.Browser)).Flow!;
        link.Center.Script(Complete, new FakeFault.Refusal(Arc(category, code)));
        await ScriptedBrowser.GetAsync(link.Center.ApproveFlow());
        await Eventually.TrueAsync(() => link.Service.SignIn.Get(flow.FlowId)!.State == state, code);
        Assert.Single(link.Center.CallsOf(Complete));
        Assert.Equal(state == SignInFlowState.Failed ? code : null, link.Service.SignIn.Get(flow.FlowId)!.Error?.Code);
        Assert.Equal(CloudLinkPhase.SignedOut, link.Service.Phase);
    }

    [Fact]
    public async Task ANodeIdOfAnotherAccountFailsTheFlow()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        link.Center.ForeignNodes.Add(Convert.ToHexString(link.NodeId));
        var flow = (await BeginAsync(link, SignInMethod.Browser)).Flow!;
        await ScriptedBrowser.GetAsync(link.Center.ApproveFlow());
        await Eventually.TrueAsync(() => link.Service.SignIn.Get(flow.FlowId)!.State == SignInFlowState.Failed, "failed");
        Assert.Equal("node", link.Service.SignIn.Get(flow.FlowId)!.Error.Details.State.State);
    }

    [Fact]
    public async Task KeyHeldAtBeginIsReplacedOnce()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        byte[] held;
        using (var key = link.Keys.Create(link.NodeId, link.Center.Endpoint.Origin, link.Clock))
        {
            held = key.PublicKey;
        }

        link.Center.HoldKey(held);
        var flow = (await BeginAsync(link, SignInMethod.Browser)).Flow!;
        Assert.Equal(SignInFlowState.Pending, flow.State);
        Assert.Equal(2, link.Center.CallsOf("BeginNodeSignIn").Count);
        Assert.Equal(1, link.Center.FlowCount);

        // N2 review FX-5: the retry carries a fresh PKCE verifier and state, and the receiver expects the new state.
        var begins = link.Center.CallsOf("BeginNodeSignIn").Select(call => NodeEnrollmentServiceBeginNodeSignInRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body))).ToList();
        Assert.NotEqual(begins[0].State, begins[1].State);
        Assert.NotEqual(begins[0].CodeChallenge, begins[1].CodeChallenge);
        Assert.Equal(begins[0].RedirectUri, begins[1].RedirectUri);
        Assert.Equal("HTTP/1.1 400 Bad Request", await ScriptedBrowser.GetAsync(link.Service.SignIn.Receiver!.RedirectUri + "?code=" + new string('A', 43) + "&state=" + begins[0].State));
        Assert.Equal("HTTP/1.1 200 OK", await ScriptedBrowser.GetAsync(link.Center.ApproveFlow()));
        await Eventually.TrueAsync(() => link.Service.SignIn.Get(flow.FlowId)!.State == SignInFlowState.SignedIn, "signed in");
        Assert.NotEqual(CloudIdentity.Fingerprint(held), flow.NodeKeyFingerprint);
        Assert.Equal(link.Keys.Recorded()!.Fingerprint, flow.NodeKeyFingerprint);
    }

    [Fact]
    public async Task KeyHeldAtStartIsReplacedOnceAndASecondRefusalIsTheReply()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        using (var key = link.Keys.Create(link.NodeId, link.Center.Endpoint.Origin, link.Clock))
        {
            link.Center.HoldKey(key.PublicKey);
        }

        var flow = (await BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        Assert.Equal(SignInFlowState.Pending, flow.State);
        Assert.Equal(2, link.Center.CallsOf("StartDeviceAuthorization").Count);
        Assert.True(link.Service.SignIn.Cancel(flow.FlowId).Error is null);

        // Both keys held (a center that refuses every key): one replacement, then the refusal, no loop.
        link.Center.Script("StartDeviceAuthorization", new FakeFault.Refusal(KeyHeld()));
        link.Center.Script("StartDeviceAuthorization", new FakeFault.Refusal(KeyHeld()));
        var refused = await BeginAsync(link, SignInMethod.DeviceCode);
        Assert.Equal("invalid_state", refused.Error!.Code);
        Assert.Equal(4, link.Center.CallsOf("StartDeviceAuthorization").Count);
    }

    [Fact]
    public async Task CredentialRevokedAtCompleteRegeneratesTheKeyOnce()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.Browser)).Flow!;
        var first = link.Keys.Load(link.NodeId, link.Center.Endpoint.Origin)!.PublicKey;
        link.Center.HoldKey(first, retired: true);
        await ScriptedBrowser.GetAsync(link.Center.ApproveFlow());

        // A new key and a new flow (the same node-local flow, PENDING again, the browser opened again).
        await Eventually.TrueAsync(() => link.Browser.Opened.Count == 2, "the browser opened again");
        var again = link.Service.SignIn.Get(flow.FlowId)!;
        Assert.Equal(SignInFlowState.Pending, again.State);
        Assert.NotEqual(flow.AuthorizeUrl, again.AuthorizeUrl);
        Assert.NotEqual(flow.NodeKeyFingerprint, again.NodeKeyFingerprint);
        await ScriptedBrowser.GetAsync(link.Center.ApproveFlow());
        await Eventually.TrueAsync(() => link.Service.AccountLinked, "signed in with the new key");
    }

    [Fact]
    public async Task ASecondKeyRefusalFailsTheFlow()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.Browser)).Flow!;
        link.Center.Script(Complete, new FakeFault.Refusal(Arc(ErrorCategory.Authentication, "credential_revoked")));
        link.Center.Script(Complete, new FakeFault.Refusal(Arc(ErrorCategory.Authentication, "credential_revoked")));
        await ScriptedBrowser.GetAsync(link.Center.ApproveFlow());
        await Eventually.TrueAsync(() => link.Browser.Opened.Count == 2, "the browser opened again");
        await ScriptedBrowser.GetAsync(link.Center.ApproveFlow());
        await Eventually.TrueAsync(() => link.Service.SignIn.Get(flow.FlowId)!.State == SignInFlowState.Failed, "failed");
        Assert.Equal("credential_revoked", link.Service.SignIn.Get(flow.FlowId)!.Error.Code);
        Assert.Equal(2, link.Center.CallsOf(Complete).Count);
    }

    [Fact]
    public async Task ADeviceSignInPollsAtTheCentersIntervalAndSucceeds()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        Assert.Equal(SignInMethod.DeviceCode, flow.Method);
        Assert.Equal(link.Center.Endpoint.Url + "/activate", flow.VerificationUri);
        Assert.Equal(link.Center.Endpoint.ActivateCompleteUrl(flow.UserCode), flow.VerificationUriComplete);
        Assert.Equal(flow.VerificationUriComplete, flow.QrPayload);
        Assert.Equal(5000UL, flow.PollIntervalMs);

        // The first poll waits one interval.
        link.Clock.Advance(TimeSpan.FromSeconds(4));
        await Task.Delay(100, Cancel);
        Assert.Empty(link.Center.CallsOf(Poll));
        await Advance(link, TimeSpan.FromSeconds(120), () => link.Center.CallsOf(Poll).Count >= 3, "three polls");
        Assert.Equal("PENDING", link.Center.LatestDeviceState);
        link.Center.ApproveDevice();
        await Advance(link, TimeSpan.FromSeconds(120), () => link.Service.SignIn.Get(flow.FlowId)!.State == SignInFlowState.SignedIn, "signed in");
        Assert.True(link.Service.AccountLinked);
        Assert.Equal("COMPLETED", link.Center.LatestDeviceState);
    }

    [Fact]
    public async Task SlowDownRaisesTheIntervalAndTheNodeNeverPollsEarly()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        var slow = new NodeEnrollmentServicePollDeviceAuthorizationResponse
        {
            Meta = new ResponseMeta(),
            Value = new NodeEnrollmentServicePollDeviceAuthorizationValue { State = DeviceAuthorizationState.SlowDown, IntervalMs = 15000 },
        };
        link.Center.Script(Poll, new FakeFault.Raw([.. FakeCenter.DataFrame(slow), .. FakeCenter.TrailerFrame(0, null)]));
        await Advance(link, TimeSpan.FromSeconds(30), () => link.Center.CallsOf(Poll).Count == 1, "the first poll");
        await Eventually.TrueAsync(() => link.Service.SignIn.Get(flow.FlowId)!.PollIntervalMs == 15000, "the raised interval");
        for (var second = 0; second < 14; second++)
        {
            link.Clock.Advance(TimeSpan.FromSeconds(1));
            await Task.Delay(15, Cancel);
        }

        Assert.Single(link.Center.CallsOf(Poll));
        await Advance(link, TimeSpan.FromSeconds(20), () => link.Center.CallsOf(Poll).Count == 2, "the next poll");

        // The next reply's interval rules again (FakeCenter's own is 5,000 ms: it never saw an early poll).
        await Eventually.TrueAsync(() => link.Service.SignIn.Get(flow.FlowId)!.PollIntervalMs == 5000, "the center's interval");
        Assert.Equal("PENDING", link.Center.LatestDeviceState);
    }

    [Fact]
    public async Task ACenterIntervalBelowTheFloorIsNeverUsed()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        var fast = new NodeEnrollmentServicePollDeviceAuthorizationResponse
        {
            Meta = new ResponseMeta(),
            Value = new NodeEnrollmentServicePollDeviceAuthorizationValue { State = DeviceAuthorizationState.Pending, IntervalMs = 1000 },
        };
        link.Center.Script(Poll, new FakeFault.Raw([.. FakeCenter.DataFrame(fast), .. FakeCenter.TrailerFrame(0, null)]));
        await Advance(link, TimeSpan.FromSeconds(30), () => link.Center.CallsOf(Poll).Count == 1, "the first poll");
        await Task.Delay(100, Cancel);
        for (var second = 0; second < 4; second++)
        {
            link.Clock.Advance(TimeSpan.FromSeconds(1));
            await Task.Delay(15, Cancel);
        }

        Assert.Single(link.Center.CallsOf(Poll));
        Assert.Equal(5000UL, link.Service.SignIn.Get(flow.FlowId)!.PollIntervalMs);
    }

    [Fact]
    public async Task DeviceDenialAndExpiryEndTheFlow()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        link.Center.DenyDevice();
        await Advance(link, TimeSpan.FromSeconds(120),
            () => link.Service.SignIn.Get(flow.FlowId)!.State == SignInFlowState.Denied, "denied");
        flow = (await BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        await Eventually.AdvanceUntilAsync(link.Clock, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(700),
            () => link.Service.SignIn.Get(flow.FlowId)!.State == SignInFlowState.Expired, "expired");
        var polls = link.Center.CallsOf(Poll).Count;
        link.Clock.Advance(TimeSpan.FromMinutes(5));
        await Task.Delay(100, Cancel);
        Assert.Equal(polls, link.Center.CallsOf(Poll).Count);
    }

    [Fact]
    public async Task CompletedWithoutCredentialsFailsTheFlow()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        var completed = new NodeEnrollmentServicePollDeviceAuthorizationResponse
        {
            Meta = new ResponseMeta(),
            Value = new NodeEnrollmentServicePollDeviceAuthorizationValue { State = DeviceAuthorizationState.Completed, IntervalMs = 5000 },
        };
        link.Center.Script(Poll, new FakeFault.Raw([.. FakeCenter.DataFrame(completed), .. FakeCenter.TrailerFrame(0, null)]));
        await Advance(link, TimeSpan.FromSeconds(30),
            () => link.Service.SignIn.Get(flow.FlowId)!.State == SignInFlowState.Failed, "failed");
        Assert.Equal("credentials_already_delivered", link.Service.SignIn.Get(flow.FlowId)!.Error.Details.State.Reason);
    }

    [Fact]
    public async Task APollReplyLostAfterDeliveryIsPollReplyLost()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        link.Center.ApproveDevice();
        link.Center.Script(Poll, new FakeFault.DropReply());
        await Advance(link, TimeSpan.FromSeconds(180),
            () => link.Service.SignIn.Get(flow.FlowId)!.State == SignInFlowState.Failed, "failed");
        Assert.Equal("poll_reply_lost", link.Service.SignIn.Get(flow.FlowId)!.Error.Details.State.Reason);

        // The reuse rule revoked the delivered family at the center; the node never held it.
        Assert.False(link.Center.IsLive(link.Center.LatestDelivered!));
        Assert.False(link.Service.AccountLinked);
    }

    [Fact]
    public async Task CredentialsThatReachACancelledFlowAreRevokedAndNeverStored()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        link.Center.ApproveDevice();
        var hold = new TaskCompletionSource();
        link.Center.Script(Poll, new FakeFault.Hold(hold));
        await Advance(link, TimeSpan.FromSeconds(30), () => link.Center.CallsOf(Poll).Count == 1, "the poll in flight");
        var cancelled = link.Service.SignIn.Cancel(flow.FlowId);
        Assert.Equal(SignInFlowState.Cancelled, cancelled.Flow!.State);
        Assert.Equal(CloudLinkPhase.SignedOut, link.Service.Phase);
        hold.SetResult();
        await Eventually.TrueAsync(() => link.Center.CallsOf("SignOutNode").Count == 1, "the late credentials revoked");
        Assert.False(link.Center.IsLive(link.Center.LatestDelivered!));
        Assert.Null(link.StoredRecord());
        Assert.False(link.Service.AccountLinked);
        Assert.Null(link.Keys.Recorded());
    }

    [Fact]
    public async Task OneActiveFlowIsReservedAtomically()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        link.Center.Script("BeginNodeSignIn", new FakeFault.Delay(TimeSpan.FromMilliseconds(500)));
        var both = await Task.WhenAll(BeginAsync(link, SignInMethod.Browser), BeginAsync(link, SignInMethod.DeviceCode));
        Assert.All(both, reply => Assert.NotNull(reply.Flow));
        Assert.Equal(both[0].Flow!.FlowId, both[1].Flow!.FlowId);
        Assert.Single(link.Center.CallsOf("BeginNodeSignIn"));
        Assert.Empty(link.Center.CallsOf("StartDeviceAuthorization"));

        // A later Begin returns the same flow too.
        Assert.Equal(both[0].Flow!.FlowId, (await BeginAsync(link, SignInMethod.Browser)).Flow!.FlowId);
    }

    [Fact]
    public async Task CancelEndsAPendingFlowAndNothingElse()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.Browser)).Flow!;
        var receiver = link.Service.SignIn.Receiver!;
        var cancelled = link.Service.SignIn.Cancel(flow.FlowId);
        Assert.Equal(SignInFlowState.Cancelled, cancelled.Flow!.State);
        await receiver.Closed.WaitAsync(TimeSpan.FromSeconds(5), Cancel);
        Assert.Equal(CloudLinkPhase.SignedOut, link.Service.Phase);
        Assert.Equal("invalid_state", link.Service.SignIn.Cancel(flow.FlowId).Error!.Code);
        Assert.Equal("cancelled", link.Service.SignIn.Cancel(flow.FlowId).Error!.Details.State.Reason);
        Assert.Equal("not_found", link.Service.SignIn.Cancel(new Id { Value = Google.Protobuf.ByteString.CopyFrom(new byte[16]) }).Error!.Code);
        Assert.Null(link.Service.SignIn.Get(new Id { Value = Google.Protobuf.ByteString.CopyFrom(new byte[16]) }));
    }

    [Fact]
    public async Task ACompletingFlowCannotBeCancelled()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.Browser)).Flow!;
        var hold = new TaskCompletionSource();
        link.Center.Script(Complete, new FakeFault.Hold(hold));
        await ScriptedBrowser.GetAsync(link.Center.ApproveFlow());
        await Eventually.TrueAsync(() => link.Center.CallsOf(Complete).Count == 1, "the Complete in flight");
        var refused = link.Service.SignIn.Cancel(flow.FlowId);
        Assert.Equal("completing", refused.Error!.Details.State.Reason);
        hold.SetResult();
        await Eventually.TrueAsync(() => link.Service.AccountLinked, "signed in");
    }

    [Fact]
    public async Task ASignedInNodeRefusesASignInAndAFlowNeverReplacesALiveCredential()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        var refused = await BeginAsync(link, SignInMethod.Browser);
        Assert.Equal("invalid_state", refused.Error!.Code);
        Assert.Equal("signed_in", refused.Error.Details.State.State);
        Assert.Equal("sign_in", refused.Error.Details.State.Reason);
        Assert.Equal(0, link.Center.FlowCount);
    }

    [Fact]
    public async Task ADeliveredCredentialIsRevokedWhenAnotherBecameLiveMeanwhile()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.DeviceCode)).Flow!;

        // Another credential becomes live while the flow is pending (R-2's race, forced through the adoption seam).
        var live = await link.SignInAsync();
        link.Center.ApproveDevice();
        await Advance(link, TimeSpan.FromSeconds(120),
            () => link.Service.SignIn.Get(flow.FlowId)!.State == SignInFlowState.Failed, "failed");
        Assert.Equal("signed_in", link.Service.SignIn.Get(flow.FlowId)!.Error.Details.State.Reason);
        Assert.Equal(live.RefreshToken, link.StoredRecord()!.RefreshToken);
        Assert.False(link.Center.IsLive(link.Center.LatestDelivered!));
        Assert.True(link.Center.IsLive(live.RefreshToken));
        Assert.True(link.Service.AccountLinked);

        // The revocation keeps the key the live credential uses (N2 review sec N-2, S5).
        Assert.NotNull(link.Keys.Load(link.NodeId, link.Center.Endpoint.Origin));
    }

    [Fact]
    public async Task AHeldRejectedCredentialIsReplacedOnlyAfterSuccess()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var first = await link.SignInAsync();
        link.Center.Script("RefreshNodeSession", new FakeFault.Refusal(Arc(ErrorCategory.Authentication, "unauthenticated")));
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(45),
            () => link.Service.Status().Warnings.Contains("center_rejected_credential"), "the rejection");

        // A denied sign-in leaves the held record; the center change refusal is reached while signing in.
        var denied = (await BeginAsync(link, SignInMethod.Browser)).Flow!;
        Assert.Equal(CloudLinkPhase.SigningIn, link.Service.Phase);
        await ScriptedBrowser.GetAsync(link.Center.DenyFlow());
        await Eventually.TrueAsync(() => link.Service.SignIn.Get(denied.FlowId)!.State == SignInFlowState.Denied, "denied");
        Assert.Equal(first.RefreshToken, link.StoredRecord()!.RefreshToken);
        Assert.Equal(CloudLinkPhase.SignedOut, link.Service.Phase);

        var flow = (await BeginAsync(link, SignInMethod.Browser)).Flow!;
        await ScriptedBrowser.GetAsync(link.Center.ApproveFlow());
        await Eventually.TrueAsync(() => link.Service.AccountLinked, "signed in");
        Assert.Equal(link.Center.LatestDelivered, link.StoredRecord()!.RefreshToken);
        Assert.DoesNotContain("center_rejected_credential", link.Service.Status().Warnings);
        Assert.Equal(SignInFlowState.SignedIn, link.Service.SignIn.Get(flow.FlowId)!.State);
    }

    [Fact]
    public async Task ACenterChangedOutOfBandDuringAFlowEndsItWithoutSending()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.DeviceCode)).Flow!;
        await using var other = await FakeCenter.StartAsync("/other");
        link.ConfiguredCenter = other.Endpoint;
        await Advance(link, TimeSpan.FromSeconds(60),
            () => link.Service.SignIn.Get(flow.FlowId)!.State == SignInFlowState.Failed, "failed");
        Assert.Equal("center_url", link.Service.SignIn.Get(flow.FlowId)!.Error.Details.State.Reason);
        Assert.Empty(link.Center.CallsOf(Poll));
        Assert.Empty(other.Calls);
    }

    [Fact]
    public async Task ANodeWithoutACenterOrWithAStrandedLinkRefusesTheSignIn()
    {
        await using var link = await LinkFixture.CreateAsync();
        link.ConfiguredCenter = null;
        await link.StartAsync();
        var refused = await BeginAsync(link, SignInMethod.Browser);
        Assert.Equal("center_url", refused.Error!.Details.State.Reason);
        await link.StopAsync();

        link.ConfiguredCenter = link.Center.Endpoint;
        await link.StartAsync();
        await link.SignInAsync();
        await link.StopAsync();
        var file = link.Storage.ReadLink()!;
        file.NodeId = Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        link.Storage.WriteLink(file);
        await link.StartAsync();
        refused = await BeginAsync(link, SignInMethod.Browser);
        Assert.Equal("credential_for_other_node", refused.Error!.Details.State.Reason);
        Assert.Equal(0, link.Center.FlowCount);
    }

    [Fact]
    public async Task ARestartCancelsAFlow()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var flow = (await BeginAsync(link, SignInMethod.Browser)).Flow!;
        var receiver = link.Service.SignIn.Receiver!;
        await link.StopAsync();
        await receiver.Closed.WaitAsync(TimeSpan.FromSeconds(5), Cancel);
        await link.StartAsync();
        Assert.Null(link.Service.SignIn.Get(flow.FlowId));
        Assert.Equal(CloudLinkPhase.SignedOut, link.Service.Phase);
    }

    /// <summary>
    /// Advances the manual clock a second at a time until <paramref name="condition"/> holds, at most <paramref name="limit"/> of the clock,
    /// and only while the flow waits on the clock (N2 review tests N-4): a poll or a Complete over the real HTTP seam runs in real time, so
    /// the clock stands still until the flow waits again. After a step the next one comes only when the wait it saw is still pending or a
    /// new wait began, so no simulated time passes while a woken flow runs.
    /// </summary>
    internal static async Task Advance(LinkFixture link, TimeSpan limit, Func<bool> condition, string what)
    {
        var moved = TimeSpan.Zero;
        var flows = link.Service.SignIn;
        while (!condition())
        {
            if (moved >= limit)
            {
                await Eventually.TrueAsync(condition, what);
                return;
            }

            var waiting = await Until(() => condition() || flows.ClockWait.Blocked);
            if (!waiting)
            {
                Assert.Fail(what + ": the flow neither waits on the clock nor reached the condition");
            }

            if (condition())
            {
                return;
            }

            var (count, wait, _) = flows.ClockWait;
            link.Clock.Advance(TimeSpan.FromSeconds(1));
            moved += TimeSpan.FromSeconds(1);
            if (wait is not { IsCompleted: false })
            {
                // The wait ended: the flow runs on in real time until it is blocked in the next wait or reaches the condition.
                await Until(() => condition() || (flows.ClockWait is { Blocked: true } next && next.Count != count));
            }
        }

        static async Task<bool> Until(Func<bool> done)
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();
            while (!done())
            {
                if (watch.Elapsed > TimeSpan.FromSeconds(30))
                {
                    return false;
                }

                await Task.Delay(5, Cancel);
            }

            return true;
        }
    }

    internal static Task<SignInReply> BeginAsync(LinkFixture link, SignInMethod method) =>
        link.Service.SignIn.BeginAsync(method, link.Clock.GetTimestamp(), Cancel);

    internal static ArcError Arc(ErrorCategory category, string code) => new()
    {
        Category = category,
        Code = code,
        MessageKey = "error." + category.ToString().ToLowerInvariant() + "." + code,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        Effect = EffectCertainty.DidNotHappen,
    };

    private static ArcError KeyHeld()
    {
        var error = Arc(ErrorCategory.Conflict, "already_exists");
        error.Details = new ErrorDetails { State = new StateFailure { State = "node_key", Reason = "already_registered" } };
        return error;
    }
}
