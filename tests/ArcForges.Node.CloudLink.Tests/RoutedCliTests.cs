// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.CommandLine;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Store.Policy;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>REAL CLI process, local endpoint and node proxy; the scripted center is MOCKED and never claimed as task execution.</summary>
public sealed class RoutedCliTests
{
    private const string SyntheticEnvironmentValue = "fixture-only-d3-sentinel";

    [Theory(Timeout = 60000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DefaultRoutedRunNeverExportsSyntheticCallerSecrets(bool foreign)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var target = foreign ? CommandIds.New() : fixture.NodeId;
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(target, CommandIds.New())));
        var args = new List<string> { "run", "--detach" };
        if (foreign)
        {
            args.AddRange(["--node", new Guid(target.Value.Span, bigEndian: true).ToString("D"), "--cwd", "/target/work"]);
        }
        args.AddRange(["--", "test-program"]);
        var result = await fixture.CliSyntheticAsync(args.ToArray());
        Assert.True(result.ExitCode == 0, "safe default submission should be accepted");
        var outer = FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(fixture.Center.CallsOf("SubmitNodeTask")).Body));
        var environment = TaskServiceSubmitTaskRequest.Parser.ParseFrom(outer.Request).Spec.Environment;
        Assert.False(outer.Request.Span.IndexOf(Encoding.UTF8.GetBytes(SyntheticEnvironmentValue)) >= 0, "no synthetic secret may cross the center");
        Assert.Equal(EnvironmentInherit.Node, environment.Inherit);
        Assert.Empty(environment.CallerEnvironment);
    }

    [Theory(Timeout = 60000)]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ExplicitSecretEnvironmentIsRefusedBeforeRelay(bool caller)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, CommandIds.New())));
        var nonceCount = NonceRequests(fixture.Center);
        var args = caller
            ? new[] { "run", "--detach", "--env-inherit", "caller", "--", "test-program" }
            : new[] { "run", "--detach", "--env-inherit", "none", "--env", "AF_SYNTH_TOKEN=" + SyntheticEnvironmentValue, "--", "test-program" };
        var result = await fixture.CliSyntheticAsync(args);
        Assert.True(fixture.Center.CallsOf("SubmitNodeTask").Count == 0, "secret-shaped values must be refused before center send");
        Assert.Equal(nonceCount, NonceRequests(fixture.Center));
        Assert.True(result.ExitCode is not 0 and not 131, "explicit unsafe environment must be refused by the product, not by runtime startup");
        Assert.True(result.Stderr.Contains("environment", StringComparison.OrdinalIgnoreCase)
            && result.Stderr.Contains("center", StringComparison.OrdinalIgnoreCase), "refusal explains the center environment restriction");
        Assert.False(result.Stdout.Contains(SyntheticEnvironmentValue, StringComparison.Ordinal));
        Assert.False(result.Stderr.Contains(SyntheticEnvironmentValue, StringComparison.Ordinal));
    }

    [Fact(Timeout = 60000)]
    public async Task MalformedEnvironmentDiagnosticDoesNotEchoItsInput()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var result = await fixture.CliSyntheticAsync("run", "--detach", "--env", SyntheticEnvironmentValue, "--", "test-program");
        Assert.Equal(2, result.ExitCode);
        Assert.True(result.Stderr.Contains("--env", StringComparison.Ordinal));
        Assert.False(result.Stdout.Contains(SyntheticEnvironmentValue, StringComparison.Ordinal));
        Assert.False(result.Stderr.Contains(SyntheticEnvironmentValue, StringComparison.Ordinal));
        Assert.True(fixture.Center.CallsOf("SubmitNodeTask").Count == 0);
    }

    [Theory(Timeout = 60000)]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task DirectFleetSubmitCannotBypassTheEnvironmentBoundary(bool foreign, bool unusedCallerField)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var target = foreign ? CommandIds.New() : fixture.NodeId;
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(target, CommandIds.New())));
        var nonceCount = NonceRequests(fixture.Center);
        var environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Node };
        if (unusedCallerField)
        {
            environment.CallerEnvironment["AF_SYNTH_TOKEN"] = SyntheticEnvironmentValue;
        }
        else
        {
            environment.Set[foreign ? "AF_SAFE_VALUE" : "AF_SYNTH_TOKEN"] = SyntheticEnvironmentValue;
        }
        var answer = await DirectSubmitAsync(fixture, target, environment);
        Assert.True(fixture.Center.CallsOf("SubmitNodeTask").Count == 0, "direct Fleet caller must not send unsafe or unclassifiable values");
        Assert.Equal(nonceCount, NonceRequests(fixture.Center));
        Assert.True(answer.Error is { Code: "invalid_argument", Effect: EffectCertainty.DidNotHappen }, "direct refusal must be definite");
        Assert.Equal(RetryMode.Never, answer.Error.Retry.Mode);
        Assert.True(ArcForges.Contracts.Node.Shapes.ContractShapeValidation.IsValid(answer.Error));
        Assert.True(answer.Error.Details.State.Reason.Contains("environment", StringComparison.OrdinalIgnoreCase));
        Assert.False(answer.Error.ToString().Contains(SyntheticEnvironmentValue, StringComparison.Ordinal));
    }

    [Fact(Timeout = 60000)]
    public async Task DirectFleetUsesCustomAndDefaultSecretPatterns()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        await using (var human = await fixture.Node.ChannelAsync(Origin.Human))
        {
            var current = await human.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = CloudNode.Command() }, cancellationToken: TestContext.Current.CancellationToken);
            Assert.Null(current.Error);
            var document = current.Value.Document.Clone();
            document.Privacy.SecretNamePatterns.Clear();
            document.Privacy.SecretNamePatterns.Add("AF_ZEBRA_*");
            var meta = CloudNode.Command();
            meta.ExpectedRev = current.Value.Revision.Revision;
            var changed = await human.Policy.UpdatePolicyAsync(new PolicyServiceUpdatePolicyRequest { Meta = meta, Document = document }, cancellationToken: TestContext.Current.CancellationToken);
            Assert.Null(changed.Error);
        }
        foreach (var name in new[] { "AF_ZEBRA_VALUE", "AF_SYNTH_TOKEN" })
        {
            fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, CommandIds.New())));
            var nonceCount = NonceRequests(fixture.Center);
            var environment = new EnvironmentSpec { Inherit = EnvironmentInherit.None };
            environment.Set[name] = SyntheticEnvironmentValue;
            var answer = await DirectSubmitAsync(fixture, fixture.NodeId, environment);
            Assert.True(fixture.Center.CallsOf("SubmitNodeTask").Count == 0, "custom and default patterns must both stop at local boundary");
            Assert.Equal(nonceCount, NonceRequests(fixture.Center));
            Assert.True(answer.Error is { Code: "invalid_argument", Effect: EffectCertainty.DidNotHappen });
            Assert.Equal(RetryMode.Never, answer.Error.Retry.Mode);
            Assert.True(ArcForges.Contracts.Node.Shapes.ContractShapeValidation.IsValid(answer.Error));
            Assert.False(answer.Error.ToString().Contains(SyntheticEnvironmentValue, StringComparison.Ordinal));
        }
    }

    [Fact(Timeout = 60000)]
    public async Task InconsistentCurrentPolicyDigestIsRefusedBeforeNonceOrCenter()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        await UpdateSyntheticPolicyAsync(fixture, customPattern: true, reverseMaps: false);
        var store = fixture.Node.Runtime.Store;
        var original = store.Read(PolicyRules.Current);
        Assert.True(CryptographicOperations.FixedTimeEquals(original.Digest, PolicyDocuments.Digest(original.Document)), "normal policy write must retain its digest");
        var environment = new EnvironmentSpec { Inherit = EnvironmentInherit.None };
        environment.Set["AF_ZEBRA_VALUE"] = SyntheticEnvironmentValue;
        var nonceCount = NonceRequests(fixture.Center);
        var before = await DirectSubmitAsync(fixture, fixture.NodeId, environment);
        Assert.True(before.Error is { Code: "invalid_argument", Effect: EffectCertainty.DidNotHappen }, "configured pattern must be refused before damage");
        Assert.Equal(nonceCount, NonceRequests(fixture.Center));
        Assert.True(fixture.Center.CallsOf("SubmitNodeTask").Count == 0);

        // Damage only this test-owned fixture's current document; leave its original, valid-length stored digest untouched.
        var damaged = original.Document.Clone();
        damaged.Privacy.SecretNamePatterns.Clear();
        store.Write(transaction => transaction.Execute("UPDATE policy_document SET document = $document WHERE is_current = 1", ("$document", damaged.ToByteArray())));
        var current = store.Read(PolicyRules.Current);
        Assert.False(CryptographicOperations.FixedTimeEquals(current.Digest, PolicyDocuments.Digest(current.Document)), "fixture must have a parseable mismatch");
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, CommandIds.New())));
        nonceCount = NonceRequests(fixture.Center);
        var after = await DirectSubmitAsync(fixture, fixture.NodeId, environment);
        Assert.True(fixture.Center.CallsOf("SubmitNodeTask").Count == 0, "an inconsistent policy must never send a value to the center");
        Assert.Equal(nonceCount, NonceRequests(fixture.Center));
        Assert.True(after.Error is { Code: "invalid_state", Effect: EffectCertainty.DidNotHappen });
        Assert.Equal(RetryMode.Never, after.Error.Retry.Mode);
        Assert.True(ArcForges.Contracts.Node.Shapes.ContractShapeValidation.IsValid(after.Error));
        Assert.True(after.Error.Details.State.Reason.Contains("policy", StringComparison.OrdinalIgnoreCase));
        Assert.False(after.Error.ToString().Contains(SyntheticEnvironmentValue, StringComparison.Ordinal));
    }

    [Theory(Timeout = 60000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ValidEmptyPolicyAndMapOrdersRetainDefaultProtection(bool reverseMaps)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        await UpdateSyntheticPolicyAsync(fixture, customPattern: false, reverseMaps);
        var current = fixture.Node.Runtime.Store.Read(PolicyRules.Current);
        Assert.Empty(current.Document.Privacy.SecretNamePatterns);
        Assert.Equal(2, current.Document.ResultCache.WorkspaceModes.Count);
        Assert.True(CryptographicOperations.FixedTimeEquals(current.Digest, PolicyDocuments.Digest(current.Document)), "writer and reader must agree for map order");

        var nonceCount = NonceRequests(fixture.Center);
        var secret = new EnvironmentSpec { Inherit = EnvironmentInherit.None };
        secret.Set["AF_SYNTH_TOKEN"] = SyntheticEnvironmentValue;
        var refused = await DirectSubmitAsync(fixture, fixture.NodeId, secret);
        Assert.True(refused.Error is { Code: "invalid_argument", Effect: EffectCertainty.DidNotHappen });
        Assert.Equal(nonceCount, NonceRequests(fixture.Center));
        Assert.True(fixture.Center.CallsOf("SubmitNodeTask").Count == 0);
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, CommandIds.New())));
        var safe = new EnvironmentSpec { Inherit = EnvironmentInherit.None };
        safe.Set["AF_ZEBRA_VALUE"] = "fixture-safe";
        var accepted = await DirectSubmitAsync(fixture, fixture.NodeId, safe);
        Assert.NotNull(accepted.Value);
        Assert.Single(fixture.Center.CallsOf("SubmitNodeTask"));
    }

    private static async Task UpdateSyntheticPolicyAsync(Fixture fixture, bool customPattern, bool reverseMaps)
    {
        await using var human = await fixture.Node.ChannelAsync(Origin.Human);
        var current = await human.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = CloudNode.Command() }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(current.Error);
        var document = current.Value.Document.Clone();
        document.Privacy.SecretNamePatterns.Clear();
        if (customPattern)
        {
            document.Privacy.SecretNamePatterns.Add("AF_ZEBRA_*");
        }
        document.ResultCache.WorkspaceModes.Clear();
        if (reverseMaps)
        {
            document.ResultCache.WorkspaceModes.Add("synthetic-a", ResultCacheMode.Off);
            document.ResultCache.WorkspaceModes.Add("synthetic-z", ResultCacheMode.Observe);
        }
        else
        {
            document.ResultCache.WorkspaceModes.Add("synthetic-z", ResultCacheMode.Observe);
            document.ResultCache.WorkspaceModes.Add("synthetic-a", ResultCacheMode.Off);
        }
        var meta = CloudNode.Command();
        meta.ExpectedRev = current.Value.Revision.Revision;
        var changed = await human.Policy.UpdatePolicyAsync(new PolicyServiceUpdatePolicyRequest { Meta = meta, Document = document }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(changed.Error);
    }

    [Fact]
    public void MissingPolicyFailsClosedWithoutClaimingASecretWasSupplied()
    {
        var meta = CloudNode.Command();
        var environment = new EnvironmentSpec { Inherit = EnvironmentInherit.None };
        environment.Set["AF_DISPLAY"] = "blue";
        var request = new TaskServiceSubmitTaskRequest { Meta = meta, Spec = new TaskSpec { Environment = environment } };
        var error = RoutedEnvironmentGuard.Check(request.ToByteString(), ownNode: true, meta.CorrelationId, TimeProvider.System,
            () => throw new InvalidOperationException("synthetic policy read failure"));
        Assert.True(error is { Code: "invalid_state", Effect: EffectCertainty.DidNotHappen });
        Assert.Equal(RetryMode.Never, error.Retry.Mode);
        Assert.True(ArcForges.Contracts.Node.Shapes.ContractShapeValidation.IsValid(error));
        Assert.True(error.Details.State.Reason.Contains("policy", StringComparison.OrdinalIgnoreCase));
        Assert.False(error.Details.State.Reason.Contains("secret values", StringComparison.OrdinalIgnoreCase));
    }

    [Fact(Timeout = 60000)]
    public async Task UnknownEnvironmentFieldCannotCarryUnclassifiedBytes()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, CommandIds.New())));
        var encoded = Encode(output => { output.WriteTag(42); output.WriteString(SyntheticEnvironmentValue); });
        var environment = EnvironmentSpec.Parser.ParseFrom(encoded);
        var nonceCount = NonceRequests(fixture.Center);
        var answer = await DirectSubmitAsync(fixture, fixture.NodeId, environment);
        Assert.True(fixture.Center.CallsOf("SubmitNodeTask").Count == 0, "unknown environment fields must fail closed");
        Assert.Equal(nonceCount, NonceRequests(fixture.Center));
        Assert.True(answer.Error is { Code: "invalid_argument", Effect: EffectCertainty.DidNotHappen });
        Assert.True(ArcForges.Contracts.Node.Shapes.ContractShapeValidation.IsValid(answer.Error));
        Assert.False(answer.Error.ToString().Contains(SyntheticEnvironmentValue, StringComparison.Ordinal));
    }

    [Fact(Timeout = 60000)]
    public async Task DuplicateMapKeysCannotHideSecretBytesFromTheBoundary()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, CommandIds.New())));
        var meta = CloudNode.Command();
        var entry = Encode(output =>
        {
            output.WriteTag(10); output.WriteString("AF_SYNTH_TOKEN");
            output.WriteTag(18); output.WriteString(SyntheticEnvironmentValue);
            output.WriteTag(10); output.WriteString("AF_SAFE_VALUE");
        });
        var environment = Encode(output => { output.WriteTag(18); output.WriteBytes(ByteString.CopyFrom(entry)); });
        var spec = Encode(output => { output.WriteTag(26); output.WriteBytes(ByteString.CopyFrom(environment)); });
        var request = Encode(output =>
        {
            output.WriteTag(10); output.WriteMessage(meta);
            output.WriteTag(82); output.WriteBytes(ByteString.CopyFrom(spec));
        });
        var nonceCount = NonceRequests(fixture.Center);
        var answer = await DirectRawSubmitAsync(fixture, fixture.NodeId, meta, ByteString.CopyFrom(request));
        Assert.True(fixture.Center.CallsOf("SubmitNodeTask").Count == 0, "the original wire bytes must not hide a secret-shaped key");
        Assert.Equal(nonceCount, NonceRequests(fixture.Center));
        Assert.True(answer.Error is { Code: "invalid_argument", Effect: EffectCertainty.DidNotHappen });
        Assert.True(ArcForges.Contracts.Node.Shapes.ContractShapeValidation.IsValid(answer.Error));
        Assert.False(answer.Error.ToString().Contains(SyntheticEnvironmentValue, StringComparison.Ordinal));
    }

    private static byte[] Encode(Action<CodedOutputStream> write)
    {
        using var stream = new MemoryStream();
        using (var output = new CodedOutputStream(stream, leaveOpen: true))
        {
            write(output);
            output.Flush();
        }
        return stream.ToArray();
    }

    [Fact(Timeout = 60000)]
    public async Task ClosedPolicyStoreFailsClosedWithoutFallingBackToDefaults()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var store = fixture.Node.Runtime.Store;
        await fixture.Node.StopAsync();
        Assert.Throws<ObjectDisposedException>(() => store.Read(PolicyRules.Current));
        var meta = CloudNode.Command();
        var environment = new EnvironmentSpec { Inherit = EnvironmentInherit.None };
        environment.Set["AF_DISPLAY"] = "blue";
        var request = new TaskServiceSubmitTaskRequest { Meta = meta, Spec = new TaskSpec { Environment = environment } };
        var error = RoutedEnvironmentGuard.Check(request.ToByteString(), ownNode: true, meta.CorrelationId, TimeProvider.System,
            () => store.Read(PolicyRules.Current).Document.Privacy?.SecretNamePatterns.ToArray() ?? []);
        Assert.True(error is { Code: "invalid_state", Effect: EffectCertainty.DidNotHappen });
        Assert.Equal(RetryMode.Never, error.Retry.Mode);
        Assert.True(ArcForges.Contracts.Node.Shapes.ContractShapeValidation.IsValid(error));
        Assert.True(error.Details.State.Reason.Contains("policy", StringComparison.OrdinalIgnoreCase));
        Assert.True(fixture.Center.CallsOf("SubmitNodeTask").Count == 0);
    }

    [Fact(Timeout = 60000)]
    public async Task SafeNonCanonicalWireAndUnrelatedUnknownFieldsKeepExactBytesOnRetry()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Script("SubmitNodeTask", new FakeFault.Transport(14, "dependency.unavailable"));
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, CommandIds.New())));
        var meta = CloudNode.Command();
        var entry = Encode(output =>
        {
            output.WriteTag(18); output.WriteString("blue"); // value before key is valid protobuf
            output.WriteTag(10); output.WriteString("AF_DISPLAY");
        });
        var environment = Encode(output => { output.WriteTag(18); output.WriteBytes(ByteString.CopyFrom(entry)); output.WriteTag(8); output.WriteEnum((int)EnvironmentInherit.None); });
        var spec = Encode(output =>
        {
            output.WriteTag(192); output.WriteUInt32(1); // unrelated future TaskSpec field
            output.WriteTag(26); output.WriteBytes(ByteString.CopyFrom(environment));
        });
        var request = ByteString.CopyFrom(Encode(output =>
        {
            output.WriteTag(82); output.WriteBytes(ByteString.CopyFrom(spec)); // spec before meta
            output.WriteTag(10); output.WriteMessage(meta);
            output.WriteTag(128); output.WriteUInt32(1); // unrelated future request field
        }));
        var error = await Assert.ThrowsAsync<Grpc.Core.RpcException>(async () => await DirectRawSubmitAsync(fixture, fixture.NodeId, meta, request));
        Assert.Equal(Grpc.Core.StatusCode.Unavailable, error.StatusCode);
        var answer = await DirectRawSubmitAsync(fixture, fixture.NodeId, meta, request);
        Assert.NotNull(answer.Value);
        var calls = fixture.Center.CallsOf("SubmitNodeTask").Select(call => FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body))).ToList();
        Assert.Equal(2, calls.Count);
        Assert.All(calls, call => Assert.True(call.Request.Equals(request), "the exact accepted wire bytes must be retained"));
        Assert.All(calls, call => Assert.Equal(meta.CommandId, call.Meta.CommandId));
    }

    [Fact(Timeout = 60000)]
    public async Task SafeOwnEnvironmentRetriesTheSameBytesAndCommand()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Script("SubmitNodeTask", new FakeFault.Transport(14, "dependency.unavailable"));
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, CommandIds.New())));
        var result = await fixture.CliSyntheticAsync("run", "--detach", "--env-inherit", "none", "--env", "AF_DISPLAY=blue", "--", "test-program");
        Assert.Equal(0, result.ExitCode);
        var calls = fixture.Center.CallsOf("SubmitNodeTask").Select(call => FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body))).ToList();
        Assert.Equal(2, calls.Count);
        Assert.True(calls[0].Request.Equals(calls[1].Request), "safe retries preserve the exact inner bytes");
        Assert.Equal(calls[0].Meta.CommandId, calls[1].Meta.CommandId);
        Assert.False(calls[0].Request.Span.IndexOf(Encoding.UTF8.GetBytes(SyntheticEnvironmentValue)) >= 0);
    }

    [Fact(Timeout = 60000)]
    public async Task ExplicitSafeCallerEnvironmentCanReachItsOwnNode()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, CommandIds.New())));
        var result = await fixture.CliSyntheticSafeAsync("run", "--detach", "--env-inherit", "caller", "--", "test-program");
        Assert.Equal(0, result.ExitCode);
        var outer = FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(fixture.Center.CallsOf("SubmitNodeTask")).Body));
        var environment = TaskServiceSubmitTaskRequest.Parser.ParseFrom(outer.Request).Spec.Environment;
        Assert.Equal(EnvironmentInherit.Caller, environment.Inherit);
        Assert.True(environment.CallerEnvironment.TryGetValue("AF_DISPLAY", out var value) && value == "blue", "safe caller entry remains intact");
        Assert.False(outer.Request.Span.IndexOf(Encoding.UTF8.GetBytes(SyntheticEnvironmentValue)) >= 0);
    }

    [Fact(Timeout = 60000)]
    public async Task LocalDiagnosticCanStillSubmitWithCallerInheritance()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var result = await fixture.CliSyntheticAsync("run", "--local", "--detach", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.True(result.ExitCode == 0, "local diagnostic caller inheritance remains available");
        Assert.True(IdText.TryParse(result.Stdout.Trim(), out var taskId));
        await using var human = await fixture.Node.ChannelAsync(Origin.Human);
        var task = await human.Tasks.GetTaskAsync(new TaskServiceGetTaskRequest
        {
            Meta = CloudNode.Command(),
            TaskId = new Id { Value = ByteString.CopyFrom(taskId) },
            Detail = TaskDetail.Full,
        }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(task.Error);
        Assert.Equal(EnvironmentInherit.Caller, task.Value.Task.Spec.Environment.Inherit);
        Assert.True(fixture.Center.CallsOf("SubmitNodeTask").Count == 0);
        Assert.False(result.Stdout.Contains(SyntheticEnvironmentValue, StringComparison.Ordinal));
        Assert.False(result.Stderr.Contains(SyntheticEnvironmentValue, StringComparison.Ordinal));
    }

    private static int NonceRequests(FakeCenter center) => center.Channel.Connections.SelectMany(connection => connection.Received)
        .Count(frame => frame.FrameCase == RelayFrame.FrameOneofCase.RelayNonceRequest);

    private static async Task<FleetServiceSubmitNodeTaskResponse> DirectSubmitAsync(Fixture fixture, Id target, EnvironmentSpec environment)
    {
        await using var script = await fixture.Node.ChannelAsync(Origin.Script);
        var meta = CloudNode.Command();
        var inner = new TaskServiceSubmitTaskRequest { Meta = meta.Clone(), Spec = new TaskSpec { Environment = environment } };
        var fleet = new FleetService.FleetServiceClient(script.CallInvoker);
        return await fleet.SubmitNodeTaskAsync(new FleetServiceSubmitNodeTaskRequest { Meta = meta, NodeId = target, Request = inner.ToByteString() },
            deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: TestContext.Current.CancellationToken);
    }

    private static async Task<FleetServiceSubmitNodeTaskResponse> DirectRawSubmitAsync(Fixture fixture, Id target, RequestMeta meta, ByteString request)
    {
        await using var script = await fixture.Node.ChannelAsync(Origin.Script);
        var fleet = new FleetService.FleetServiceClient(script.CallInvoker);
        return await fleet.SubmitNodeTaskAsync(new FleetServiceSubmitNodeTaskRequest { Meta = meta, NodeId = target, Request = request },
            deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: TestContext.Current.CancellationToken);
    }

    [Fact(Timeout = 60000)]
    public async Task TheDefaultRunRefusesWithoutAConnectedAccount()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync(signedIn: false);
        var result = await fixture.CliAsync("run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.Equal(4, result.ExitCode);
        Assert.Empty(result.Stdout);
        Assert.Contains("not signed in", result.Stderr, StringComparison.Ordinal);
        Assert.Contains("run --local", result.Stderr, StringComparison.Ordinal);
        Assert.Empty(fixture.Center.CallsOf("SubmitNodeTask"));
    }

    [Fact(Timeout = 60000)]
    public async Task ADisconnectedOwnChannelDoesNotFallBackToLocalExecution()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        await using var human = await fixture.Node.ChannelAsync(Origin.Human);
        var disabled = await human.Account.SetCloudLinkAsync(new AccountServiceSetCloudLinkRequest { Meta = CloudNode.Command(), Enabled = false },
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(disabled.Error);
        var result = await fixture.CliAsync("run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.Equal(4, result.ExitCode);
        Assert.Empty(result.Stdout);
        Assert.Contains("unavailable", result.Stderr, StringComparison.Ordinal);
        Assert.Contains("run --local", result.Stderr, StringComparison.Ordinal);
        Assert.Empty(fixture.Center.CallsOf("SubmitNodeTask"));
    }

    [Fact(Timeout = 60000)]
    public async Task ATargetOfflineWithoutAnEarlierUncertainResultExitsSeventyFive()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Script("SubmitNodeTask", Reply(new FleetServiceSubmitNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Error = new ArcError
            {
                Category = ErrorCategory.State,
                Code = "node_offline",
                MessageKey = "error.state.node_offline",
                Effect = EffectCertainty.DidNotHappen,
                Retry = new RetryAdvice { Mode = RetryMode.Never },
            },
        }));
        var result = await fixture.CliAsync("run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.Equal(75, result.ExitCode);
        Assert.Empty(result.Stdout);
        Assert.DoesNotContain("may have run", result.Stderr, StringComparison.Ordinal);
        Assert.Single(fixture.Center.CallsOf("SubmitNodeTask"));
    }

    [Fact(Timeout = 60000)]
    public async Task ExplicitWaitWithoutDurationIsAttachedAndConflictsWithDetach()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync(signedIn: false);
        var waiting = await fixture.CliAsync("run", "--wait", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.Equal(4, waiting.ExitCode);
        Assert.Contains("not signed in", waiting.Stderr, StringComparison.Ordinal);
        var conflicting = await fixture.CliAsync("run", "--detach", "--wait", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.Equal(2, conflicting.ExitCode);
        Assert.Contains("cannot be combined", conflicting.Stderr, StringComparison.Ordinal);
    }

    [Fact(Timeout = 60000)]
    public async Task APreviouslyUncertainMutationIsNotReclassifiedAsOffline()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Script("SubmitNodeTask", new FakeFault.Transport(14, "dependency.unavailable"));
        fixture.Center.Script("SubmitNodeTask", Reply(new FleetServiceSubmitNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Error = new ArcError
            {
                Category = ErrorCategory.State,
                Code = "node_offline",
                MessageKey = "error.state.node_offline",
                Effect = EffectCertainty.DidNotHappen,
                Retry = new RetryAdvice { Mode = RetryMode.Never },
            },
        }));
        var result = await fixture.CliAsync("run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.NotEqual(0, result.ExitCode);
        Assert.NotEqual(75, result.ExitCode);
        Assert.Contains("may have run", result.Stderr, StringComparison.Ordinal);
        Assert.Equal(2, fixture.Center.CallsOf("SubmitNodeTask").Count);
    }

    [Theory(Timeout = 60000)]
    [InlineData(@"C:\target\work", @"C:\target\input.bin", @"C:\target\ready")]
    [InlineData("/target/work", "/target/input.bin", "/target/ready")]
    [InlineData(@"\\server\share\work", @"\\server\share\input.bin", @"\\server\share\ready")]
    public async Task ForeignTargetPathsAreNotInterpretedByTheCallingOs(string cwd, string stdin, string ready)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var target = CommandIds.New();
        var task = CommandIds.New();
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(target, task)));
        var uuid = new Guid(target.Value.Span, bigEndian: true).ToString("D");
        var result = await fixture.CliAsync("run", "--detach", "--node", uuid, "--cwd", cwd, "--stdin", "file:" + stdin,
            "--ready-file", ready, "--env-inherit", "none", "--", "test-program");
        Assert.Equal(0, result.ExitCode);
        var outer = FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(fixture.Center.CallsOf("SubmitNodeTask")).Body));
        var inner = TaskServiceSubmitTaskRequest.Parser.ParseFrom(outer.Request);
        Assert.Equal(cwd, inner.Spec.WorkingDirectory);
        Assert.Equal(stdin, inner.Spec.Stdin.FilePath);
        Assert.Equal(ready, inner.Spec.Readiness.FileExists);
    }

    [Fact(Timeout = 60000)]
    public async Task ForeignTargetRequiresExplicitAbsolutePaths()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var target = CommandIds.New();
        var uuid = new Guid(target.Value.Span, bigEndian: true).ToString("D");
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(target, CommandIds.New())));
        var missing = await fixture.CliAsync("run", "--detach", "--node", uuid, "--env-inherit", "none", "--", "test-program");
        Assert.Equal(2, missing.ExitCode);
        Assert.Contains("--cwd", missing.Stderr, StringComparison.Ordinal);
        var relative = await fixture.CliAsync("run", "--detach", "--node", uuid, "--cwd", "relative", "--env-inherit", "none", "--", "test-program");
        Assert.Equal(2, relative.ExitCode);
        Assert.Contains("absolute", relative.Stderr, StringComparison.Ordinal);
        var stdin = await fixture.CliAsync("run", "--detach", "--node", uuid, "--cwd", "/target/work", "--stdin", "file:relative", "--", "test-program");
        Assert.Equal(2, stdin.ExitCode);
        Assert.Contains("--stdin", stdin.Stderr, StringComparison.Ordinal);
        var ready = await fixture.CliAsync("run", "--detach", "--node", uuid, "--cwd", "/target/work", "--ready-file", "relative", "--", "test-program");
        Assert.Equal(2, ready.ExitCode);
        Assert.Contains("--ready-file", ready.Stderr, StringComparison.Ordinal);
        Assert.Empty(fixture.Center.CallsOf("SubmitNodeTask"));
    }

    [Fact(Timeout = 60000)]
    public async Task ExplicitOwnNodeKeepsLocalPathDefaultsAndRelativePaths()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, CommandIds.New())));
        var uuid = new Guid(fixture.NodeId.Value.Span, bigEndian: true).ToString("D");
        var result = await fixture.CliAsync("run", "--detach", "--node", uuid, "--stdin", "file:input.bin", "--ready-file", "ready", "--", "test-program");
        Assert.Equal(0, result.ExitCode);
        var outer = FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(fixture.Center.CallsOf("SubmitNodeTask")).Body));
        var spec = TaskServiceSubmitTaskRequest.Parser.ParseFrom(outer.Request).Spec;
        Assert.Equal(Directory.GetCurrentDirectory(), spec.WorkingDirectory);
        Assert.Equal(Path.GetFullPath("input.bin"), spec.Stdin.FilePath);
        Assert.Equal(Path.GetFullPath("ready"), spec.Readiness.FileExists);
    }

    [Fact(Timeout = 60000)]
    public async Task JsonOutputPreservesBinaryDataIndexAndEof()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var task = CommandIds.New();
        var attempt = CommandIds.New();
        fixture.Center.Script("GetNodeTask", Reply(GetResult(fixture.NodeId, task, attempt, TaskState.Succeeded)));
        fixture.Center.Script("ReadNodeTaskOutput", Reply(ReadResult(fixture.NodeId, new TaskServiceReadTaskOutputValue
        {
            Data = ByteString.CopyFrom([0, 255, 65]),
            NextOffset = 3,
            Eof = true,
            TruncatedByRetention = true,
            Index = { new OutputIndexRecord { Stream = OutputStream.Stdout, Offset = 0, Length = 1 }, new OutputIndexRecord { Stream = OutputStream.Stderr, Offset = 0, Length = 2 } },
        })));
        var result = await fixture.CliAsync("--json", "output", IdText.Format(task));
        Assert.Equal(0, result.ExitCode);
        using var document = System.Text.Json.JsonDocument.Parse(result.Stdout);
        var value = document.RootElement;
        Assert.Equal(new byte[] { 0, 255, 65 }, value.GetProperty("data").GetBytesFromBase64());
        Assert.Equal("3", value.GetProperty("nextOffset").GetString());
        Assert.True(value.GetProperty("eof").GetBoolean());
        Assert.True(value.GetProperty("truncatedByRetention").GetBoolean());
        Assert.Equal(2, value.GetProperty("index").GetArrayLength());
        Assert.Equal("OUTPUT_STREAM_STDOUT", value.GetProperty("index")[0].GetProperty("stream").GetString());
        Assert.Equal("OUTPUT_STREAM_STDERR", value.GetProperty("index")[1].GetProperty("stream").GetString());
        Assert.Equal("0", value.GetProperty("index")[0].GetProperty("offset").GetString());
        Assert.Equal(1U, value.GetProperty("index")[0].GetProperty("length").GetUInt32());
        Assert.Equal("0", value.GetProperty("index")[1].GetProperty("offset").GetString());
        Assert.Equal(2U, value.GetProperty("index")[1].GetProperty("length").GetUInt32());
    }

    [Fact(Timeout = 60000)]
    public async Task JsonOutputFollowUsesLinesAndPreservesOffsetsAndBothStreams()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var task = CommandIds.New();
        var attempt = CommandIds.New();
        fixture.Center.Script("GetNodeTask", Reply(GetResult(fixture.NodeId, task, attempt, TaskState.Running)));
        fixture.Center.Script("ReadNodeTaskOutput", Reply(ReadResult(fixture.NodeId, new TaskServiceReadTaskOutputValue
        {
            Data = ByteString.CopyFrom([255, 0]),
            NextOffset = 2,
            Eof = false,
            Index = { new OutputIndexRecord { Stream = OutputStream.Stdout, Offset = 0, Length = 2 } },
        })));
        fixture.Center.Script("GetNodeTask", Reply(GetResult(fixture.NodeId, task, attempt, TaskState.Succeeded)));
        fixture.Center.Script("ReadNodeTaskOutput", Reply(ReadResult(fixture.NodeId, new TaskServiceReadTaskOutputValue
        {
            Data = ByteString.CopyFrom([128, 66]),
            NextOffset = 4,
            Eof = true,
            Index = { new OutputIndexRecord { Stream = OutputStream.Stderr, Offset = 0, Length = 2 } },
        })));
        var result = await fixture.CliAsync("--json", "output", IdText.Format(task), "--follow");
        Assert.Equal(0, result.ExitCode);
        Assert.Empty(result.Stderr);
        var lines = result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        using var first = System.Text.Json.JsonDocument.Parse(lines[0]);
        using var last = System.Text.Json.JsonDocument.Parse(lines[1]);
        Assert.Equal(new byte[] { 255, 0 }, first.RootElement.GetProperty("data").GetBytesFromBase64());
        Assert.Equal("2", first.RootElement.GetProperty("nextOffset").GetString());
        Assert.False(first.RootElement.GetProperty("eof").GetBoolean());
        Assert.Equal("OUTPUT_STREAM_STDOUT", first.RootElement.GetProperty("index")[0].GetProperty("stream").GetString());
        Assert.Equal(new byte[] { 128, 66 }, last.RootElement.GetProperty("data").GetBytesFromBase64());
        Assert.Equal("4", last.RootElement.GetProperty("nextOffset").GetString());
        Assert.True(last.RootElement.GetProperty("eof").GetBoolean());
        Assert.Equal("OUTPUT_STREAM_STDERR", last.RootElement.GetProperty("index")[0].GetProperty("stream").GetString());
        var reads = fixture.Center.CallsOf("ReadNodeTaskOutput").Select(call => TaskServiceReadTaskOutputRequest.Parser.ParseFrom(
            FleetServiceReadNodeTaskOutputRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body)).Request).FromOffset).ToList();
        Assert.Equal([0UL, 2UL], reads);
    }

    [Fact(Timeout = 60000)]
    public async Task SentMutationTransportFailureStaysUncertain()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        await using var script = await fixture.Node.ChannelAsync(Origin.Script);
        var fleet = new FleetService.FleetServiceClient(script.CallInvoker);
        fixture.Center.Script("CancelNodeTask", new FakeFault.Transport(14, "dependency.unavailable"));
        var meta = CloudNode.Command();
        var inner = new TaskServiceCancelTaskRequest { Meta = meta.Clone(), TaskId = CommandIds.New() }.ToByteString();
        var error = await Assert.ThrowsAsync<Grpc.Core.RpcException>(async () => await fleet.CancelNodeTaskAsync(
            new FleetServiceCancelNodeTaskRequest { Meta = meta, NodeId = fixture.NodeId, Request = inner }, deadline: DateTime.UtcNow.AddSeconds(15),
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(Grpc.Core.StatusCode.Unavailable, error.StatusCode);
        Assert.Single(fixture.Center.CallsOf("CancelNodeTask"));
    }

    [Fact(Timeout = 60000)]
    public async Task DisconnectedProxyErrorHasAValidRetryContract()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        await using var human = await fixture.Node.ChannelAsync(Origin.Human);
        var disabled = await human.Account.SetCloudLinkAsync(new AccountServiceSetCloudLinkRequest { Meta = CloudNode.Command(), Enabled = false },
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(disabled.Error);
        await using var script = await fixture.Node.ChannelAsync(Origin.Script);
        var fleet = new FleetService.FleetServiceClient(script.CallInvoker);
        var correlation = CommandIds.New();
        var response = await fleet.ListNodesAsync(new FleetServiceListNodesRequest { Meta = new RequestMeta { CorrelationId = correlation } },
            deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("cloud_unreachable", response.Error.Code);
        Assert.True(ArcForges.Contracts.Node.Shapes.ContractShapeValidation.IsValid(response.Error));
        Assert.Equal(correlation, response.Error.CorrelationId);
        Assert.Equal("cloud_link", response.Error.Details.State.State);
        Assert.Equal("channel_not_connected", response.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        Assert.Equal(RetryMode.AfterTime, response.Error.Retry.Mode);
        Assert.InRange(ProtoTime.ToDateTimeOffset(response.Error.Retry.RetryAt)!.Value, DateTimeOffset.UtcNow.AddSeconds(-2), DateTimeOffset.UtcNow.AddSeconds(10));
        Assert.Empty(fixture.Center.CallsOf("ListNodes"));
    }

    [Fact(Timeout = 60000)]
    public async Task PreSendConnectionFailureReturnsAValidDidNotHappenError()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        await using var script = await fixture.Node.ChannelAsync(Origin.Script);
        var fleet = new FleetService.FleetServiceClient(script.CallInvoker);
        fixture.Node.Cloud.BeforeRelayForward = async token =>
        {
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(token);
            stop.CancelAfter(TimeSpan.FromSeconds(3));
            try
            {
                await fixture.Center.StopAsync(stop.Token);
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                // The listener is stopped before the bounded drain of its existing WebSocket completes.
            }
        };
        var meta = CloudNode.Command();
        var inner = new TaskServiceCancelTaskRequest { Meta = meta.Clone(), TaskId = CommandIds.New() }.ToByteString();
        var response = await fleet.CancelNodeTaskAsync(new FleetServiceCancelNodeTaskRequest { Meta = meta, NodeId = fixture.NodeId, Request = inner },
            deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("cloud_unreachable", response.Error.Code);
        Assert.True(ArcForges.Contracts.Node.Shapes.ContractShapeValidation.IsValid(response.Error));
        Assert.Equal(meta.CorrelationId, response.Error.CorrelationId);
        Assert.Equal("cloud_link", response.Error.Details.State.State);
        Assert.Equal("center_unreachable", response.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        Assert.Equal(RetryMode.AfterTime, response.Error.Retry.Mode);
        Assert.InRange(ProtoTime.ToDateTimeOffset(response.Error.Retry.RetryAt)!.Value, DateTimeOffset.UtcNow.AddSeconds(-2), DateTimeOffset.UtcNow.AddSeconds(10));
        Assert.Empty(fixture.Center.CallsOf("CancelNodeTask"));
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task RoutedListHonorsTheGlobalUnaryDeadline()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Script("ListNodeTasks", new FakeFault.Delay(TimeSpan.FromSeconds(5)));
        fixture.Center.Script("ListNodeTasks", Reply(new FleetServiceListNodeTasksResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceListNodeTasksValue
            {
                NodeId = fixture.NodeId,
                Response = new TaskServiceListTasksResponse
                {
                    Meta = new ResponseMeta(),
                    Value = new TaskServiceListTasksValue { Page = new PageState { HasMore = false } },
                }.ToByteString(),
            },
        }));
        var started = Stopwatch.StartNew();
        var result = await fixture.CliAsync("tasks", "list", "--timeout", "1s");
        Assert.NotEqual(0, result.ExitCode);
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(4), "a one-second unary budget must not wait for the five-second reply");
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task RoutedWaitHonorsItsRemainingTargetBudget()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var task = CommandIds.New();
        fixture.Center.Script("WaitNodeTask", new FakeFault.Delay(TimeSpan.FromSeconds(5)));
        fixture.Center.Script("WaitNodeTask", Reply(new FleetServiceWaitNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceWaitNodeTaskValue
            {
                NodeId = fixture.NodeId,
                Response = new TaskServiceWaitTaskResponse
                {
                    Meta = new ResponseMeta(),
                    Value = new TaskServiceWaitTaskValue { Task = new ManagedTask { TaskId = task, State = TaskState.Running }, Reached = false },
                }.ToByteString(),
            },
        }));
        var started = Stopwatch.StartNew();
        var result = await fixture.CliAsync("tasks", "wait", IdText.Format(task), "--timeout", "1s", "--output", "none");
        Assert.Equal(9, result.ExitCode);
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(4), "a one-second wait budget must not wait for the five-second reply");
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task UnaryDeadlineCancelsAStalledNonceWithoutSendingTheRequest()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Channel.AnswerNonces = false;
        var started = Stopwatch.StartNew();
        var result = await fixture.CliAsync("tasks", "list", "--timeout", "1s");
        Assert.NotEqual(0, result.ExitCode);
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(4), "the deadline must include the local proxy signing/nonce wait");
        Assert.Empty(fixture.Center.CallsOf("ListNodeTasks"));
        Assert.Contains(fixture.Center.Channel.Connections.SelectMany(connection => connection.Received),
            frame => frame.FrameCase == RelayFrame.FrameOneofCase.RelayNonceRequest);
    }

    [Fact(Timeout = 60000)]
    public async Task CallerCancellationDuringNonceWaitNeverSendsTheRequest()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Channel.AnswerNonces = false;
        await using var script = await fixture.Node.ChannelAsync(Origin.Script);
        var fleet = new FleetService.FleetServiceClient(script.CallInvoker);
        using var cancelled = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var pending = fleet.ListNodesAsync(new FleetServiceListNodesRequest { Meta = CloudNode.Command() }, cancellationToken: cancelled.Token).ResponseAsync;
        await Eventually.TrueAsync(() => fixture.Center.Channel.Connections.SelectMany(connection => connection.Received)
            .Any(frame => frame.FrameCase == RelayFrame.FrameOneofCase.RelayNonceRequest), "nonce requested");
        await cancelled.CancelAsync();
        var error = await Record.ExceptionAsync(async () => await pending);
        Assert.True(error is OperationCanceledException or Grpc.Core.RpcException { StatusCode: Grpc.Core.StatusCode.Cancelled },
            "the local caller's cancellation must propagate");
        Assert.Empty(fixture.Center.CallsOf("ListNodes"));
    }

    [Fact(Timeout = 60000)]
    public async Task ClosingTheLocalSessionDuringNonceWaitCannotSendTheMutation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Channel.AnswerNonces = false;
        var script = await fixture.Node.ChannelAsync(Origin.Script);
        var disposed = false;
        try
        {
            var meta = CloudNode.Command();
            var inner = new TaskServiceSubmitTaskRequest { Meta = meta.Clone(), Spec = new TaskSpec { Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.None } } };
            var fleet = new FleetService.FleetServiceClient(script.CallInvoker);
            var before = NonceRequests(fixture.Center);
            var pending = fleet.SubmitNodeTaskAsync(new FleetServiceSubmitNodeTaskRequest { Meta = meta, NodeId = fixture.NodeId, Request = inner.ToByteString() },
                deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: ct).ResponseAsync;
            await Eventually.TrueAsync(() => NonceRequests(fixture.Center) > before, "mutation nonce requested");
            await script.DisposeAsync();
            disposed = true;
            var error = await Record.ExceptionAsync(async () => await pending);
            Assert.True(error is OperationCanceledException or ObjectDisposedException
                or Grpc.Core.RpcException { StatusCode: Grpc.Core.StatusCode.Cancelled or Grpc.Core.StatusCode.Unavailable });
            Assert.Empty(fixture.Center.CallsOf("SubmitNodeTask"));
        }
        finally
        {
            if (!disposed)
            {
                await script.DisposeAsync();
            }
        }
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task RoutedNameResolutionHonorsTheGlobalUnaryDeadline()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Script("ListNodes", new FakeFault.Delay(TimeSpan.FromSeconds(5)));
        fixture.Center.Script("ListNodes", Reply(new FleetServiceListNodesResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceListNodesValue { Nodes = { new FleetNode { NodeId = fixture.NodeId, Name = "build-box" } } },
        }));
        var started = Stopwatch.StartNew();
        var result = await fixture.CliAsync("tasks", "list", "--node", "build-box", "--timeout", "1s");
        Assert.NotEqual(0, result.ExitCode);
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(4), "node-name resolution must honor the one-second unary deadline");
        Assert.Empty(fixture.Center.CallsOf("ListNodeTasks"));
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task TimedOutMutationRetriesTheSameBytesAndCommandWithinTheUnaryDeadline()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var task = CommandIds.New();
        fixture.Center.Script("CancelNodeTask", new FakeFault.Delay(TimeSpan.FromSeconds(5)));
        fixture.Center.Script("CancelNodeTask", Reply(new FleetServiceCancelNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceCancelNodeTaskValue
            {
                NodeId = fixture.NodeId,
                Response = new TaskServiceCancelTaskResponse
                {
                    Meta = new ResponseMeta(),
                    Value = new TaskServiceCancelTaskValue { State = TaskState.Cancelled },
                }.ToByteString(),
            },
        }));
        var result = await fixture.CliAsync("tasks", "cancel", IdText.Format(task), "--timeout", "1s");
        Assert.Equal(0, result.ExitCode);
        var calls = fixture.Center.CallsOf("CancelNodeTask");
        Assert.Equal(2, calls.Count);
        var first = FleetServiceCancelNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(calls[0].Body));
        var second = FleetServiceCancelNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(calls[1].Body));
        Assert.Equal(first.Meta.CommandId, second.Meta.CommandId);
        Assert.Equal(first.Request, second.Request);
        Assert.All(calls, call => Assert.InRange(GrpcTimeout(call.GrpcTimeout), TimeSpan.Zero, TimeSpan.FromMilliseconds(1100)));
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task RunTimeoutIsTheTasksExecutionLimitNotTheUnaryDeadline()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Script("ListNodes", new FakeFault.Delay(TimeSpan.FromSeconds(2)));
        fixture.Center.Script("ListNodes", Reply(new FleetServiceListNodesResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceListNodesValue { Nodes = { new FleetNode { NodeId = fixture.NodeId, Name = "build-box" } } },
        }));
        fixture.Center.Script("SubmitNodeTask", new FakeFault.Delay(TimeSpan.FromSeconds(2)));
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, CommandIds.New())));
        var result = await fixture.CliAsync("run", "--detach", "--node", "build-box", "--timeout", "1s", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.Equal(0, result.ExitCode);
        Assert.True(GrpcTimeout(Assert.Single(fixture.Center.CallsOf("ListNodes")).GrpcTimeout) > TimeSpan.FromSeconds(2));
        var call = Assert.Single(fixture.Center.CallsOf("SubmitNodeTask"));
        var outer = FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body));
        Assert.Equal(1000UL, TaskServiceSubmitTaskRequest.Parser.ParseFrom(outer.Request).Spec.TimeoutMs);
        Assert.True(GrpcTimeout(call.GrpcTimeout) > TimeSpan.FromSeconds(2));
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task DefaultRoutedWaitRetainsTheLongPollBudget()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var task = CommandIds.New();
        fixture.Center.Script("WaitNodeTask", new FakeFault.Delay(TimeSpan.FromSeconds(2)));
        fixture.Center.Script("WaitNodeTask", Reply(new FleetServiceWaitNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceWaitNodeTaskValue
            {
                NodeId = fixture.NodeId,
                Response = new TaskServiceWaitTaskResponse
                {
                    Meta = new ResponseMeta(),
                    Value = new TaskServiceWaitTaskValue
                    {
                        Reached = true,
                        Task = new ManagedTask
                        {
                            TaskId = task,
                            State = TaskState.Succeeded,
                            CurrentAttempt = new Attempt { Result = new AttemptResult { TerminationReason = TerminationReason.Exited, ExitCode = 0 } }
                        },
                    },
                }.ToByteString(),
            },
        }));
        var result = await fixture.CliAsync("tasks", "wait", IdText.Format(task), "--output", "none");
        Assert.Equal(0, result.ExitCode);
        var call = Assert.Single(fixture.Center.CallsOf("WaitNodeTask"));
        var outer = FleetServiceWaitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body));
        Assert.Equal(50_000UL, TaskServiceWaitTaskRequest.Parser.ParseFrom(outer.Request).WaitMs);
        Assert.True(GrpcTimeout(call.GrpcTimeout) > TimeSpan.FromSeconds(50));
    }

    private static TimeSpan GrpcTimeout(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            throw new InvalidOperationException("The center did not receive a gRPC timeout.");
        }

        var amount = double.Parse(text[..^1], System.Globalization.CultureInfo.InvariantCulture);
        return text[^1] switch
        {
            'H' => TimeSpan.FromHours(amount),
            'M' => TimeSpan.FromMinutes(amount),
            'S' => TimeSpan.FromSeconds(amount),
            'm' => TimeSpan.FromMilliseconds(amount),
            'u' => TimeSpan.FromMicroseconds(amount),
            'n' => TimeSpan.FromTicks((long)(amount / 100)),
            _ => throw new InvalidOperationException("Unknown gRPC timeout unit."),
        };
    }

    [Fact(Timeout = 60000)]
    public async Task ATransportRetryUsesTheSameCommandAndExactInnerBytes()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var taskId = CommandIds.New();
        fixture.Center.Script("SubmitNodeTask", new FakeFault.Transport(14, "dependency.unavailable"));
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, taskId)));
        var result = await fixture.CliAsync("run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.Equal(0, result.ExitCode);
        Assert.Equal(IdText.Format(taskId), result.Stdout.Trim());
        var calls = fixture.Center.CallsOf("SubmitNodeTask").Select(call => FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body))).ToList();
        Assert.Equal(2, calls.Count);
        Assert.Equal(calls[0].Request, calls[1].Request);
        Assert.Equal(calls[0].Meta.CommandId, calls[1].Meta.CommandId);
        var first = RelayAssertion.Parser.ParseFrom(calls[0].RelayAssertion);
        var second = RelayAssertion.Parser.ParseFrom(calls[1].RelayAssertion);
        Assert.Equal(first.CommandId, second.CommandId);
        Assert.Equal(first.RequestSha256, second.RequestSha256);
        Assert.NotEqual(first.RelayNonce, second.RelayNonce);
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task UncertainSubmitWaitsForTheOwnChannelAndRetriesTheOriginalBytes()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var taskId = CommandIds.New();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Center.Script("SubmitNodeTask", new FakeFault.Hold(release));
        fixture.Center.Script("SubmitNodeTask", new FakeFault.Transport(14, "dependency.unavailable"));
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, taskId)));
        var cli = fixture.CliSyntheticSafeAsync("--verbose", "run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        try
        {
            await Eventually.TrueAsync(() => fixture.Center.CallsOf("SubmitNodeTask").Count == 1, "the first CLI submit reached FakeCenter");
            var first = FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(fixture.Center.CallsOf("SubmitNodeTask")[0].Body));
            var connection = await fixture.Center.Channel.ProvedAsync();
            await connection.CloseAsync(4500, "shutting_down", 8_000);
            await Eventually.TrueAsync(() => fixture.Node.Cloud.Status().Relay == RelayState.Backoff, "the node channel entered reconnect backoff");
            await using var script = await fixture.Node.ChannelAsync(Origin.Script);
            var proxy = new FleetService.FleetServiceClient(script.CallInvoker);
            var probe = await proxy.SubmitNodeTaskAsync(new FleetServiceSubmitNodeTaskRequest
            {
                Meta = first.Meta.Clone(),
                NodeId = first.NodeId.Clone(),
                Request = first.Request,
            }, deadline: DateTime.UtcNow.AddSeconds(5), cancellationToken: ct);
            TestContext.Current.TestOutputHelper?.WriteLine("disconnected proxy probe: at=" + DateTimeOffset.UtcNow.ToString("O")
                + "; relay=" + fixture.Node.Cloud.Status().Relay + "; code=" + probe.Error?.Code + "; effect=" + probe.Error?.Effect
                + "; retry=" + probe.Error?.Retry?.Mode + "; reason=" + probe.Error?.Details?.State?.Reason
                + "; rawSha256=" + Convert.ToHexStringLower(SHA256.HashData(first.Request.Span)));
            Assert.True(probe.Error is { Code: "cloud_unreachable", Effect: EffectCertainty.DidNotHappen });
            Assert.Equal(RetryMode.AfterTime, probe.Error.Retry.Mode);
            Assert.Equal("channel_not_connected", probe.Error.Details.State.Reason);
            Assert.Single(fixture.Center.CallsOf("SubmitNodeTask"));
            release.TrySetResult();
            var result = await cli;
            Assert.True(result.ExitCode == 0, "CLI must recover its uncertain submission after the same channel reconnects: " + result.Stderr);
            Assert.Equal(IdText.Format(taskId), result.Stdout.Trim());
            Assert.Contains("retrying the same routed command", result.Stderr, StringComparison.Ordinal);
            var calls = fixture.Center.CallsOf("SubmitNodeTask").Select(call => FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body))).ToList();
            Assert.Equal(2, calls.Count);
            Assert.Equal(calls[0].Request, calls[1].Request);
            Assert.Equal(calls[0].Meta.CommandId, calls[1].Meta.CommandId);
        }
        finally
        {
            release.TrySetResult();
            if (!cli.IsCompleted)
            {
                await cli;
            }
        }
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task RelayReconnectWaitRespectsRemainingBudgetAndCallerCancellation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = await Fixture.StartAsync();
        var channel = await fixture.Node.ChannelAsync(Origin.Script);
        await using var session = new NodeSession(channel, new ResolvedEndpoint(fixture.Node.Endpoint, "test", fixture.Node.DataRoot), new NodeServiceHelloValue(), null);
        var cli = new Cli(new CliOutput(TextWriter.Null, TextWriter.Null, json: false, quiet: false, color: false, verbose: false, width: 120), false, null, false);
        var route = new TaskRoute(cli, session, fixture.NodeId, local: false, unaryTimeout: null);
        var connection = await fixture.Center.Channel.ProvedAsync();
        await connection.CloseAsync(4500, "shutting_down", 8_000);
        await Eventually.TrueAsync(() => fixture.Node.Cloud.Status().Relay == RelayState.Backoff, "the node channel entered reconnect backoff");

        var almostExpired = Stopwatch.GetTimestamp() - (long)(119.75 * Stopwatch.Frequency);
        var watch = Stopwatch.StartNew();
        Assert.False(await route.AwaitOwnRelayAsync(almostExpired, ct));
        Assert.InRange(watch.Elapsed, TimeSpan.FromMilliseconds(50), TimeSpan.FromSeconds(3));
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cancel.CancelAfter(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => route.AwaitOwnRelayAsync(Stopwatch.GetTimestamp(), cancel.Token));
        Assert.Empty(fixture.Center.CallsOf("SubmitNodeTask"));
    }

    [Fact(Timeout = 60000)]
    public async Task SwitchingOffTheLinkAfterAnUncertainSubmitStopsWithTheOriginalUnknownOutcome()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = await Fixture.StartAsync();
        await using var human = await fixture.Node.ChannelAsync(Origin.Human);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Center.Script("SubmitNodeTask", new FakeFault.Hold(release));
        fixture.Center.Script("SubmitNodeTask", new FakeFault.Transport(14, "dependency.unavailable"));
        var cli = fixture.CliSyntheticSafeAsync("run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        try
        {
            await Eventually.TrueAsync(() => fixture.Center.CallsOf("SubmitNodeTask").Count == 1, "the first submit reached FakeCenter");
            var first = FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(fixture.Center.CallsOf("SubmitNodeTask")[0].Body));
            Assert.Null((await human.Account.SetCloudLinkAsync(new AccountServiceSetCloudLinkRequest { Meta = CloudNode.Command(), Enabled = false },
                cancellationToken: ct)).Error);
            release.TrySetResult();
            var result = await cli;
            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains("may have run", result.Stderr, StringComparison.Ordinal);
            Assert.Contains(IdText.Format(first.Meta.CommandId), result.Stderr, StringComparison.Ordinal);
            Assert.Single(fixture.Center.CallsOf("SubmitNodeTask"));
        }
        finally
        {
            release.TrySetResult();
            if (!cli.IsCompleted)
            {
                await cli;
            }
        }
    }

    [Fact(Timeout = 60000)]
    public async Task AnUncertainCliSubmitCannotBeRetriedUnderAnotherInstallation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = await Fixture.StartAsync();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Center.Script("SubmitNodeTask", new FakeFault.Hold(release));
        fixture.Center.Script("SubmitNodeTask", new FakeFault.Transport(14, "dependency.unavailable"));
        var cli = fixture.CliSyntheticSafeAsync("run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        try
        {
            await Eventually.TrueAsync(() => fixture.Center.CallsOf("SubmitNodeTask").Count == 1, "the first submit reached FakeCenter");
            var first = FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(fixture.Center.CallsOf("SubmitNodeTask")[0].Body));
            var original = await fixture.Center.Channel.ProvedAsync();
            var id = fixture.Node.Runtime.NodeId.ToArray();
            var replacement = fixture.Center.Issue(id); // same center and display name, distinct account/installation
            using (var key = NodeKeyStores.ForTestDataRoot(fixture.Node.DataRoot).Load(id, fixture.Center.Endpoint.Origin))
            {
                Assert.NotNull(key);
                fixture.Center.Channel.RegisterNodeKey(replacement.AccessToken, key.PublicKey);
            }
            await fixture.Node.Cloud.AdoptAsync(replacement, fixture.Center.Endpoint);
            await original.CloseAsync(4500, "shutting_down", 0);
            await fixture.Center.Channel.ProvedAsync(2);
            await Eventually.TrueAsync(() => fixture.Node.Cloud.Status().Relay == RelayState.Connected, "replacement installation connected");
            release.TrySetResult();
            var result = await cli;
            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains("may have run", result.Stderr, StringComparison.Ordinal);
            Assert.Contains(IdText.Format(first.Meta.CommandId), result.Stderr, StringComparison.Ordinal);
            Assert.Single(fixture.Center.CallsOf("SubmitNodeTask"));
        }
        finally
        {
            release.TrySetResult();
            if (!cli.IsCompleted)
            {
                await cli;
            }
        }
    }

    [Fact(Timeout = 60000)]
    public async Task CredentialRefreshKeepsTheSameCliSessionRelayBinding()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = await Fixture.StartAsync();
        await using var script = await fixture.Node.ChannelAsync(Origin.Script);
        var fleet = new FleetService.FleetServiceClient(script.CallInvoker);
        async Task<FleetServiceSubmitNodeTaskResponse> SubmitAsync()
        {
            var meta = CloudNode.Command();
            var inner = new TaskServiceSubmitTaskRequest { Meta = meta.Clone(), Spec = new TaskSpec { Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.None } } };
            return await fleet.SubmitNodeTaskAsync(new FleetServiceSubmitNodeTaskRequest { Meta = meta, NodeId = fixture.NodeId, Request = inner.ToByteString() },
                deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: ct);
        }

        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, CommandIds.New())));
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, CommandIds.New())));
        Assert.NotNull((await SubmitAsync()).Value);
        var generation = fixture.Node.Cloud.Generation;
        await fixture.Node.Cloud.RefreshAsync(generation, ct);
        Assert.True(fixture.Node.Cloud.Generation > generation);
        await Eventually.TrueAsync(() => fixture.Node.Cloud.Status().Relay == RelayState.Connected, "the refreshed channel remains connected");
        Assert.NotNull((await SubmitAsync()).Value);
        Assert.Equal(2, fixture.Center.CallsOf("SubmitNodeTask").Count);
    }

    [Fact(Timeout = 60000)]
    public async Task ConcurrentFirstRelayBindingsChooseExactlyOneIdentity()
    {
        var ct = TestContext.Current.CancellationToken;
        var binding = new RelayMutationBinding();
        var one = ByteString.CopyFrom(new byte[16]);
        var two = ByteString.CopyFrom(Enumerable.Repeat((byte)1, 16).ToArray());
        Assert.False(binding.TryBind(string.Empty, one));
        Assert.False(binding.TryBind("https://one.example", ByteString.Empty));
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var left = Task.Run(async () => { await start.Task.WaitAsync(ct); return binding.TryBind("https://one.example", one); }, ct);
        var right = Task.Run(async () => { await start.Task.WaitAsync(ct); return binding.TryBind("https://two.example", two); }, ct);
        start.TrySetResult();
        var results = await Task.WhenAll(left, right).WaitAsync(ct);
        Assert.NotEqual(results[0], results[1]);
        var center = results[0] ? "https://one.example" : "https://two.example";
        var installation = results[0] ? one : two;
        var different = results[0] ? two : one;
        Assert.True(binding.TryBind(center, installation)); // a credential refresh with the same identity keeps the binding
        Assert.False(binding.TryBind(center, different));
        Assert.False(binding.TryBind(center + "/other", installation));
        Assert.True(new RelayMutationBinding().TryBind(center, different)); // a new connection has no prior binding
    }

    [Fact(Timeout = 90000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task PinnedLocalConnectionCannotRebindAfterTheNodeRestarts()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = await Fixture.StartAsync();
        await using var channel = await fixture.Node.ChannelAsync(Origin.Script);
        var generation = channel.ConnectionGeneration;
        var session = new NodeSession(channel, new ResolvedEndpoint(fixture.Node.Endpoint, "test", fixture.Node.DataRoot), new NodeServiceHelloValue(), null);
        var cli = new Cli(new CliOutput(TextWriter.Null, TextWriter.Null, json: false, quiet: false, color: false, verbose: false, width: 120), false, null, false);
        var route = new TaskRoute(cli, session, fixture.NodeId, local: false, unaryTimeout: null);
        using (var pin = channel.PinConnection(generation))
        {
            Assert.NotNull(pin);
            await fixture.Node.StopAsync();
            await fixture.Node.StartAsync();
            var error = await Record.ExceptionAsync(async () => await channel.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(),
                deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: ct));
            Assert.IsType<Grpc.Core.RpcException>(error);
            Assert.Equal(generation, channel.ConnectionGeneration);
        }

        // Normal reconnect is available again after the mutation scope, but a new generation cannot impersonate the old hello.
        var answer = await channel.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(),
            deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: ct);
        Assert.Null(answer.Error);
        Assert.True(channel.ConnectionGeneration > generation);
        Assert.Null(channel.PinConnection(generation));
        var refused = await route.SubmitAsync(new TaskServiceSubmitTaskRequest { Meta = CloudNode.Command() }, ct);
        Assert.True(refused.Error is { Code: "invalid_state", Effect: EffectCertainty.DidNotHappen });
        Assert.Equal(RetryMode.Never, refused.Error.Retry.Mode);
        Assert.Equal("session_changed", refused.Error.Details.State.Reason);
        Assert.True(ArcForges.Contracts.Node.Shapes.ContractShapeValidation.IsValid(refused.Error));
        Assert.Empty(fixture.Center.CallsOf("SubmitNodeTask"));
        using var current = channel.PinConnection(channel.ConnectionGeneration);
        Assert.NotNull(current);
    }

    [Fact(Timeout = 60000)]
    public async Task AChangedInstallationCannotReuseTheCliSessionsRelayBindingEvenIfTheFirstSendWasCancelled()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = await Fixture.StartAsync();
        await using var script = await fixture.Node.ChannelAsync(Origin.Script);
        var fleet = new FleetService.FleetServiceClient(script.CallInvoker);
        var meta = CloudNode.Command();
        var inner = new TaskServiceSubmitTaskRequest { Meta = meta.Clone(), Spec = new TaskSpec { Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.None } } };
        var request = new FleetServiceSubmitNodeTaskRequest { Meta = meta, NodeId = fixture.NodeId, Request = inner.ToByteString() };
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(ct);
        fixture.Node.Cloud.BeforeRelayForward = async token =>
        {
            entered.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
        };
        try
        {
            var pending = fleet.SubmitNodeTaskAsync(request, deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: cancel.Token).ResponseAsync;
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
            await cancel.CancelAsync();
            var stopped = await Record.ExceptionAsync(async () => await pending);
            Assert.True(stopped is OperationCanceledException or Grpc.Core.RpcException);
        }
        finally
        {
            fixture.Node.Cloud.BeforeRelayForward = null;
        }

        Assert.Empty(fixture.Center.CallsOf("SubmitNodeTask"));
        var original = await fixture.Center.Channel.ProvedAsync();
        var id = fixture.Node.Runtime.NodeId.ToArray();
        var replacement = fixture.Center.Issue(id);
        using (var key = NodeKeyStores.ForTestDataRoot(fixture.Node.DataRoot).Load(id, fixture.Center.Endpoint.Origin))
        {
            Assert.NotNull(key);
            fixture.Center.Channel.RegisterNodeKey(replacement.AccessToken, key.PublicKey);
        }
        await fixture.Node.Cloud.AdoptAsync(replacement, fixture.Center.Endpoint);
        await original.CloseAsync(4500, "shutting_down", 0);
        await fixture.Center.Channel.ProvedAsync(2);
        await Eventually.TrueAsync(() => fixture.Node.Cloud.Status().Relay == RelayState.Connected, "replacement installation connected");
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, CommandIds.New())));
        var again = await script.Node.HelloAsync(new NodeServiceHelloRequest { Hello = ClientProcess.Hello(ClientKind.McpAdapter) },
            deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: ct);
        Assert.Null(again.Error);
        var refused = await fleet.SubmitNodeTaskAsync(request, deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: ct);
        Assert.True(refused.Error is { Code: "invalid_state", Effect: EffectCertainty.DidNotHappen });
        Assert.Equal(RetryMode.Never, refused.Error.Retry.Mode);
        Assert.Equal("relay_binding_changed", refused.Error.Details.State.Reason);
        Assert.True(ArcForges.Contracts.Node.Shapes.ContractShapeValidation.IsValid(refused.Error));
        Assert.Empty(fixture.Center.CallsOf("SubmitNodeTask"));

        // A new CLI connection is independent: an ordinary new command can use the new installation.
        var freshMeta = CloudNode.Command();
        var freshInner = new TaskServiceSubmitTaskRequest { Meta = freshMeta.Clone(), Spec = new TaskSpec { Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.None } } };
        await using var fresh = await fixture.Node.ChannelAsync(Origin.Script);
        var allowed = await new FleetService.FleetServiceClient(fresh.CallInvoker).SubmitNodeTaskAsync(new FleetServiceSubmitNodeTaskRequest
        {
            Meta = freshMeta,
            NodeId = fixture.NodeId,
            Request = freshInner.ToByteString(),
        }, deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: ct);
        Assert.NotNull(allowed.Value);
        Assert.Single(fixture.Center.CallsOf("SubmitNodeTask"));
    }

    [Fact(Timeout = 60000)]
    public async Task AReplayWindowRefusalNamesTheTaskAndNeverCreatesANewCommand()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var taskId = CommandIds.New();
        fixture.Center.Script("SubmitNodeTask", new FakeFault.Transport(14, "dependency.unavailable"));
        fixture.Center.Script("SubmitNodeTask", Reply(new FleetServiceSubmitNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Error = new ArcError
            {
                Category = ErrorCategory.State,
                Code = "invalid_state",
                MessageKey = "error.state.invalid_state",
                Effect = EffectCertainty.DidNotHappen,
                Retry = new RetryAdvice { Mode = RetryMode.Never },
                Details = new ErrorDetails { State = new StateFailure { State = "task", Reason = "replay_window_passed", Resource = new AggregateRef { Kind = "task", Id = taskId } } },
            },
        }));
        var result = await fixture.CliAsync("run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("may have run", result.Stderr, StringComparison.Ordinal);
        Assert.Contains(IdText.Format(taskId), result.Stderr, StringComparison.Ordinal);
        var calls = fixture.Center.CallsOf("SubmitNodeTask").Select(call => FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body))).ToList();
        Assert.Equal(2, calls.Count);
        Assert.Equal(calls[0].Request, calls[1].Request);
        Assert.Equal(calls[0].Meta.CommandId, calls[1].Meta.CommandId);
        Assert.Contains(IdText.Format(calls[0].Meta.CommandId), result.Stderr, StringComparison.Ordinal);
    }

    [Fact(Timeout = 60000)]
    public async Task AttachedRunMirrorsOutputByOffsetAndReturnsTheTasksExitCode()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var taskId = CommandIds.New();
        var attemptId = CommandIds.New();
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, taskId)));
        fixture.Center.Script("GetNodeTask", Reply(GetResult(fixture.NodeId, taskId, attemptId, TaskState.Running)));
        fixture.Center.Script("ReadNodeTaskOutput", Reply(ReadResult(fixture.NodeId, new TaskServiceReadTaskOutputValue
        {
            Data = ByteString.CopyFromUtf8("abXY"),
            NextOffset = 4,
            Index = { new OutputIndexRecord { Stream = OutputStream.Stdout, Length = 2 }, new OutputIndexRecord { Stream = OutputStream.Stderr, Length = 2 } },
        })));
        fixture.Center.Script("GetNodeTask", Reply(GetResult(fixture.NodeId, taskId, attemptId, TaskState.Succeeded)));
        fixture.Center.Script("ReadNodeTaskOutput", Reply(ReadResult(fixture.NodeId, new TaskServiceReadTaskOutputValue { Data = ByteString.Empty, NextOffset = 4, Eof = true })));
        var result = await fixture.CliAsync("run", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.Equal(7, result.ExitCode);
        Assert.Equal("ab", result.Stdout);
        Assert.Equal("XY", result.Stderr);
        var calls = fixture.Center.CallsOf("ReadNodeTaskOutput").Select(call => FleetServiceReadNodeTaskOutputRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body))).ToList();
        Assert.Equal(2, calls.Count);
        var first = TaskServiceReadTaskOutputRequest.Parser.ParseFrom(calls[0].Request);
        var second = TaskServiceReadTaskOutputRequest.Parser.ParseFrom(calls[1].Request);
        Assert.Equal(0UL, first.FromOffset);
        Assert.Equal(4UL, second.FromOffset);
        Assert.Equal(attemptId, first.AttemptId);
        Assert.True(first.MaxBytes <= 262_144 && second.MaxBytes <= 262_144);
    }

    [Fact(Timeout = 60000)]
    public async Task NodeSelectionUsesExactNamesOrTheCanonicalUuid()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var selected = fixture.NodeId;
        var other = CommandIds.New();
        fixture.Center.Script("ListNodes", Reply(new FleetServiceListNodesResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceListNodesValue
            {
                Nodes = { new FleetNode { NodeId = selected, Name = "build-box" }, new FleetNode { NodeId = other, Name = "build-box" } },
            },
        }));
        var ambiguous = await fixture.CliAsync("tasks", "list", "--node", "build-box");
        Assert.Equal(2, ambiguous.ExitCode);
        Assert.Contains("ambiguous", ambiguous.Stderr, StringComparison.Ordinal);
        Assert.Empty(fixture.Center.CallsOf("ListNodeTasks"));

        var uuid = new Guid(selected.Value.Span, bigEndian: true).ToString("D");
        fixture.Center.Script("ListNodeTasks", Reply(new FleetServiceListNodeTasksResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceListNodeTasksValue
            {
                NodeId = selected,
                Response = new TaskServiceListTasksResponse
                {
                    Meta = new ResponseMeta(),
                    Value = new TaskServiceListTasksValue { Page = new PageState { HasMore = false } },
                }.ToByteString(),
            },
        }));
        var direct = await fixture.CliAsync("tasks", "list", "--node", uuid, "--json");
        Assert.Equal(0, direct.ExitCode);
        using var json = System.Text.Json.JsonDocument.Parse(direct.Stdout);
        Assert.Equal(System.Text.Json.JsonValueKind.Object, json.RootElement.ValueKind);
        var request = FleetServiceListNodeTasksRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(fixture.Center.CallsOf("ListNodeTasks")).Body));
        Assert.Equal(selected, request.NodeId);
        Assert.Single(fixture.Center.CallsOf("ListNodes"));
    }

    [Fact(Timeout = 60000)]
    public async Task OutputResumesAtTheRequestedOffset()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var taskId = CommandIds.New();
        var attemptId = CommandIds.New();
        fixture.Center.Script("GetNodeTask", Reply(GetResult(fixture.NodeId, taskId, attemptId, TaskState.Succeeded)));
        fixture.Center.Script("ReadNodeTaskOutput", Reply(ReadResult(fixture.NodeId,
            new TaskServiceReadTaskOutputValue { Data = ByteString.CopyFromUtf8("cd"), NextOffset = 4, Eof = true })));
        var result = await fixture.CliAsync("output", IdText.Format(taskId), "--from-offset", "2");
        Assert.Equal(0, result.ExitCode);
        Assert.Equal("cd", result.Stdout);
        var outer = FleetServiceReadNodeTaskOutputRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(fixture.Center.CallsOf("ReadNodeTaskOutput")).Body));
        Assert.Equal(2UL, TaskServiceReadTaskOutputRequest.Parser.ParseFrom(outer.Request).FromOffset);
    }

    [Fact(Timeout = 60000)]
    public async Task OutputFollowKeepsAFutureOffsetWithoutReplayingEarlierBytes()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var taskId = CommandIds.New();
        var attemptId = CommandIds.New();
        fixture.Center.Script("GetNodeTask", Reply(GetResult(fixture.NodeId, taskId, attemptId, TaskState.Running)));
        fixture.Center.Script("ReadNodeTaskOutput", Reply(ReadResult(fixture.NodeId,
            new TaskServiceReadTaskOutputValue { Data = ByteString.Empty, NextOffset = 2, Eof = false })));
        fixture.Center.Script("GetNodeTask", Reply(GetResult(fixture.NodeId, taskId, attemptId, TaskState.Succeeded)));
        fixture.Center.Script("ReadNodeTaskOutput", Reply(ReadResult(fixture.NodeId,
            new TaskServiceReadTaskOutputValue { Data = ByteString.CopyFromUtf8("xy"), NextOffset = 7, Eof = true })));
        var result = await fixture.CliAsync("output", IdText.Format(taskId), "--from-offset", "5", "--follow");
        Assert.Equal(0, result.ExitCode);
        Assert.Equal("xy", result.Stdout);
        Assert.Empty(result.Stderr);
        var offsets = fixture.Center.CallsOf("ReadNodeTaskOutput").Select(call =>
            TaskServiceReadTaskOutputRequest.Parser.ParseFrom(FleetServiceReadNodeTaskOutputRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body)).Request).FromOffset).ToList();
        Assert.Equal([5UL, 5UL], offsets);
    }

    [Fact(Timeout = 60000)]
    public async Task WaitShowAndCancelUseTheSelectedRoutedMethods()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var taskId = CommandIds.New();
        var attemptId = CommandIds.New();
        var task = new ManagedTask
        {
            TaskId = taskId,
            State = TaskState.Succeeded,
            Title = "safe\u001b[2Jtitle",
            CurrentAttempt = new Attempt { AttemptId = attemptId, Result = new AttemptResult { TerminationReason = TerminationReason.Exited, ExitCode = 0 } },
        };
        fixture.Center.Script("GetNodeTask", Reply(new FleetServiceGetNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceGetNodeTaskValue
            {
                NodeId = fixture.NodeId,
                Response = new TaskServiceGetTaskResponse { Meta = new ResponseMeta(), Value = new TaskServiceGetTaskValue { Task = task } }.ToByteString(),
            },
        }));
        var shown = await fixture.CliAsync("tasks", "show", IdText.Format(taskId));
        Assert.Equal(0, shown.ExitCode);
        Assert.DoesNotContain("\u001b", shown.Stdout, StringComparison.Ordinal);
        Assert.Contains("safe?[2Jtitle", shown.Stdout, StringComparison.Ordinal);

        fixture.Center.Script("WaitNodeTask", Reply(new FleetServiceWaitNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceWaitNodeTaskValue
            {
                NodeId = fixture.NodeId,
                Response = new TaskServiceWaitTaskResponse { Meta = new ResponseMeta(), Value = new TaskServiceWaitTaskValue { Task = task, Reached = true } }.ToByteString(),
            },
        }));
        var waited = await fixture.CliAsync("tasks", "wait", IdText.Format(taskId), "--output", "none");
        Assert.Equal(0, waited.ExitCode);
        var wait = FleetServiceWaitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(fixture.Center.CallsOf("WaitNodeTask")).Body));
        Assert.True(TaskServiceWaitTaskRequest.Parser.ParseFrom(wait.Request).WaitMs <= 50_000);

        fixture.Center.Script("CancelNodeTask", Reply(new FleetServiceCancelNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceCancelNodeTaskValue
            {
                NodeId = fixture.NodeId,
                Response = new TaskServiceCancelTaskResponse { Meta = new ResponseMeta(), Value = new TaskServiceCancelTaskValue { State = TaskState.Cancelled } }.ToByteString(),
            },
        }));
        var cancelled = await fixture.CliAsync("tasks", "cancel", IdText.Format(taskId), "--reason", "test");
        Assert.Equal(0, cancelled.ExitCode);
        var cancel = FleetServiceCancelNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(fixture.Center.CallsOf("CancelNodeTask")).Body));
        Assert.Equal(cancel.Meta.CommandId, TaskServiceCancelTaskRequest.Parser.ParseFrom(cancel.Request).Meta.CommandId);
    }

    [Fact(Timeout = 60000)]
    public async Task OversizedFullGetAndDigestMismatchAreNotReportedAsSuccess()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var taskId = CommandIds.New();
        fixture.Center.Script("GetNodeTask", Reply(new FleetServiceGetNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Error = new ArcError
            {
                Category = ErrorCategory.Internal,
                Code = "internal",
                MessageKey = "error.internal.internal",
                Effect = EffectCertainty.Unknown,
                Retry = new RetryAdvice { Mode = RetryMode.Never },
            },
        }));
        var get = await fixture.CliAsync("tasks", "show", IdText.Format(taskId), "--full");
        Assert.NotEqual(0, get.ExitCode);
        Assert.Contains("INTERNAL/internal", get.Stderr, StringComparison.Ordinal);
        Assert.DoesNotContain("may have run", get.Stderr, StringComparison.Ordinal);

        fixture.Center.Script("SubmitNodeTask", Reply(new FleetServiceSubmitNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Error = new ArcError
            {
                Category = ErrorCategory.State,
                Code = "node_unreachable",
                MessageKey = "error.state.node_unreachable",
                Effect = EffectCertainty.Unknown,
                Retry = new RetryAdvice { Mode = RetryMode.Never },
                Details = new ErrorDetails { State = new StateFailure { State = "node", Reason = "replay_digest_differs" } },
            },
        }));
        var submit = await fixture.CliAsync("run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.NotEqual(0, submit.ExitCode);
        Assert.Contains("defect", submit.Stderr, StringComparison.Ordinal);
        var sent = FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(fixture.Center.CallsOf("SubmitNodeTask")).Body));
        Assert.Contains(IdText.Format(sent.Meta.CommandId), submit.Stderr, StringComparison.Ordinal);
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task FiveTransportRetriesKeepOneCommandAndFinishWithAnUncertainOutcome()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        for (var i = 0; i < 6; i++)
        {
            fixture.Center.Script("SubmitNodeTask", new FakeFault.Transport(14, "dependency.unavailable"));
        }

        var result = await fixture.CliAsync("run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.NotEqual(0, result.ExitCode);
        Assert.NotEqual(75, result.ExitCode);
        Assert.Contains("may have run", result.Stderr, StringComparison.Ordinal);
        var calls = fixture.Center.CallsOf("SubmitNodeTask").Select(call => FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body))).ToList();
        Assert.Equal(6, calls.Count);
        Assert.All(calls, call => Assert.Equal(calls[0].Request, call.Request));
        Assert.All(calls, call => Assert.Equal(calls[0].Meta.CommandId, call.Meta.CommandId));
        Assert.Contains(IdText.Format(calls[0].Meta.CommandId), result.Stderr, StringComparison.Ordinal);
    }

    private static FleetServiceSubmitNodeTaskResponse SubmitResult(Id node, Id task) => new()
    {
        Meta = new ResponseMeta(),
        Value = new FleetServiceSubmitNodeTaskValue
        {
            NodeId = node,
            Response = new TaskServiceSubmitTaskResponse { Meta = new ResponseMeta(), Value = new TaskServiceSubmitTaskValue { TaskId = task, State = TaskState.Queued } }.ToByteString(),
        },
    };

    private static FleetServiceGetNodeTaskResponse GetResult(Id node, Id task, Id attempt, TaskState state) => new()
    {
        Meta = new ResponseMeta(),
        Value = new FleetServiceGetNodeTaskValue
        {
            NodeId = node,
            Response = new TaskServiceGetTaskResponse
            {
                Meta = new ResponseMeta(),
                Value = new TaskServiceGetTaskValue
                {
                    Task = new ManagedTask
                    {
                        TaskId = task,
                        State = state,
                        CurrentAttempt = new Attempt { AttemptId = attempt, Result = new AttemptResult { TerminationReason = TerminationReason.Exited, ExitCode = 7 } },
                    },
                },
            }.ToByteString(),
        },
    };

    private static FleetServiceReadNodeTaskOutputResponse ReadResult(Id node, TaskServiceReadTaskOutputValue value) => new()
    {
        Meta = new ResponseMeta(),
        Value = new FleetServiceReadNodeTaskOutputValue
        {
            NodeId = node,
            Response = new TaskServiceReadTaskOutputResponse { Meta = new ResponseMeta(), Value = value }.ToByteString(),
        },
    };

    private static FakeFault.Raw Reply(IMessage response) => new([.. FakeCenter.DataFrame(response), .. FakeCenter.TrailerFrame(0, null)]);

    private sealed class Fixture(FakeCenter center, CloudNode node) : IAsyncDisposable
    {
        public FakeCenter Center { get; } = center;

        public CloudNode Node { get; } = node;

        public Id NodeId => new() { Value = ByteString.CopyFrom(Node.Runtime.NodeId.Span) };

        public static async Task<Fixture> StartAsync(bool signedIn = true)
        {
            var center = await FakeCenter.StartAsync();
            center.ScriptedFleet = true;
            var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
            var fixture = new Fixture(center, node);
            if (signedIn)
            {
                var id = node.Runtime.NodeId.ToArray();
                var credentials = center.Issue(id);
                using var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Load(id, center.Endpoint.Origin)
                    ?? NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(id, center.Endpoint.Origin, TimeProvider.System);
                center.CommandKeys.Add(center.Channel.CommandPublicKey);
                center.Channel.RegisterNodeKey(credentials.AccessToken, key.PublicKey);
                await node.Cloud.AdoptAsync(credentials, center.Endpoint);
                await center.Channel.ProvedAsync();
                await Eventually.TrueAsync(() => node.Cloud.Status().Relay == RelayState.Connected, "the node channel is connected");
            }

            return fixture;
        }

        public Task<(int ExitCode, string Stdout, string Stderr)> CliAsync(params string[] args) => StartCliAsync(false, false, args);

        public Task<(int ExitCode, string Stdout, string Stderr)> CliSyntheticAsync(params string[] args) => StartCliAsync(true, true, args);

        public Task<(int ExitCode, string Stdout, string Stderr)> CliSyntheticSafeAsync(params string[] args) => StartCliAsync(true, false, args);

        private async Task<(int ExitCode, string Stdout, string Stderr)> StartCliAsync(bool synthetic, bool includeMarker, string[] args)
        {
            var start = new ProcessStartInfo(CloudNode.HelperExecutable)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                CreateNoWindow = true,
            };
            start.ArgumentList.Add(NodeLocations.TestModeOption);
            foreach (var arg in args)
            {
                start.ArgumentList.Add(arg);
            }

            if (synthetic)
            {
                // Never copy the host environment into these privacy tests; only this deliberately synthetic child receives the marker.
                start.Environment.Clear();
                if (includeMarker)
                {
                    start.Environment["AF_SYNTH_TOKEN"] = SyntheticEnvironmentValue;
                }
                start.Environment["AF_DISPLAY"] = "blue";
                // The installed runtime can live outside the machine-wide default; derive its root from this test process, not the host environment.
                start.Environment["DOTNET_ROOT"] = new DirectoryInfo(System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory()).Parent!.Parent!.Parent!.FullName;
                start.Environment["HOME"] = Node.Root;
                start.Environment["TMP"] = Node.Root;
                start.Environment["TEMP"] = Node.Root;
                start.Environment["TMPDIR"] = Node.Root;
                if (OperatingSystem.IsWindows())
                {
                    start.Environment["SystemRoot"] = @"C:\Windows";
                    start.Environment["WINDIR"] = @"C:\Windows";
                    start.Environment["PATH"] = @"C:\Windows\System32";
                }
                else
                {
                    start.Environment["PATH"] = "/usr/bin:/bin";
                }
            }
            start.Environment[NodeLocations.EndpointVariable] = Node.Endpoint.Address;
            start.Environment[NodeLocations.ConfigDirectoryVariable] = Path.GetDirectoryName(Node.ConfigPath)!;
            start.Environment.Remove("ARCFORGES_OS_SECRET_STORE_TESTS");
            using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start the test CLI.");
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            try
            {
                await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(40));
            }
            catch (TimeoutException)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
                throw;
            }

            return (process.ExitCode, await stdout, await stderr);
        }

        public async ValueTask DisposeAsync()
        {
            await Node.DisposeAsync();
            await Center.DisposeAsync();
        }
    }
}
