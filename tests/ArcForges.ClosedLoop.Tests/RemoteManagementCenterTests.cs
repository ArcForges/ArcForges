// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Platform.Capabilities;
using ArcForges.Tests;
using Google.Protobuf;
using Grpc.Core;
using static ArcForges.ClosedLoop.Tests.CloudLinkCenterControlTests;

namespace ArcForges.ClosedLoop.Tests;

[Trait("loop", "cloud")]
public sealed class RemoteManagementCenterTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 290_000, DisableParallelization = true)]
    public async Task InstalledNodeRoutesTypedControlAndReconcilesItsOriginalRemoteRun()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var (origin, coordination) = RequireNativeFixture();
        await using var fixture = TestNode.Create();
        ConfigureNativeFixture(fixture, origin);
        var process = await fixture.StartNodeAsync();
        await using var local = OpenChannel(fixture);
        var node = new NodeService.NodeServiceClient(local.CallInvoker);
        var control = new CenterControlService.CenterControlServiceClient(local.CallInvoker);
        var sandboxes = new SandboxService.SandboxServiceClient(local.CallInvoker);
        var runs = new RunService.RunServiceClient(local.CallInvoker);
        var resources = new ResourceService.ResourceServiceClient(local.CallInvoker);
        var hello = await node.HandshakeAsync(new() { Meta = Meta() }, deadline: Deadline, cancellationToken: Ct);
        var identity = Value(hello.Value, hello.Error);
        var epoch = identity.OwnerEpoch;
        Assert.NotNull(epoch);
        await using var cleanup = new OwnedNodeCleanup(fixture, process, control, epoch);

        var begin = new CenterControlServiceBeginConnectRequest
        {
            Meta = Meta(mutation: true),
            OwnerEpoch = epoch,
            CenterOrigin = origin,
            ServiceMode = "self_hosted",
            FlowKind = "browser",
        };
        var connecting = await control.BeginConnectAsync(begin, deadline: Deadline, cancellationToken: Ct);
        var flowId = Value(connecting.Value, connecting.Error).FlowId;
        Assert.NotNull(flowId);
        var approval = await WaitForFlowAsync(control, flowId, flow => flow.State == "pending" && flow.HasVerificationUri);
        await WriteObservationAsync(coordination, "approval.json", new { verificationUri = approval.VerificationUri });
        await WaitForFlowAsync(control, flowId, flow => flow.State == "succeeded");
        var connected = await WaitForStatusAsync(control, status => status.ChannelState == "online");
        Assert.NotNull(connected.EnrollmentId);
        await WriteObservationAsync(coordination, "connected.json", new { ownerEpoch = Hex(epoch), nodeEpoch = identity.NodeEpoch });
        await WaitForFixtureAsync(coordination, "connected-confirmed", NativeBound, "the authenticated V2 control peer");

        var config = FixtureConfig();
        var created = await sandboxes.CreateAsync(new()
        {
            Meta = Meta(mutation: true),
            OwnerEpoch = epoch,
            DisplayName = "Unrelated local fixture",
            Config = config,
        }, deadline: Deadline, cancellationToken: Ct);
        var unrelated = Value(created.Value, created.Error).Sandbox;
        var sentinel = Path.Combine(unrelated.DataLocation, "work", "sentinel.txt");
        await File.WriteAllTextAsync(sentinel, "unrelated", Ct);
        var provision = await SetGrantAsync(node, epoch, new()
        {
            GrantId = CommandIds.New(),
            EnrollmentId = connected.EnrollmentId,
            ScopeKind = "provision",
            CreationTemplate = config,
            Methods = { "/arcforges.sandbox.v2.SandboxService/Create", "/arcforges.sandbox.v2.NodeService/GetOperation" },
        });
        await WriteObservationAsync(coordination, "provision.json", new
        {
            grant = Hex(provision.GrantId),
            revision = provision.Revision.Value,
            templateRevision = provision.TemplateRevision.Value,
            config = Convert.ToBase64String(config.ToByteArray()),
            unrelated = Hex(unrelated.SandboxId),
        });

        var createdAtCenter = await ReadAsync(coordination, "center-sandbox.json");
        var sandboxId = ParseId(createdAtCenter, "sandbox");
        var sandbox = await InspectSandboxAsync(sandboxes, sandboxId);
        Assert.Equal("Remote native fixture", sandbox.DisplayName);
        Assert.Equal(config.ProfileId, sandbox.Config.ProfileId);
        Assert.Equal(config.ProfileVersion, sandbox.Config.ProfileVersion);
        Assert.Equal(config.Network, sandbox.Config.Network);
        Assert.Equal(config.Resources, sandbox.Config.Resources);
        await using var drain = new OwnedRunCleanup(runs, epoch, sandboxId);
        var working = Path.Combine(sandbox.DataLocation, "work");
        var argv = HoldingPayload(working);
        var grant = await SetGrantAsync(node, epoch, new()
        {
            GrantId = CommandIds.New(),
            EnrollmentId = connected.EnrollmentId,
            ScopeKind = "sandbox",
            SandboxId = sandboxId,
            ResourceCeiling = config.Resources,
            Methods =
            {
                "/arcforges.sandbox.v2.SandboxService/Configure",
                "/arcforges.sandbox.v2.SandboxService/Inspect",
                "/arcforges.sandbox.v2.ResourceService/GetBudget",
                "/arcforges.sandbox.v2.ResourceService/SetPolicy",
                "/arcforges.sandbox.v2.RunService/Start",
                "/arcforges.sandbox.v2.RunService/Stop",
                "/arcforges.sandbox.v2.RunService/Inspect",
                "/arcforges.sandbox.v2.NodeService/GetOperation",
            },
        });
        await WriteObservationAsync(coordination, "scope.json", new
        {
            grant = Hex(grant.GrantId),
            revision = grant.Revision.Value,
            argv,
        });

        var start = await ReadAsync(coordination, "start-uncertain.json");
        var command = ParseId(start, "command");
        var held = ParseId(start, "run");
        var marker = Path.Combine(working, "remote-held.txt");
        await TestNode.WaitAsync(async () => File.Exists(marker) && (await InspectRunAsync(runs, held)).State == RunState.Running,
            NativeBound, "the native workload marker and durable Running state");
        var original = await InspectOperationAsync(node, epoch, command);
        Assert.Equal(held, original.AggregateId);
        Assert.Equal(OperationState.Succeeded, original.State);
        Assert.Equal(EffectCertainty.Happened, original.Effect);
        Assert.False(original.ResponseCompacted);
        Assert.Equal(held, (await OnlyRunAsync(runs, sandboxId)).RunId);
        var configured = await InspectSandboxAsync(sandboxes, sandboxId);
        Assert.Equal(start.GetProperty("sandboxRevision").GetInt64(), configured.Revision.Value);
        Assert.Equal(224UL << 20, configured.Config.Resources.MemoryMaxBytes);
        var budget = await resources.GetBudgetAsync(new() { Meta = Meta(), ScopeKind = "sandbox", ScopeId = sandboxId },
            deadline: Deadline, cancellationToken: Ct);
        Assert.Equal(start.GetProperty("policyRevision").GetInt64(), Value(budget.Value, budget.Error).Snapshot.PolicyRevision.Value);

        var off = await control.DisconnectAsync(new() { Meta = Meta(mutation: true), OwnerEpoch = epoch },
            deadline: Deadline, cancellationToken: Ct);
        Assert.False(Value(off.Value, off.Error).Connection.ConnectionEnabled);
        Assert.Equal(RunState.Running, (await InspectRunAsync(runs, held)).State);
        begin.Meta = Meta(mutation: true);
        var reenable = await control.BeginConnectAsync(begin, deadline: Deadline, cancellationToken: Ct);
        Assert.Null(Value(reenable.Value, reenable.Error).FlowId);
        var renewed = await WaitForStatusAsync(control, status => status.ChannelState == "online");
        Assert.Equal(connected.EnrollmentId, renewed.EnrollmentId);
        var freshHello = await node.HandshakeAsync(new() { Meta = Meta() }, deadline: Deadline, cancellationToken: Ct);
        var fresh = Value(freshHello.Value, freshHello.Error);
        Assert.Equal(epoch, fresh.OwnerEpoch);
        Assert.Equal(identity.NodeEpoch, fresh.NodeEpoch);
        await WriteObservationAsync(coordination, "reconnected.json", new { ownerEpoch = Hex(epoch), nodeEpoch = fresh.NodeEpoch });

        await WaitForFixtureAsync(coordination, "revoke-ready", NativeBound, "the original receipt was reconciled");
        Assert.Equal(RunState.Running, (await InspectRunAsync(runs, held)).State);
        Assert.Equal(original, await InspectOperationAsync(node, epoch, command));
        var revoke = await node.RevokeRemoteGrantAsync(new()
        {
            Meta = Meta(mutation: true, grant.Revision),
            OwnerEpoch = epoch,
            GrantId = grant.GrantId,
        }, deadline: Deadline, cancellationToken: Ct);
        Assert.Equal(GrantState.Revoked, Value(revoke.Value, revoke.Error).Grant.State);
        Assert.Equal(RunState.Running, (await InspectRunAsync(runs, held)).State);
        await WriteObservationAsync(coordination, "revoked.json", new { run = Hex(held) });

        await WaitForFixtureAsync(coordination, "revocation-confirmed", NativeBound, "the real Center's grant-refusal observations");
        var running = await OnlyRunAsync(runs, sandboxId);
        Assert.Equal(held, running.RunId);
        Assert.Equal(RunState.Running, running.State);
        Assert.Equal(original, await InspectOperationAsync(node, epoch, command));
        const string stopMethod = "/arcforges.sandbox.v2.RunService/Stop";
        var stopGrant = await SetGrantAsync(node, epoch, new()
        {
            GrantId = CommandIds.New(),
            EnrollmentId = connected.EnrollmentId,
            ScopeKind = "sandbox",
            SandboxId = sandboxId,
            Methods = { stopMethod },
        });
        Assert.NotEqual(grant.GrantId, stopGrant.GrantId);
        Assert.Equal(stopMethod, Assert.Single(stopGrant.Methods));
        await WriteObservationAsync(coordination, "stop-authority.json", new
        {
            grant = Hex(stopGrant.GrantId),
            revision = stopGrant.Revision.Value,
            runRevision = running.Revision.Value,
        });

        await WaitForFixtureAsync(coordination, "stopped", NativeBound, "the exact remote Stop response under the new Stop grant");
        await TestNode.WaitAsync(async () => (await InspectRunAsync(runs, held)).State == RunState.Exited,
            NativeBound, "the remote Run and its native process tree drained");
        Assert.Equal(held, (await OnlyRunAsync(runs, sandboxId)).RunId);
        Assert.Equal(original, await InspectOperationAsync(node, epoch, command));
        var unrelatedRuns = await runs.ListAsync(new() { Meta = Meta(), SandboxId = unrelated.SandboxId },
            deadline: Deadline, cancellationToken: Ct);
        Assert.Empty(Value(unrelatedRuns.Value, unrelatedRuns.Error).Runs);
        Assert.Equal(unrelated.Revision, (await InspectSandboxAsync(sandboxes, unrelated.SandboxId)).Revision);
        Assert.Equal("unrelated", await File.ReadAllTextAsync(sentinel, Ct));
    }

    private static SandboxConfig FixtureConfig()
    {
        var windows = OperatingSystem.IsWindows();
        return new()
        {
            ProfileId = windows ? MxcProfileAdmission.WindowsProfileId : MxcProfileAdmission.LinuxProfileId,
            ProfileVersion = windows ? MxcProfileAdmission.WindowsProfileRevision : MxcProfileAdmission.LinuxProfileRevision,
            Network = new() { Egress = NetworkMode.Deny, Ingress = NetworkMode.Deny, HostLoopback = false },
            Resources = new() { CpuMaxMillicores = 500, MemoryMaxBytes = 256UL << 20, PressureAction = PressureAction.Throttle },
        };
    }

    private static async Task<RemoteGrant> SetGrantAsync(NodeService.NodeServiceClient node, Id epoch, RemoteGrant grant)
    {
        var reply = await node.SetRemoteGrantAsync(new() { Meta = Meta(mutation: true), OwnerEpoch = epoch, Grant = grant },
            deadline: Deadline, cancellationToken: Ct);
        var admitted = Value(reply.Value, reply.Error).Grant;
        Assert.Equal(GrantState.Active, admitted.State);
        return admitted;
    }

    private static async Task<Sandbox> InspectSandboxAsync(SandboxService.SandboxServiceClient sandboxes, Id id)
    {
        var reply = await sandboxes.InspectAsync(new() { Meta = Meta(), SandboxId = id }, deadline: Deadline, cancellationToken: Ct);
        return Value(reply.Value, reply.Error).Sandbox;
    }

    private static async Task<Run> InspectRunAsync(RunService.RunServiceClient runs, Id id)
    {
        var reply = await runs.InspectAsync(new() { Meta = Meta(), RunId = id }, deadline: Deadline, cancellationToken: Ct);
        return Value(reply.Value, reply.Error).Run;
    }

    private static async Task<Run> OnlyRunAsync(RunService.RunServiceClient runs, Id sandbox)
    {
        var reply = await runs.ListAsync(new() { Meta = Meta(), SandboxId = sandbox }, deadline: Deadline, cancellationToken: Ct);
        return Assert.Single(Value(reply.Value, reply.Error).Runs);
    }

    private static async Task<Operation> InspectOperationAsync(NodeService.NodeServiceClient node, Id epoch, Id command)
    {
        var reply = await node.GetOperationAsync(new() { Meta = Meta(), OwnerEpoch = epoch, CommandId = command },
            deadline: Deadline, cancellationToken: Ct);
        var operation = Value(reply.Value, reply.Error).Operation;
        Assert.Equal(epoch, operation.OwnerEpoch);
        Assert.Equal(command, operation.CommandId);
        return operation;
    }

    private static string[] HoldingPayload(string working)
    {
        if (!OperatingSystem.IsWindows())
            return ["/usr/bin/dash", "-c", "printf 'running\n' > remote-held.txt; /usr/bin/sleep 120"];

        File.Copy(TestNode.TestLoad, Path.Combine(working, "arcforges-testload.exe"));
        return [Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/d", "/c",
            ".\\arcforges-testload.exe hold --hold-ms 120000 --marker remote-held.txt"];
    }

    private static async Task<JsonElement> ReadAsync(string directory, string name)
    {
        await WaitForFixtureAsync(directory, name, NativeBound, "Center observation " + name);
        using var json = JsonDocument.Parse(await File.ReadAllBytesAsync(Path.Combine(directory, name), Ct));
        return json.RootElement.Clone();
    }

    private static Id ParseId(JsonElement value, string name)
    {
        var bytes = Convert.FromHexString(value.GetProperty(name).GetString()!);
        Assert.Equal(16, bytes.Length);
        return new() { Value = ByteString.CopyFrom(bytes) };
    }

    private static string Hex(Id value) => Convert.ToHexStringLower(value.Value.Span);

    private sealed class OwnedRunCleanup(RunService.RunServiceClient runs, Id epoch, Id sandbox) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            using var bound = new CancellationTokenSource(TimeSpan.FromSeconds(12));
            try
            {
                var listed = await runs.ListAsync(new() { Meta = Meta(), SandboxId = sandbox }, deadline: Deadline, cancellationToken: bound.Token);
                foreach (var owned in Value(listed.Value, listed.Error).Runs.Where(run => run.SandboxId.Equals(sandbox)))
                {
                    var current = owned;
                    while (current.State is RunState.Starting or RunState.Running or RunState.Stopping or RunState.Draining)
                    {
                        if (current.State is RunState.Starting or RunState.Running)
                        {
                            var stopped = await runs.StopAsync(new()
                            {
                                Meta = Meta(mutation: true, current.Revision),
                                OwnerEpoch = epoch,
                                RunId = owned.RunId,
                                GraceMs = 0,
                            }, deadline: Deadline, cancellationToken: bound.Token);
                            if (stopped.Error is not
                                {
                                    Category: ErrorCategory.Conflict,
                                    Code: "revision_mismatch",
                                    Effect: EffectCertainty.DidNotHappen,
                                    Details.Revision: { Expected: { } expected, Actual: { } actual },
                                } || expected.Value != current.Revision.Value || actual.Value <= expected.Value)
                            {
                                current = Value(stopped.Value, stopped.Error).Run;
                            }
                        }

                        await Task.Delay(100, bound.Token);
                        var refreshed = await runs.InspectAsync(new() { Meta = Meta(), RunId = owned.RunId },
                            deadline: Deadline, cancellationToken: bound.Token);
                        current = Value(refreshed.Value, refreshed.Error).Run;
                        Assert.Equal(owned.RunId, current.RunId);
                        Assert.Equal(sandbox, current.SandboxId);
                    }

                    Assert.True(current.State is RunState.Exited or RunState.Failed, "the owned remote fixture Run must drain");
                }
            }
            catch (Exception failure) when (failure is RpcException or OperationCanceledException or Xunit.Sdk.XunitException)
            {
                TestContext.Current.SendDiagnosticMessage("The owned remote fixture Run cleanup could not be confirmed: " + failure.GetType().Name);
            }
        }
    }
}
