// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.LocalRpc;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Platform.Capabilities;
using ArcForges.Node.Store;
using ArcForges.Tests;
using Grpc.Core;
using Microsoft.Data.Sqlite;

namespace ArcForges.ClosedLoop.Tests;

[Trait("loop", "cloud")]
public sealed class CloudLinkCenterControlTests
{
    private static readonly TimeSpan NativeBound = TimeSpan.FromSeconds(35);
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static DateTime Deadline => DateTime.UtcNow.AddSeconds(10);

    [Fact(Timeout = 290_000, DisableParallelization = true)]
    public async Task InstalledNodeUsesTheTypedLocalCenterAndContinuesRunsThroughAnActualCenterOutage()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        var origin = Environment.GetEnvironmentVariable("ARCFORGES_CENTER02_URL");
        Assert.SkipUnless(Environment.GetEnvironmentVariable("ARCFORGES_CENTER02_E2E_REQUIRED") == "1",
            "Run this supplement under the real Go Center and PostgreSQL fixture.");
        Assert.True(Uri.TryCreate(origin, UriKind.Absolute, out var center) && center.Scheme == Uri.UriSchemeHttps && center.IsLoopback
            && center.GetLeftPart(UriPartial.Authority) == origin);
        Assert.Equal("1", Environment.GetEnvironmentVariable("ARCFORGES_MXC_PACKAGE_TESTS"));
        Assert.True(File.Exists(Path.Combine(Path.GetDirectoryName(TestNode.Host)!, "mxc", "mxc-manifest.json")),
            "the Node must come from the verified package");
        if (OperatingSystem.IsLinux()) Assert.Null(SystemdTestEnvironment.SkipReason);
        var coordination = Environment.GetEnvironmentVariable("ARCFORGES_CENTER02_COORDINATION_DIR");
        Assert.True(!string.IsNullOrEmpty(coordination) && Path.IsPathFullyQualified(coordination) && Directory.Exists(coordination));

        await using var fixture = TestNode.Create();
        CreatePrivateRoot(fixture.DataRoot);
        fixture.Environment[CloudLinkTestHooks.CenterUrl] = origin;
        fixture.Environment[CloudLinkTestHooks.RefreshSeconds] = "15";
        fixture.Environment["ARCFORGES_TEST_CLIENT_IMAGES"] = null;
        var process = await fixture.StartNodeAsync();
        await using var local = OpenChannel(fixture);
        var node = new NodeService.NodeServiceClient(local.CallInvoker);
        var control = new CenterControlService.CenterControlServiceClient(local.CallInvoker);
        var sandboxes = new SandboxService.SandboxServiceClient(local.CallInvoker);
        var runs = new RunService.RunServiceClient(local.CallInvoker);
        var hello = await node.HandshakeAsync(new() { Meta = Meta() }, deadline: Deadline, cancellationToken: ct);
        var identity = Value(hello.Value, hello.Error);
        var ownerEpoch = identity.OwnerEpoch;
        Assert.NotNull(ownerEpoch);
        await using var cleanup = new OwnedNodeCleanup(fixture, process, control, ownerEpoch);
        var initial = await StatusAsync(control);
        Assert.False(initial.ConnectionEnabled);
        Assert.Equal("offline", initial.ChannelState);
        await CliAsync(fixture, 0, "center", "status");
        var sandbox = await CreateSandboxAsync(sandboxes, ownerEpoch);
        var working = Path.Combine(sandbox.DataLocation, "work");
        await File.WriteAllTextAsync(Path.Combine(working, "persistent.txt"), "owned through outage", ct);

        var stale = await control.BeginConnectAsync(new()
        {
            Meta = Meta(mutation: true),
            OwnerEpoch = CommandIds.New(),
            CenterOrigin = origin,
            ServiceMode = "self_hosted",
            FlowKind = "device_code",
        }, deadline: Deadline, cancellationToken: ct);
        Assert.Null(stale.Value);
        Assert.Equal("owner_epoch_retired", stale.Error?.Code);

        var first = Connect(ownerEpoch, origin!, "device_code");
        var pending = await BeginAsync(control, first);
        Assert.NotNull(pending.FlowId);
        await WaitForFlowAsync(control, pending.FlowId, flow => flow.HasUserCode);
        var shown = await CliAsync(fixture, 0, "center", "flow", IdText.Format(pending.FlowId));
        Assert.Equal(IdText.Format(pending.FlowId), shown.GetProperty("flow").GetProperty("flowId").GetString());
        var replayed = await BeginAsync(control, first.Clone());
        Assert.Equal(pending.FlowId, replayed.FlowId);
        RequireReceipt(replayed.Operation, ownerEpoch, first.Meta);
        var conflict = first.Clone();
        conflict.FlowKind = "browser";
        var reused = await control.BeginConnectAsync(conflict, deadline: Deadline, cancellationToken: ct);
        Assert.Equal("command_id_reused", reused.Error?.Code);

        var cancel = new CenterControlServiceCancelConnectRequest { Meta = Meta(mutation: true), OwnerEpoch = ownerEpoch, FlowId = pending.FlowId };
        var cancelled = await control.CancelConnectAsync(cancel, deadline: Deadline, cancellationToken: ct);
        RequireReceipt(Value(cancelled.Value, cancelled.Error).Operation, ownerEpoch, cancel.Meta);
        await WaitForFlowAsync(control, pending.FlowId, flow => flow.State == "cancelled");
        var cancellation = await CliAsync(fixture, 0, "center", "cancel", IdText.Format(pending.FlowId),
            "--owner-epoch", IdText.Format(ownerEpoch), "--command-id", IdText.Format(cancel.Meta.CommandId));
        RequireCliReceipt(cancellation, ownerEpoch, cancel.Meta);

        var browser = Connect(ownerEpoch, origin!, "browser");
        var connecting = await BeginAsync(control, browser);
        RequireReceipt(connecting.Operation, ownerEpoch, browser.Meta);
        Assert.NotNull(connecting.FlowId);
        var connectingCli = await CliAsync(fixture, 0, "center", "connect", origin!, "--mode", "self_hosted", "--flow", "browser",
            "--owner-epoch", IdText.Format(ownerEpoch), "--command-id", IdText.Format(browser.Meta.CommandId));
        RequireCliReceipt(connectingCli, ownerEpoch, browser.Meta);
        Assert.Equal(IdText.Format(connecting.FlowId), connectingCli.GetProperty("flowId").GetString());
        var approval = await WaitForFlowAsync(control, connecting.FlowId, flow => flow.HasVerificationUri);
        await WriteObservationAsync(coordination!, "approval.json", new { verificationUri = approval.VerificationUri });
        await WaitForFlowAsync(control, connecting.FlowId, flow => flow.State == "succeeded");
        var connected = await WaitForStatusAsync(control, value => value.ChannelState == "online");
        Assert.Equal(origin, connected.CenterOrigin);
        Assert.NotNull(connected.EnrollmentId);
        Assert.True(connected.ConnectionEnabled);
        await WriteObservationAsync(coordination!, "connected.json", new
        {
            ownerEpoch = Convert.ToHexStringLower(ownerEpoch.Value.Span),
            nodeEpoch = identity.NodeEpoch,
        });
        await WaitForFixtureAsync(coordination!, "connected-confirmed", NativeBound, "the exact Go V2 connection observation");

        var hold = await StartAsync(runs, sandbox, ownerEpoch, HoldingPayload(working));
        await TestNode.WaitAsync(() => File.Exists(Path.Combine(working, "holding.txt")), NativeBound, "the exact native workload started");
        var disconnected = new CenterControlServiceDisconnectRequest { OwnerEpoch = ownerEpoch, Meta = Meta(mutation: true) };
        var off = await control.DisconnectAsync(disconnected, deadline: Deadline, cancellationToken: ct);
        var offValue = Value(off.Value, off.Error);
        RequireReceipt(offValue.Operation, ownerEpoch, disconnected.Meta);
        Assert.False(offValue.Connection.ConnectionEnabled);
        Assert.Null(offValue.Connection.EnrollmentId);
        Assert.Equal("not_requested", offValue.Connection.RemoteRevocation);
        var disconnectCli = await CliAsync(fixture, 0, "center", "disconnect", "--owner-epoch", IdText.Format(ownerEpoch),
            "--command-id", IdText.Format(disconnected.Meta.CommandId));
        RequireCliReceipt(disconnectCli, ownerEpoch, disconnected.Meta);
        Assert.Equal(RunState.Running, (await InspectRunAsync(runs, hold.RunId)).State);

        var reconnect = Connect(ownerEpoch, origin!, "browser");
        var resumed = await BeginAsync(control, reconnect);
        Assert.Null(resumed.FlowId);
        RequireReceipt(resumed.Operation, ownerEpoch, reconnect.Meta);
        var reconnected = await WaitForStatusAsync(control, value => value.ChannelState == "online");
        Assert.Equal(connected.EnrollmentId, reconnected.EnrollmentId);

        await File.WriteAllTextAsync(Path.Combine(coordination!, "outage-request"), string.Empty, ct);
        await WaitForFixtureAsync(coordination!, "outage-ready", TimeSpan.FromSeconds(65), "the actual Center listener stopped");
        await WaitForStatusAsync(control, value => value.ChannelState is "offline" or "stale");

        var signOut = new CenterControlServiceSignOutRequest { OwnerEpoch = ownerEpoch, Meta = Meta(mutation: true) };
        var ended = await control.SignOutAsync(signOut, deadline: Deadline, cancellationToken: ct);
        RequireReceipt(Value(ended.Value, ended.Error).Operation, ownerEpoch, signOut.Meta);
        var endedStatus = await WaitForStatusAsync(control, value => !value.ConnectionEnabled && value.EnrollmentId is null && value.RemoteRevocation == "unknown");
        Assert.Equal("unknown", endedStatus.RemoteRevocation);
        var operation = await node.GetOperationAsync(new() { Meta = Meta(), CommandId = signOut.Meta.CommandId, OwnerEpoch = ownerEpoch },
            deadline: Deadline, cancellationToken: ct);
        var reconciliation = Value(operation.Value, operation.Error).Operation;
        RequireReceipt(reconciliation, ownerEpoch, signOut.Meta);
        Assert.Equal(OperationState.Unknown, reconciliation.State);
        var signOutCli = await CliAsync(fixture, 8, "center", "signout", "--owner-epoch", IdText.Format(ownerEpoch),
            "--command-id", IdText.Format(signOut.Meta.CommandId));
        RequireCliReceipt(signOutCli, ownerEpoch, signOut.Meta);
        Assert.Equal("outcome_unknown", signOutCli.GetProperty("error").GetProperty("code").GetString());

        var stillRunning = await InspectRunAsync(runs, hold.RunId);
        Assert.Equal(RunState.Running, stillRunning.State);
        var stop = await runs.StopAsync(new()
        {
            Meta = Meta(mutation: true, stillRunning.Revision),
            OwnerEpoch = ownerEpoch,
            RunId = hold.RunId,
            GraceMs = 0,
        }, deadline: Deadline, cancellationToken: ct);
        _ = Value(stop.Value, stop.Error);
        await TestNode.WaitAsync(async () => (await InspectRunAsync(runs, hold.RunId)).State == RunState.Exited, NativeBound, "the held native Run drained");
        Assert.Equal("owned through outage", await File.ReadAllTextAsync(Path.Combine(working, "persistent.txt"), ct));

        await CliAsync(fixture, 0, "sandbox", "inspect", IdText.Format(sandbox.SandboxId));
        var offline = await StartAsync(runs, sandbox, ownerEpoch, OfflinePayload());
        await TestNode.WaitAsync(async () => (await InspectRunAsync(runs, offline.RunId)).State == RunState.Exited, NativeBound,
            "a new native Run completed with Center unreachable");
        Assert.Equal("local", (await File.ReadAllTextAsync(Path.Combine(working, "offline.txt"), ct)).Trim());
    }

    private static CenterControlServiceBeginConnectRequest Connect(Id owner, string origin, string flow) => new()
    {
        Meta = Meta(mutation: true),
        OwnerEpoch = owner,
        CenterOrigin = origin,
        ServiceMode = "self_hosted",
        FlowKind = flow,
    };

    private static NodeChannel OpenChannel(TestNode fixture) => NodeChannel.Create(OperatingSystem.IsWindows()
        ? LocalRpcEndpoint.NamedPipe(fixture.Endpoint)
        : LocalRpcEndpoint.UnixDomainSocket(fixture.Endpoint));

    private static async Task<CenterControlServiceBeginConnectValue> BeginAsync(CenterControlService.CenterControlServiceClient client,
        CenterControlServiceBeginConnectRequest request)
    {
        var reply = await client.BeginConnectAsync(request, deadline: Deadline, cancellationToken: Ct);
        return Value(reply.Value, reply.Error);
    }

    private static async Task<CenterConnection> StatusAsync(CenterControlService.CenterControlServiceClient client)
    {
        var reply = await client.GetStatusAsync(new() { Meta = Meta() }, deadline: Deadline, cancellationToken: Ct);
        return Value(reply.Value, reply.Error).Connection;
    }

    private static async Task<CenterConnection> WaitForStatusAsync(CenterControlService.CenterControlServiceClient client,
        Func<CenterConnection, bool> matches)
    {
        CenterConnection? state = null;
        await TestNode.WaitAsync(async () =>
        {
            CheckFixtureAbort();
            state = await StatusAsync(client);
            return matches(state);
        }, NativeBound, "the installed Node's Center state");
        return Assert.IsType<CenterConnection>(state);
    }

    private static async Task<CenterConnectFlow> WaitForFlowAsync(CenterControlService.CenterControlServiceClient client, Id id,
        Func<CenterConnectFlow, bool> matches)
    {
        CenterConnectFlow? flow = null;
        await TestNode.WaitAsync(async () =>
        {
            CheckFixtureAbort();
            var reply = await client.GetConnectFlowAsync(new() { Meta = Meta(), FlowId = id }, deadline: Deadline, cancellationToken: Ct);
            flow = Value(reply.Value, reply.Error).Flow;
            return matches(flow);
        }, NativeBound, "the installed Node's exact owner-local flow");
        return Assert.IsType<CenterConnectFlow>(flow);
    }

    private static void RequireReceipt(Operation operation, Id epoch, RequestMeta request)
    {
        Assert.Equal(epoch, operation.OwnerEpoch);
        Assert.Equal(request.CommandId, operation.CommandId);
    }

    private static void RequireCliReceipt(JsonElement document, Id epoch, RequestMeta request)
    {
        Assert.Equal(IdText.Format(epoch), document.GetProperty("ownerEpoch").GetString());
        Assert.Equal(IdText.Format(request.CommandId), document.GetProperty("commandId").GetString());
    }

    private static async Task<Sandbox> CreateSandboxAsync(SandboxService.SandboxServiceClient client, Id owner)
    {
        var windows = OperatingSystem.IsWindows();
        var response = await client.CreateAsync(new()
        {
            Meta = Meta(mutation: true),
            OwnerEpoch = owner,
            DisplayName = "Center-outage native fixture",
            Config = new()
            {
                ProfileId = windows ? MxcProfileAdmission.WindowsProfileId : MxcProfileAdmission.LinuxProfileId,
                ProfileVersion = windows ? MxcProfileAdmission.WindowsProfileRevision : MxcProfileAdmission.LinuxProfileRevision,
                Network = new() { Egress = NetworkMode.Deny, Ingress = NetworkMode.Deny, HostLoopback = false },
                Resources = new() { CpuMaxMillicores = 500, MemoryMaxBytes = 256UL << 20, PressureAction = PressureAction.Throttle },
            },
        }, deadline: Deadline, cancellationToken: Ct);
        return Value(response.Value, response.Error).Sandbox;
    }

    private static async Task<Run> StartAsync(RunService.RunServiceClient client, Sandbox sandbox, Id owner, string[] argv)
    {
        var response = await client.StartAsync(new()
        {
            Meta = Meta(mutation: true, sandbox.Revision),
            OwnerEpoch = owner,
            SandboxId = sandbox.SandboxId,
            Argv = { argv },
            WorkingDirectory = "work",
            TerminalMode = TerminalMode.Pipes,
        }, deadline: Deadline, cancellationToken: Ct);
        return Value(response.Value, response.Error).Run;
    }

    private static async Task<Run> InspectRunAsync(RunService.RunServiceClient client, Id run)
    {
        var response = await client.InspectAsync(new() { Meta = Meta(), RunId = run }, deadline: Deadline, cancellationToken: Ct);
        return Value(response.Value, response.Error).Run;
    }

    private static string[] HoldingPayload(string working)
    {
        if (!OperatingSystem.IsWindows())
            return ["/usr/bin/dash", "-c", "printf 'running\\n' > holding.txt; /usr/bin/sleep 120"];

        File.Copy(TestNode.TestLoad, Path.Combine(working, "arcforges-testload.exe"));
        return [Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/d", "/c", ".\\arcforges-testload.exe hold --hold-ms 120000 --marker holding.txt"];
    }

    private static string[] OfflinePayload() => OperatingSystem.IsWindows()
        ? [Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/d", "/c", "echo local>offline.txt"]
        : ["/usr/bin/dash", "-c", "printf 'local\\n' > offline.txt"];

    private static void CreatePrivateRoot(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            using var identity = WindowsIdentity.GetCurrent();
            var owner = Assert.IsType<SecurityIdentifier>(identity.User);
            var security = new DirectorySecurity();
            security.SetOwner(owner);
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(path).Create(security);
        }
        else if (OperatingSystem.IsLinux())
        {
            Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private static async Task<JsonElement> CliAsync(TestNode fixture, int exitCode, params string[] args)
    {
        var reply = await fixture.ProductCliBytesAsync(NativeBound, ["--json", .. args]);
        Assert.True(reply.ExitCode == exitCode, $"the installed {args[0]} {args[1]} command returned {reply.ExitCode}");
        using var document = JsonDocument.Parse(reply.Stdout);
        return document.RootElement.Clone();
    }

    private static async Task WriteObservationAsync<T>(string directory, string name, T data)
    {
        var file = Path.Combine(directory, name);
        await File.WriteAllBytesAsync(file + ".input", JsonSerializer.SerializeToUtf8Bytes(data), Ct);
        File.Move(file + ".input", file);
    }

    private static Task WaitForFixtureAsync(string directory, string name, TimeSpan bound, string description) =>
        TestNode.WaitAsync(() =>
        {
            CheckFixtureAbort();
            return File.Exists(Path.Combine(directory, name));
        }, bound, description);

    private static void CheckFixtureAbort()
    {
        var directory = Environment.GetEnvironmentVariable("ARCFORGES_CENTER02_COORDINATION_DIR");
        Assert.False(directory is not null && File.Exists(Path.Combine(directory, "fixture-abort")),
            "the real Go Center fixture requested teardown");
    }

    private static RequestMeta Meta(bool mutation = false, Revision? revision = null) => new()
    {
        CorrelationId = CommandIds.New(),
        CommandId = mutation ? CommandIds.New() : null,
        ExpectedRev = revision,
    };

    private static T Value<T>(T? value, ArcError? error) where T : class
    {
        Assert.True(error is null, $"Unexpected installed operation refusal: {error?.Category}/{error?.Code}");
        return Assert.IsType<T>(value);
    }

    private sealed class OwnedNodeCleanup(TestNode fixture, Process process, CenterControlService.CenterControlServiceClient center, Id epoch)
        : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            if (!process.HasExited)
            {
                await SignOutAsync();
                await StopAsync();
            }

            if (process.HasExited)
            {
                RemoveReceiptKey();
            }
        }

        private async Task SignOutAsync()
        {
            using var bound = new CancellationTokenSource(TimeSpan.FromSeconds(9));
            try
            {
                var before = await center.GetStatusAsync(new() { Meta = Meta() }, deadline: DateTime.UtcNow.AddSeconds(2),
                    cancellationToken: bound.Token);
                if (before.Value?.Connection?.State == "signed_out")
                    return;

                var signedOut = await center.SignOutAsync(new() { Meta = Meta(mutation: true), OwnerEpoch = epoch },
                    deadline: DateTime.UtcNow.AddSeconds(6), cancellationToken: bound.Token);
                if (signedOut.Value?.Connection?.State != "signed_out")
                    WriteCleanupDiagnostic("The fixture Center credential did not finish signing out before Node shutdown.");
            }
            catch (Exception error) when (error is RpcException or IOException or OperationCanceledException)
            {
                WriteCleanupDiagnostic("The fixture Center sign-out did not finish. " + error.GetType().Name);
            }
        }

        private async Task StopAsync()
        {
            try
            {
                var stopped = await fixture.ProductCliBytesAsync(TimeSpan.FromSeconds(16), "node", "stop", "--timeout", "12s");
                if (stopped.ExitCode != 0)
                {
                    WriteCleanupDiagnostic("The installed fixture Node stop command returned " + stopped.ExitCode + ".");
                    return;
                }

                using var bound = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await process.WaitForExitAsync(bound.Token);
            }
            catch (Exception error) when (error is IOException or Win32Exception or InvalidOperationException or OperationCanceledException or TimeoutException)
            {
                WriteCleanupDiagnostic("The installed fixture Node did not stop before receipt key cleanup. " + error.GetType().Name);
            }
        }

        private void RemoveReceiptKey()
        {
            try
            {
                using var database = new SqliteConnection(new SqliteConnectionStringBuilder
                {
                    DataSource = StorePaths.Database(fixture.DataRoot), Mode = SqliteOpenMode.ReadOnly, Pooling = false,
                }.ToString());
                database.Open();
                using var command = database.CreateCommand();
                command.CommandText = "SELECT node_id FROM store_meta WHERE singleton = 1;";
                if (command.ExecuteScalar() is not byte[] { Length: 16 } node)
                {
                    WriteCleanupDiagnostic("Could not identify the isolated fixture Node receipt key.");
                    return;
                }

                var name = NodeDataKeyRing.TargetName(node, "v2-owner-" + Convert.ToHexStringLower(epoch.Value.Span));
                NodeSecretStores.ForTestDataRoot(fixture.DataRoot).Store.Delete(name);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or SqliteException)
            {
                WriteCleanupDiagnostic("The exact isolated fixture receipt key could not be removed. " + error.GetType().Name);
            }
        }

        private static void WriteCleanupDiagnostic(string message) => TestContext.Current.TestOutputHelper?.WriteLine(message);
    }
}
