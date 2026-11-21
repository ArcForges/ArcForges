// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.LocalRpc;
using ArcForges.Node.Api;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Sandboxes;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Platform.Capabilities;
using ArcForges.Node.Store;
using ArcForges.Tests;
using Google.Protobuf;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    [Fact(Timeout = 270_000, DisableParallelization = true)]
    public async Task InstalledCliManagesOfflineSandboxRunAndResourcesWithExactArgumentsAndReceipts()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var fixture = TestNode.Create();
        PrepareInstalledCliFixture(fixture);
        var process = await fixture.StartNodeAsync();
        Id? ownerEpoch = null;
        Id? heldRun = null;
        try
        {
            var config = InstalledCliProfile();
            var configFile = WriteInstalledCliInput(fixture, "profile with spaces.json", config);
            var create = await InstalledCliSuccessAsync(fixture, "sandbox", "create", "Offline native CLI 四", "--file", configFile);
            var sandboxId = InstalledCliId(create.GetProperty("sandbox"), "sandboxId");
            var sandboxText = IdText.Format(sandboxId);
            ownerEpoch = InstalledCliId(create, "ownerEpoch");
            _ = InstalledCliId(create, "commandId");
            var status = await InstalledCliSuccessAsync(fixture, "node", "status");
            Assert.True(status.GetProperty("state").GetString() is "ready" or "degraded");
            _ = InstalledCliId(status, "nodeId");
            Assert.False((await InstalledCliSuccessAsync(fixture, "node", "start")).GetProperty("started").GetBoolean());
            var doctor = await InstalledCliSuccessAsync(fixture, "doctor", "--sandbox", sandboxText);
            Assert.Equal(sandboxId, InstalledCliId(doctor.GetProperty("sandbox"), "sandboxId"));
            Assert.Equal(config.ProfileId, doctor.GetProperty("sandbox").GetProperty("profileId").GetString());
            Assert.Equal("node", doctor.GetProperty("resources").GetProperty("scopeKind").GetString());

            Run argumentRun;
            Sandbox renamed;
            string replacement;
            string[] argumentStart;
            Id originalCommand;
            var firstEpochText = IdText.Format(ownerEpoch);
            await using (var channel = OpenChannel(fixture))
            {
                var node = new NodeService.NodeServiceClient(channel.CallInvoker);
                var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
                var runs = new RunService.RunServiceClient(channel.CallInvoker);
                var resources = new ResourceService.ResourceServiceClient(channel.CallInvoker);
                Assert.Equal(ownerEpoch, (await HandshakeAsync(node)).OwnerEpoch);
                var sandbox = await InspectInstalledCliSandboxAsync(sandboxes, sandboxId, ct);
                var listed = await InstalledCliSuccessAsync(fixture, "sandbox", "list");
                Assert.Equal(sandboxId, InstalledCliId(Assert.Single(listed.GetProperty("sandboxes").EnumerateArray()), "sandboxId"));
                var inspect = (await InstalledCliSuccessAsync(fixture, "sandbox", "inspect", sandboxText)).GetProperty("sandbox");
                Assert.Equal(sandboxId, InstalledCliId(inspect, "sandboxId"));
                Assert.Equal(sandbox.DisplayName, inspect.GetProperty("displayName").GetString());
                var human = await RunInstalledCliAsync(fixture, "sandbox", "inspect", sandboxText);
                Assert.Equal(0, human.ExitCode);
                Assert.Contains(sandboxText, Encoding.UTF8.GetString(human.Stdout), StringComparison.Ordinal);
                Assert.Contains("Offline native CLI", Encoding.UTF8.GetString(human.Stdout), StringComparison.Ordinal);

                var revised = sandbox.Config.Clone();
                revised.OutputRetentionBytes = 32_768;
                replacement = WriteInstalledCliInput(fixture, "replacement profile.json", revised);
                await InstalledCliSuccessAsync(fixture, "sandbox", "configure", sandboxText, "--file", replacement,
                    "--expected-revision", CliRevision(sandbox.Revision));
                var configured = await InspectInstalledCliSandboxAsync(sandboxes, sandboxId, ct);
                Assert.Equal(revised, configured.Config);
                await InstalledCliSuccessAsync(fixture, "sandbox", "rename", sandboxText, "Renamed offline native CLI",
                    "--expected-revision", CliRevision(configured.Revision));
                renamed = await InspectInstalledCliSandboxAsync(sandboxes, sandboxId, ct);
                Assert.Equal("Renamed offline native CLI", renamed.DisplayName);
                Assert.Equal(configured.Config, renamed.Config);
                Assert.Equal(sandbox.DataLocation, renamed.DataLocation);
                await InstalledCliRefusalAsync(fixture, 3, "revision_mismatch", "sandbox", "configure", sandboxText,
                    "--file", replacement, "--expected-revision", CliRevision(configured.Revision));
                await InstalledCliRefusalAsync(fixture, 3, "busy", "sandbox", "repair", sandboxText,
                    "--file", replacement, "--expected-revision", CliRevision(renamed.Revision));
                Assert.Equal(renamed.Revision, (await InspectInstalledCliSandboxAsync(sandboxes, sandboxId, ct)).Revision);

                var initial = await ReadInstalledBudgetAsync(resources, "sandbox", sandboxId, ct);
                var resourceFile = WriteInstalledCliInput(fixture, "resource limits.json", new ResourcePolicy
                {
                    CpuMaxMillicores = 400,
                    MemoryMaxBytes = MemoryBytes,
                    MaxConcurrentRuns = 1,
                    PressureAction = PressureAction.Throttle,
                });
                var policy = await InstalledCliSuccessAsync(fixture, "resources", "set", "--scope", "sandbox", "--id", sandboxText,
                    "--file", resourceFile, "--expected-revision", CliRevision(initial.PolicyRevision));
                var policyCommand = InstalledCliId(policy, "commandId");
                Assert.Equal(ownerEpoch, InstalledCliId(policy, "ownerEpoch"));
                Assert.Equal(OperationState.Succeeded, (await OperationAsync(node, ownerEpoch, policyCommand)).State);
                var current = await ReadInstalledBudgetAsync(resources, "sandbox", sandboxId, ct);
                Assert.Equal(initial.PolicyRevision.Value + 1, current.PolicyRevision.Value);
                var show = await InstalledCliSuccessAsync(fixture, "resources", "show", "--scope", "sandbox", "--id", sandboxText);
                Assert.Equal(sandboxId, InstalledCliId(show, "scopeId"));
                await RequireInstalledCliResourceWatchAsync(fixture, sandboxText, ct);

                var working = Directory.CreateDirectory(Path.Combine(renamed.DataLocation, "work", "quoted directory")).FullName;
                var image = CopySecurityTestLoad(working);
                string[] operands = ["two words", "", "with \"quotes\"", "trailing\\", "--queue", "--", "雪 café"];
                argumentStart = ["run", "start", sandboxText, "--terminal", "off", "--cwd", RelativeWorkdir,
                    "--expected-revision", CliRevision(renamed.Revision), "--", image, "args", .. operands];
                await InstalledCliRefusalAsync(fixture, 2, "invalid_argument", "run", "start", sandboxText, "--terminal", "off",
                    "--cwd", "../outside", "--", image, "args", "refused");
                Assert.Empty(await ListAsync(runs, sandboxId));
                var started = await InstalledCliSuccessAsync(fixture, argumentStart);
                originalCommand = InstalledCliId(started, "commandId");
                Assert.Equal(ownerEpoch, InstalledCliId(started, "ownerEpoch"));
                heldRun = InstalledCliId(started.GetProperty("run"), "runId");
                argumentRun = await WaitForStateAsync(fixture, runs, heldRun, RunState.Exited, ct);
                Assert.True(argumentRun.Exit.GroupEmptyVerified);
                Assert.True(argumentRun.Exit.HasRawCode);
                Assert.DoesNotContain("two words", started.GetRawText(), StringComparison.Ordinal);
                var nativeOutput = await WatchAsync(runs, argumentRun, StreamKind.Stdout);
                Assert.Null(nativeOutput.Gap);
                using (var actual = JsonDocument.Parse(nativeOutput.Bytes))
                {
                    Assert.Equal(operands, actual.RootElement.GetProperty("argv").EnumerateArray().Select(x => x.GetString()).ToArray());
                    Assert.Equal(Path.GetFullPath(working), Path.GetFullPath(actual.RootElement.GetProperty("cwd").GetString()!),
                        ignoreCase: OperatingSystem.IsWindows());
                }

                var inspected = (await InstalledCliSuccessAsync(fixture, "run", "inspect", IdText.Format(heldRun))).GetProperty("run");
                Assert.Equal(heldRun, InstalledCliId(inspected, "runId"));
                Assert.DoesNotContain("with ", inspected.GetProperty("safeCommandDisplay").GetString(), StringComparison.Ordinal);
                Assert.Equal(argumentRun.Exit.RawCode.ToString(CultureInfo.InvariantCulture), CliScalar(inspected.GetProperty("exit").GetProperty("rawCode")));
                var list = await InstalledCliSuccessAsync(fixture, "run", "list", "--sandbox", sandboxText);
                Assert.Equal(heldRun, InstalledCliId(Assert.Single(list.GetProperty("runs").EnumerateArray()), "runId"));

                var stopMarker = Path.Combine(working, "cli-stop.log");
                var held = await InstalledCliSuccessAsync(fixture, "run", "start", sandboxText, "--terminal", "off", "--cwd", RelativeWorkdir,
                    "--", image, "hold", "--hold-ms", "60000", "--marker", stopMarker);
                heldRun = InstalledCliId(held.GetProperty("run"), "runId");
                var running = await WaitForStateAsync(fixture, runs, heldRun, RunState.Running, ct);
                await TestNode.WaitAsync(() => ReadLines(stopMarker).Any(line => line.StartsWith("ready ", StringComparison.Ordinal)),
                    NativeBound, "the real CLI-started disposable workload");
                var refusedMarker = Path.Combine(working, "cli-resources-refused.log");
                var blocked = await InstalledCliRefusalAsync(fixture, 6, "budget_unavailable", "run", "start", sandboxText,
                    "--terminal", "off", "--cwd", RelativeWorkdir, "--", image, "hold", "--hold-ms", "100", "--marker", refusedMarker);
                Assert.Equal(ownerEpoch, InstalledCliId(blocked, "ownerEpoch"));
                Assert.False(File.Exists(refusedMarker));
                Assert.Equal(2, (await ListAsync(runs, sandboxId)).Length);
                var stopped = await InstalledCliSuccessAsync(fixture, "run", "stop", IdText.Format(heldRun),
                    "--expected-revision", CliRevision(running.Revision), "--grace-ms", "0");
                var stopCommand = InstalledCliId(stopped, "commandId");
                Assert.Equal(ownerEpoch, InstalledCliId(stopped, "ownerEpoch"));
                Assert.True((await WaitForStateAsync(fixture, runs, heldRun, RunState.Exited, ct)).Exit.GroupEmptyVerified);
                Assert.Equal(EffectCertainty.Happened, (await OperationAsync(node, ownerEpoch, stopCommand)).Effect);
                heldRun = null;

                var timeoutMarker = Path.Combine(working, "cli-timeout-stop.log");
                var timeoutStart = await InstalledCliSuccessAsync(fixture, "run", "start", sandboxText, "--terminal", "off",
                    "--cwd", RelativeWorkdir, "--", image, "hold", "--hold-ms", "60000", "--marker", timeoutMarker);
                heldRun = InstalledCliId(timeoutStart.GetProperty("run"), "runId");
                var timeoutStartCommand = InstalledCliId(timeoutStart, "commandId");
                Assert.Equal(ownerEpoch, InstalledCliId(timeoutStart, "ownerEpoch"));
                await RequireInstalledCliStopTimeoutAsync(fixture, node, runs, ownerEpoch, heldRun, timeoutStartCommand, image, timeoutMarker, ct);
                heldRun = null;
                Assert.Equal(3, (await ListAsync(runs, sandboxId)).Length);
            }

            var repairMarker = Path.Combine(renamed.DataLocation, "data", "keep-while-repairing.txt");
            File.WriteAllText(repairMarker, "existing owned data");
            await StopInstalledCliNodeAsync(fixture, process);
            CompactActualResponse(fixture.DataRoot, new RunServiceStartRequest
            {
                Meta = new RequestMeta { CommandId = originalCommand },
                OwnerEpoch = ownerEpoch,
            }, argumentRun.RunId);
            SetInstalledCliRepairPrecondition(fixture.DataRoot, renamed);
            var previousProcess = process;
            process = await fixture.StartNodeAsync();
            previousProcess.Dispose();
            var compacted = await InstalledCliSuccessAsync(fixture, "operation", "inspect", IdText.Format(originalCommand), "--owner-epoch", firstEpochText);
            Assert.True(compacted.GetProperty("operation").GetProperty("responseCompacted").GetBoolean());
            Assert.Equal(argumentRun.RunId, InstalledCliId(compacted.GetProperty("operation"), "aggregateId"));
            var replay = ReplayInstalledCliStart(argumentStart, IdText.Format(originalCommand), firstEpochText);
            var refused = await InstalledCliRefusalAsync(fixture, 3, "receipt_compacted", replay);
            Assert.Equal(originalCommand, InstalledCliId(refused, "commandId"));
            Assert.Equal(ownerEpoch, InstalledCliId(refused, "ownerEpoch"));
            var differentEpoch = IdText.Format(CommandIds.New());
            var stale = await InstalledCliRefusalAsync(fixture, 3, "owner_epoch_retired",
                ReplayInstalledCliStart(argumentStart, IdText.Format(originalCommand), differentEpoch));
            Assert.Equal(differentEpoch, stale.GetProperty("ownerEpoch").GetString());
            await InstalledCliRefusalAsync(fixture, 2, "not_found", "operation", "inspect", IdText.Format(originalCommand),
                "--owner-epoch", differentEpoch);
            await using var fresh = OpenChannel(fixture);
            var after = new RunService.RunServiceClient(fresh.CallInvoker);
            var afterSandboxes = new SandboxService.SandboxServiceClient(fresh.CallInvoker);
            var beforeRepair = await InspectInstalledCliSandboxAsync(afterSandboxes, sandboxId, ct);
            Assert.Equal(SandboxState.Error, beforeRepair.State);
            var repaired = await InstalledCliSuccessAsync(fixture, "sandbox", "repair", sandboxText, "--file", replacement,
                "--expected-revision", CliRevision(renamed.Revision));
            Assert.Equal(ownerEpoch, InstalledCliId(repaired, "ownerEpoch"));
            var afterRepair = await InspectInstalledCliSandboxAsync(afterSandboxes, sandboxId, ct);
            Assert.Equal(SandboxState.Ready, afterRepair.State);
            Assert.Equal(renamed.Revision.Value + 1, afterRepair.Revision.Value);
            Assert.Equal(renamed.DataLocation, afterRepair.DataLocation);
            Assert.Equal("existing owned data", File.ReadAllText(repairMarker));
            // The argument, normal Stop, and deadline Stop scenarios each created exactly one Run.
            Assert.Equal(3, (await ListAsync(after, sandboxId)).Length);
            Assert.Equal(argumentRun, await InspectAsync(after, argumentRun.RunId, ct));
        }
        finally
        {
            await CleanInstalledCliFixtureAsync(fixture, process, ownerEpoch, heldRun);
        }
    }

    private static async Task RequireInstalledCliStopTimeoutAsync(TestNode fixture, NodeService.NodeServiceClient node,
        RunService.RunServiceClient runs, Id ownerEpoch, Id runId, Id startCommand, string image, string marker, CancellationToken ct)
    {
        const uint graceMs = 12_000;
        var running = await WaitForStateAsync(fixture, runs, runId, RunState.Running, ct);
        await TestNode.WaitAsync(() => CountFinalRecoveryMarkers(marker, "ready") == 1, NativeBound, "the deferred Stop's native Pipes payload");
        var binding = ReadRecoveryBinding(fixture.DataRoot, running);
        using var native = await CaptureFinalRecoveryBoundaryAsync(binding, image, marker, descendants: false);
        Assert.True(native.Owner.IsRunning());
        Assert.True(native.Root.IsRunning());
        var runText = IdText.Format(runId);
        string graceText = graceMs.ToString(CultureInfo.InvariantCulture);
        string[] stopArguments = ["run", "stop", runText, "--expected-revision", CliRevision(running.Revision), "--grace-ms", graceText];
        var timedOut = await InstalledCliRefusalAsync(fixture, 8, "outcome_unknown", ["--timeout", "3s", .. stopArguments]);
        var command = InstalledCliId(timedOut, "commandId");
        Assert.Equal(ownerEpoch, InstalledCliId(timedOut, "ownerEpoch"));
        Assert.Equal("stop_outcome_unconfirmed", timedOut.GetProperty("error").GetProperty("details").GetProperty("state")
            .GetProperty("reason").GetString());

        var pending = await OperationAsync(node, ownerEpoch, command);
        Assert.Equal(command, pending.CommandId);
        Assert.Equal(ownerEpoch, pending.OwnerEpoch);
        Assert.Equal(runId, pending.AggregateId);
        Assert.Equal("RunService.Stop", pending.Method);
        Assert.Equal(OperationState.Accepted, pending.State);
        Assert.Equal(EffectCertainty.Unknown, pending.Effect);
        Assert.True(native.Owner.IsRunning());
        Assert.True(native.Root.IsRunning());
        var originalStop = BuildStop(ownerEpoch, running);
        originalStop.Meta.CommandId = command;
        originalStop.GraceMs = graceMs;
        var originalStart = new RunServiceStartRequest { Meta = new RequestMeta { CommandId = startCommand }, OwnerEpoch = ownerEpoch };
        var intent = ReadRecoveryStopIntent(fixture.DataRoot, originalStart, originalStop, running.Epoch);
        Assert.Equal("ACCEPTED", intent.ReceiptState);
        Assert.Equal(TimeSpan.FromMilliseconds(graceMs), intent.Deadline - intent.AcceptedAt);

        var settled = await WaitForStateAsync(fixture, runs, runId, RunState.Exited, ct);
        Assert.True(settled.Exit.GroupEmptyVerified);
        Assert.True(native.IsEmpty());
        AssertFinalWindowsEvidence(fixture, settled, binding);
        var settledReceipt = await OperationAsync(node, ownerEpoch, command);
        AssertStopReceipt(settledReceipt, originalStop, settled.Revision, EffectCertainty.Happened);
        var reconciled = await InstalledCliSuccessAsync(fixture, "operation", "inspect", IdText.Format(command), "--owner-epoch", IdText.Format(ownerEpoch));
        var shown = reconciled.GetProperty("operation");
        Assert.Equal(command, InstalledCliId(shown, "commandId"));
        Assert.Equal(runId, InstalledCliId(shown, "aggregateId"));
        using var typedReceipt = JsonDocument.Parse(JsonFormatter.Default.Format(settledReceipt));
        Assert.Equal(typedReceipt.RootElement.GetProperty("state").GetString(), shown.GetProperty("state").GetString());
        Assert.Equal(typedReceipt.RootElement.GetProperty("effect").GetString(), shown.GetProperty("effect").GetString());
        var replayed = await InstalledCliSuccessAsync(fixture, [.. stopArguments, "--command-id", IdText.Format(command),
            "--owner-epoch", IdText.Format(ownerEpoch)]);
        Assert.Equal(command, InstalledCliId(replayed, "commandId"));
        Assert.Equal(ownerEpoch, InstalledCliId(replayed, "ownerEpoch"));
        Assert.Equal(runId, InstalledCliId(replayed.GetProperty("run"), "runId"));
        Assert.Equal(1, CountFinalRecoveryMarkers(marker, "ready"));
        using var database = ReadDatabase(fixture.DataRoot);
        using var receipts = database.CreateCommand();
        receipts.CommandText = "SELECT count(*) FROM command_receipt WHERE method = 'RunService.Stop' AND aggregate_id = $run;";
        receipts.Parameters.AddWithValue("$run", Hex(runId));
        Assert.Equal(1L, Assert.IsType<long>(receipts.ExecuteScalar()));
    }

    [Fact(Timeout = 180_000, DisableParallelization = true)]
    public async Task InstalledCliDoesNotAdvertiseOrAcceptRetiredCommandRoutes()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var fixture = TestNode.Create();
        PrepareInstalledCliFixture(fixture);
        await RequireInstalledCliGrammarAsync(fixture);
    }

    private static void SetInstalledCliRepairPrecondition(string dataRoot, Sandbox sandbox)
    {
        // Use the REC-01 fixture precondition on the closed store. The actual CLI must perform guarded repair.
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = dataRoot, BootIdentity = BootIdentity.Read() });
        Assert.Equal(1, store.Write(transaction => transaction.Execute("""
            UPDATE sandbox SET state = $error
             WHERE sandbox_id = $id AND revision = $revision AND state = $ready;
            """, ("$error", (int)StoredSandboxState.Error), ("$id", Hex(sandbox.SandboxId)), ("$revision", sandbox.Revision.Value),
            ("$ready", (int)StoredSandboxState.Ready)), CommitDurability.Full));
    }

    [Fact(Timeout = 180_000, DisableParallelization = true)]
    public async Task InstalledCliMapsLocalGrantSetListAndRevokeToRealCoreWithOriginalReceipts()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var fixture = TestNode.Create();
        PrepareInstalledCliFixture(fixture);
        var owner = Assert.IsType<string>(SandboxLocalOwner.Current());
        var enrollmentId = CommandIds.New();
        const string audience = "https://cli-grant-fixture.example.invalid";
        var enrollment = new ActiveRemoteEnrollment(owner, Hex(enrollmentId), Hex(CommandIds.New()),
            audience, audience, Hex(CommandIds.New()));
        var managerReady = new TaskCompletionSource<SandboxManager>(TaskCreationOptions.RunContinuationsAsynchronously);
        var nodeReady = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var stop = new CancellationTokenSource();
        var options = new NodeHostOptions
        {
            ConfigPath = Path.Combine(fixture.ConfigDirectory, "node.json"),
            Endpoint = OperatingSystem.IsWindows() ? LocalRpcEndpoint.NamedPipe(fixture.Endpoint)
                : LocalRpcEndpoint.UnixDomainSocket(fixture.Endpoint),
            TestMode = true,
            SecretStore = NodeSecretStores.ForTestDataRoot,
            NodeKeys = NodeKeyStores.ForTestDataRoot,
            IsolatedFromMachineLoad = true,
            LinuxSlice = fixture.Slice,
            HelperExecutable = InstalledCliHost,
            SandboxMxcInstallationRoot = Path.Combine(Path.GetDirectoryName(InstalledCliHost)!, "mxc"),
            BeforeReady = runtime =>
            {
                managerReady.TrySetResult(Assert.IsType<SandboxManager>(runtime.Sandboxes));
                return Task.CompletedTask;
            },
            Ready = _ => nodeReady.TrySetResult(),
            Output = TextWriter.Null,
            Error = TextWriter.Null,
        };
        var serving = Task.Run(() => NodeHost.RunAsync(options, stop.Token), ct);
        Id? ownerEpoch = null;
        try
        {
            var first = await Task.WhenAny(nodeReady.Task, serving).WaitAsync(NativeBound, ct);
            if (first == serving) Assert.Fail($"The isolated Node exited before readiness with status {await serving}.");
            var manager = await managerReady.Task.WaitAsync(NativeBound, ct);
            var config = WriteInstalledCliInput(fixture, "grant fixture profile.json", InstalledCliProfile());
            var created = await InstalledCliSuccessAsync(fixture, "sandbox", "create", "Isolated grant fixture", "--file", config);
            var sandbox = InstalledCliId(created.GetProperty("sandbox"), "sandboxId");
            ownerEpoch = InstalledCliId(created, "ownerEpoch");
            var grant = new RemoteGrant
            {
                EnrollmentId = enrollmentId,
                ScopeKind = "sandbox",
                SandboxId = sandbox,
                GrantId = CommandIds.New(),
                Methods = { "/arcforges.sandbox.v2.SandboxService/Inspect" },
            };
            var grantFile = WriteInstalledCliInput(fixture, "remote grant with spaces.json", grant);
            var denial = await InstalledCliRefusalAsync(fixture, 4, "permission_denied", "grant", "set", "--file", grantFile);
            Assert.Equal("active_v2_enrollment_required", denial.GetProperty("error").GetProperty("details")
                .GetProperty("state").GetProperty("reason").GetString());
            await using var channel = OpenChannel(fixture);
            var node = new NodeService.NodeServiceClient(channel.CallInvoker);
            var initial = await node.ListRemoteGrantsAsync(new NodeServiceListRemoteGrantsRequest { Meta = Query(), SandboxId = sandbox },
                deadline: Deadline, cancellationToken: ct);
            Assert.Empty(Value(initial.Value, initial.Error).Grants);

            // Seed only the established SEC-01 enrollment input. The CLI and protected local services perform all effects.
            manager.UpdateRemoteEnrollment(enrollment);
            var set = await InstalledCliSuccessAsync(fixture, "grant", "set", "--file", grantFile);
            var id = InstalledCliId(set.GetProperty("grant"), "grantId");
            Assert.Equal(grant.GrantId, id);
            var command = InstalledCliId(set, "commandId");
            Assert.Equal(ownerEpoch, InstalledCliId(set, "ownerEpoch"));
            var setOperation = await OperationAsync(node, ownerEpoch, command);
            Assert.Equal("NodeService.SetRemoteGrant", setOperation.Method);
            Assert.Equal(OperationState.Succeeded, setOperation.State);
            Assert.Equal(id, setOperation.AggregateId);
            var listed = await InstalledCliSuccessAsync(fixture, "grant", "list", "--sandbox", IdText.Format(sandbox));
            Assert.Equal(id, InstalledCliId(Assert.Single(listed.GetProperty("grants").EnumerateArray()), "grantId"));
            var observed = await node.ListRemoteGrantsAsync(new NodeServiceListRemoteGrantsRequest { Meta = Query(), SandboxId = sandbox },
                deadline: Deadline, cancellationToken: ct);
            var retained = Assert.Single(Value(observed.Value, observed.Error).Grants);
            Assert.Equal(grant.GrantId, retained.GrantId);
            Assert.Equal(grant.Methods, retained.Methods);
            Assert.Equal(GrantState.Active, retained.State);

            var revoked = await InstalledCliSuccessAsync(fixture, "grant", "revoke", IdText.Format(id),
                "--expected-revision", CliRevision(retained.Revision));
            Assert.Equal(ownerEpoch, InstalledCliId(revoked, "ownerEpoch"));
            var revokeCommand = InstalledCliId(revoked, "commandId");
            var revokeOperation = await OperationAsync(node, ownerEpoch, revokeCommand);
            Assert.Equal("NodeService.RevokeRemoteGrant", revokeOperation.Method);
            Assert.Equal(OperationState.Succeeded, revokeOperation.State);
            Assert.Equal(id, revokeOperation.AggregateId);
            var final = await node.ListRemoteGrantsAsync(new NodeServiceListRemoteGrantsRequest { Meta = Query(), SandboxId = sandbox },
                deadline: Deadline, cancellationToken: ct);
            var closed = Assert.Single(Value(final.Value, final.Error).Grants);
            Assert.Equal(GrantState.Revoked, closed.State);
            Assert.Equal(retained.Revision.Value + 1, closed.Revision.Value);
            var operation = await InstalledCliSuccessAsync(fixture, "operation", "inspect", IdText.Format(revokeCommand),
                "--owner-epoch", IdText.Format(ownerEpoch));
            Assert.Equal(id, InstalledCliId(operation.GetProperty("operation"), "aggregateId"));
            Assert.Equal(revokeCommand, InstalledCliId(operation.GetProperty("operation"), "commandId"));
        }
        finally
        {
            await stop.CancelAsync();
            Assert.Equal(NodeExitCodes.Success, await serving.WaitAsync(NativeBound, CancellationToken.None));
            if (ownerEpoch is not null) RemoveFixtureOwnerKey(fixture.DataRoot, ownerEpoch);
        }
    }

    private static async Task<Sandbox> InspectInstalledCliSandboxAsync(SandboxService.SandboxServiceClient client, Id id, CancellationToken ct)
    {
        var reply = await client.InspectAsync(new SandboxServiceInspectRequest { Meta = Query(), SandboxId = id },
            deadline: Deadline, cancellationToken: ct);
        return Value(reply.Value, reply.Error).Sandbox;
    }

    private static string[] ReplayInstalledCliStart(string[] argv, string command, string epoch)
    {
        var separator = Array.IndexOf(argv, "--");
        Assert.True(separator > 0);
        return [.. argv[..separator], "--command-id", command, "--owner-epoch", epoch, .. argv[separator..]];
    }

    private static async Task CleanInstalledCliFixtureAsync(TestNode fixture, Process process, Id? epoch, Id? heldRun)
    {
        try
        {
            if (epoch is null || heldRun is null || process.HasExited) return;
            await using var channel = OpenChannel(fixture);
            var runs = new RunService.RunServiceClient(channel.CallInvoker);
            var run = await InspectAsync(runs, heldRun, CancellationToken.None);
            if (run.State is RunState.Starting or RunState.Running)
            {
                await StopAsync(runs, BuildStop(epoch, run), CancellationToken.None);
            }

            if (run.State is RunState.Starting or RunState.Running or RunState.Stopping or RunState.Draining)
            {
                await WaitForStateAsync(fixture, runs, heldRun, RunState.Exited, CancellationToken.None);
            }
        }
        finally
        {
            using (process)
            {
                await StopInstalledCliNodeAsync(fixture, process);
                if (epoch is not null) RemoveFixtureOwnerKey(fixture.DataRoot, epoch);
            }
        }
    }

    private static async Task RequireInstalledCliGrammarAsync(TestNode fixture)
    {
        var help = await RunInstalledCliAsync(fixture, "--help");
        Assert.Equal(0, help.ExitCode);
        var text = Encoding.UTF8.GetString(help.Stdout);
        foreach (var current in new[] { "sandbox", "run", "resources", "grant", "operation", "doctor" })
        {
            Assert.Contains(current, text, StringComparison.Ordinal);
        }

        foreach (var removed in new[] { "tasks", "queue", "jobs" })
        {
            Assert.DoesNotContain(text.Split('\n'), line => line.TrimStart().StartsWith(removed + " ", StringComparison.Ordinal));
            Assert.Equal(2, (await RunInstalledCliAsync(fixture, removed, "list")).ExitCode);
        }

        const string line = "arcforges ";
        using var completion = fixture.StartProduct([$"[suggest:{line.Length}]", NodeLocations.TestModeOption, line]);
        var result = await TestNode.CompleteAsync(completion, NativeBound);
        Assert.Equal(0, result.ExitCode);
        var suggestions = result.Output.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        Assert.Contains("sandbox", suggestions);
        Assert.DoesNotContain("tasks", suggestions);
        Assert.DoesNotContain("queue", suggestions);
        Assert.DoesNotContain("jobs", suggestions);
        var runHelp = await RunInstalledCliAsync(fixture, "run", "start", "--help");
        Assert.Equal(0, runHelp.ExitCode);
        var options = Encoding.UTF8.GetString(runHelp.Stdout);
        foreach (var obsolete in new[] { "--depends-on", "--retry", "--agent", "--queue", "--toolchain", "--local" })
        {
            Assert.DoesNotContain(obsolete, options, StringComparison.Ordinal);
        }
    }

    private static async Task RequireInstalledCliResourceWatchAsync(TestNode fixture, string sandbox, CancellationToken ct)
    {
        using var watch = fixture.StartProduct([NodeLocations.TestModeOption, "--json", "resources", "watch",
            "--scope", "sandbox", "--id", sandbox, "--interval", "1s"]);
        try
        {
            using var first = JsonDocument.Parse(Assert.IsType<string>(await watch.StandardOutput.ReadLineAsync(ct).AsTask().WaitAsync(NativeBound, ct)));
            using var second = JsonDocument.Parse(Assert.IsType<string>(await watch.StandardOutput.ReadLineAsync(ct).AsTask().WaitAsync(NativeBound, ct)));
            Assert.Equal(sandbox, first.RootElement.GetProperty("scopeId").GetString());
            Assert.Equal(sandbox, second.RootElement.GetProperty("scopeId").GetString());
            Assert.Equal(first.RootElement.GetProperty("sampleEpoch").GetString(), second.RootElement.GetProperty("sampleEpoch").GetString());
            Assert.True(ulong.Parse(CliScalar(second.RootElement.GetProperty("sampleSequence")), CultureInfo.InvariantCulture)
                > ulong.Parse(CliScalar(first.RootElement.GetProperty("sampleSequence")), CultureInfo.InvariantCulture));
        }
        finally
        {
            if (!watch.HasExited)
            {
                watch.Kill();
                await watch.WaitForExitAsync(CancellationToken.None).WaitAsync(NativeBound, CancellationToken.None);
            }
        }
    }

    private static void PrepareInstalledCliFixture(TestNode fixture)
    {
        fixture.Environment[LocalSubmission.Variable] = null;
        fixture.Environment["ARCFORGES_TEST_CLIENT_IMAGES"] = null;
        PrepareDataRoot(fixture.DataRoot);
    }

    private static string InstalledCliHost => Environment.GetEnvironmentVariable("ARCFORGES_HOST_PATH")
        ?? throw new InvalidOperationException("The exact installed product path is required.");

    private static Task<(int ExitCode, byte[] Stdout, byte[] Stderr)> RunInstalledCliAsync(TestNode fixture, params string[] args) =>
        fixture.ProductCliBytesAsync(NativeBound, args);

    private static async Task StopInstalledCliNodeAsync(TestNode fixture, Process process)
    {
        if (process.HasExited) return;
        var result = await RunInstalledCliAsync(fixture, "node", "stop", "--timeout", "30s");
        Assert.Equal(0, result.ExitCode);
        await process.WaitForExitAsync(CancellationToken.None).WaitAsync(NativeBound, CancellationToken.None);
    }

    private static SandboxConfig InstalledCliProfile()
    {
        var windows = OperatingSystem.IsWindows();
        return new SandboxConfig
        {
            ProfileId = windows ? MxcProfileAdmission.WindowsProfileId : MxcProfileAdmission.LinuxProfileId,
            ProfileVersion = windows ? MxcProfileAdmission.WindowsProfileRevision : MxcProfileAdmission.LinuxProfileRevision,
            Network = new NetworkPolicy { Egress = NetworkMode.Deny, Ingress = NetworkMode.Deny, HostLoopback = false },
            Resources = new ResourcePolicy { CpuMaxMillicores = CpuMillicores, MemoryMaxBytes = MemoryBytes, PressureAction = PressureAction.Throttle },
        };
    }

    private static string WriteInstalledCliInput(TestNode fixture, string name, IMessage message)
    {
        var dir = Directory.CreateDirectory(Path.Combine(fixture.Root, "CLI inputs with spaces")).FullName;
        var path = Path.Combine(dir, name);
        File.WriteAllText(path, JsonFormatter.Default.Format(message));
        return path;
    }

    private static Id InstalledCliId(JsonElement document, string property)
    {
        var text = document.GetProperty(property).GetString();
        Assert.True(IdText.TryParse(text, out var bytes), $"Expected a canonical {property} ID.");
        var id = new Id { Value = ByteString.CopyFrom(bytes) };
        Assert.Equal(text, IdText.Format(id));
        return id;
    }

    private static string CliRevision(Revision revision) => revision.Value.ToString(CultureInfo.InvariantCulture);

    private static string CliScalar(JsonElement value) => value.ValueKind == JsonValueKind.String ? value.GetString()! : value.GetRawText();

    private static async Task<JsonElement> InstalledCliSuccessAsync(TestNode fixture, params string[] args)
    {
        var result = await RunInstalledCliAsync(fixture, ["--json", .. args]);
        if (result.ExitCode != 0)
        {
            Assert.Fail($"The installed CLI {args[0]} command returned {result.ExitCode} ({InstalledCliFailureDiagnostic(result.Stdout)}).");
        }

        using var json = JsonDocument.Parse(result.Stdout);
        Assert.False(json.RootElement.TryGetProperty("error", out _));
        return json.RootElement.Clone();
    }

    private static string InstalledCliFailureDiagnostic(byte[] output)
    {
        if (output.Length > 65_536) return "oversized_diagnostic";
        try
        {
            using var document = JsonDocument.Parse(output);
            if (document.RootElement.ValueKind == JsonValueKind.Object && document.RootElement.TryGetProperty("error", out var error)
                && error.ValueKind == JsonValueKind.Object && error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String
                && code.GetString() is { Length: > 0 and <= 64 } text && text.All(c => char.IsAsciiLetterOrDigit(c) || c == '_'))
            {
                if (text == "unsupported_combination" && error.TryGetProperty("details", out var details)
                    && details.ValueKind == JsonValueKind.Object && details.TryGetProperty("state", out var state)
                    && state.ValueKind == JsonValueKind.Object && state.TryGetProperty("reason", out var reason)
                    && reason.ValueKind == JsonValueKind.String && reason.GetString() is { Length: > 0 and <= 160 } reasonText
                    && reasonText.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or ':' or '-' or ',' or ' ' or '.'))
                {
                    return $"{text}, reason {reasonText}";
                }

                return text;
            }
        }
        catch (JsonException)
        {
            return "invalid_cli_json";
        }

        return "no_typed_error_code";
    }

    private static async Task<JsonElement> InstalledCliRefusalAsync(TestNode fixture, int code, string error, params string[] args)
    {
        var result = await RunInstalledCliAsync(fixture, ["--json", .. args]);
        Assert.Equal(code, result.ExitCode);
        using var json = JsonDocument.Parse(result.Stdout);
        Assert.Equal(error, json.RootElement.GetProperty("error").GetProperty("code").GetString());
        return json.RootElement.Clone();
    }
}
