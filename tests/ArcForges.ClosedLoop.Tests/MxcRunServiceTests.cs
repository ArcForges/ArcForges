// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.LocalRpc;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform.Capabilities;
using ArcForges.Node.Platform.Linux.Mxc;
using ArcForges.Node.Platform.Windows.Mxc;
using ArcForges.Node.Store;
using ArcForges.RunSupervisor.Protocol;
using ArcForges.Tests;
using Microsoft.Data.Sqlite;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>V2 Run admission, native foreground cleanup, and durable replay through an extracted release archive.</summary>
[Trait("loop", "local")]
[Trait("env", "windows-real")]
[Trait("env", "linux-real")]
[Trait("isolation", "exclusive")]
public sealed class MxcRunServiceTests
{
    private static readonly TimeSpan NativeBound = TimeSpan.FromSeconds(35);
    private const string MarkerName = "entered.log";
    private const string ChildMarkerName = "child.log";
    private const string FixtureArgument = "quoted two words";
    private const string EnvironmentName = "CORE02_PAYLOAD_MARKER";
    private const string EnvironmentValue = "explicit run value";
    private const string RelativeWorkdir = "work/quoted directory";
    private const uint CpuMillicores = 500;
    private const ulong MemoryBytes = 256UL << 20;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static DateTime Deadline => DateTime.UtcNow.AddSeconds(30);

    [Fact(Timeout = 240_000, DisableParallelization = true)]
    public async Task InstalledRunStopsItsNativeScopeAndCannotReplayAfterCompactionAndColdRestart()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var fixture = TestNode.Create();
        PrepareDataRoot(fixture.DataRoot);
        var process = await fixture.StartNodeAsync();
        Id? ownerEpoch = null;
        Id? cleanupRun = null;
        try
        {
            RunServiceStartRequest original;
            Run settled;
            string marker;
            string childMarker;
            string firstNodeEpoch;
            await using (var channel = OpenChannel(fixture))
            {
                var node = new NodeService.NodeServiceClient(channel.CallInvoker);
                var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
                var runs = new RunService.RunServiceClient(channel.CallInvoker);
                var hello = await HandshakeAsync(node);
                ownerEpoch = hello.OwnerEpoch;
                firstNodeEpoch = hello.NodeEpoch;
                var sandbox = await CreateSandboxAsync(sandboxes, ownerEpoch);
                var working = Path.Combine(sandbox.DataLocation, "work", "quoted directory");
                Directory.CreateDirectory(working);
                marker = Path.Combine(working, MarkerName);
                childMarker = Path.Combine(working, ChildMarkerName);
                original = BuildStart(sandbox, ownerEpoch, PreparePayload(working));

                var outside = original.Clone();
                outside.Meta = Mutation(sandbox.Revision);
                outside.WorkingDirectory = "../outside";
                var refused = await runs.StartAsync(outside, deadline: Deadline, cancellationToken: Ct);
                Assert.Equal("invalid_argument", refused.Error?.Code);
                Assert.Equal(EffectCertainty.DidNotHappen, refused.Error!.Effect);
                Assert.False(File.Exists(marker));
                Assert.False(File.Exists(childMarker));
                Assert.Empty(await ListAsync(runs, sandbox.SandboxId));

                var submitted = await runs.StartAsync(original, deadline: Deadline, cancellationToken: Ct);
                var start = Value(submitted.Value, submitted.Error);
                cleanupRun = start.Run.RunId;
                Assert.Equal(original.Meta.CommandId, start.Operation.CommandId);
                Assert.Equal(ownerEpoch, start.Operation.OwnerEpoch);
                Assert.Equal(cleanupRun, start.Operation.AggregateId);
                AssertRunProjection(start.Run, sandbox, original.Argv[0]);
                var running = await WaitForStateAsync(fixture, runs, cleanupRun, RunState.Running);
                await TestNode.WaitAsync(() => ChildIsReady(childMarker), NativeBound, "the real foreground workload's child marker");
                Assert.Equal(FixtureArgument + "," + EnvironmentValue, Assert.Single(ReadLines(marker)));
                AssertRunProjection(running, sandbox, original.Argv[0]);
                Assert.Equal(running.RunId, Assert.Single(await ListAsync(runs, sandbox.SandboxId)).RunId);

                using var native = await ObserveNativeBoundaryAsync(fixture, running, childMarker);
                Assert.Equal(CpuMillicores, DesiredCpu(running));
                Assert.Equal(MemoryBytes, DesiredMemory(running));
                Assert.False(native.IsEmpty(), "The running foreground payload must occupy its native boundary.");
                var stop = BuildStop(ownerEpoch, running);
                var requested = await StopAsync(runs, stop, Ct);
                Assert.Equal(running.RunId, requested.Run.RunId);
                Assert.Equal(stop.Meta.CommandId, requested.Operation.CommandId);
                Assert.Equal(running.RunId, requested.Operation.AggregateId);
                Assert.Contains(requested.Run.State, new[] { RunState.Stopping, RunState.Draining, RunState.Exited });
                settled = await WaitForStateAsync(fixture, runs, running.RunId, RunState.Exited);
                Assert.True(settled.Exit.GroupEmptyVerified);
                Assert.True(native.IsEmpty(), "The native process boundary must be empty when the Run becomes terminal.");
                Assert.NotEqual(PayloadStartEvidence.NotStarted, settled.Exit.PayloadStarted);
                if (settled.Exit.HasRawCode)
                {
                    Assert.Contains(settled.Exit.Source, new[] { ExitSource.OfficialExecutor, ExitSource.Supervisor });
                }

                var linkedReceipt = await OperationAsync(node, stop.OwnerEpoch, stop.Meta.CommandId);
                AssertStopReceipt(linkedReceipt, stop, settled.Revision, EffectCertainty.Happened);

                var terminalStop = BuildStop(ownerEpoch, settled);
                Assert.NotEqual(stop.Meta.CommandId, terminalStop.Meta.CommandId);
                var noOp = await StopAsync(runs, terminalStop, Ct);
                Assert.Equal(settled, noOp.Run);
                AssertStopReceipt(noOp.Operation, terminalStop, settled.Revision, EffectCertainty.DidNotHappen);
                Assert.Equal(noOp, await StopAsync(runs, terminalStop, Ct));
                var terminalReceipt = await OperationAsync(node, terminalStop.OwnerEpoch, terminalStop.Meta.CommandId);
                AssertStopReceipt(terminalReceipt, terminalStop, settled.Revision, EffectCertainty.DidNotHappen);
                Assert.True(native.IsEmpty());
                Assert.Equal(FixtureArgument + "," + EnvironmentValue, Assert.Single(ReadLines(marker)));

                AssertRunProjection(settled, sandbox, original.Argv[0]);
                var renamed = await sandboxes.ConfigureAsync(new SandboxServiceConfigureRequest
                {
                    Meta = Mutation(sandbox.Revision), OwnerEpoch = ownerEpoch, SandboxId = sandbox.SandboxId,
                    Config = sandbox.Config.Clone(), DisplayName = "Renamed native Run package fixture",
                }, deadline: Deadline, cancellationToken: Ct);
                Assert.True(Value(renamed.Value, renamed.Error).Sandbox.Revision.Value > sandbox.Revision.Value);
                AssertRunProjection(await InspectAsync(runs, settled.RunId, Ct), sandbox, original.Argv[0]);
                var recorded = await OperationAsync(node, original.OwnerEpoch, original.Meta.CommandId);
                Assert.Equal(OperationState.Succeeded, recorded.State);
                Assert.Equal(EffectCertainty.Happened, recorded.Effect);
                Assert.False(recorded.ResponseCompacted);
                cleanupRun = null;
            }

            await StopNodeAsync(fixture, process);
            CompactActualResponse(fixture.DataRoot, original, settled.RunId);
            process = await fixture.StartNodeAsync();
            await using var recovered = OpenChannel(fixture);
            var recoveredNode = new NodeService.NodeServiceClient(recovered.CallInvoker);
            var recoveredRuns = new RunService.RunServiceClient(recovered.CallInvoker);
            var newHello = await HandshakeAsync(recoveredNode);
            Assert.NotEqual(firstNodeEpoch, newHello.NodeEpoch);
            Assert.Equal(ownerEpoch, newHello.OwnerEpoch);

            var replay = await recoveredRuns.StartAsync(original, deadline: Deadline, cancellationToken: Ct);
            Assert.Equal("receipt_compacted", replay.Error?.Code);
            Assert.Equal(EffectCertainty.Happened, replay.Error!.Effect);
            Assert.Equal("SUCCEEDED", replay.Error.Details.State.State);
            Assert.Equal(settled.RunId, replay.Error.Details.State.Resource.Id);
            var retained = await OperationAsync(recoveredNode, original.OwnerEpoch, original.Meta.CommandId);
            Assert.True(retained.ResponseCompacted);
            Assert.Equal(original.Meta.CommandId, retained.CommandId);
            Assert.Equal(ownerEpoch, retained.OwnerEpoch);
            Assert.Equal(settled.RunId, retained.AggregateId);
            Assert.Equal(OperationState.Succeeded, retained.State);
            Assert.Equal(EffectCertainty.Happened, retained.Effect);

            var conflict = original.Clone();
            conflict.Argv[^1] = "different synthetic argument";
            var conflicted = await recoveredRuns.StartAsync(conflict, deadline: Deadline, cancellationToken: Ct);
            Assert.Equal("command_id_reused", conflicted.Error?.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, conflicted.Error!.Effect);
            var stale = original.Clone();
            stale.OwnerEpoch = CommandIds.New();
            var retired = await recoveredRuns.StartAsync(stale, deadline: Deadline, cancellationToken: Ct);
            Assert.Equal("owner_epoch_retired", retired.Error?.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, retired.Error!.Effect);

            Assert.Equal(settled, await InspectAsync(recoveredRuns, settled.RunId, Ct));
            Assert.Equal(settled.RunId, Assert.Single(await ListAsync(recoveredRuns, settled.SandboxId)).RunId);
            Assert.Equal(FixtureArgument + "," + EnvironmentValue, Assert.Single(ReadLines(marker)));
            TestContext.Current.TestOutputHelper?.WriteLine("One native payload wrote the expected argv and explicit environment at the requested working directory. Stop verified the boundary empty. Compacted, conflicting, and retired-epoch requests left the marker unchanged.");
        }
        finally
        {
            try
            {
                if (ownerEpoch is not null && cleanupRun is not null && !process.HasExited)
                {
                    await using var channel = OpenChannel(fixture);
                    var runs = new RunService.RunServiceClient(channel.CallInvoker);
                    var run = await InspectAsync(runs, cleanupRun, CancellationToken.None);
                    if (run.State is RunState.Starting or RunState.Running)
                    {
                        await StopAsync(runs, BuildStop(ownerEpoch, run), CancellationToken.None);
                    }
                }
            }
            finally
            {
                await StopNodeAsync(fixture, process);
                if (ownerEpoch is not null)
                {
                    RemoveFixtureOwnerKey(fixture.DataRoot, ownerEpoch);
                }
            }
        }
    }

    [Fact(Timeout = 150_000, DisableParallelization = true)]
    public async Task InstalledRunContinuesAfterItsClientDisconnectsAndTheNodeDies()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        cancellationToken.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var fixture = TestNode.Create();
        PrepareDataRoot(fixture.DataRoot);
        var process = await fixture.StartNodeAsync();
        Id? ownerEpoch = null;
        NativeBoundary? native = null;
        try
        {
            Run running;
            string marker;
            const string ready = "ready";
            const string late = "late";
            await using (var channel = OpenChannel(fixture))
            {
                var node = new NodeService.NodeServiceClient(channel.CallInvoker);
                var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
                var runs = new RunService.RunServiceClient(channel.CallInvoker);
                ownerEpoch = (await HandshakeAsync(node)).OwnerEpoch;
                var sandbox = await CreateSandboxAsync(sandboxes, ownerEpoch, explicitLimits: false);
                Assert.False(sandbox.Config.Resources.HasCpuMaxMillicores);
                Assert.False(sandbox.Config.Resources.HasMemoryMaxBytes);
                var working = Path.Combine(sandbox.DataLocation, "work", "quoted directory");
                Directory.CreateDirectory(working);
                marker = Path.Combine(working, MarkerName);
                var childMarker = Path.Combine(working, ChildMarkerName);
                var request = BuildStart(sandbox, ownerEpoch, PrepareSelfSettlingPayload(working));
                Assert.Null(request.RequestedResources);
                var submitted = await runs.StartAsync(request, deadline: Deadline, cancellationToken: cancellationToken);
                running = await WaitForStateAsync(fixture, runs, Value(submitted.Value, submitted.Error).Run.RunId, RunState.Running);
                await TestNode.WaitAsync(() => ChildIsReady(childMarker), NativeBound, "the self-settling payload's ready child");
                Assert.Equal(ready, Assert.Single(ReadLines(marker)));
                native = await ObserveNativeBoundaryAsync(fixture, running, childMarker);
                Assert.True(DesiredCpu(running) > 0);
                Assert.True(DesiredMemory(running) > 0);
            }

            Assert.NotEqual(process.Id, native.Supervisor.Pid);
            Assert.NotEqual(process.Id, native.Payload.Pid);
            Assert.NotEqual(native.Supervisor.Pid, native.Payload.Pid);
            Assert.True(native.Supervisor.IsRunning(), "The exact bound supervisor must survive local RPC client disposal.");
            Assert.True(native.Payload.IsRunning(), "The real native foreground child must survive local RPC client disposal.");
            Assert.False(native.IsEmpty());
            Assert.Equal(ready, Assert.Single(ReadLines(marker)));
            process.Kill();
            await process.WaitForExitAsync(cancellationToken).WaitAsync(NativeBound, cancellationToken);
            Assert.True(native.Supervisor.IsRunning(), "The exact bound supervisor must survive Node exit.");
            Assert.True(native.Payload.IsRunning(), "The exact native child must survive Node exit.");
            Assert.Equal(ready, Assert.Single(ReadLines(marker)));

            await TestNode.WaitAsync(() => ReadLines(marker).Contains(late, StringComparer.Ordinal), NativeBound,
                "the original payload to complete after both client and Node are gone");
            await TestNode.WaitAsync(native.IsEmpty, NativeBound, "the exact native Run scope to drain with no Node process");
            Assert.Equal(new[] { ready, late }, ReadLines(marker));
            var observation = ReadProtectedDrain(fixture.DataRoot, running);
            Assert.Equal(RunOwnerState.Exited, observation.State);
            Assert.True(observation.GroupEmptyVerified);
            Assert.NotEqual(RunPayloadStart.NotStarted, observation.PayloadStarted);
            Assert.Null(observation.NativeError);
            TestContext.Current.TestOutputHelper?.WriteLine("The bound supervisor and foreground child survived both losses. The original payload wrote one late marker and the protected native drain observation agreed with the empty scope.");
        }
        finally
        {
            await StopNodeAsync(fixture, process);
            if (native is not null)
            {
                using (native)
                {
                    await TestNode.WaitAsync(native.IsEmpty, NativeBound, "the bounded fixture payload and its native scope to exit");
                }
            }

            if (ownerEpoch is not null)
            {
                RemoveFixtureOwnerKey(fixture.DataRoot, ownerEpoch);
            }
        }
    }

    private static void RequireExtractedPackage()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("ARCFORGES_MXC_PACKAGE_TESTS") == "1",
            "Set ARCFORGES_MXC_PACKAGE_TESTS for the verified, extracted native package lane.");
        Assert.True(OperatingSystem.IsWindows() || OperatingSystem.IsLinux());
        if (OperatingSystem.IsLinux())
        {
            Assert.Null(SystemdTestEnvironment.SkipReason);
        }

        var host = Environment.GetEnvironmentVariable("ARCFORGES_HOST_PATH");
        Assert.True(host is not null && Path.IsPathFullyQualified(host) && File.Exists(host),
            "The package fixture requires an absolute ARCFORGES_HOST_PATH in the verified extraction.");
        var mxc = Path.Combine(Path.GetDirectoryName(host!)!, "mxc");
        var image = OperatingSystem.IsWindows() ? "arcforges-run-supervisor.exe" : "arcforges-run-supervisor";
        Assert.True(File.Exists(Path.Combine(mxc, image)), "The package must contain its own per-Run supervisor.");
        Assert.True(File.Exists(Path.Combine(mxc, "mxc-manifest.json")), "The package must contain its own official MXC manifest.");
    }

    private static void PrepareDataRoot(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            using var principal = WindowsIdentity.GetCurrent();
            var owner = principal.User ?? throw new InvalidOperationException("The fixture principal has no user SID.");
            var security = new DirectorySecurity();
            security.SetOwner(owner);
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(path).Create(security);
        }
        else if (OperatingSystem.IsLinux())
        {
            Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private static string[] PreparePayload(string working)
    {
        if (!OperatingSystem.IsWindows())
        {
            const string script = """
                printf '%s,%s\n' "$1" "$CORE02_PAYLOAD_MARKER" >> entered.log
                /usr/bin/sleep 120 &
                printf '%s\n' "$!" > child.log
                wait
                """;
            return ["/usr/bin/dash", "-c", script, "arcforges-run-fixture", FixtureArgument];
        }

        InstallWindowsTestLoad(working);
        const string batch = """
            @echo off
            >>entered.log echo %~1,%CORE02_PAYLOAD_MARKER%
            .\arcforges-testload.exe hold --hold-ms 120000 --marker child.log
            """;
        File.WriteAllText(Path.Combine(working, "fixture.cmd"), batch.ReplaceLineEndings("\r\n") + "\r\n");
        return [Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/d", "/c", "fixture.cmd", FixtureArgument];
    }

    private static string[] PrepareSelfSettlingPayload(string working)
    {
        if (!OperatingSystem.IsWindows())
        {
            const string script = """
                printf 'ready\n' >> entered.log
                /usr/bin/sleep 8 &
                printf '%s\n' "$!" > child.log
                wait "$!" || exit 1
                printf 'late\n' >> entered.log
                """;
            return ["/usr/bin/dash", "-c", script];
        }

        InstallWindowsTestLoad(working);
        const string batch = """
            @echo off
            >>entered.log echo ready
            .\arcforges-testload.exe hold --hold-ms 8000 --marker child.log
            if not "%errorlevel%"=="0" exit /b 1
            >>entered.log echo late
            """;
        File.WriteAllText(Path.Combine(working, "fixture.cmd"), batch.ReplaceLineEndings("\r\n") + "\r\n");
        return [Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/d", "/c", "fixture.cmd"];
    }

    private static void InstallWindowsTestLoad(string working)
    {
        var testload = Environment.GetEnvironmentVariable("ARCFORGES_TESTLOAD_PATH");
        Assert.True(testload is not null && Path.IsPathFullyQualified(testload) && File.Exists(testload),
            "The Windows package fixture needs the published native testload.");
        File.Copy(testload!, Path.Combine(working, "arcforges-testload.exe"));
    }

    private static NodeChannel OpenChannel(TestNode fixture) => NodeChannel.Create(OperatingSystem.IsWindows()
        ? LocalRpcEndpoint.NamedPipe(fixture.Endpoint)
        : LocalRpcEndpoint.UnixDomainSocket(fixture.Endpoint));

    private static async Task<NodeServiceHandshakeValue> HandshakeAsync(NodeService.NodeServiceClient node)
    {
        var reply = await node.HandshakeAsync(new NodeServiceHandshakeRequest { Meta = Query() }, deadline: Deadline, cancellationToken: Ct);
        return Value(reply.Value, reply.Error);
    }

    private static async Task<Sandbox> CreateSandboxAsync(SandboxService.SandboxServiceClient sandboxes, Id ownerEpoch, bool explicitLimits = true)
    {
        bool windows = OperatingSystem.IsWindows();
        var resources = new ResourcePolicy { PressureAction = PressureAction.Throttle };
        if (explicitLimits)
        {
            resources.CpuMaxMillicores = CpuMillicores;
            resources.MemoryMaxBytes = MemoryBytes;
        }

        var reply = await sandboxes.CreateAsync(new SandboxServiceCreateRequest
        {
            Meta = Mutation(),
            OwnerEpoch = ownerEpoch,
            DisplayName = "Native Run package fixture",
            Config = new SandboxConfig
            {
                ProfileId = windows ? MxcProfileAdmission.WindowsProfileId : MxcProfileAdmission.LinuxProfileId,
                ProfileVersion = windows ? MxcProfileAdmission.WindowsProfileRevision : MxcProfileAdmission.LinuxProfileRevision,
                Network = new NetworkPolicy { Egress = NetworkMode.Deny, Ingress = NetworkMode.Deny, HostLoopback = false },
                Resources = resources,
            },
        }, deadline: Deadline, cancellationToken: Ct);
        var sandbox = Value(reply.Value, reply.Error).Sandbox;
        Assert.Equal(SandboxState.Ready, sandbox.State);
        return sandbox;
    }

    private static RunServiceStartRequest BuildStart(Sandbox sandbox, Id ownerEpoch, string[] argv) => new()
    {
        Meta = Mutation(sandbox.Revision),
        OwnerEpoch = ownerEpoch,
        SandboxId = sandbox.SandboxId,
        WorkingDirectory = RelativeWorkdir,
        Argv = { argv },
        Environment = { new EnvironmentEntry { Name = EnvironmentName, Value = EnvironmentValue } },
        TerminalMode = TerminalMode.Interactive,
        TerminalSize = new TerminalSize { Rows = 24, Columns = 80 },
    };

    private static async Task<Run> InspectAsync(RunService.RunServiceClient runs, Id runId, CancellationToken cancellationToken)
    {
        var reply = await runs.InspectAsync(new RunServiceInspectRequest { Meta = Query(), RunId = runId },
            deadline: Deadline, cancellationToken: cancellationToken);
        return Value(reply.Value, reply.Error).Run;
    }

    private static async Task<Run> WaitForStateAsync(TestNode fixture, RunService.RunServiceClient runs, Id runId, RunState state)
    {
        var clock = Stopwatch.StartNew();
        while (true)
        {
            var run = await InspectAsync(runs, runId, Ct);
            if (run.State == state)
            {
                return run;
            }

            if (run.State is not (RunState.Starting or RunState.Running or RunState.Stopping or RunState.Draining) || clock.Elapsed >= NativeBound)
            {
                var diagnostics = ReadRunDiagnostics(fixture, runId);
                Assert.Fail($"Run did not reach {state}. Observed {run.State} with {run.Exit?.TerminationReason ?? "no exit reason"}. {diagnostics}");
            }

            await Task.Delay(50, Ct);
        }
    }

    private static string ReadRunDiagnostics(TestNode fixture, Id runId)
    {
        try
        {
            var id = Hex(runId);
            var entries = TestNode.LogEvents(fixture.NodeLog, "run.owner")
                .Select(entry => entry.GetProperty("fields"))
                .Where(fields => fields.GetProperty("run").GetString() == id)
                .TakeLast(4)
                .Select(fields => $"{fields.GetProperty("phase").GetString()}={fields.GetProperty("native").GetString()}");
            return string.Join(", ", entries);
        }
        catch (Exception error) when (error is IOException or JsonException or KeyNotFoundException)
        {
            return "Run owner diagnostics unavailable.";
        }
    }

    private static async Task<Run[]> ListAsync(RunService.RunServiceClient runs, Id sandboxId)
    {
        var reply = await runs.ListAsync(new RunServiceListRequest { Meta = Query(), SandboxId = sandboxId }, deadline: Deadline, cancellationToken: Ct);
        return Value(reply.Value, reply.Error).Runs.ToArray();
    }

    private static RunServiceStopRequest BuildStop(Id ownerEpoch, Run run) => new()
    {
        Meta = Mutation(run.Revision), OwnerEpoch = ownerEpoch, RunId = run.RunId, GraceMs = 0,
    };

    private static async Task<RunServiceStopValue> StopAsync(RunService.RunServiceClient runs, RunServiceStopRequest request,
        CancellationToken cancellationToken)
    {
        var reply = await runs.StopAsync(request, deadline: Deadline, cancellationToken: cancellationToken);
        return Value(reply.Value, reply.Error);
    }

    private static void AssertStopReceipt(Operation operation, RunServiceStopRequest request, Revision revision, EffectCertainty effect)
    {
        Assert.Equal(request.Meta.CommandId, operation.CommandId);
        Assert.Equal(request.OwnerEpoch, operation.OwnerEpoch);
        Assert.Equal(request.RunId, operation.AggregateId);
        Assert.Equal(revision, operation.Revision);
        Assert.Equal("RunService.Stop", operation.Method);
        Assert.Equal(OperationState.Succeeded, operation.State);
        Assert.Equal(effect, operation.Effect);
        Assert.False(operation.ResponseCompacted);
    }

    private static void AssertRunProjection(Run run, Sandbox sandbox, string executable)
    {
        Assert.Equal(sandbox.SandboxId, run.SandboxId);
        Assert.Equal(sandbox.Revision, run.SandboxRevision);
        Assert.Equal(sandbox.Config.ProfileId, run.ProfileId);
        Assert.Equal(sandbox.Config.ProfileVersion, run.ProfileVersion);
        Assert.Equal(TerminalMode.Interactive, run.TerminalMode);
        Assert.Matches("^[0-9a-f]{64}$", run.LaunchSha256);
        Assert.StartsWith(Path.GetFileName(executable), run.SafeCommandDisplay);
        Assert.DoesNotContain(FixtureArgument, run.SafeCommandDisplay);
        Assert.DoesNotContain(EnvironmentValue, run.SafeCommandDisplay);
        Assert.DoesNotContain(Path.GetDirectoryName(executable)!, run.SafeCommandDisplay);
    }

    private static async Task<NativeBoundary> ObserveNativeBoundaryAsync(TestNode fixture, Run run, string childMarker)
    {
        var native = ReadSupervisor(fixture.DataRoot, run);
        var owner = ProcessIdentity.Capture(native.Pid);
        Assert.NotNull(owner);
        var observedBirth = OperatingSystem.IsWindows()
            ? new DateTime(owner.Value.StartKey, DateTimeKind.Utc).ToFileTimeUtc()
            : owner.Value.StartKey;
        Assert.Equal(native.Creation, observedBirth.ToString(CultureInfo.InvariantCulture));

        if (OperatingSystem.IsWindows())
        {
            var start = ReadLines(childMarker).First(line => line.StartsWith("start ", StringComparison.Ordinal)).Split(' ');
            var child = ProcessIdentity.Capture(int.Parse(start[1], CultureInfo.InvariantCulture));
            Assert.NotNull(child);
            return new NativeBoundary(owner.Value, child.Value, null);
        }

        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException();
        }

        var boundary = native.Boundary.Split('|');
        Assert.Equal(5, boundary.Length);
        Assert.StartsWith("arcforges-run-", boundary[0]);
        var group = LinuxRunCgroup.Open(boundary[2]);
        try
        {
            Assert.Equal(boundary[3], group.MountId.ToString(CultureInfo.InvariantCulture));
            Assert.Equal(boundary[4], group.Inode.ToString(CultureInfo.InvariantCulture));
            Assert.True(LinuxRunCgroup.MatchesProcess(owner.Value.Pid, owner.Value.StartKey, group.Path));
            var limits = group.ReadLimits();
            Assert.Equal(100_000UL, limits.CpuPeriod);
            Assert.Equal(DesiredCpu(run) * 100UL, limits.CpuQuota);
            Assert.Equal(DesiredMemory(run), limits.MemoryBytes);

            return new NativeBoundary(owner.Value, await WaitForLinuxSleepAsync(group.Path), group);
        }
        catch
        {
            group.Dispose();
            throw;
        }
    }

    private static (int Pid, string Creation, string Boundary) ReadSupervisor(string dataRoot, Run run)
    {
        using var database = ReadDatabase(dataRoot);
        using var command = database.CreateCommand();
        command.CommandText = "SELECT process_id, creation_identity, boundary_identity, control_epoch FROM supervisor_identity WHERE run_id = $id;";
        command.Parameters.AddWithValue("$id", Hex(run.RunId));
        using var row = command.ExecuteReader();
        Assert.True(row.Read(), "The Node must durably bind the exact native Run owner before reporting RUNNING.");
        Assert.Equal(run.Epoch, row.GetString(3));
        return (row.GetInt32(0), row.GetString(1), row.GetString(2));
    }

    [SupportedOSPlatform("linux")]
    private static async Task<ProcessIdentity> WaitForLinuxSleepAsync(string group)
    {
        ProcessIdentity? child = null;
        await TestNode.WaitAsync(() => (child = FindLinuxSleep(group)) is not null, NativeBound,
            "the real sleep child to appear in the bound cgroup");
        Assert.NotNull(child);
        return child.Value;
    }

    [SupportedOSPlatform("linux")]
    private static ProcessIdentity? FindLinuxSleep(string group)
    {
        var processes = Path.Combine("/sys/fs/cgroup", group.TrimStart('/'), "cgroup.procs");
        foreach (var line in File.ReadLines(processes))
        {
            if (!int.TryParse(line, CultureInfo.InvariantCulture, out var pid) || ProcessIdentity.Capture(pid) is not { } identity)
            {
                continue;
            }

            try
            {
                if (File.ReadAllText($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/comm").Trim() == "sleep"
                    && LinuxRunCgroup.MatchesProcess(pid, identity.StartKey, group))
                {
                    return identity;
                }
            }
            catch (IOException error) when (error is FileNotFoundException or DirectoryNotFoundException)
            {
                // A transient native member exited before inspection. A reused PID cannot pass the creation check.
            }
        }

        return null;
    }

    private static uint DesiredCpu(Run run) => uint.Parse(run.Limits.Single(limit => limit.Dimension == "cpu").DesiredValue, CultureInfo.InvariantCulture);

    private static ulong DesiredMemory(Run run) => ulong.Parse(run.Limits.Single(limit => limit.Dimension == "memory").DesiredValue, CultureInfo.InvariantCulture);

    private sealed class NativeBoundary(ProcessIdentity supervisor, ProcessIdentity payload, LinuxRunCgroup? cgroup) : IDisposable
    {
        public ProcessIdentity Supervisor { get; } = supervisor;
        public ProcessIdentity Payload { get; } = payload;

        public bool IsEmpty() => !Supervisor.IsRunning() && !Payload.IsRunning()
            && (!OperatingSystem.IsLinux() || cgroup is null || cgroup.IsEmpty());

        public void Dispose()
        {
            if (OperatingSystem.IsLinux())
            {
                cgroup?.Dispose();
            }
        }
    }

    private static RunOwnerObservation ReadProtectedDrain(string dataRoot, Run run)
    {
        var control = Path.Combine(dataRoot, "control", "run-" + Hex(run.RunId));
        var path = Path.Combine(control, "observed.bin");
        if (OperatingSystem.IsWindows())
        {
            using var heldControl = WindowsMxcPathLease.Open(control, directory: true, privateObject: true);
            using var heldObservation = WindowsMxcPathLease.Open(path, directory: false, privateObject: true);
            return ReadReceipt();
        }

        if (OperatingSystem.IsLinux())
        {
            using var heldControl = LinuxRunCgroup.OpenPrivateDirectory(control);
            using var heldObservation = LinuxRunCgroup.OpenTrustedFile(path, rootOnly: false, executable: false);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
            return ReadReceipt();
        }

        throw new PlatformNotSupportedException();

        RunOwnerObservation ReadReceipt()
        {
            // The owner consumes the ephemeral authentication key before running the workload. Post-crash evidence
            // here is the protected worker record bound to the same launch plus independent native emptiness.
            using var stream = File.OpenRead(path);
            Assert.InRange(stream.Length, RunWire.KeyLength + 1L, RunWire.KeyLength + 65_536L);
            var bytes = new byte[checked((int)stream.Length)];
            stream.ReadExactly(bytes);
            using var receipt = JsonDocument.Parse(bytes.AsMemory(0, bytes.Length - RunWire.KeyLength));
            var value = receipt.RootElement;
            Assert.Equal(Hex(run.RunId), value.GetProperty("RunId").GetString());
            Assert.Equal(run.Epoch, value.GetProperty("Epoch").GetString());
            Assert.Equal(run.LaunchSha256, value.GetProperty("LaunchSha256").GetString());
            return Assert.IsType<RunOwnerObservation>(value.GetProperty("Observation").Deserialize<RunOwnerObservation>());
        }
    }

    private static async Task<Operation> OperationAsync(NodeService.NodeServiceClient node, Id ownerEpoch, Id commandId)
    {
        var reply = await node.GetOperationAsync(new NodeServiceGetOperationRequest
        {
            Meta = Query(), CommandId = commandId, OwnerEpoch = ownerEpoch,
        }, deadline: Deadline, cancellationToken: Ct);
        return Value(reply.Value, reply.Error).Operation;
    }

    private static async Task StopNodeAsync(TestNode fixture, Process process)
    {
        if (!process.HasExited)
        {
            var stopped = await fixture.CliAsync("node", "stop", "--timeout", "30s");
            Assert.Equal(0, stopped.ExitCode);
            await process.WaitForExitAsync().WaitAsync(NativeBound);
        }
    }

    private static void CompactActualResponse(string dataRoot, RunServiceStartRequest original, Id runId)
    {
        var owner = SandboxLocalOwner.Current();
        Assert.NotNull(owner);
        using var store = NodeStore.Open(new NodeStoreOptions
        {
            DataRoot = dataRoot,
            BootIdentity = BootIdentity.Read(),
            Clock = new PostRetentionClock(),
        });
        using var durable = new DurableCommandStore(store, owner, NodeSecretStores.ForTestDataRoot(dataRoot));
        Assert.True(durable.OwnerEpoch.Span.SequenceEqual(original.OwnerEpoch.Value.Span));
        var before = durable.Inspect(original.Meta.CommandId.Value.Span);
        Assert.NotNull(before);
        Assert.Equal(Hex(runId), before.AggregateId);
        Assert.False(before.Compacted);
        Assert.NotNull(before.ResponseJson);
        Assert.True(durable.CompactKnownResponses() > 0);
        var after = durable.Inspect(original.Meta.CommandId.Value.Span);
        Assert.NotNull(after);
        Assert.Equal(before.AggregateId, after.AggregateId);
        Assert.Equal(before.Effect, after.Effect);
        Assert.True(after.Compacted);
        Assert.Null(after.ResponseJson);
    }

    private static void RemoveFixtureOwnerKey(string dataRoot, Id ownerEpoch)
    {
        using var database = ReadDatabase(dataRoot);
        using var command = database.CreateCommand();
        command.CommandText = "SELECT node_id FROM store_meta WHERE singleton = 1;";
        var nodeId = Assert.IsType<byte[]>(command.ExecuteScalar());
        var target = NodeDataKeyRing.TargetName(nodeId, "v2-owner-" + Hex(ownerEpoch));
        Assert.True(NodeSecretStores.ForTestDataRoot(dataRoot).Store.Delete(target));
    }

    private static SqliteConnection ReadDatabase(string dataRoot)
    {
        var database = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = StorePaths.Database(dataRoot),
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        database.Open();
        return database;
    }

    private static string[] ReadLines(string path) => TestNode.ReadShared(path).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static bool ChildIsReady(string path) => OperatingSystem.IsWindows()
        ? ReadLines(path).Any(line => line.StartsWith("ready ", StringComparison.Ordinal))
        : ReadLines(path).Any(line => int.TryParse(line, CultureInfo.InvariantCulture, out var pid) && pid > 0);

    private static string Hex(Id id) => Convert.ToHexStringLower(id.Value.Span);

    private static RequestMeta Query() => new() { CorrelationId = CommandIds.New() };

    private static RequestMeta Mutation(Revision? revision = null) => new()
    {
        CorrelationId = CommandIds.New(), CommandId = CommandIds.New(), ExpectedRev = revision,
    };

    private static T Value<T>(T? value, ArcError? error) where T : class
    {
        var reason = error?.Details?.State?.Reason;
        if (reason is not null && (reason.Length > 320 || reason.Any(character => !char.IsAsciiLetterOrDigit(character)
            && character is not ('_' or ':' or '-' or ',' or ' ' or '.'))))
        {
            reason = "reason_filtered";
        }

        Assert.True(value is not null, $"Local V2 operation returned {error?.Category}/{error?.Code} ({reason ?? "no typed reason"}).");
        return value;
    }

    private sealed class PostRetentionClock : TimeProvider
    {
        private readonly DateTimeOffset _afterRetention = DateTimeOffset.UtcNow.AddHours(25);

        public override DateTimeOffset GetUtcNow() => _afterRetention;
    }
}
