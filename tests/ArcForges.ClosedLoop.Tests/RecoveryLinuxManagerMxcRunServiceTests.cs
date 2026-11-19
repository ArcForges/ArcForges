// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.Versioning;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Platform.Linux.Mxc;
using ArcForges.Tests;

namespace ArcForges.ClosedLoop.Tests;

[Trait("loop", "local")]
[Trait("env", "linux-real")]
[Trait("isolation", "exclusive")]
public sealed class RecoveryLinuxManagerMxcRunServiceTests
{
    [Fact(Timeout = 180_000, DisableParallelization = true)]
    public async Task InstalledRecoveryKeepsOriginalRunThroughUserManagerReexec()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        Assert.SkipUnless(Environment.GetEnvironmentVariable("ARCFORGES_MXC_MANAGER_REEXEC_TEST") == "1",
            "Requires the designated Linux host's exclusive manager-reexec qualification.");
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux user manager and cgroup v2 are required.");
            return;
        }

        await MxcRunServiceTests.VerifyLinuxManagerReexecAsync(cancellationToken);
    }
}

public sealed partial class MxcRunServiceTests
{
    [SupportedOSPlatform("linux")]
    internal static async Task VerifyLinuxManagerReexecAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequireExtractedPackage();

        await using var fixture = await RecoveryNativeFixture.StartAsync();
        var original = fixture.Running;
        var native = fixture.Native;
        var nodeIdentity = Assert.IsType<ProcessIdentity>(ProcessIdentity.Capture(fixture.Process.Id));
        var binding = ReadRecoveryBinding(fixture.Node.DataRoot, original);
        var boundary = binding.Boundary.Split('|');
        Assert.Equal(5, boundary.Length);
        Assert.Matches("^arcforges-run-[0-9a-f]{32}\\.service$", boundary[0]);
        using var held = LinuxRunCgroup.Open(boundary[2]);
        Assert.True(held.MatchesIdentity(ulong.Parse(boundary[3], CultureInfo.InvariantCulture),
            ulong.Parse(boundary[4], CultureInfo.InvariantCulture)));
        var before = await LinuxRunSystemd.ReadAsync(boundary[0], cancellationToken);
        Assert.True(before.Loaded);
        Assert.Equal(binding.Instance, before.Invocation);
        Assert.Equal(held.Path, before.Group);
        Assert.Equal("active", before.ActiveState);
        Assert.Equal(native.Supervisor.Pid, before.OwnerPid);
        Assert.Equal(native.Supervisor.StartKey, before.OwnerStartTicks);
        Assert.True(LinuxRunCgroup.MatchesProcess(native.Payload.Pid, native.Payload.StartKey, held.Path));
        fixture.RequireOneEntry();

        // This bounded user-manager action is reserved for the exclusive, explicitly opted-in fixture.
        var reexec = SystemdTestEnvironment.Systemctl("daemon-reexec");
        Assert.True(reexec.ExitCode == 0, reexec.Output);
        var after = await LinuxRunSystemd.ReadAsync(before.Name, cancellationToken);
        Assert.Equal(before, after);
        using (var reopened = LinuxRunCgroup.Open(after.Group))
        {
            Assert.True(held.MatchesIdentity(reopened.MountId, reopened.Inode));
        }

        Assert.True(LinuxRunCgroup.MatchesProcess(native.Supervisor.Pid, native.Supervisor.StartKey, held.Path));
        Assert.True(LinuxRunCgroup.MatchesProcess(native.Payload.Pid, native.Payload.StartKey, held.Path));
        Assert.True(nodeIdentity.IsRunning());
        fixture.RequireOneEntry();

        await using var channel = OpenChannel(fixture.Node);
        var node = new NodeService.NodeServiceClient(channel.CallInvoker);
        var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
        var runs = new RunService.RunServiceClient(channel.CallInvoker);
        var hello = await HandshakeAsync(node);
        Assert.Equal(fixture.FirstNodeEpoch, hello.NodeEpoch);
        Assert.Equal(fixture.Original.OwnerEpoch, hello.OwnerEpoch);
        var continued = await InspectAsync(runs, original.RunId, cancellationToken);
        Assert.Equal(RunState.Running, continued.State);
        Assert.Equal(original.Epoch, continued.Epoch);
        Assert.Equal(original.LaunchSha256, continued.LaunchSha256);
        Assert.Equal(original.StartedAt, continued.StartedAt);
        Assert.Equal(binding, ReadRecoveryBinding(fixture.Node.DataRoot, continued));

        // A new, short Run requires a fresh user-manager service creation from this same Node.
        var originalSandboxReply = await sandboxes.InspectAsync(new SandboxServiceInspectRequest
        {
            Meta = Query(),
            SandboxId = original.SandboxId,
        }, deadline: Deadline, cancellationToken: cancellationToken);
        var originalSandbox = Value(originalSandboxReply.Value, originalSandboxReply.Error).Sandbox;
        Assert.Equal(original.SandboxRevision, originalSandbox.Revision);
        var probeSandboxReply = await sandboxes.CreateAsync(new SandboxServiceCreateRequest
        {
            Meta = Mutation(),
            OwnerEpoch = hello.OwnerEpoch,
            DisplayName = "Linux user manager reconnect probe",
            Config = originalSandbox.Config.Clone(),
        }, deadline: Deadline, cancellationToken: cancellationToken);
        var probeSandbox = Value(probeSandboxReply.Value, probeSandboxReply.Error).Sandbox;
        Assert.Equal(SandboxState.Ready, probeSandbox.State);
        var probeWorkdir = Path.Combine(probeSandbox.DataLocation, RelativeWorkdir);
        Directory.CreateDirectory(probeWorkdir);
        var probe = BuildStart(probeSandbox, hello.OwnerEpoch, ["/bin/sh", "-c", "printf '%s\\n' manager-reconnected > manager-probe.log"]);
        probe.TerminalMode = TerminalMode.Pipes;
        probe.TerminalSize = null;
        var reply = await runs.StartAsync(probe, deadline: Deadline, cancellationToken: cancellationToken);
        var probeRun = Value(reply.Value, reply.Error).Run;
        Assert.NotEqual(original.RunId, probeRun.RunId);
        var probeExit = await WaitForStateAsync(fixture.Node, runs, probeRun.RunId, RunState.Exited, cancellationToken);
        Assert.True(probeExit.Exit.GroupEmptyVerified);
        Assert.True(probeExit.Exit.HasRawCode);
        Assert.Equal(0, probeExit.Exit.RawCode);
        Assert.Equal("manager-reconnected", Assert.Single(ReadLines(Path.Combine(probeWorkdir, "manager-probe.log"))));
        Assert.True(nodeIdentity.IsRunning());
        Assert.True(native.Supervisor.IsRunning());
        Assert.True(native.Payload.IsRunning());

        var stop = BuildStop(hello.OwnerEpoch, await InspectAsync(runs, original.RunId, cancellationToken));
        await StopAsync(runs, stop, cancellationToken);
        var settled = await WaitForStateAsync(fixture.Node, runs, original.RunId, RunState.Exited, cancellationToken);
        Assert.True(settled.Exit.GroupEmptyVerified);
        Assert.True(held.IsEmpty());
        Assert.True(native.IsEmpty());
        AssertStopReceipt(await OperationAsync(node, hello.OwnerEpoch, stop.Meta.CommandId), stop, settled.Revision, EffectCertainty.Happened);
        fixture.RequireOneEntry();
        TestContext.Current.TestOutputHelper?.WriteLine(FormattableString.Invariant(
            $"User manager reexec preserved {before.Name} invocation {before.Invocation}, cgroup mount {held.MountId} inode {held.Inode}, supervisor {before.OwnerPid}/{before.OwnerStartTicks}, and payload {native.Payload.Pid}/{native.Payload.StartKey}. The same Node completed a new Run and stopped the original scope."));
    }
}
