// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Sandboxes;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Capabilities;
using ArcForges.Node.Platform.Linux.Mxc;
using ArcForges.Node.Platform.Windows.Mxc;
using ArcForges.RunSupervisor.Protocol;
using ArcForges.Tests;
using Google.Protobuf;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    [Fact(Timeout = 180_000, DisableParallelization = true)]
    public async Task InstalledRecoveryDoesNotReleaseAPreparedNativeOwner()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        cancellationToken.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        if (OperatingSystem.IsWindows() && !Path.GetFileName(WindowsMxcProcess.CurrentImagePath()).Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase))
        {
            await RunFixtureFromTrustedRuntimeAsync(nameof(InstalledRecoveryDoesNotReleaseAPreparedNativeOwner), TimeSpan.FromSeconds(110));
            return;
        }

        await using var fixture = TestNode.Create();
        PrepareDataRoot(fixture.DataRoot);
        var nodeProcess = await fixture.StartNodeAsync();
        Id? ownerEpoch = null;
        try
        {
            await using var channel = OpenChannel(fixture);
            var node = new NodeService.NodeServiceClient(channel.CallInvoker);
            var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
            var runs = new RunService.RunServiceClient(channel.CallInvoker);
            ownerEpoch = (await HandshakeAsync(node)).OwnerEpoch;
            var sandbox = await CreateSandboxAsync(sandboxes, ownerEpoch);
            var installation = Path.Combine(Path.GetDirectoryName(TestNode.Host)!, "mxc");
            var spec = BuildPreparedRecoverySpec(fixture, sandbox, ownerEpoch, installation);
            var marker = Path.Combine(spec.WorkingDirectory, "unreleased-payload.log");
            try
            {
                IRunLauncher launcher = OperatingSystem.IsWindows() ? new WindowsRunLauncher()
                    : OperatingSystem.IsLinux() ? new LinuxRunLauncher() : throw new PlatformNotSupportedException();
                await using var lease = await launcher.PrepareAsync(spec, cancellationToken);
                var identity = lease.Identity;
                Assert.Equal(spec.Epoch, identity.ControlEpoch);
                var owner = Assert.IsType<ProcessIdentity>(ProcessIdentity.Capture(identity.ProcessId));
                long birth = OperatingSystem.IsWindows() ? new DateTime(owner.StartKey, DateTimeKind.Utc).ToFileTimeUtc() : owner.StartKey;
                Assert.Equal(birth.ToString(CultureInfo.InvariantCulture), identity.CreationIdentity);
                using var cgroup = OperatingSystem.IsLinux() ? HoldPreparedLinuxScope(identity, owner) : null;
                var prepared = await lease.ObserveAsync(cancellationToken);
                Assert.Equal(RunOwnerState.Ready, prepared.State);
                Assert.Equal(RunPayloadStart.NotStarted, prepared.PayloadStarted);
                Assert.True(owner.IsRunning());
                var resources = Assert.IsAssignableFrom<IRunResourceSource>(lease);
                Assert.Equal(1u, Assert.IsType<RunResourceObservation>(resources.ObserveRunResources()).ProcessCount);
                Assert.False(File.Exists(marker));

                // The real actuator never receives an Activate request. Its authenticated Stop closes the release gate.
                await lease.StopAsync(TimeSpan.Zero, cancellationToken);
                var stopped = await WaitForPreparedDrainAsync(lease, cancellationToken);
                var signed = Assert.IsType<RunOwnerObservation>(RunWire.TryReadObservation(spec, identity));
                Assert.Equal(RunOwnerState.Exited, stopped.State);
                Assert.Equal(RunPayloadStart.NotStarted, stopped.PayloadStarted);
                Assert.Equal("stopped_before_payload", signed.TerminationReason);
                Assert.Equal(RunPayloadStart.NotStarted, signed.PayloadStarted);
                Assert.Null(stopped.RawExitCode);
                Assert.True(stopped.GroupEmptyVerified);
                Assert.False(owner.IsRunning());
                if (OperatingSystem.IsLinux()) Assert.True(cgroup!.IsEmpty());
                if (OperatingSystem.IsWindows())
                {
                    Assert.Equal(0u, Assert.IsType<RunResourceObservation>(resources.ObserveRunResources()).ProcessCount);
                }

                Assert.False(File.Exists(marker));
                Assert.False(File.Exists(RunWire.LaunchPath(spec)));
                Assert.Empty(await ListAsync(runs, sandbox.SandboxId));
                TestContext.Current.TestOutputHelper?.WriteLine("The installed supervisor authenticated in Ready. With release withheld, its signed observation proved NOT_STARTED and the original native boundary drained.");
            }
            finally
            {
                spec.ClearInputs();
                CryptographicOperations.ZeroMemory(spec.ControlKey);
            }
        }
        finally
        {
            await StopNodeAsync(fixture, nodeProcess);
            if (ownerEpoch is not null) RemoveFixtureOwnerKey(fixture.DataRoot, ownerEpoch);
        }
    }

    [SupportedOSPlatform("windows")]
    private static async Task RunFixtureFromTrustedRuntimeAsync(string method, TimeSpan timeout)
    {
        // The workspace apphost can inherit write access for unrelated principals. The owner still validates
        // its real launcher image; use the existing native .NET muxer to run this same compiled test body.
        var runtimeRoot = new DirectoryInfo(Path.GetFullPath(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "..", "..", "..")));
        var resolvedRoot = runtimeRoot.ResolveLinkTarget(returnFinalTarget: true) ?? runtimeRoot;
        var dotnet = Path.Combine(resolvedRoot.FullName, "dotnet.exe");
        var start = new ProcessStartInfo(dotnet)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add(typeof(MxcRunServiceTests).Assembly.Location);
        start.ArgumentList.Add("-method");
        start.ArgumentList.Add(typeof(MxcRunServiceTests).FullName + "." + method);
        start.ArgumentList.Add("-failSkips");
        start.ArgumentList.Add("-automated");
        start.ArgumentList.Add("async");
        using var helper = Process.Start(start) ?? throw new InvalidOperationException("The existing .NET runtime host could not start.");
        var run = await TestNode.CompleteAsync(helper, timeout);
        Assert.True(run.ExitCode == 0, $"The trusted-image native test failed: {run}");
        var finished = Assert.Single(run.Output.Split('\n'), line =>
            line.StartsWith("{\"$type\":\"test-assembly-finished\",", StringComparison.Ordinal));
        using var receipt = JsonDocument.Parse(finished);
        Assert.Equal(1, receipt.RootElement.GetProperty("TestsTotal").GetInt32());
        Assert.Equal(0, receipt.RootElement.GetProperty("TestsFailed").GetInt32());
        Assert.Equal(0, receipt.RootElement.GetProperty("TestsNotRun").GetInt32());
        Assert.Equal(0, receipt.RootElement.GetProperty("TestsSkipped").GetInt32());
        TestContext.Current.TestOutputHelper?.WriteLine(run.Output);
    }

    private static RunLaunchSpec BuildPreparedRecoverySpec(TestNode fixture, Sandbox sandbox, Id ownerEpoch, string installation)
    {
        var sandboxId = Hex(sandbox.SandboxId);
        var runId = Guid.NewGuid().ToString("N");
        var rootIdentity = ReadPreparedSandboxRoot(fixture.DataRoot, sandboxId);
        var roots = new SandboxPrivateRoots(fixture.DataRoot);
        roots.ValidateControlPaths();
        using var sandboxRoot = roots.Inspect(sandboxId, rootIdentity);
        using var root = WorkspacePath.OpenRoot(sandboxRoot.RootPath);
        using var work = root.OpenSandboxDirectory("work");
        using var data = WorkspacePath.OpenRoot(fixture.DataRoot);
        using var control = data.OpenSandboxDirectory("control", configuredRoot: true);
        using var exactControl = control.CreateSandboxDirectory("run-" + runId);
        using var installed = WorkspacePath.OpenRoot(installation);
        WorkspacePath.CheckMxcTrustedObject(installed.RootHandle);

        var supervisor = OperatingSystem.IsWindows() ? "arcforges-run-supervisor.exe" : "arcforges-run-supervisor";
        var heldSupervisor = installed.OpenRead(supervisor);
        WorkspacePath.CheckMxcTrustedObject(heldSupervisor);
        using var image = new FileStream(heldSupervisor, FileAccess.Read);
        Assert.InRange(image.Length, 1, 128 * 1024 * 1024);
        var supervisorHash = Convert.ToHexStringLower(SHA256.HashData(image));
        var policy = SandboxPolicyAdmission.Evaluate(sandbox.Config, data.RootPath, installed.RootPath, MxcTerminalMode.Pipes);
        Assert.True(policy.Admission.Admitted);
        Assert.Empty(sandbox.Config.HostGrants);
        Assert.Equal(NetworkMode.Deny, sandbox.Config.Network.Egress);
        Assert.Equal(NetworkMode.Deny, sandbox.Config.Network.Ingress);
        Assert.False(sandbox.Config.Network.HostLoopback);

        var imageName = OperatingSystem.IsWindows() ? "prepared-fixture.exe" : "prepared-fixture";
        var executable = Path.Combine(work.RootPath, imageName);
        File.Copy(TestNode.TestLoad, executable);
        if (OperatingSystem.IsLinux())
        {
            File.SetUnixFileMode(executable, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        string[] args = [executable, "hold", "--hold-ms", "300", "--marker", Path.Combine(work.RootPath, "unreleased-payload.log")];
        var request = BuildStart(sandbox, ownerEpoch, args);
        request.WorkingDirectory = "work";
        request.TerminalMode = TerminalMode.Pipes;
        request.TerminalSize = null;
        using var payloadImage = work.OpenRead(imageName);
        return new RunLaunchSpec
        {
            RunId = runId,
            SandboxId = sandboxId,
            Epoch = Guid.NewGuid().ToString("N"),
            OwnerId = Guid.NewGuid().ToString("N"),
            LaunchSha256 = Convert.ToHexStringLower(SHA256.HashData(request.ToByteArray())),
            ControlDirectory = exactControl.RootPath,
            ControlEndpoint = OperatingSystem.IsWindows() ? "arcforges-run-" + runId : Path.Combine(exactControl.RootPath, "owner.sock"),
            ControlKey = RandomNumberGenerator.GetBytes(RunWire.KeyLength),
            SupervisorPath = Path.Combine(installed.RootPath, supervisor),
            SupervisorSha256 = supervisorHash,
            InstallationRoot = installed.RootPath,
            ProfileId = sandbox.Config.ProfileId,
            ProfileVersion = sandbox.Config.ProfileVersion,
            PrivateRoot = sandboxRoot.RootPath,
            PrivateRootIdentity = rootIdentity,
            WorkingDirectory = work.RootPath,
            WorkingDirectoryIdentity = EncodePreparedPath(work.RootIdentity, directory: true),
            ExecutablePath = executable,
            ExecutableIdentity = EncodePreparedPath(WorkspacePath.Identity(payloadImage), directory: false),
            Argv = args,
            Environment = [.. request.Environment.Select(entry => new RunEnvironment(entry.Name, entry.Value))],
            Mounts = [],
            Network = new RunNetwork(false, false, false, []),
            TerminalMode = RunTerminalMode.Pipes,
            Rows = 0,
            Columns = 0,
            CpuMillicores = sandbox.Config.Resources.CpuMaxMillicores,
            MemoryMaxBytes = sandbox.Config.Resources.MemoryMaxBytes,
            MaxProcesses = 128,
            OutputLimitBytes = SandboxPolicyAdmission.DefaultOutputRetentionBytes,
            BubblewrapPath = OperatingSystem.IsLinux() ? "/usr/bin/bwrap" : null,
            BubblewrapIdentity = OperatingSystem.IsLinux() ? policy.Host?.LinuxHelperSha256?["bwrap"] : null,
        };
    }

    private static string ReadPreparedSandboxRoot(string dataRoot, string sandboxId)
    {
        using var database = ReadDatabase(dataRoot);
        using var command = database.CreateCommand();
        command.CommandText = "SELECT root_identity FROM sandbox WHERE sandbox_id = $id AND owner_id = $owner;";
        command.Parameters.AddWithValue("$id", sandboxId);
        command.Parameters.AddWithValue("$owner", Assert.IsType<string>(SandboxLocalOwner.Current()));
        return Assert.IsType<string>(command.ExecuteScalar());
    }

    private static string EncodePreparedPath(WorkspaceObjectIdentity identity, bool directory)
    {
        var native = RegisteredWorkspaces.RootIdentity.Encode(identity, directory);
        return FormattableString.Invariant($"{native.Platform}:{Convert.ToHexStringLower(native.Bytes)}");
    }

    [SupportedOSPlatform("linux")]
    private static LinuxRunCgroup HoldPreparedLinuxScope(RunOwnerIdentity owner, ProcessIdentity process)
    {
        var boundary = owner.BoundaryIdentity.Split('|');
        Assert.Equal(5, boundary.Length);
        Assert.Equal(owner.InstanceId, boundary[1]);
        var scope = LinuxRunCgroup.Open(boundary[2]);
        try
        {
            Assert.Equal(boundary[3], scope.MountId.ToString(CultureInfo.InvariantCulture));
            Assert.Equal(boundary[4], scope.Inode.ToString(CultureInfo.InvariantCulture));
            Assert.True(scope.ContainsOnlyOwner(process.Pid, process.StartKey));
            return scope;
        }
        catch
        {
            scope.Dispose();
            throw;
        }
    }

    private static async Task<RunOwnerObservation> WaitForPreparedDrainAsync(IRunOwnerLease lease, CancellationToken token)
    {
        RunOwnerObservation? final = null;
        await TestNode.WaitAsync(async () =>
        {
            var observation = await lease.ObserveAsync(token);
            if (!observation.IsTerminal || !observation.GroupEmptyVerified) return false;
            final = observation;
            return true;
        }, NativeBound, "the original prepared owner to prove native drain");
        return Assert.IsType<RunOwnerObservation>(final);
    }
}
