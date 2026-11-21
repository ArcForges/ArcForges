// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform.Linux;
using ArcForges.Node.Platform.Linux.Mxc;
using ArcForges.Node.Platform.Windows;
using ArcForges.Node.Platform.Windows.Mxc;
using ArcForges.Node.Store;
using ArcForges.RunSupervisor.Protocol;
using ArcForges.Tests;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    [Fact(Timeout = 180_000, DisableParallelization = true)]
    public async Task InstalledRecoveryRetainsTheOriginalEffectWhenTheWorkerFinalPrecedesNodeCommit()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        cancellationToken.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var fixture = TestNode.Create();
        PrepareDataRoot(fixture.DataRoot);
        var process = await fixture.StartNodeAsync();
        Id? ownerEpoch = null;
        string? release = null;
        FinalRecoveryBoundary? native = null;
        try
        {
            RunServiceStartRequest original;
            Run running;
            RecoveryBinding binding;
            string marker;
            string image;
            await using (var channel = OpenChannel(fixture))
            {
                var node = new NodeService.NodeServiceClient(channel.CallInvoker);
                var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
                var runs = new RunService.RunServiceClient(channel.CallInvoker);
                ownerEpoch = (await HandshakeAsync(node)).OwnerEpoch;
                var sandbox = await CreateSandboxAsync(sandboxes, ownerEpoch);
                var working = CreateFinalRecoveryWorkingDirectory(sandbox);
                image = InstallFinalRecoveryPayload(working);
                marker = Path.Combine(working, "final-window.log");
                release = Path.Combine(working, "release-final-window");
                original = FinalRecoveryStart(sandbox, ownerEpoch,
                    [image, "hold", "--marker", marker, "--until-file", release, "--hold-ms", "20000"]);
                running = await StartFinalRecoveryPayloadAsync(fixture, runs, original, cancellationToken);
                await TestNode.WaitAsync(() => CountFinalRecoveryMarkers(marker, "ready") == 1, NativeBound, "the gated native payload");
                await RequireKnownRecoveryStartAsync(node, original, running.RunId, compacted: false);
                binding = ReadRecoveryBinding(fixture.DataRoot, running);
            }

            native = await CaptureFinalRecoveryBoundaryAsync(binding, image, marker, descendants: false);
            Assert.True(native.Owner.IsRunning());
            Assert.True(native.Root.IsRunning());
            await CrashFinalRecoveryNodeAsync(process, native.Owner, cancellationToken);
            Assert.True(native.Owner.IsRunning());
            Assert.True(native.Root.IsRunning());
            Assert.DoesNotContain(ReadLines(marker), line => line.StartsWith("end ", StringComparison.Ordinal));
            File.WriteAllText(release, "release");
            await TestNode.WaitAsync(native.IsEmpty, NativeBound, "the original worker and its held native scope to drain while Node is dead");
            Assert.True(process.HasExited);
            Assert.Equal(1, CountFinalRecoveryMarkers(marker, "ready"));
            Assert.Equal(1, CountFinalRecoveryMarkers(marker, "end"));
            var (crashedState, crashedRawCode, _) = ReadCrashedFinalRecoveryState(fixture.DataRoot, running);
            Assert.Equal(StoredRunState.Running, crashedState);
            Assert.Null(crashedRawCode);
            var originalFinalHash = HashFinalRecoveryObservationBytes(fixture.DataRoot, running);
            AssertFinalWindowsEvidence(fixture, running, binding);

            process = await fixture.StartNodeAsync();
            await using var recovered = OpenChannel(fixture);
            var recoveredNode = new NodeService.NodeServiceClient(recovered.CallInvoker);
            var recoveredRuns = new RunService.RunServiceClient(recovered.CallInvoker);
            Assert.Equal(ownerEpoch, (await HandshakeAsync(recoveredNode)).OwnerEpoch);
            var inspected = await WaitForStateAsync(fixture, recoveredRuns, running.RunId, RunState.RecoveryRequired, cancellationToken);
            Assert.Null(inspected.Exit);
            Assert.Null(inspected.EndedAt);
            Assert.Equal(running.Epoch, inspected.Epoch);
            Assert.Equal(running.LaunchSha256, inspected.LaunchSha256);
            await RequireKnownRecoveryStartAsync(recoveredNode, original, running.RunId, compacted: false);
            var replay = await recoveredRuns.StartAsync(original, deadline: Deadline, cancellationToken: cancellationToken);
            Assert.Equal(inspected.RunId, Value(replay.Value, replay.Error).Run.RunId);
            Assert.Equal(inspected.RunId, Assert.Single(await ListAsync(recoveredRuns, inspected.SandboxId)).RunId);
            Assert.Equal(1, CountFinalRecoveryMarkers(marker, "ready"));
            Assert.Equal(1, CountFinalRecoveryMarkers(marker, "end"));
            await StopNodeAsync(fixture, process);
            Assert.Equal(originalFinalHash, HashFinalRecoveryObservationBytes(fixture.DataRoot, running));
            var (_, final) = ReadAuthenticatedFinalRecoveryObservation(fixture.DataRoot, running, binding);
            Assert.Equal(RunOwnerState.Exited, final.State);
            Assert.True(final.GroupEmptyVerified);
            Assert.Equal(RunExitSources.OfficialExecutor, final.ExitSource);
            Assert.Equal(0, final.RawExitCode);
            TestContext.Current.TestOutputHelper?.WriteLine(
                "The authenticated worker final existed while the original durable Run was still Running. Restart preserved the original Start and reported RecoveryRequired when it could no longer verify the boundary independently.");
        }
        finally
        {
            await CloseFinalRecoveryFixtureAsync(fixture, process, ownerEpoch, release, native);
        }
    }

    [Fact(Timeout = 180_000, DisableParallelization = true)]
    public async Task InstalledRecoveryVerifiesTheOriginalScopeWhenItsRootExitsWithADescendant()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        cancellationToken.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var fixture = TestNode.Create();
        PrepareDataRoot(fixture.DataRoot);
        var process = await fixture.StartNodeAsync();
        Id? ownerEpoch = null;
        string? release = null;
        FinalRecoveryBoundary? native = null;
        try
        {
            RunServiceStartRequest original;
            Run running;
            RecoveryBinding binding;
            string marker;
            string image;
            await using (var channel = OpenChannel(fixture))
            {
                var node = new NodeService.NodeServiceClient(channel.CallInvoker);
                var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
                var runs = new RunService.RunServiceClient(channel.CallInvoker);
                ownerEpoch = (await HandshakeAsync(node)).OwnerEpoch;
                var sandbox = await CreateSandboxAsync(sandboxes, ownerEpoch);
                var working = CreateFinalRecoveryWorkingDirectory(sandbox);
                image = InstallFinalRecoveryPayload(working);
                marker = Path.Combine(working, "root-descendant.log");
                release = Path.Combine(working, "release-scope-root");
                original = FinalRecoveryStart(sandbox, ownerEpoch, BuildRootWithDescendantPayload(image, marker, release));
                running = await StartFinalRecoveryPayloadAsync(fixture, runs, original, cancellationToken);
                int required = OperatingSystem.IsWindows() ? 2 : 1;
                await TestNode.WaitAsync(() => CountFinalRecoveryMarkers(marker, "ready") == required,
                    NativeBound, "the original native payload and its real background descendant");
                await RequireKnownRecoveryStartAsync(node, original, running.RunId, compacted: false);
                binding = ReadRecoveryBinding(fixture.DataRoot, running);
            }

            native = await CaptureFinalRecoveryBoundaryAsync(binding, image, marker, descendants: true);
            var child = Assert.IsType<ProcessIdentity>(native.Descendant);
            Assert.True(native.Root.IsRunning());
            Assert.True(child.IsRunning());
            File.WriteAllText(release, "release");
            var rootDeadline = Stopwatch.StartNew();
            while (native.Root.IsRunning())
            {
                Assert.True(rootDeadline.Elapsed < NativeBound, "The exact native payload root did not exit in its bounded fixture window.");
                await Task.Delay(5, cancellationToken);
            }

            bool descendantAfterRoot = child.IsRunning();
            if (descendantAfterRoot) Assert.False(native.IsEmpty());
            await CrashFinalRecoveryNodeAsync(process, native.Owner, cancellationToken);
            bool descendantAfterLoss = child.IsRunning();
            await TestNode.WaitAsync(native.IsEmpty, NativeBound, "the original native boundary and all observed members to drain");
            var (priorState, priorRawCode, priorExitSource) = ReadCrashedFinalRecoveryState(fixture.DataRoot, running);
            var originalFinalHash = HashFinalRecoveryObservationBytes(fixture.DataRoot, running);
            AssertFinalWindowsEvidence(fixture, running, binding);

            process = await fixture.StartNodeAsync();
            await using var recovered = OpenChannel(fixture);
            var recoveredNode = new NodeService.NodeServiceClient(recovered.CallInvoker);
            var recoveredRuns = new RunService.RunServiceClient(recovered.CallInvoker);
            var state = priorState == StoredRunState.Exited ? RunState.Exited : RunState.RecoveryRequired;
            var inspected = await WaitForStateAsync(fixture, recoveredRuns, running.RunId, state, cancellationToken);
            if (state == RunState.Exited)
            {
                Assert.True(inspected.Exit.GroupEmptyVerified);
            }
            else
            {
                Assert.Null(inspected.Exit);
                Assert.Null(inspected.EndedAt);
            }

            Assert.Equal(running.Epoch, inspected.Epoch);
            Assert.Equal(running.LaunchSha256, inspected.LaunchSha256);
            await RequireKnownRecoveryStartAsync(recoveredNode, original, running.RunId, compacted: false);
            Assert.Equal(running.RunId, Assert.Single(await ListAsync(recoveredRuns, running.SandboxId)).RunId);
            int count = OperatingSystem.IsWindows() ? 2 : 1;
            Assert.Equal(count, CountFinalRecoveryMarkers(marker, "ready"));
            await StopNodeAsync(fixture, process);
            Assert.Equal(originalFinalHash, HashFinalRecoveryObservationBytes(fixture.DataRoot, running));
            var (_, signed) = ReadAuthenticatedFinalRecoveryObservation(fixture.DataRoot, running, binding);
            AssertRetainedFinalExit(priorState, priorRawCode, priorExitSource, signed);
            Assert.Equal(RunOwnerState.Exited, signed.State);
            Assert.True(signed.GroupEmptyVerified);
            Assert.Equal(RunExitSources.OfficialExecutor, signed.ExitSource);
            TestContext.Current.TestOutputHelper?.WriteLine(FormattableString.Invariant(
                $"Original payload root exited with a previously verified background descendant. Live descendant after root: {descendantAfterRoot}. Live descendant after Node loss: {descendantAfterLoss}. Original native scope drained; cold state was {state}."));
        }
        finally
        {
            await CloseFinalRecoveryFixtureAsync(fixture, process, ownerEpoch, release, native);
        }
    }

    private static async Task CloseFinalRecoveryFixtureAsync(TestNode fixture, Process process, Id? ownerEpoch,
        string? release, FinalRecoveryBoundary? native)
    {
        using (native)
        {
            try
            {
                if (release is not null && !File.Exists(release)) File.WriteAllText(release, "release");
                await StopNodeAsync(fixture, process);
                if (native is not null)
                {
                    await TestNode.WaitAsync(native.IsEmpty, NativeBound, "the bounded final recovery fixture to drain before teardown");
                }
            }
            finally
            {
                if (ownerEpoch is not null) RemoveFixtureOwnerKey(fixture.DataRoot, ownerEpoch);
            }
        }
    }

    private static string[] BuildRootWithDescendantPayload(string image, string marker, string release)
    {
        if (OperatingSystem.IsWindows())
        {
            return [image, "signal", "--child", "same", "--hold-ms", "6500", "--child-hold-ms", "9000", "--marker", marker];
        }

        const string script = """
            "$1" hold --marker "$2" --hold-ms 4500 &
            for tick in $(/usr/bin/seq 1 120); do
                [ ! -f "$3" ] || exit 0
                /usr/bin/sleep 0.025
            done
            exit 1
            """;
        return ["/usr/bin/dash", "-c", script, "arcforges-recovery-root", image, marker, release];
    }

    private static string CreateFinalRecoveryWorkingDirectory(Sandbox sandbox)
    {
        var working = Path.Combine(sandbox.DataLocation, "work", "quoted directory");
        Directory.CreateDirectory(working);
        return working;
    }

    private static string InstallFinalRecoveryPayload(string working)
    {
        if (OperatingSystem.IsWindows())
        {
            InstallWindowsTestLoad(working);
            return Path.GetFullPath(Path.Combine(working, "arcforges-testload.exe"));
        }

        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var image = Path.Combine(working, "recovery-final-fixture");
        File.Copy(TestNode.TestLoad, image);
        File.SetUnixFileMode(image, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return image;
    }

    private static RunServiceStartRequest FinalRecoveryStart(Sandbox sandbox, Id ownerEpoch, string[] args)
    {
        var request = BuildStart(sandbox, ownerEpoch, args);
        request.TerminalMode = TerminalMode.Pipes;
        request.TerminalSize = null;
        return request;
    }

    private static async Task<Run> StartFinalRecoveryPayloadAsync(TestNode fixture, RunService.RunServiceClient runs,
        RunServiceStartRequest original, CancellationToken cancellationToken)
    {
        var accepted = await runs.StartAsync(original, deadline: Deadline, cancellationToken: cancellationToken);
        var run = Value(accepted.Value, accepted.Error).Run;
        return await WaitForStateAsync(fixture, runs, run.RunId, RunState.Running, cancellationToken);
    }

    private static int CountFinalRecoveryMarkers(string path, string name) =>
        ReadLines(path).Count(line => line.StartsWith(name + " ", StringComparison.Ordinal));

    private static async Task CrashFinalRecoveryNodeAsync(Process node, ProcessIdentity owner, CancellationToken token)
    {
        Assert.False(node.HasExited);
        Assert.NotEqual(owner.Pid, node.Id);
        node.Kill();
        await node.WaitForExitAsync(token).WaitAsync(NativeBound, token);
    }

    private static (StoredRunState State, int? RawExitCode, string? ExitSource) ReadCrashedFinalRecoveryState(string dataRoot, Run run)
    {
        // The production SQLite writer must first reopen this store as part of the actual Node restart.
        using var database = ReadDatabase(dataRoot);
        using var command = database.CreateCommand();
        command.CommandText = """
            SELECT r.state, r.ended_utc, r.raw_exit_code, r.exit_source, m.clean_shutdown_at FROM run AS r
              JOIN store_meta AS m ON m.singleton = 1
             WHERE r.run_id = $run AND r.epoch = $epoch AND r.launch_sha256 = $digest;
            """;
        command.Parameters.AddWithValue("$run", Hex(run.RunId));
        command.Parameters.AddWithValue("$epoch", run.Epoch);
        command.Parameters.AddWithValue("$digest", run.LaunchSha256);
        using var row = command.ExecuteReader();
        Assert.True(row.Read());
        Assert.True(row.IsDBNull(4), "The original crash must remain unclean until the real Node restarts.");
        var state = (StoredRunState)row.GetInt32(0);
        if (state != StoredRunState.Exited)
        {
            Assert.True(row.IsDBNull(1));
        }

        int? rawExitCode = row.IsDBNull(2) ? null : row.GetInt32(2);
        string? exitSource = row.IsDBNull(3) ? null : row.GetString(3);
        Assert.False(row.Read());
        return (state, rawExitCode, exitSource);
    }

    private static string HashFinalRecoveryObservationBytes(string dataRoot, Run run)
    {
        var control = Path.Combine(dataRoot, "control", "run-" + Hex(run.RunId));
        var path = Path.Combine(control, "observed.bin");
        if (OperatingSystem.IsWindows())
        {
            using var heldControl = WindowsMxcPathLease.Open(control, directory: true, privateObject: true);
            using var heldObservation = WindowsMxcPathLease.Open(path, directory: false, privateObject: true);
            return Hash();
        }

        if (OperatingSystem.IsLinux())
        {
            using var heldControl = LinuxRunCgroup.OpenPrivateDirectory(control);
            using var heldObservation = LinuxRunCgroup.OpenTrustedFile(path, rootOnly: false, executable: false);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
            return Hash();
        }

        throw new PlatformNotSupportedException();

        string Hash()
        {
            using var stream = File.OpenRead(path);
            Assert.InRange(stream.Length, RunWire.KeyLength + 1L, RunWire.KeyLength + 65_536L);
            return Convert.ToHexStringLower(SHA256.HashData(stream));
        }
    }

    private static (StoredRunState State, RunOwnerObservation Observation) ReadAuthenticatedFinalRecoveryObservation(
        string dataRoot, Run run, RecoveryBinding binding)
    {
        var owner = Assert.IsType<string>(SandboxLocalOwner.Current());
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = dataRoot, BootIdentity = BootIdentity.Read() });
        using var authority = new DurableCommandStore(store, owner, NodeSecretStores.ForTestDataRoot(dataRoot));
        var stored = Assert.IsType<StoredRun>(store.Read(reader => RunRecords.Get(reader, owner, Hex(run.RunId))));
        var recovery = Assert.IsType<StoredRunRecovery>(store.Read(reader => RunRecoveryRecords.Read(reader, owner, stored)));
        var exactOwner = new RunOwnerIdentity(binding.Instance, binding.Boot, binding.Pid, binding.Creation,
            binding.Endpoint, binding.Boundary, binding.Backend, binding.Cohort, binding.RunEpoch);
        var key = authority.DeriveRunControlKey(stored.RunId, stored.LaunchSha256);
        try
        {
            var spec = new RunRecoverySpec(stored.RunId, stored.SandboxId, stored.Epoch, stored.LaunchSha256,
                Path.Combine(dataRoot, "control", "run-" + stored.RunId), recovery.SupervisorPath, recovery.SupervisorSha256,
                recovery.InstallationRoot, key, exactOwner, recovery.Generation);
            var observation = Assert.IsType<RunOwnerObservation>(RunWire.TryReadObservation(spec));
            if (stored.State != StoredRunState.Exited)
            {
                Assert.Null(stored.EndedAt);
            }

            AssertRetainedFinalExit(stored.State, stored.RawExitCode, stored.ExitSource, observation);
            return (stored.State, observation);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static void AssertRetainedFinalExit(StoredRunState state, int? rawExitCode, string? exitSource,
        RunOwnerObservation authenticatedFinal)
    {
        if (state == StoredRunState.Exited || rawExitCode is not { } raw)
        {
            return;
        }

        Assert.True(state is StoredRunState.Draining or StoredRunState.RecoveryRequired);
        Assert.True(exitSource is RunExitSources.Payload or RunExitSources.OfficialExecutor or RunExitSources.Supervisor);
        Assert.Equal(raw, authenticatedFinal.RawExitCode);
        Assert.Equal(exitSource, authenticatedFinal.ExitSource);
    }

    private static void AssertFinalWindowsEvidence(TestNode fixture, Run run, RecoveryBinding binding)
    {
        if (!OperatingSystem.IsWindows()) return;
        var evidence = ReadWindowsJobResource(fixture.DataRoot, run,
            (binding.Pid, binding.Creation, binding.Boundary), "windows-drained.json");
        Assert.Equal(binding.Pid, Assert.Single(evidence.ProcessIds));
        Assert.Empty(evidence.PayloadProcessIds);
        Assert.True(evidence.OutputDrainCompleted);
    }

    private static async Task<FinalRecoveryBoundary> CaptureFinalRecoveryBoundaryAsync(RecoveryBinding binding,
        string image, string marker, bool descendants)
    {
        var owner = Assert.IsType<ProcessIdentity>(ProcessIdentity.Capture(binding.Pid));
        long birth = OperatingSystem.IsWindows() ? new DateTime(owner.StartKey, DateTimeKind.Utc).ToFileTimeUtc() : owner.StartKey;
        Assert.Equal(binding.Creation, birth.ToString(CultureInfo.InvariantCulture));
        if (OperatingSystem.IsWindows())
        {
            var (root, child) = ReadWindowsFinalPayloads(image, marker, descendants);
            return new FinalRecoveryBoundary(owner, root, child, null);
        }

        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var boundary = binding.Boundary.Split('|');
        Assert.Equal(5, boundary.Length);
        Assert.Equal(binding.Instance, boundary[1]);
        var scope = LinuxRunCgroup.Open(boundary[2]);
        try
        {
            Assert.Equal(boundary[3], scope.MountId.ToString(CultureInfo.InvariantCulture));
            Assert.Equal(boundary[4], scope.Inode.ToString(CultureInfo.InvariantCulture));
            Assert.True(LinuxRunCgroup.MatchesProcess(owner.Pid, owner.StartKey, scope.Path));
            var payload = await ReadLinuxFinalPayloadAsync(scope, image);
            if (!descendants) return new FinalRecoveryBoundary(owner, payload, null, scope);
            var parent = ProcFs.Stat(payload.Pid);
            Assert.NotNull(parent);
            Assert.Equal(payload.StartKey, parent.Value.StartTicks);
            var root = Assert.IsType<ProcessIdentity>(ProcessIdentity.Capture(parent.Value.ParentPid));
            Assert.NotEqual(owner.Pid, root.Pid);
            Assert.True(LinuxRunCgroup.MatchesProcess(root.Pid, root.StartKey, scope.Path));
            var executable = File.ResolveLinkTarget($"/proc/{root.Pid.ToString(CultureInfo.InvariantCulture)}/exe", returnFinalTarget: false);
            Assert.Equal("/usr/bin/dash", executable?.FullName);
            return new FinalRecoveryBoundary(owner, root, payload, scope);
        }
        catch
        {
            scope.Dispose();
            throw;
        }
    }

    [SupportedOSPlatform("windows")]
    private static (ProcessIdentity Root, ProcessIdentity? Descendant) ReadWindowsFinalPayloads(string image, string marker, bool descendants)
    {
        var records = ReadLines(marker).Where(line => line.StartsWith("ready ", StringComparison.Ordinal))
            .Select(line => line.Split(' ')).ToArray();
        var needed = descendants ? 2 : 1;
        Assert.Equal(needed, records.Length);
        var exact = new Dictionary<int, ProcessIdentity>();
        foreach (var record in records)
        {
            int pid = int.Parse(record[1], CultureInfo.InvariantCulture);
            var markedAt = DateTimeOffset.FromUnixTimeMilliseconds(long.Parse(record[2], CultureInfo.InvariantCulture));
            using var held = ProcessInfo.Open(pid);
            Assert.NotNull(held);
            Assert.True(ProcessInfo.IsRunning(held));
            using var payload = Process.GetProcessById(pid);
            var identity = Assert.IsType<ProcessIdentity>(ProcessIdentity.Capture(pid));
            var created = ProcessInfo.FromFileTime(ProcessInfo.CreationFileTime(held));
            Assert.Equal(identity.StartKey, created.UtcTicks);
            Assert.True(created <= markedAt.AddMilliseconds(100));
            Assert.Equal(image, payload.MainModule?.FileName, ignoreCase: true);
            exact.Add(pid, identity);
        }

        if (!descendants) return (Assert.Single(exact.Values), null);
        var item = Assert.Single(ProcessInfo.Snapshot(), entry => exact.ContainsKey(entry.Pid) && exact.ContainsKey(entry.ParentPid));
        Assert.Equal(Path.GetFileName(image), item.Image, ignoreCase: true);
        return (exact[item.ParentPid], exact[item.Pid]);
    }

    [SupportedOSPlatform("linux")]
    private static async Task<ProcessIdentity> ReadLinuxFinalPayloadAsync(LinuxRunCgroup scope, string image)
    {
        ProcessIdentity? found = null;
        string members = Path.Combine("/sys/fs/cgroup", scope.Path.TrimStart('/'), "cgroup.procs");
        await TestNode.WaitAsync(() =>
        {
            foreach (string line in File.ReadLines(members))
            {
                if (!int.TryParse(line, CultureInfo.InvariantCulture, out int pid) || ProcessIdentity.Capture(pid) is not { } candidate
                    || !LinuxRunCgroup.MatchesProcess(pid, candidate.StartKey, scope.Path)) continue;
                try
                {
                    var executable = File.ResolveLinkTarget($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/exe", returnFinalTarget: false);
                    if (executable?.FullName != image) continue;
                }
                catch (IOException) when (!candidate.IsRunning())
                {
                    continue;
                }

                found = candidate;
                return true;
            }

            return false;
        }, NativeBound, "the exact native test payload within its original cgroup");
        return Assert.IsType<ProcessIdentity>(found);
    }

    private sealed class FinalRecoveryBoundary(ProcessIdentity owner, ProcessIdentity root, ProcessIdentity? descendant,
        LinuxRunCgroup? cgroup) : IDisposable
    {
        public ProcessIdentity Owner { get; } = owner;
        public ProcessIdentity Root { get; } = root;
        public ProcessIdentity? Descendant { get; } = descendant;

        public bool IsEmpty() => !Owner.IsRunning() && !Root.IsRunning() && Descendant?.IsRunning() != true
            && (!OperatingSystem.IsLinux() || cgroup is null || cgroup.IsEmpty());

        public void Dispose()
        {
            if (OperatingSystem.IsLinux()) cgroup?.Dispose();
        }
    }
}
