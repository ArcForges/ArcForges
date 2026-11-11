// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.CloudLink.Tests;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;
using Microsoft.Win32.SafeHandles;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// Real Linux Host and child interruption with actual native files and journal. The WebSocket peer is synthetic;
/// this is not proof that an I/O syscall already inside the kernel has physically completed by its deadline.
/// </summary>
[Trait("loop", "local")]
[Trait("env", "linux-real")]
public sealed partial class LinuxWorkerInterruptionHostTests
{
    [Fact(Timeout = 120_000)]
    public async Task StoppedOwnedNodeCannotResumeAnExpiredWorkerAndPartialEffectRemainsUnknown()
    {
        if (!OperatingSystem.IsLinux()) { Assert.Skip("Linux pidfd and real worker deadline."); return; }
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        center.CommandKeys.Add(center.Channel.CommandPublicKey);
        await using var node = TestNode.Create();
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        using var host = await node.StartNodeAsync();
        using var hostPidfd = OpenPidfd(host.Id);
        await using var human = await node.HumanChannelAsync();
        var info = await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: ct);
        Assert.Null(info.Error);
        Assert.Equal(host.Id, node.NodePid());
        Assert.Equal(0, PollOnce(hostPidfd, 0));
        var nodeId = info.Value.Node.Node.NodeId;
        var begun = await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest
        {
            Meta = Command(),
            Method = SignInMethod.DeviceCode,
        }, cancellationToken: ct);
        Assert.Null(begun.Error);
        center.ApproveDevice();
        await TestNode.WaitAsync(async () => (await human.Account.GetAccountStatusAsync(
            new AccountServiceGetAccountStatusRequest(), cancellationToken: ct)).Value.Status.Relay == RelayState.Connected,
            TimeSpan.FromSeconds(30), "the synthetic center channel is connected");
        var connection = await center.Channel.ProvedAsync();
        var caller = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = new Id { Value = ByteString.CopyFrom(connection.AccountId) },
            RelayingNodeId = nodeId.Clone(),
            LocalOrigin = Origin.Human,
            LocalSessionId = CommandIds.New(),
        };
        var outerRoot = Directory.CreateDirectory(Path.Combine(node.Root, "interrupted-parent")).FullName;
        var root = Directory.CreateDirectory(Path.Combine(outerRoot, "child")).FullName;
        var target = Path.Combine(root, "target.txt");
        var independent = Path.Combine(root, "independent.txt");
        File.WriteAllText(independent, "independent-before");
        var original = Enumerable.Repeat((byte)'x', 4_194_304).ToArray();
        "FINDME"u8.CopyTo(original);
        File.WriteAllBytes(target, original);
        File.SetLastWriteTimeUtc(target, DateTime.UtcNow.AddDays(-1));
        var before = Modification(target);

        async Task<(ChannelCall Call, byte[] Payload)> Invoke(RoutedMethod method, IMessage request, Id command)
        {
            var (call, _) = center.Channel.BuildCall(connection, new FakeCallSpec
            {
                Method = method,
                Payload = request.ToByteArray(),
                Caller = caller,
                CommandId = command,
                Lifetime = TimeSpan.FromSeconds(30),
            });
            await connection.SendCallAsync(call);
            var result = await connection.ResultOfAsync(call.CallId);
            await TestNode.WaitAsync(() => connection.VerifiedResults.Any(item => item.Header.CallId.Equals(call.CallId)),
                TimeSpan.FromSeconds(15), "a fresh signed reply after pidfd open");
            return (call, result.Payload.ToByteArray());
        }

        var stopped = false;
        try
        {
            // A fresh signed registration after pidfd_open binds the already-owned Host and its verified channel.
            var registerOuter = new WorkspaceServiceRegisterWorkspaceRequest { Meta = Command(), Path = outerRoot, Name = "worker-outer" };
            var (_, outerRegistration) = await Invoke(RoutedMethod.RegisterNodeWorkspace, registerOuter, registerOuter.Meta.CommandId);
            var outer = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(outerRegistration);
            Assert.Null(outer.Error);
            var register = new WorkspaceServiceRegisterWorkspaceRequest { Meta = Command(), Path = root, Name = "worker-stop" };
            var (_, registration) = await Invoke(RoutedMethod.RegisterNodeWorkspace, register, register.Meta.CommandId);
            var registered = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(registration);
            Assert.Null(registered.Error);
            Assert.Equal(host.Id, node.NodePid());
            Assert.Equal(0, PollOnce(hostPidfd, 0));

            var edit = new FileServiceEditFileRequest
            {
                Meta = Command(),
                Path = new NodeFilePath { WorkspaceId = registered.Value.Workspace.WorkspaceId.Clone(), Path = "target.txt" },
                ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(original)),
                OldText = "FINDME",
                NewText = "CHANGE",
                ExpectedOccurrences = 1,
            };
            var raw = edit.ToByteArray();
            var (call, _) = center.Channel.BuildCall(connection, new FakeCallSpec
            {
                Method = RoutedMethod.EditNodeFile,
                Payload = raw,
                Caller = caller,
                CommandId = edit.Meta.CommandId,
                Lifetime = TimeSpan.FromSeconds(30),
            });
            await connection.SendCallAsync(call);
            var observation = await WaitForFirstActualWrite(node.DataRoot, edit.Meta.CommandId, target, before, ct);

            // Only the verified, held pidfd of this test's own Host is signaled; no worker PID is signaled.
            Assert.Equal(0, Signal(hostPidfd, 19)); // SIGSTOP
            stopped = true;
            await WaitForStopped(hostPidfd, host.Id, ct);
            Assert.False(host.HasExited);
            var workerBefore = ReadProc(observation.Pid);
            Assert.Equal(host.Id, workerBefore.Parent);
            Assert.Equal(observation.StartTicks, workerBefore.StartTicks);
            Assert.NotEqual('Z', workerBefore.State);
            using var workerPidfd = OpenPidfd(observation.Pid); // observation only; never signaled
            var workerAfterOpen = ReadProc(observation.Pid);
            Assert.Equal(workerBefore.StartTicks, workerAfterOpen.StartTicks);
            Assert.Equal(host.Id, workerAfterOpen.Parent);
            Assert.NotEqual('Z', workerAfterOpen.State);

            // The parent is actually stopped. A real kernel timer, not a test clock, must end this same worker.
            Assert.True(PollOnce(workerPidfd, 15_000) > 0);
            var dead = ReadProc(observation.Pid); // Node remains stopped and cannot reap this child.
            Assert.Equal(observation.StartTicks, dead.StartTicks);
            Assert.Equal('Z', dead.State);
            Assert.Equal(9, dead.ExitCode & 0x7f); // SIGKILL
            Assert.False(host.HasExited);
            var afterWorker = File.ReadAllBytes(target);
            Assert.False(original.AsSpan().SequenceEqual(afterWorker)); // the test reached a real effect before stopping the node

            Assert.Equal(0, Signal(hostPidfd, 18)); // SIGCONT, same owned pidfd
            stopped = false;
            await TestNode.WaitAsync(async () =>
            {
                var shown = await human.Files.GetFileOperationAsync(new FileServiceGetFileOperationRequest
                {
                    Meta = new RequestMeta { CorrelationId = CommandIds.New() },
                    OperationCommandId = edit.Meta.CommandId.Clone(),
                }, cancellationToken: ct);
                return shown.Error is null && shown.Value.Operation.State == FileOperationState.Unknown;
            }, TimeSpan.FromSeconds(20), "the real partial effect is durably UNKNOWN");
            var status = await human.Files.GetFileOperationAsync(new FileServiceGetFileOperationRequest
            {
                Meta = new RequestMeta { CorrelationId = CommandIds.New() },
                OperationCommandId = edit.Meta.CommandId.Clone(),
            }, cancellationToken: ct);
            Assert.Null(status.Error);
            Assert.Equal(FileOperationState.Unknown, status.Value.Operation.State);
            Assert.True(status.Value.Operation.Held);
            Assert.Equal(SHA256.HashData(raw), status.Value.Operation.RequestSha256.ToByteArray());
            Assert.Equal("file_outcome_unknown", status.Value.Operation.Error.Details.State.Reason);
            Assert.Equal(afterWorker, File.ReadAllBytes(target));

            await node.StopNodeAsync();
            await node.StartNodeAsync();
            connection = await center.Channel.ProvedAsync(2);
            await using var restartedHuman = await node.HumanChannelAsync();
            var recovered = await restartedHuman.Files.GetFileOperationAsync(new FileServiceGetFileOperationRequest
            {
                Meta = new RequestMeta { CorrelationId = CommandIds.New() },
                OperationCommandId = edit.Meta.CommandId.Clone(),
            }, cancellationToken: ct);
            Assert.Null(recovered.Error);
            Assert.Equal(FileOperationState.Unknown, recovered.Value.Operation.State);
            Assert.True(recovered.Value.Operation.Held);
            var (_, replayBytes) = await Invoke(RoutedMethod.EditNodeFile, edit, edit.Meta.CommandId);
            var replay = FileServiceEditFileResponse.Parser.ParseFrom(replayBytes);
            Assert.Equal("operation_failed", replay.Error.Code);
            Assert.Equal(EffectCertainty.Unknown, replay.Error.Effect);
            Assert.Equal(afterWorker, File.ReadAllBytes(target));

            // The same actual target is selected through an independently registered ancestor, not a string alias.
            var alias = new FileServiceWriteFileRequest
            {
                Meta = Command(),
                Path = new NodeFilePath { WorkspaceId = outer.Value.Workspace.WorkspaceId.Clone(), Path = "child/target.txt" },
                ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(afterWorker)),
                Data = ByteString.CopyFromUtf8("after-explicit-human-ack"),
            };
            var (_, aliasBytes) = await Invoke(RoutedMethod.WriteNodeFile, alias, alias.Meta.CommandId);
            var aliasRefusal = FileServiceWriteFileResponse.Parser.ParseFrom(aliasBytes);
            Assert.Equal("invalid_state", aliasRefusal.Error.Code);
            Assert.Equal("file_recovery_pending", aliasRefusal.Error.Details.State.Reason);
            Assert.Equal(EffectCertainty.DidNotHappen, aliasRefusal.Error.Effect);
            Assert.Equal(afterWorker, File.ReadAllBytes(target));

            // A separate existing file in the same directory can really be written while the first target stays held.
            var other = new FileServiceWriteFileRequest
            {
                Meta = Command(),
                Path = new NodeFilePath { WorkspaceId = registered.Value.Workspace.WorkspaceId.Clone(), Path = "independent.txt" },
                ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData("independent-before"u8)),
                Data = ByteString.CopyFromUtf8("independent-after"),
            };
            var (_, otherBytes) = await Invoke(RoutedMethod.WriteNodeFile, other, other.Meta.CommandId);
            var otherResult = FileServiceWriteFileResponse.Parser.ParseFrom(otherBytes);
            Assert.Null(otherResult.Error);
            Assert.Equal("independent-after", File.ReadAllText(independent));
            Assert.Equal(afterWorker, File.ReadAllBytes(target));

            var acknowledgment = new FileServiceAcknowledgeFileOperationRequest
            {
                Meta = Command(),
                OperationCommandId = edit.Meta.CommandId.Clone(),
                OperationDigest = ByteString.CopyFrom(new byte[32]),
            };
            var wrong = await restartedHuman.Files.AcknowledgeFileOperationAsync(acknowledgment, cancellationToken: ct);
            Assert.Equal("digest_mismatch", wrong.Error.Code);
            acknowledgment.Meta = Command();
            acknowledgment.OperationDigest = ByteString.CopyFrom(SHA256.HashData(raw));
            var acknowledged = await restartedHuman.Files.AcknowledgeFileOperationAsync(acknowledgment, cancellationToken: ct);
            Assert.Null(acknowledged.Error);
            Assert.Equal(FileOperationState.Unknown, acknowledged.Value.Operation.State);
            Assert.False(acknowledged.Value.Operation.Held);
            Assert.True(acknowledged.Value.Operation.Acknowledged);
            var (_, afterAckReplay) = await Invoke(RoutedMethod.EditNodeFile, edit, edit.Meta.CommandId);
            Assert.Equal(replayBytes, afterAckReplay);
            Assert.Equal(afterWorker, File.ReadAllBytes(target));
            var (_, afterAckAliasBytes) = await Invoke(RoutedMethod.WriteNodeFile, alias, alias.Meta.CommandId);
            var afterAckAlias = FileServiceWriteFileResponse.Parser.ParseFrom(afterAckAliasBytes);
            Assert.Null(afterAckAlias.Error);
            Assert.Equal("after-explicit-human-ack", File.ReadAllText(target));
            Assert.Empty(connection.UnverifiedResults);
            Console.WriteLine("owned-node-pid=" + host.Id.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                " worker-pid=" + observation.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                " worker-start-ticks=" + observation.StartTicks.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                " observed-worker-exit=SIGKILL; node-stopped=true; target-effect-observed=true; recovered=UNKNOWN");
        }
        finally
        {
            if (stopped) Assert.Equal(0, Signal(hostPidfd, 18));
            if (node.Descriptor() is { } descriptor && descriptor.ProcessIsAlive())
            {
                await using var cleanup = await node.HumanChannelAsync();
                var signedOut = await cleanup.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = Command() },
                    deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: CancellationToken.None);
                Assert.Null(signedOut.Error);
                await node.StopNodeAsync();
            }
        }
    }

    private static RequestMeta Command() => new() { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };

    private static async Task<(int Pid, long StartTicks)> WaitForFirstActualWrite(string dataRoot, Id command, string path,
        (long Seconds, uint Nanoseconds) before, CancellationToken ct)
    {
        var until = Stopwatch.StartNew();
        while (until.Elapsed < TimeSpan.FromSeconds(8))
        {
            ct.ThrowIfCancellationRequested();
            var worker = FindWorker(dataRoot, command);
            if (worker is not null && Modification(path) != before) return worker.Value;
            await Task.Delay(2, ct);
        }
        throw new TimeoutException("The owned worker and its first actual target write were not both observed.");
    }

    private static (int Pid, long StartTicks)? FindWorker(string dataRoot, Id command)
    {
        var builder = new SqliteConnectionStringBuilder { DataSource = StorePaths.Database(dataRoot), Mode = SqliteOpenMode.ReadOnly, Pooling = false };
        using var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT process_id, start_ticks FROM file_effect_worker WHERE command_id = $id AND ended = 0;";
        query.Parameters.AddWithValue("$id", command.Value.ToByteArray());
        using var row = query.ExecuteReader();
        return row.Read() ? (row.GetInt32(0), row.GetInt64(1)) : null;
    }

    private static (char State, int Parent, long StartTicks, int ExitCode) ReadProc(int pid)
    {
        var text = File.ReadAllText("/proc/" + pid.ToString(System.Globalization.CultureInfo.InvariantCulture) + "/stat");
        var close = text.LastIndexOf(')');
        Assert.True(close > 0);
        var fields = text[(close + 2)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        Assert.True(fields.Length > 49);
        return (fields[0][0], int.Parse(fields[1], System.Globalization.CultureInfo.InvariantCulture),
            long.Parse(fields[19], System.Globalization.CultureInfo.InvariantCulture),
            int.Parse(fields[49], System.Globalization.CultureInfo.InvariantCulture));
    }

    private static async Task WaitForStopped(SafeFileHandle pidfd, int pid, CancellationToken ct)
    {
        var until = Stopwatch.StartNew();
        while (until.Elapsed < TimeSpan.FromSeconds(5))
        {
            if (Stopped(pidfd, pid)) return;
            await Task.Delay(2, ct);
        }
        throw new TimeoutException("The owned node did not stop.");
    }

    private static unsafe bool Stopped(SafeFileHandle pidfd, int pid)
    {
        byte* data = stackalloc byte[128];
        new Span<byte>(data, 128).Clear();
        Assert.Equal(0, WaitId(3, checked((uint)pidfd.DangerousGetHandle()), data, 1 | 2 | 4 | 0x01000000));
        return *(int*)(data + 8) == 5 && *(int*)(data + 16) == pid && *(int*)(data + 24) == 19;
    }

    private static SafeFileHandle OpenPidfd(int pid)
    {
        var descriptor = PidfdOpen(434, pid, 0);
        Assert.True(descriptor >= 0);
        return new SafeFileHandle(descriptor, ownsHandle: true);
    }

    private static int Signal(SafeFileHandle pidfd, int signal) =>
        checked((int)PidfdSignal(424, checked((int)pidfd.DangerousGetHandle()), signal, 0, 0));

    private static int PollOnce(SafeFileHandle pidfd, int timeout)
    {
        var poll = new PollDescriptor { FileDescriptor = checked((int)pidfd.DangerousGetHandle()), Events = 1 };
        return Poll(ref poll, 1, timeout);
    }

    private static (long Seconds, uint Nanoseconds) Modification(string path)
    {
        Assert.Equal(0, Statx(-100, path, 0x100, 0x1fff, out var stat));
        Assert.True((stat.Mask & 0x40) != 0);
        return (stat.ModificationSeconds, stat.ModificationNanoseconds);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PollDescriptor { public int FileDescriptor; public short Events; public short Revents; }

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct NativeStat
    {
        [FieldOffset(0)] public uint Mask;
        [FieldOffset(112)] public long ModificationSeconds;
        [FieldOffset(120)] public uint ModificationNanoseconds;
    }

    [LibraryImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static partial nint PidfdOpen(nint number, int pid, uint flags);

    [LibraryImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static partial nint PidfdSignal(nint number, int fd, int signal, nint info, uint flags);

    [LibraryImport("libc", EntryPoint = "poll", SetLastError = true)]
    private static partial int Poll(ref PollDescriptor descriptors, nuint count, int timeout);

    [LibraryImport("libc", EntryPoint = "waitid", SetLastError = true)]
    private static unsafe partial int WaitId(int kind, uint id, byte* information, int options);

    [LibraryImport("libc", EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int Statx(int directory, string path, int flags, uint mask, out NativeStat buffer);
}
