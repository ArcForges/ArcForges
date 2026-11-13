// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.CloudLink.Tests;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>Real Linux Host, native files, SQLite, WebSocket and signatures; only the center peer is synthetic.</summary>
[Trait("loop", "local")]
[Trait("env", "linux-real")]
public sealed partial class LinuxFileMutationHostTests
{
    [Fact(Timeout = 180_000)]
    public async Task SignedExistingWriteAndEditUseOwnedWorkerAndReplayAcrossRealNodeRestart()
    {
        if (!OperatingSystem.IsLinux()) { Assert.Skip("Linux native file-effect worker."); return; }
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        center.CommandKeys.Add(center.Channel.CommandPublicKey);
        await using var node = TestNode.Create();
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        using var host = await node.StartNodeAsync();
        Assert.False(host.HasExited);
        await using var human = await node.HumanChannelAsync();
        var info = await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: ct);
        Assert.Null(info.Error);
        Assert.Contains("files.v1", info.Value.Node.Features);
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
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "worker-workspace")).FullName;
        var targetParent = Directory.CreateDirectory(Path.Combine(root, "a", "b")).FullName;
        var target = Path.Combine(targetParent, "target.txt");
        var original = Encoding.UTF8.GetBytes("HOST_ORIGINAL_8a6d hello");
        var written = Encoding.UTF8.GetBytes("HOST_PRIVATE_BODY_47bc hello");
        var edited = Encoding.UTF8.GetBytes("HOST_PRIVATE_BODY_47bc world");
        File.WriteAllBytes(target, original);
        PutAttribute(target, "user.arcforges.test", "owned-user-attribute"u8.ToArray());
        var acl = AclFromText("u::rw-,u:1:r--,g::r--,m::r--,o::---");
        Assert.NotEqual(IntPtr.Zero, acl);
        try { Assert.Equal(0, AclSetFile(target, 0x8000, acl)); }
        finally { _ = AclFree(acl); }
        var userAttribute = ReadAttribute(target, "user.arcforges.test");
        var accessAcl = ReadAttribute(target, "system.posix_acl_access");
        Assert.NotEmpty(accessAcl);
        var identityBefore = Identity(target);
        var modeBefore = File.GetUnixFileMode(target);

        async Task<(ResultHeader Header, byte[] Payload)> Invoke(RoutedMethod method, IMessage request, Id? id, CenterCaller actor)
        {
            var (call, _) = center.Channel.BuildCall(connection, new FakeCallSpec
            {
                Method = method,
                Payload = request.ToByteArray(),
                Caller = actor,
                CommandId = id,
                Lifetime = TimeSpan.FromSeconds(30),
            });
            await connection.SendCallAsync(call);
            var frame = await connection.ResultOfAsync(call.CallId);
            await TestNode.WaitAsync(() => connection.VerifiedResults.Any(value => value.Header.CallId.Equals(call.CallId)),
                TimeSpan.FromSeconds(15), "the real Host result signature verifies");
            return (connection.VerifiedResults.Single(value => value.Header.CallId.Equals(call.CallId)).Header, frame.Payload.ToByteArray());
        }

        var register = new WorkspaceServiceRegisterWorkspaceRequest { Meta = Command(), Path = root, Name = "owned-worker" };
        var (registerHeader, registerBytes) = await Invoke(RoutedMethod.RegisterNodeWorkspace, register, register.Meta.CommandId, caller);
        Assert.Equal(RoutedOutcome.Executed, registerHeader.Outcome);
        var registered = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(registerBytes);
        Assert.Null(registered.Error);
        var workspace = registered.Value.Workspace.WorkspaceId;
        var filePath = new NodeFilePath { WorkspaceId = workspace.Clone(), Path = "a/b/target.txt" };
        var stale = new FileServiceWriteFileRequest
        {
            Meta = Command(),
            Path = filePath.Clone(),
            Data = ByteString.CopyFrom(written),
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData("wrong-original"u8)),
        };
        var (_, staleBytes) = await Invoke(RoutedMethod.WriteNodeFile, stale, stale.Meta.CommandId, caller);
        var staleReply = FileServiceWriteFileResponse.Parser.ParseFrom(staleBytes);
        Assert.True(NodeShapes.IsValid(staleReply));
        Assert.Equal("file_changed", staleReply.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, staleReply.Error.Effect);
        Assert.Equal(original, File.ReadAllBytes(target));
        Assert.Equal(identityBefore, Identity(target));

        // A pre-existing independent data descriptor must prevent the real Linux write lease before any effect.
        using (var holder = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            var occupied = stale.Clone();
            occupied.Meta = Command();
            occupied.ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(original));
            var (_, occupiedBytes) = await Invoke(RoutedMethod.WriteNodeFile, occupied, occupied.Meta.CommandId, caller);
            var busy = FileServiceWriteFileResponse.Parser.ParseFrom(occupiedBytes);
            Assert.True(NodeShapes.IsValid(busy));
            Assert.Equal(ErrorCategory.State, busy.Error.Category);
            Assert.Equal("file_access_denied", busy.Error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, busy.Error.Effect);
        }
        Assert.Equal(original, File.ReadAllBytes(target));
        var agent = caller.Clone();
        agent.LocalOrigin = Origin.Agent;
        var denied = stale.Clone();
        denied.Meta = Command();
        denied.ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(original));
        var (deniedHeader, _) = await Invoke(RoutedMethod.WriteNodeFile, denied, denied.Meta.CommandId, agent);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, deniedHeader.Outcome);
        Assert.Equal(original, File.ReadAllBytes(target));

        var privileged = Path.Combine(root, "setuid-target.txt");
        File.WriteAllBytes(privileged, original);
        File.SetUnixFileMode(privileged, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.SetUser);
        var privilegedMode = File.GetUnixFileMode(privileged);
        Assert.True((privilegedMode & UnixFileMode.SetUser) != 0);
        var refused = stale.Clone();
        refused.Meta = Command();
        refused.Path.Path = "setuid-target.txt";
        refused.ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(original));
        var (_, refusalBytes) = await Invoke(RoutedMethod.WriteNodeFile, refused, refused.Meta.CommandId, caller);
        var refusal = FileServiceWriteFileResponse.Parser.ParseFrom(refusalBytes);
        Assert.True(NodeShapes.IsValid(refusal));
        Assert.Equal(ErrorCategory.Resource, refusal.Error.Category);
        Assert.Equal("enforcement_unavailable", refusal.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, refusal.Error.Effect);
        Assert.Equal(original, File.ReadAllBytes(privileged));
        Assert.Equal(privilegedMode, File.GetUnixFileMode(privileged));

        var write = stale.Clone();
        write.Meta = Command();
        write.ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(original));
        var raw = write.ToByteArray();
        var (writeHeader, writeBytes) = await Invoke(RoutedMethod.WriteNodeFile, write, write.Meta.CommandId, caller);
        Assert.Equal(RoutedOutcome.Executed, writeHeader.Outcome);
        var writeReply = FileServiceWriteFileResponse.Parser.ParseFrom(writeBytes);
        Assert.True(NodeShapes.IsValid(writeReply));
        Assert.Null(writeReply.Error);
        Assert.Equal(written, File.ReadAllBytes(target));
        Assert.Equal(SHA256.HashData(written), writeReply.Value.Result.Sha256.ToByteArray());
        Assert.Equal(identityBefore, Identity(target));
        Assert.Equal(modeBefore, File.GetUnixFileMode(target));
        Assert.Equal(userAttribute, ReadAttribute(target, "user.arcforges.test"));
        Assert.Equal(accessAcl, ReadAttribute(target, "system.posix_acl_access"));
        AssertJournal(node.DataRoot, write.Meta.CommandId, raw, original, written);

        var edit = new FileServiceEditFileRequest
        {
            Meta = Command(),
            Path = filePath.Clone(),
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(written)),
            OldText = "hello",
            NewText = "world",
            ExpectedOccurrences = 1,
        };
        var (editHeader, editBytes) = await Invoke(RoutedMethod.EditNodeFile, edit, edit.Meta.CommandId, caller);
        Assert.Equal(RoutedOutcome.Executed, editHeader.Outcome);
        var editReply = FileServiceEditFileResponse.Parser.ParseFrom(editBytes);
        Assert.True(NodeShapes.IsValid(editReply));
        Assert.Null(editReply.Error);
        Assert.Equal(1U, editReply.Value.Result.Replacements);
        Assert.Equal(edited, File.ReadAllBytes(target));
        Assert.Equal(identityBefore, Identity(target));
        Assert.Equal(modeBefore, File.GetUnixFileMode(target));
        Assert.Equal(userAttribute, ReadAttribute(target, "user.arcforges.test"));
        Assert.Equal(accessAcl, ReadAttribute(target, "system.posix_acl_access"));
        AssertJournal(node.DataRoot, edit.Meta.CommandId, edit.ToByteArray(), written, edited);

        var outside = Encoding.UTF8.GetBytes("changed-after-completed");
        File.WriteAllBytes(target, outside);
        await node.StopNodeAsync();
        await node.StartNodeAsync();
        connection = await center.Channel.ProvedAsync(2);
        var (_, replay) = await Invoke(RoutedMethod.WriteNodeFile, write, write.Meta.CommandId, caller);
        Assert.Equal(writeBytes, replay);
        var (_, editReplay) = await Invoke(RoutedMethod.EditNodeFile, edit, edit.Meta.CommandId, caller);
        Assert.Equal(editBytes, editReplay);
        Assert.Equal(outside, File.ReadAllBytes(target));

        var altered = write.Clone();
        altered.Meta.CorrelationId = CommandIds.New();
        var (_, changedBytes) = await Invoke(RoutedMethod.WriteNodeFile, altered, altered.Meta.CommandId, caller);
        Assert.Equal("command_id_reused", FileServiceWriteFileResponse.Parser.ParseFrom(changedBytes).Error.Code);
        var foreign = caller.Clone();
        foreign.LocalSessionId = CommandIds.New();
        var (_, foreignBytes) = await Invoke(RoutedMethod.WriteNodeFile, write, write.Meta.CommandId, foreign);
        Assert.Equal("command_id_reused", FileServiceWriteFileResponse.Parser.ParseFrom(foreignBytes).Error.Code);
        Assert.Empty(connection.UnverifiedResults);
        foreach (var file in new[] { StorePaths.Database(node.DataRoot), StorePaths.Database(node.DataRoot) + "-wal", node.NodeLog })
        {
            if (CloudLinkHostTests.ReadAllShared(file) is not { } bytes) continue;
            Assert.Equal(-1, bytes.AsSpan().IndexOf(written));
            Assert.Equal(-1, bytes.AsSpan().IndexOf(edited));
        }
        await using (var restartedHuman = await node.HumanChannelAsync())
        {
            var signedOut = await restartedHuman.Account.SignOutAsync(new AccountServiceSignOutRequest
            {
                Meta = Command(),
            }, cancellationToken: ct);
            Assert.Null(signedOut.Error);
        }
        await node.StopNodeAsync();
    }

    private static RequestMeta Command() => new() { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };

    private static void AssertJournal(string dataRoot, Id command, byte[] raw, byte[] original, byte[] intended)
    {
        var builder = new SqliteConnectionStringBuilder { DataSource = StorePaths.Database(dataRoot), Mode = SqliteOpenMode.ReadOnly, Pooling = false };
        using var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT j.phase, j.held, j.request_sha256, j.target_identity, j.original_stage_identity, j.intended_stage_identity,
                   j.original_size, j.original_sha256, j.intended_size, j.intended_sha256, w.process_id, w.start_ticks, w.ended
            FROM file_operation_journal j JOIN file_effect_worker w ON w.command_id = j.command_id WHERE j.command_id = $id;
            """;
        query.Parameters.AddWithValue("$id", command.Value.ToByteArray());
        using var row = query.ExecuteReader();
        Assert.True(row.Read());
        Assert.Equal(2L, row.GetInt64(0));
        Assert.Equal(0L, row.GetInt64(1));
        Assert.Equal(SHA256.HashData(raw), (byte[])row.GetValue(2));
        var target = (byte[])row.GetValue(3);
        var originalStage = (byte[])row.GetValue(4);
        var intendedStage = (byte[])row.GetValue(5);
        Assert.Equal(53, target.Length);
        Assert.Equal(53, originalStage.Length);
        Assert.Equal(53, intendedStage.Length);
        Assert.False(target.AsSpan().SequenceEqual(originalStage));
        Assert.False(target.AsSpan().SequenceEqual(intendedStage));
        Assert.False(originalStage.AsSpan().SequenceEqual(intendedStage));
        Assert.Equal(original.Length, row.GetInt64(6));
        Assert.Equal(SHA256.HashData(original), (byte[])row.GetValue(7));
        Assert.Equal(intended.Length, row.GetInt64(8));
        Assert.Equal(SHA256.HashData(intended), (byte[])row.GetValue(9));
        var pid = row.GetInt32(10);
        var started = row.GetInt64(11);
        Assert.True(pid > 1 && started > 0);
        Assert.Equal(1L, row.GetInt64(12));
        Assert.False(row.Read());
        var stat = "/proc/" + pid.ToString(System.Globalization.CultureInfo.InvariantCulture) + "/stat";
        if (File.Exists(stat))
        {
            var text = File.ReadAllText(stat);
            var close = text.LastIndexOf(')');
            Assert.True(close > 0);
            var fields = text[(close + 2)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            Assert.NotEqual(started.ToString(System.Globalization.CultureInfo.InvariantCulture), fields[19]);
        }
        Console.WriteLine("owned-worker target=" + Convert.ToHexString(target) +
            " original-stage=" + Convert.ToHexString(originalStage) + " intended-stage=" + Convert.ToHexString(intendedStage) +
            " original-sha256=" + Convert.ToHexString(SHA256.HashData(original)) +
            " intended-sha256=" + Convert.ToHexString(SHA256.HashData(intended)) +
            " pid=" + pid.ToString(System.Globalization.CultureInfo.InvariantCulture) +
            " start-ticks=" + started.ToString(System.Globalization.CultureInfo.InvariantCulture) + " ended=1");
    }

    private static NativeIdentity Identity(string path)
    {
        Assert.Equal(0, Statx(-100, path, 0x100, 0x1fff, out var stat));
        Assert.True((stat.Mask & 0x1000) != 0);
        return new NativeIdentity(stat.DeviceMajor, stat.DeviceMinor, stat.Inode, stat.BirthSeconds, stat.BirthNanoseconds, stat.User, stat.Group);
    }

    private readonly record struct NativeIdentity(uint Major, uint Minor, ulong Inode, long BirthSeconds, uint BirthNanoseconds,
        uint User, uint Group);

    private static unsafe void PutAttribute(string path, string name, byte[] value)
    {
        fixed (byte* pointer = value) Assert.Equal(0, SetXattr(path, name, pointer, (nuint)value.Length, 0));
    }

    private static unsafe byte[] ReadAttribute(string path, string name)
    {
        var length = GetXattr(path, name, null, 0);
        Assert.InRange(length, 0, 65_536);
        var result = new byte[checked((int)length)];
        fixed (byte* pointer = result) Assert.Equal(length, GetXattr(path, name, pointer, (nuint)result.Length));
        return result;
    }

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct NativeStat
    {
        [FieldOffset(0)] public uint Mask;
        [FieldOffset(20)] public uint User;
        [FieldOffset(24)] public uint Group;
        [FieldOffset(32)] public ulong Inode;
        [FieldOffset(80)] public long BirthSeconds;
        [FieldOffset(88)] public uint BirthNanoseconds;
        [FieldOffset(136)] public uint DeviceMajor;
        [FieldOffset(140)] public uint DeviceMinor;
    }

    [LibraryImport("libc", EntryPoint = "setxattr", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static unsafe partial int SetXattr(string path, string name, byte* value, nuint size, int flags);

    [LibraryImport("libc", EntryPoint = "getxattr", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static unsafe partial nint GetXattr(string path, string name, byte* value, nuint size);

    [LibraryImport("libacl.so.1", EntryPoint = "acl_from_text", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial nint AclFromText(string text);

    [LibraryImport("libacl.so.1", EntryPoint = "acl_set_file", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int AclSetFile(string path, int type, nint acl);

    [LibraryImport("libacl.so.1", EntryPoint = "acl_free")]
    private static partial int AclFree(nint acl);

    [LibraryImport("libc", EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int Statx(int directory, string path, int flags, uint mask, out NativeStat buffer);
}
