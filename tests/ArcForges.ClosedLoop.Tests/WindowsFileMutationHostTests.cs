// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
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
using Microsoft.Win32.SafeHandles;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>Real Windows Host, NTFS, SQLite and signed channel; the center peer is synthetic.</summary>
[Trait("loop", "local")]
[Trait("env", "windows-real")]
public sealed partial class WindowsFileMutationHostTests
{
    [Fact(Timeout = 180_000)]
    public async Task SignedExistingWriteAndEditPreserveTheObjectAndReplayAfterRealRestart()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows native guarded file effect."); return; }
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        center.CommandKeys.Add(center.Channel.CommandPublicKey);
        await using var node = TestNode.Create();
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        using var host = await node.StartNodeAsync();
        Assert.False(host.HasExited);
        try
        {
            await using var human = await node.HumanChannelAsync();
            var info = await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: ct);
            Assert.Null(info.Error);
            Assert.DoesNotContain("files.v1", info.Value.Node.Features);
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
            var root = Directory.CreateDirectory(Path.Combine(node.Root, "windows-file-workspace")).FullName;
            var target = Path.Combine(root, "target.txt");
            var stream = target + ":arcforges-test";
            var original = Encoding.UTF8.GetBytes("WIN_HOST_ORIGINAL_80ae hello");
            var written = Encoding.UTF8.GetBytes("WIN_HOST_WRITTEN_21f3 hello");
            var edited = Encoding.UTF8.GetBytes("WIN_HOST_WRITTEN_21f3 world");
            var alternate = Encoding.UTF8.GetBytes("WIN_HOST_ALTERNATE_STREAM_786c");
            File.WriteAllBytes(target, original);
            File.WriteAllBytes(stream, alternate);
            File.SetAttributes(target, FileAttributes.Archive);
            var attributes = File.GetAttributes(target);
            var identity = NativeIdentity(target);
            var sections = AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access;
            var security = new FileInfo(target).GetAccessControl(sections).GetSecurityDescriptorBinaryForm();

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
                    TimeSpan.FromSeconds(15), "the real Windows Host result signature verifies");
                return (connection.VerifiedResults.Single(value => value.Header.CallId.Equals(call.CallId)).Header, frame.Payload.ToByteArray());
            }

            var register = new WorkspaceServiceRegisterWorkspaceRequest { Meta = Command(), Path = root, Name = "windows-file" };
            var (registrationHeader, registration) = await Invoke(RoutedMethod.RegisterNodeWorkspace, register, register.Meta.CommandId, caller);
            Assert.Equal(RoutedOutcome.Executed, registrationHeader.Outcome);
            var workspace = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(registration);
            Assert.Null(workspace.Error);
            var path = new NodeFilePath { WorkspaceId = workspace.Value.Workspace.WorkspaceId.Clone(), Path = "target.txt" };
            var stale = new FileServiceWriteFileRequest
            {
                Meta = Command(),
                Path = path.Clone(),
                ExpectedSha256 = ByteString.CopyFrom(new byte[32]),
                Data = ByteString.CopyFrom(written),
            };
            var (_, staleBytes) = await Invoke(RoutedMethod.WriteNodeFile, stale, stale.Meta.CommandId, caller);
            var staleResult = FileServiceWriteFileResponse.Parser.ParseFrom(staleBytes);
            Assert.Equal("file_changed", staleResult.Error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, staleResult.Error.Effect);
            Assert.Equal(original, File.ReadAllBytes(target));

            var agent = caller.Clone();
            agent.LocalOrigin = Origin.Agent;
            agent.LocalSessionId = CommandIds.New();
            var agentWrite = stale.Clone();
            agentWrite.Meta = Command();
            agentWrite.ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(original));
            var (denied, _) = await Invoke(RoutedMethod.WriteNodeFile, agentWrite, agentWrite.Meta.CommandId, agent);
            Assert.Equal(RoutedOutcome.RefusedByPolicy, denied.Outcome);
            Assert.Equal(original, File.ReadAllBytes(target));

            var write = agentWrite.Clone();
            write.Meta = Command();
            var (writeHeader, writeBytes) = await Invoke(RoutedMethod.WriteNodeFile, write, write.Meta.CommandId, caller);
            Assert.Equal(RoutedOutcome.Executed, writeHeader.Outcome);
            var writeResult = FileServiceWriteFileResponse.Parser.ParseFrom(writeBytes);
            Assert.Null(writeResult.Error);
            Assert.Equal(SHA256.HashData(written), writeResult.Value.Result.Sha256.ToByteArray());
            Assert.Equal(write.Meta.CorrelationId, writeResult.Meta.CorrelationId);
            Assert.Equal(written, File.ReadAllBytes(target));

            var edit = new FileServiceEditFileRequest
            {
                Meta = Command(),
                Path = path.Clone(),
                ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(written)),
                OldText = "hello",
                NewText = "world",
                ExpectedOccurrences = 1,
            };
            var (editHeader, editBytes) = await Invoke(RoutedMethod.EditNodeFile, edit, edit.Meta.CommandId, caller);
            Assert.Equal(RoutedOutcome.Executed, editHeader.Outcome);
            var editResult = FileServiceEditFileResponse.Parser.ParseFrom(editBytes);
            Assert.Null(editResult.Error);
            Assert.Equal(1U, editResult.Value.Result.Replacements);
            Assert.Equal(SHA256.HashData(edited), editResult.Value.Result.Sha256.ToByteArray());
            Assert.Equal(edited, File.ReadAllBytes(target));
            Assert.Equal(identity, NativeIdentity(target));
            Assert.Equal(attributes, File.GetAttributes(target));
            Assert.Equal(security, new FileInfo(target).GetAccessControl(sections).GetSecurityDescriptorBinaryForm());
            Assert.Equal(alternate, File.ReadAllBytes(stream));
            AssertJournal(node.DataRoot, write.Meta.CommandId, write.ToByteArray(), written);
            AssertJournal(node.DataRoot, edit.Meta.CommandId, edit.ToByteArray(), edited);

            var external = Encoding.UTF8.GetBytes("later independent content");
            File.WriteAllBytes(target, external);
            await node.StopNodeAsync();
            await node.StartNodeAsync();
            connection = await center.Channel.ProvedAsync(2);
            var (_, writeReplay) = await Invoke(RoutedMethod.WriteNodeFile, write, write.Meta.CommandId, caller);
            var (_, editReplay) = await Invoke(RoutedMethod.EditNodeFile, edit, edit.Meta.CommandId, caller);
            Assert.Equal(writeBytes, writeReplay);
            Assert.Equal(editBytes, editReplay);
            Assert.Equal(external, File.ReadAllBytes(target));
            var changed = write.Clone();
            changed.Meta.CorrelationId = CommandIds.New();
            var (_, changedBytes) = await Invoke(RoutedMethod.WriteNodeFile, changed, changed.Meta.CommandId, caller);
            Assert.Equal("command_id_reused", FileServiceWriteFileResponse.Parser.ParseFrom(changedBytes).Error.Code);
            Assert.Empty(connection.UnverifiedResults);

            foreach (var file in new[] { StorePaths.Database(node.DataRoot), StorePaths.Database(node.DataRoot) + "-wal", node.NodeLog })
            {
                if (CloudLinkHostTests.ReadAllShared(file) is not { } bytes) continue;
                Assert.Equal(-1, bytes.AsSpan().IndexOf(written));
                Assert.Equal(-1, bytes.AsSpan().IndexOf(edited));
            }
        }
        finally
        {
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

    private static void AssertJournal(string dataRoot, Id command, byte[] raw, byte[] expected)
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = StorePaths.Database(dataRoot),
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        };
        using var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT phase, held, request_sha256, target_identity, intended_size, intended_sha256
            FROM file_operation_journal WHERE command_id = $id;
            """;
        query.Parameters.AddWithValue("$id", command.Value.ToByteArray());
        using var row = query.ExecuteReader();
        Assert.True(row.Read());
        Assert.Equal(2, row.GetInt32(0));
        Assert.Equal(0, row.GetInt32(1));
        Assert.Equal(SHA256.HashData(raw), (byte[])row.GetValue(2));
        Assert.NotEmpty((byte[])row.GetValue(3));
        Assert.Equal(expected.LongLength, row.GetInt64(4));
        Assert.Equal(SHA256.HashData(expected), (byte[])row.GetValue(5));
        Assert.False(row.Read());
    }

    private static (uint Volume, uint IndexHigh, uint IndexLow, uint CreationHigh, uint CreationLow) NativeIdentity(string path)
    {
        using var file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (!GetFileInformationByHandle(file, out var info)) throw new Win32Exception(Marshal.GetLastPInvokeError());
        return (info.Volume, info.IndexHigh, info.IndexLow, info.CreationHigh, info.CreationLow);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes;
        public uint CreationLow;
        public uint CreationHigh;
        public uint AccessLow;
        public uint AccessHigh;
        public uint WriteLow;
        public uint WriteHigh;
        public uint Volume;
        public uint SizeHigh;
        public uint SizeLow;
        public uint Links;
        public uint IndexHigh;
        public uint IndexLow;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);
}
