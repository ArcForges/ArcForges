// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Windows test-owned synchronous stage through the real Node dispatcher, filesystem and store. The routed caller is
/// synthetic (MOCKED center); this does not test named approval stages, an actual center, or strict cleanup.
/// </summary>
[Trait("env", "windows-real")]
public sealed class WorkspaceWindowsStageRoutedTests
{
    [Fact(Timeout = 120_000)]
    public async Task RoutedReadsAndSearchCannotExposeHeldStageOrItsMetadataHolderAfterNodeClose()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows delete-on-close stage and native metadata handles.");
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var path = Directory.CreateDirectory(Path.Combine(node.Root, "stage-routed-root")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(path, cancellationToken: token);
        var marker = Encoding.UTF8.GetBytes("STAGE_PRIVATE_SYNTHETIC_MARKER_8cf6612");
        using var root = WorkspacePath.OpenRoot(path);
        using var stage = root.CreateAnonymousStage(marker, token);
        var name = Path.GetFileName(Assert.Single(Directory.EnumerateFileSystemEntries(path)));
        var caller = calls.Relay(Origin.Human); // synthetic isolated caller, not an actual owner or center
        var info = new ProcessStartInfo("python")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        info.ArgumentList.Add("-u");
        info.ArgumentList.Add("-c");
        info.ArgumentList.Add(MetadataHolder);
        info.ArgumentList.Add(Path.Combine(path, name));
        using var holder = Process.Start(info) ?? throw new InvalidOperationException("Cannot start the owned metadata fixture.");
        try
        {
            Assert.Equal("READY", await holder.StandardOutput.ReadLineAsync(token).AsTask().WaitAsync(TimeSpan.FromSeconds(5), token));
            stage.CheckIntact();

            async Task ReadMustRefuse()
            {
                var request = new FileServiceReadFileRequest
                {
                    Meta = new RequestMeta { CorrelationId = CommandIds.New() },
                    Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = name },
                    Offset = 0,
                    Length = 128,
                };
                var call = await calls.CallAsync(caller, RoutedMethod.ReadNodeFile, request.ToByteArray());
                Assert.Equal(RoutedOutcome.Executed, call.Answer!.Outcome);
                var response = FileServiceReadFileResponse.Parser.ParseFrom(call.Answer.Response);
                Assert.True(NodeShapes.IsValid(response));
                Assert.NotNull(response.Error);
                Assert.Null(response.Value);
                Assert.Equal(-1, response.ToByteArray().AsSpan().IndexOf(marker));
            }

            async Task SearchMustNotReveal()
            {
                var request = new FileServiceSearchFilesRequest
                {
                    Meta = new RequestMeta { CorrelationId = CommandIds.New() },
                    Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "" },
                    Pattern = Encoding.UTF8.GetString(marker),
                    Mode = FileSearchMode.Literal,
                };
                var call = await calls.CallAsync(caller, RoutedMethod.SearchNodeFiles, request.ToByteArray());
                Assert.Equal(RoutedOutcome.Executed, call.Answer!.Outcome);
                var response = FileServiceSearchFilesResponse.Parser.ParseFrom(call.Answer.Response);
                Assert.True(NodeShapes.IsValid(response));
                if (response.Value is not null)
                {
                    Assert.Empty(response.Value.Matches);
                    Assert.Equal(0UL, response.Value.ScannedBytes);
                }
                else Assert.NotNull(response.Error);
                Assert.Equal(-1, response.ToByteArray().AsSpan().IndexOf(marker));
            }

            await ReadMustRefuse();
            await SearchMustNotReveal();
            var list = new FileServiceListDirectoryRequest
            {
                Meta = new RequestMeta { CorrelationId = CommandIds.New() },
                Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "" },
                PageSize = 100,
            };
            var listed = await calls.CallAsync(caller, RoutedMethod.ListNodeDirectory, list.ToByteArray());
            Assert.Equal(RoutedOutcome.Executed, listed.Answer!.Outcome);
            var listResponse = FileServiceListDirectoryResponse.Parser.ParseFrom(listed.Answer.Response);
            Assert.True(NodeShapes.IsValid(listResponse));
            Assert.Equal(-1, listResponse.ToByteArray().AsSpan().IndexOf(marker));

            stage.CheckIntact();
            stage.Dispose(); // the independent metadata holder still has its own handle
            await ReadMustRefuse();
            await SearchMustNotReveal();

            await holder.StandardInput.WriteLineAsync("read");
            var recovered = await holder.StandardOutput.ReadLineAsync(token).AsTask().WaitAsync(TimeSpan.FromSeconds(5), token);
            Assert.Equal("DATA:" + Convert.ToHexStringLower(SHA256.HashData(marker)) + ":same", recovered);
            await holder.WaitForExitAsync(token).WaitAsync(TimeSpan.FromSeconds(5), token);
            Assert.Equal(0, holder.ExitCode);
            Assert.Empty(Directory.EnumerateFileSystemEntries(path));
        }
        finally
        {
            if (!holder.HasExited)
            {
                holder.Kill(); // only this test-owned process
                if (!holder.WaitForExit(5000)) TestContext.Current.TestOutputHelper?.WriteLine("Owned metadata fixture did not exit after termination.");
            }
        }
    }

    private const string MetadataHolder = """
        import ctypes, ctypes.wintypes as w, hashlib, sys
        k=ctypes.WinDLL('kernel32',use_last_error=True)
        invalid=ctypes.c_void_p(-1).value
        class Info(ctypes.Structure):
            _fields_=[('attributes',w.DWORD),('creation',w.FILETIME),('access',w.FILETIME),('write',w.FILETIME),
                ('volume',w.DWORD),('size_high',w.DWORD),('size_low',w.DWORD),('links',w.DWORD),('high',w.DWORD),('low',w.DWORD)]
        k.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,ctypes.c_void_p,w.DWORD,w.DWORD,w.HANDLE];k.CreateFileW.restype=w.HANDLE
        k.ReOpenFile.argtypes=[w.HANDLE,w.DWORD,w.DWORD,w.DWORD];k.ReOpenFile.restype=w.HANDLE
        k.GetFileInformationByHandle.argtypes=[w.HANDLE,ctypes.POINTER(Info)];k.GetFileInformationByHandle.restype=w.BOOL
        k.ReadFile.argtypes=[w.HANDLE,ctypes.c_void_p,w.DWORD,ctypes.POINTER(w.DWORD),ctypes.c_void_p];k.ReadFile.restype=w.BOOL
        k.CloseHandle.argtypes=[w.HANDLE];k.CloseHandle.restype=w.BOOL
        h=k.CreateFileW(sys.argv[1],0x80,7,None,3,0x80,None)
        if h==invalid: print('METADATA_FAILED',flush=True);sys.exit(1)
        before=Info()
        if not k.GetFileInformationByHandle(h,ctypes.byref(before)): sys.exit(2)
        print('READY',flush=True)
        sys.stdin.readline()
        data=k.ReOpenFile(h,0x80000000,0,0)
        if data==invalid: print('DATA_FAILED',flush=True);sys.exit(3)
        after=Info(); buf=ctypes.create_string_buffer(128); count=w.DWORD()
        ok=k.GetFileInformationByHandle(data,ctypes.byref(after)) and k.ReadFile(data,buf,128,ctypes.byref(count),None)
        same=(before.volume,before.high,before.low)==(after.volume,after.high,after.low)
        print('DATA:'+hashlib.sha256(buf.raw[:count.value]).hexdigest()+(':'+('same' if same else 'different') if ok else ':failed'),flush=True)
        k.CloseHandle(data);k.CloseHandle(h)
        """;
}
