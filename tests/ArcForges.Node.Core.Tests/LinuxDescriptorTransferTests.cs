// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using ArcForges.Node.Core.Platform;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real Linux SCM_RIGHTS transfer; no file-effect helper, policy or cleanup acceptance is claimed.</summary>
[Trait("feature", "file-guard-helper")]
[Trait("env", "linux-real")]
public sealed partial class LinuxDescriptorTransferTests
{
    [Fact(Timeout = 30_000)]
    public void ExactDescriptorsRemainBoundWhenNamesAreReplacedAndHaveCloseOnExec()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux SCM_RIGHTS descriptor transport.");
            return;
        }
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        using var pair = new SocketPair();
        var root = pair.Root;
        var paths = Enumerable.Range(0, 4).Select(i => Path.Combine(root, "file-" + i)).ToArray();
        var originals = paths.Select((_, i) => Encoding.UTF8.GetBytes("transfer-object-" + i)).ToArray();
        var handles = new List<SafeFileHandle>();
        var received = Array.Empty<SafeFileHandle>();
        try
        {
            for (var index = 0; index < paths.Length; index++)
            {
                ct.ThrowIfCancellationRequested();
                File.WriteAllBytes(paths[index], originals[index]);
                handles.Add(File.OpenHandle(paths[index], FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete));
            }
            LinuxDescriptorTransfer.Send(pair.Client, handles);
            received = LinuxDescriptorTransfer.Receive(pair.Server, 4);
            Assert.Equal(4, received.Length);
            foreach (var handle in handles) handle.Dispose();
            handles.Clear();
            for (var index = 0; index < paths.Length; index++)
            {
                ct.ThrowIfCancellationRequested();
                File.Move(paths[index], paths[index] + ".old");
                File.WriteAllText(paths[index], "replacement");
                Assert.Equal(1, Fcntl(checked((int)received[index].DangerousGetHandle()), 1) & 1); // FD_CLOEXEC
                var bytes = new byte[originals[index].Length];
                Assert.Equal(bytes.Length, RandomAccess.Read(received[index], bytes, 0));
                Assert.Equal(originals[index], bytes);
            }
        }
        finally
        {
            foreach (var handle in received) handle.Dispose();
            foreach (var handle in handles) handle.Dispose();
        }
    }

    [Fact(Timeout = 30_000)]
    public void UnexpectedDescriptorCountIsRejectedAndTheConnectionCanContinue()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux SCM_RIGHTS descriptor transport.");
            return;
        }
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        using var pair = new SocketPair();
        var path = Path.Combine(pair.Root, "item");
        File.WriteAllText(path, "owned");
        using var source = File.OpenHandle(path);
        LinuxDescriptorTransfer.Send(pair.Client, [source]);
        Assert.Throws<InvalidDataException>(() =>
        {
            if (OperatingSystem.IsLinux()) LinuxDescriptorTransfer.Receive(pair.Server, 2);
        });
        LinuxDescriptorTransfer.Send(pair.Client, [source]);
        var actual = LinuxDescriptorTransfer.Receive(pair.Server, 1);
        try
        {
            var data = new byte[5];
            Assert.Equal(5, RandomAccess.Read(actual[0], data, 0));
            Assert.Equal("owned", Encoding.UTF8.GetString(data));
        }
        finally { foreach (var handle in actual) handle.Dispose(); }
    }

    [Fact(Timeout = 30_000)]
    public async Task IndependentNativeProcessPassesTheOpenedObjectWithoutReopeningItsName()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux SCM_RIGHTS descriptor transport.");
            return;
        }
        var ct = TestContext.Current.CancellationToken;
        var root = Directory.CreateTempSubdirectory("af-fd-process-").FullName;
        var target = Path.Combine(root, "target");
        var endpoint = Path.Combine(root, "ipc");
        var original = Encoding.UTF8.GetBytes("owned-child-transfer-4c38");
        File.WriteAllBytes(target, original);
        const string Script = """
            import array, os, socket, sys
            fd = os.open(sys.argv[2], os.O_RDONLY | os.O_CLOEXEC)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(sys.argv[1])
            sock.sendmsg([b'\xa6'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
            print('SENT', flush=True)
            sys.stdin.readline()
            os.close(fd)
            sock.close()
            """;
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(endpoint));
        listener.Listen(1);
        var start = new ProcessStartInfo("python3")
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        start.ArgumentList.Add("-c");
        start.ArgumentList.Add(Script);
        start.ArgumentList.Add(endpoint);
        start.ArgumentList.Add(target);
        using var child = Process.Start(start) ?? throw new InvalidOperationException("Could not start the owned transfer peer.");
        try
        {
            using var peer = await listener.AcceptAsync(ct).AsTask().WaitAsync(TimeSpan.FromSeconds(10), ct);
            peer.ReceiveTimeout = 5000;
            var fds = LinuxDescriptorTransfer.Receive(peer, 1);
            try
            {
                Assert.Equal("SENT", await child.StandardOutput.ReadLineAsync(ct).AsTask().WaitAsync(TimeSpan.FromSeconds(10), ct));
                File.Move(target, target + ".old");
                File.WriteAllText(target, "replacement");
                await child.StandardInput.WriteLineAsync("close");
                await child.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(10), ct);
                Assert.Equal(0, child.ExitCode);
                var data = new byte[original.Length];
                Assert.Equal(original.Length, RandomAccess.Read(fds[0], data, 0));
                Assert.Equal(original, data);
                Assert.Equal(1, Fcntl(checked((int)fds[0].DangerousGetHandle()), 1) & 1);
            }
            finally { foreach (var handle in fds) handle.Dispose(); }
        }
        finally
        {
            if (!child.HasExited)
            {
                child.Kill();
                Assert.True(child.WaitForExit(10_000), "The owned peer did not exit after termination.");
            }
            listener.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [SupportedOSPlatform("linux")]
    private sealed class SocketPair : IDisposable
    {
        internal string Root { get; } = Directory.CreateTempSubdirectory("af-fd-pair-").FullName;
        internal Socket Client { get; }
        internal Socket Server { get; }

        internal SocketPair()
        {
            using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            var endpoint = Path.Combine(Root, "ipc");
            listener.Bind(new UnixDomainSocketEndPoint(endpoint));
            listener.Listen(1);
            Client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            Client.Connect(new UnixDomainSocketEndPoint(endpoint));
            Server = listener.Accept();
            Client.SendTimeout = 5000;
            Server.ReceiveTimeout = 5000;
        }

        public void Dispose()
        {
            Server.Dispose();
            Client.Dispose();
            Directory.Delete(Root, recursive: true);
        }
    }

    [LibraryImport("libc", EntryPoint = "fcntl", SetLastError = true)]
    private static partial int Fcntl(int fd, int command);
}
