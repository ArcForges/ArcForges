// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>Private challenge and actual owned-child peer binding, without any file-effect authorization.</summary>
[Trait("feature", "file-guard-helper")]
[Trait("env", "linux-real")]
[SupportedOSPlatform("linux")]
public sealed class LinuxOwnedPeerTests
{
    [Theory(Timeout = 30_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OnlyTheExpectedChildCanConsumeAOneUseChallengeAndReceiveTheOpenedObject(bool corrupt)
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux Unix peer credentials and owned child.");
            return;
        }
        var ct = TestContext.Current.CancellationToken;
        var root = Directory.CreateTempSubdirectory("af-owned-peer-").FullName;
        var socketPath = Path.Combine(root, "ipc");
        var target = Path.Combine(root, "object");
        var data = Encoding.UTF8.GetBytes("owned-transfer-362a");
        File.WriteAllBytes(target, data);
        const string Script = """
            import array, os, socket, sys
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(sys.argv[1])
            challenge = sys.stdin.buffer.read(32)
            if len(challenge) != 32:
                sys.exit(10)
            if sys.argv[2] == 'bad':
                challenge = bytes([challenge[0] ^ 1]) + challenge[1:]
            s.sendall(challenge)
            data, ancillary, flags, addr = s.recvmsg(1, socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
            if not data:
                sys.exit(0)
            descriptors = array.array('i')
            for level, kind, value in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    descriptors.frombytes(value[:4])
            if len(descriptors) != 1:
                sys.exit(11)
            actual = os.pread(descriptors[0], 128, 0)
            print('SAME' if actual == b'owned-transfer-362a' else 'DIFFERENT', flush=True)
            os.close(descriptors[0])
            sys.stdin.buffer.read(1)
            """;
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(socketPath));
        listener.Listen(1);
        using var child = StartPython(Script, socketPath, corrupt ? "bad" : "ok");
        using var foreign = StartPython("import sys; sys.stdin.readline()", "", "");
        try
        {
            using var socket = await listener.AcceptAsync(ct).AsTask().WaitAsync(TimeSpan.FromSeconds(10), ct);
            using var challenge = new LinuxPeerChallenge();
            challenge.DeliverTo(child);
            Assert.Throws<InvalidOperationException>(() => LinuxOwnedPeer.Authenticate(socket, foreign, challenge));
            if (corrupt)
            {
                Assert.Throws<InvalidOperationException>(() => LinuxOwnedPeer.Authenticate(socket, child, challenge));
                Assert.Throws<InvalidOperationException>(() => LinuxOwnedPeer.Authenticate(socket, child, challenge));
            }
            else
            {
                var peer = LinuxOwnedPeer.Authenticate(socket, child, challenge);
                Assert.Throws<InvalidOperationException>(() => LinuxOwnedPeer.Authenticate(socket, child, challenge));
                using var source = File.OpenHandle(target);
                peer.SendDescriptorsOnce([source]);
                Assert.Throws<InvalidOperationException>(() => peer.SendDescriptorsOnce([source]));
                Assert.Equal("SAME", await child.StandardOutput.ReadLineAsync(ct).AsTask().WaitAsync(TimeSpan.FromSeconds(10), ct));
            }
            if (!corrupt) await child.StandardInput.WriteLineAsync("x");
            socket.Dispose();
            await child.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(10), ct);
            Assert.Equal(0, child.ExitCode);
        }
        finally
        {
            Stop(child);
            Stop(foreign);
            listener.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    private static Process StartPython(string script, string first, string second)
    {
        var start = new ProcessStartInfo("python3")
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        start.ArgumentList.Add("-c");
        start.ArgumentList.Add(script);
        start.ArgumentList.Add(first);
        start.ArgumentList.Add(second);
        return Process.Start(start) ?? throw new InvalidOperationException("Could not start owned native peer.");
    }

    private static void Stop(Process child)
    {
        if (child.HasExited) return;
        child.Kill();
        Assert.True(child.WaitForExit(10_000), "The owned peer did not exit after termination.");
    }
}
