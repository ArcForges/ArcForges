// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.Versioning;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>Owned-child pidfd supervision; no file-effect authorization or physical I/O deadline is claimed.</summary>
[Trait("feature", "file-guard-helper")]
[Trait("env", "linux-real")]
[SupportedOSPlatform("linux")]
public sealed class LinuxOwnedPidfdTests
{
    [Theory(Timeout = 30_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OnlyAChallengeSealedPidfdCanSignalItsExactOwnedChild(bool corrupt)
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux pidfd and Unix peer credentials.");
            return;
        }
        var ct = TestContext.Current.CancellationToken;
        var root = Directory.CreateTempSubdirectory("af-pidfd-").FullName;
        var socketPath = Path.Combine(root, "ipc");
        const string Script = """
            import socket, sys
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(sys.argv[1])
            value = sys.stdin.buffer.read(32)
            if len(value) != 32:
                sys.exit(10)
            if sys.argv[2] == 'bad':
                value = bytes([value[0] ^ 1]) + value[1:]
            s.sendall(value)
            sys.stdin.buffer.read(1)
            """;
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(socketPath));
        listener.Listen(1);
        using var child = StartPython(Script, socketPath, corrupt ? "bad" : "ok");
        using var other = StartPython("import sys; sys.stdin.readline()", "", "");
        try
        {
            using var socket = await listener.AcceptAsync(ct).AsTask().WaitAsync(TimeSpan.FromSeconds(10), ct);
            using var pidfd = LinuxOwnedPidfd.OpenPending(socket, child);
            using var challenge = new LinuxPeerChallenge();
            Assert.Throws<InvalidOperationException>(pidfd.StopSealedChild);
            if (corrupt)
            {
                Assert.Throws<InvalidOperationException>(() => pidfd.AuthenticateAndSeal(socket, challenge));
                Assert.Throws<InvalidOperationException>(pidfd.StopSealedChild);
                Assert.False(child.HasExited);
                await child.StandardInput.WriteLineAsync("x");
                await child.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(10), ct);
                Assert.Equal(0, child.ExitCode);
            }
            else
            {
                _ = pidfd.AuthenticateAndSeal(socket, challenge);
                Assert.Throws<InvalidOperationException>(() => pidfd.AuthenticateAndSeal(socket, challenge));
                pidfd.StopSealedChild();
                await child.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(10), ct);
                Assert.Equal(137, child.ExitCode);
            }
            Assert.False(other.HasExited);
            await other.StandardInput.WriteLineAsync("exit");
            await other.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(10), ct);
            Assert.Equal(0, other.ExitCode);
        }
        finally
        {
            child.StandardInput.Close();
            other.StandardInput.Close();
            if (!child.HasExited) Assert.True(child.WaitForExit(10_000), "Owned child did not exit after its input closed.");
            if (!other.HasExited) Assert.True(other.WaitForExit(10_000), "Other owned child did not exit after its input closed.");
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
}
