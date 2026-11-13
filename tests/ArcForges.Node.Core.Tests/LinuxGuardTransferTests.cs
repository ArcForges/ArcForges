// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Net.Sockets;
using System.Runtime.Versioning;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real guard and descriptor lifetime across an owned process; this does not perform a file effect.</summary>
[Trait("feature", "file-guard-helper")]
[Trait("env", "linux-real")]
[SupportedOSPlatform("linux")]
public sealed class LinuxGuardTransferTests
{
    [Theory(Timeout = 30_000)]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task TargetAndStageTransferKeepsNodeAliveAcrossBreakWindows(int scenario)
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux native lease and SCM_RIGHTS.");
            return;
        }
        var ct = TestContext.Current.CancellationToken;
        var rootPath = Directory.CreateTempSubdirectory("af-lease-transfer-").FullName;
        var target = Path.Combine(rootPath, "target");
        var socketPath = Path.Combine(rootPath, "ipc");
        const string Original = "owned-lease-target-540b";
        File.WriteAllText(target, Original);
        const string ChildScript = """
            import array, fcntl, os, signal, socket, sys
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(sys.argv[1])
            def receive():
                data, ancillary, flags, addr = s.recvmsg(1, socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
                a = array.array('i')
                for level, kind, value in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        a.frombytes(value[:4])
                if data != b'\xa6' or flags & ~socket.MSG_CMSG_CLOEXEC or len(a) != 1:
                    print('RECEIVE_REJECT', len(data), flags, len(a), file=sys.stderr, flush=True)
                    sys.exit(11)
                fd = a[0]
                if fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC != fcntl.FD_CLOEXEC:
                    sys.exit(12)
                return fd
            target = receive()
            stage = receive()
            fcntl.fcntl(target, 8, os.getpid())
            if fcntl.fcntl(target, 9) != os.getpid():
                sys.exit(13)
            print('TARGET_OWNER', os.getpid(), fcntl.fcntl(target, 9), fcntl.fcntl(target, 1025), flush=True)
            sys.stdin.readline()
            fcntl.fcntl(target, 10, signal.SIGKILL)
            fcntl.fcntl(stage, 8, os.getpid())
            if fcntl.fcntl(stage, 9) != os.getpid():
                sys.exit(14)
            fcntl.fcntl(stage, 10, signal.SIGKILL)
            print('READY', fcntl.fcntl(target, 9), fcntl.fcntl(target, 11),
                  fcntl.fcntl(stage, 9), fcntl.fcntl(stage, 11), stage, flush=True)
            sys.stdin.readline()
            print('AFTER_CLOSE', fcntl.fcntl(target, 1025), fcntl.fcntl(stage, 1025), flush=True)
            sys.stdin.readline()
            """;
        const string BreakerScript = """
            import os, sys
            try:
                fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NONBLOCK)
                os.close(fd)
                print('OPENED', flush=True)
            except BlockingIOError as error:
                print('EAGAIN:' + str(error.errno), flush=True)
            """;
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(socketPath));
        listener.Listen(1);
        using var child = StartPython(ChildScript, socketPath);
        try
        {
            using var peer = await listener.AcceptAsync(ct).AsTask().WaitAsync(TimeSpan.FromSeconds(8), ct);
            var credentials = LinuxPeerCredentialReader.Read(peer);
            Assert.Equal(child.Id, credentials.ProcessId); // Kernel SO_PEERCRED, not a stated PID.
            var identity = LinuxOwnedProcessIdentity.CaptureChild(child);
            using var root = WorkspacePath.OpenRoot(rootPath);
            using var guard = root.OpenExistingWriteGuard("target");
            using var stage = root.CreateAnonymousStage("owned-stage-540b"u8, ct);
            guard.SendLinuxGuardForTests(peer);
            stage.SendLinuxGuardForTests(peer);
            var owner = await ReadChildLine(child, ct);
            var pid = child.Id.ToString(CultureInfo.InvariantCulture);
            Assert.Equal("TARGET_OWNER " + pid + " " + pid + " 1", owner);
            if (scenario == 2)
            {
                // A real break after F_SETOWN(child) and its readback, before F_SETSIG(SIGKILL).
                await Break(target, BreakerScript, ct);
                await child.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(8), ct);
                Assert.Equal(157, child.ExitCode); // The original SIGIO was sent to the child, never the node.
                Assert.Throws<WorkspacePathException>(guard.CheckIntact);
                guard.Dispose();
                stage.Dispose();
                Assert.Equal(LinuxProcessObservation.Ended, identity.Observe());
                Assert.Equal(Original, File.ReadAllText(target));
                return;
            }

            await child.StandardInput.WriteLineAsync("continue");
            var ready = (await ReadChildLine(child, ct)).Split(' ');
            Assert.Equal(6, ready.Length);
            Assert.Equal("READY", ready[0]);
            Assert.Equal(pid, ready[1]);
            Assert.Equal("9", ready[2]);
            Assert.Equal(pid, ready[3]);
            Assert.Equal("9", ready[4]);
            Assert.True(int.TryParse(ready[5], NumberStyles.None, CultureInfo.InvariantCulture, out var stageFd) && stageFd >= 0);
            guard.CheckIntact();
            stage.CheckIntact();
            guard.Dispose();
            stage.Dispose();
            await child.StandardInput.WriteLineAsync("check");
            Assert.Equal("AFTER_CLOSE 1 1", await ReadChildLine(child, ct));
            Assert.Equal(LinuxProcessObservation.Alive, identity.Observe());
            var conflict = scenario == 0 ? target : "/proc/" + pid + "/fd/" + stageFd.ToString(CultureInfo.InvariantCulture);
            await Break(conflict, BreakerScript, ct);
            await child.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(8), ct);
            Assert.Equal(137, child.ExitCode); // A real conflict killed this child, not the node.
            Assert.Equal(LinuxProcessObservation.Ended, identity.Observe());
            Assert.Equal(Original, File.ReadAllText(target));
        }
        finally
        {
            if (!child.HasExited)
            {
                child.Kill();
                Assert.True(child.WaitForExit(10_000), "The owned child did not exit after termination.");
            }
            listener.Dispose();
            Directory.Delete(rootPath, recursive: true);
        }
    }

    private static async Task<string> ReadChildLine(Process child, CancellationToken ct)
    {
        var line = await child.StandardOutput.ReadLineAsync(ct).AsTask().WaitAsync(TimeSpan.FromSeconds(8), ct);
        if (line is not null) return line;
        await child.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(8), ct);
        var error = await child.StandardError.ReadToEndAsync(ct);
        throw new InvalidOperationException("Owned peer exited " + child.ExitCode.ToString(CultureInfo.InvariantCulture) + ": " + error);
    }

    private static async Task Break(string path, string script, CancellationToken ct)
    {
        using var breaker = StartPython(script, path);
        await breaker.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(8), ct);
        Assert.Equal(0, breaker.ExitCode);
        Assert.Equal("EAGAIN:11", (await breaker.StandardOutput.ReadToEndAsync(ct)).Trim());
    }

    private static Process StartPython(string script, string argument)
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
        start.ArgumentList.Add(argument);
        return Process.Start(start) ?? throw new InvalidOperationException("Could not start owned native test process.");
    }
}
