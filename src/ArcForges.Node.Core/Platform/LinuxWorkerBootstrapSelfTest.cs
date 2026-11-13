// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text;

namespace ArcForges.Node.Core.Platform;

/// <summary>A no-effect, test-mode-only self-check of the Host's private worker bootstrap.</summary>
[SupportedOSPlatform("linux")]
public static class LinuxWorkerBootstrapSelfTest
{
    /// <summary>Starts this executable as an owned worker, performs one challenge and sends only a stop byte.</summary>
    public static int Run()
    {
        var result = 2;
        var thread = new Thread(() => result = RunOnCreatorThread()) { IsBackground = true, Name = "file-worker-bootstrap-selftest" };
        thread.Start();
        return thread.Join(TimeSpan.FromSeconds(15)) ? result : 2;
    }

    private static int RunOnCreatorThread() => RunCycle(testTimer: false) && RunCycle(testTimer: true) ? 0 : 2;

    private static bool RunCycle(bool testTimer)
    {
        var ok = false;
        var cleaned = true;
        Process? child = null;
        Socket? peer = null;
        LinuxOwnedPidfd? pidfd = null;
        var sealedChild = false;
        try
        {
            var executable = Environment.ProcessPath ?? throw new InvalidOperationException("The Host executable is unavailable.");
            var name = "arcforges-test-" + Guid.NewGuid().ToString("N");
            using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            listener.Bind(new UnixDomainSocketEndPoint("\0" + name));
            listener.Listen(1);
            var start = new ProcessStartInfo(executable)
            {
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            start.ArgumentList.Add("node");
            start.ArgumentList.Add("file-effect-worker");
            start.ArgumentList.Add("--test-mode");
            child = Process.Start(start) ?? throw new InvalidOperationException("The owned worker could not start.");
            var bytes = Encoding.ASCII.GetBytes(name);
            child.StandardInput.BaseStream.WriteByte(checked((byte)bytes.Length));
            child.StandardInput.BaseStream.Write(bytes);
            child.StandardInput.BaseStream.Flush();
            if (!listener.Poll(5_000_000, SelectMode.SelectRead)) throw new TimeoutException("The worker did not connect.");
            peer = listener.Accept();
            if (!LinuxExecutableIdentity.MatchesCurrent(child.Id))
                throw new InvalidOperationException("The connected worker executable changed.");
            pidfd = LinuxOwnedPidfd.OpenPending(peer, child);
            using var challenge = new LinuxPeerChallenge();
            _ = pidfd.AuthenticateAndSeal(peer, challenge);
            sealedChild = true;
            peer.SendTimeout = 5000;
            peer.ReceiveTimeout = 5000;
            if (!testTimer)
            {
                if (peer.Send([0x53]) != 1 || !child.WaitForExit(5000) || child.ExitCode != 0)
                    throw new InvalidOperationException("The bootstrap worker did not stop cleanly.");
            }
            else
            {
                var armed = new byte[1];
                if (peer.Send([0x54]) != 1 || peer.Receive(armed) != 1 || armed[0] != 0x41)
                    throw new InvalidOperationException("The worker timer did not arm.");
                pidfd.PauseSealedChildForTests();
                if (!pidfd.ObserveStoppedForTests() || !child.WaitForExit(5000) || child.ExitCode != 137)
                    throw new InvalidOperationException("The stopped worker did not expire through its kernel timer.");
            }
            ok = true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException or
            TimeoutException or SocketException or System.ComponentModel.Win32Exception)
        {
            ok = false;
        }
        finally
        {
            peer?.Dispose();
            if (child is not null)
            {
                try
                {
                    child.StandardInput.Close();
                    if (!child.WaitForExit(5000))
                    {
                        if (sealedChild && pidfd is not null)
                        {
                            pidfd.StopSealedChild();
                            cleaned = child.WaitForExit(5000);
                        }
                        else cleaned = false; // No signal is permitted for an unsealed process descriptor.
                    }
                }
                catch (Exception exception) when (exception is IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                    cleaned = false;
                }
            }
            pidfd?.Dispose();
            child?.Dispose();
        }
        return ok && cleaned;
    }
}
