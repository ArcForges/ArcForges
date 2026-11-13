// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// Bootstrap for a Linux file-effect worker. Only the authenticated Node parent can give this one-use process
/// its journal-bound operation and exact descriptors; a same-executable identity alone is not operation authority.
/// </summary>
[SupportedOSPlatform("linux")]
public static unsafe partial class LinuxFileEffectWorker
{
    /// <summary>Authenticates the parent and private socket before accepting any one-use worker protocol.</summary>
    public static int Run(bool testMode)
    {
        var parent = GetParentId();
        if (parent <= 1 || !LinuxExecutableIdentity.MatchesCurrent(parent)) return 2;
        // The controller must spawn from a dedicated thread that stays alive through the handshake and worker lifetime.
        // Check after setting the signal too: a parent that died before prctl would otherwise never send it.
        if (Prctl(1, 9, 0, 0, 0) != 0 || GetParentId() != parent) return 2;
        var installed = 0;
        if (Prctl(2, (nuint)(&installed), 0, 0, 0) != 0 || installed != 9) return 2;
        var challenge = new byte[32];
        try
        {
            using var input = Console.OpenStandardInput();
            var size = input.ReadByte();
            if (size is < 1 or > 90) return 2;
            var nameBytes = new byte[size];
            input.ReadExactly(nameBytes);
            if (nameBytes.Any(value => value is not (>= (byte)'a' and <= (byte)'z') and not (>= (byte)'0' and <= (byte)'9') and not (byte)'-'))
                return 2;
            if (GetParentId() != parent || !LinuxExecutableIdentity.MatchesCurrent(parent)) return 2;
            using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            socket.SendTimeout = 5000;
            socket.Connect(new UnixDomainSocketEndPoint("\0" + Encoding.ASCII.GetString(nameBytes)));
            var peer = LinuxPeerCredentialReader.Read(socket);
            if (peer.ProcessId != parent || peer.UserId != GetEffectiveUserId() || GetParentId() != parent ||
                !LinuxExecutableIdentity.MatchesCurrent(parent))
                return 2;
            // The parent opens its pending pidfd before sending this one-use challenge.
            input.ReadExactly(challenge);
            var sent = 0;
            while (sent < challenge.Length)
            {
                var count = socket.Send(challenge.AsSpan(sent));
                if (count <= 0) return 2;
                sent += count;
            }
            // These bootstrap-only test messages carry no descriptors, write command or target effect.
            socket.ReceiveTimeout = 5000;
            Span<byte> command = stackalloc byte[1];
            if (socket.Receive(command) != 1) return 2;
            if (command[0] == 0x53) return 0;
            if (command[0] == 0x57) return LinuxFileEffectExecutor.Execute(socket);
            if (command[0] == 0x43) return LinuxFileEffectExecutor.ExecuteCreation(socket);
            if (!testMode || command[0] != 0x54) return 2;
            using var timer = LinuxFatalDeadline.ArmAbsolute(checked(LinuxFatalDeadline.MonotonicNanoseconds() + 1_500_000_000));
            if (socket.Send([0x41]) != 1) return 2;
            _ = socket.Receive(command); // The owned child is stopped; its kernel timer must end it.
            return 2;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SocketException or
            InvalidOperationException or ArgumentException or NotSupportedException)
        {
            return 2;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
        }
    }

    [LibraryImport("libc", EntryPoint = "getppid")]
    private static partial int GetParentId();

    [LibraryImport("libc", EntryPoint = "geteuid")]
    private static partial uint GetEffectiveUserId();

    [LibraryImport("libc", EntryPoint = "prctl", SetLastError = true)]
    private static partial int Prctl(int option, nuint argument2, nuint argument3, nuint argument4, nuint argument5);
}
