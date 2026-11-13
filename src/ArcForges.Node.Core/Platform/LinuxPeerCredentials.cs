// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ArcForges.Node.Core.Platform;

/// <summary>The kernel credentials captured for a connected Unix socket, not a claimed process ID.</summary>
internal readonly record struct LinuxPeerCredentials(int ProcessId, uint UserId, uint GroupId);

/// <summary>Observes SO_PEERCRED only; it does not by itself authorize the peer or a file operation.</summary>
[SupportedOSPlatform("linux")]
internal static unsafe partial class LinuxPeerCredentialReader
{
    internal static LinuxPeerCredentials Read(Socket socket)
    {
        ArgumentNullException.ThrowIfNull(socket);
        if (socket.AddressFamily != AddressFamily.Unix) throw new ArgumentException("A Unix socket is required.", nameof(socket));
        var retained = false;
        try
        {
            socket.SafeHandle.DangerousAddRef(ref retained);
            var credentials = new Credentials();
            uint length = (uint)sizeof(Credentials);
            if (GetSocketOption(checked((int)socket.SafeHandle.DangerousGetHandle()), 1, 17, &credentials, &length) != 0 ||
                length != sizeof(Credentials) || credentials.ProcessId <= 0)
                throw new IOException("The native peer credentials are unavailable.", new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
            return new LinuxPeerCredentials(credentials.ProcessId, credentials.UserId, credentials.GroupId);
        }
        finally
        {
            if (retained) socket.SafeHandle.DangerousRelease();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Credentials
    {
        internal int ProcessId;
        internal uint UserId;
        internal uint GroupId;
    }

    [LibraryImport("libc", EntryPoint = "getsockopt", SetLastError = true)]
    private static partial int GetSocketOption(int socket, int level, int option, Credentials* value, uint* length);
}
