// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// Linux SCM_RIGHTS transport for exact open descriptions. This primitive grants no authorization, does not create
/// a helper, and does not establish a lease or permit an effect. Callers must authenticate the peer, bind the exact
/// objects and operation, and manage both processes' descriptor lifetimes separately.
/// </summary>
[SupportedOSPlatform("linux")]
internal static unsafe partial class LinuxDescriptorTransfer
{
    private const int MaximumDescriptors = 4;
    private const int SocketLevel = 1;
    private const int Rights = 1;
    private const int NoSignal = 0x4000;
    private const int CloseOnExec = 0x40000000;
    private const byte Marker = 0xa6;

    internal static void Send(Socket socket, IReadOnlyList<SafeFileHandle> descriptors)
    {
        ArgumentNullException.ThrowIfNull(socket);
        ArgumentNullException.ThrowIfNull(descriptors);
        var held = descriptors.ToArray();
        if (socket.AddressFamily != AddressFamily.Unix || held.Length is < 1 or > MaximumDescriptors)
            throw new ArgumentException("Expected a Unix socket and one to four descriptors.");
        var socketReference = false;
        Span<bool> references = stackalloc bool[MaximumDescriptors];
        references.Clear();
        try
        {
            socket.SafeHandle.DangerousAddRef(ref socketReference);
            var payload = Marker;
            var vector = new Vector { Base = &payload, Length = 1 };
            byte* control = stackalloc byte[ControlSpace(MaximumDescriptors)];
            new Span<byte>(control, ControlSpace(MaximumDescriptors)).Clear();
            var header = (ControlHeader*)control;
            header->Length = (nuint)(sizeof(ControlHeader) + held.Length * sizeof(int));
            header->Level = SocketLevel;
            header->Type = Rights;
            var values = (int*)(control + sizeof(ControlHeader));
            for (var index = 0; index < held.Length; index++)
            {
                var descriptor = held[index] ?? throw new ArgumentException("A descriptor was null.", nameof(descriptors));
                descriptor.DangerousAddRef(ref references[index]);
                values[index] = checked((int)descriptor.DangerousGetHandle());
                if (values[index] < 0) throw new ArgumentException("A descriptor was invalid.", nameof(descriptors));
            }
            var message = new Message
            {
                Vector = &vector,
                VectorCount = 1,
                Control = control,
                ControlLength = (nuint)ControlSpace(held.Length),
            };
            if (SendMessage(checked((int)socket.SafeHandle.DangerousGetHandle()), &message, NoSignal) != 1)
                throw new IOException("The descriptor transfer did not complete.", new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
        }
        finally
        {
            for (var index = 0; index < held.Length; index++)
                if (references[index]) held[index].DangerousRelease();
            if (socketReference) socket.SafeHandle.DangerousRelease();
        }
    }

    internal static SafeFileHandle[] Receive(Socket socket, int expectedCount)
    {
        ArgumentNullException.ThrowIfNull(socket);
        if (socket.AddressFamily != AddressFamily.Unix || expectedCount is < 1 or > MaximumDescriptors)
            throw new ArgumentException("Expected a Unix socket and one to four descriptors.");
        var socketReference = false;
        var received = new List<SafeFileHandle>(MaximumDescriptors);
        try
        {
            socket.SafeHandle.DangerousAddRef(ref socketReference);
            byte payload = 0;
            var vector = new Vector { Base = &payload, Length = 1 };
            byte* control = stackalloc byte[ControlSpace(MaximumDescriptors)];
            new Span<byte>(control, ControlSpace(MaximumDescriptors)).Clear();
            var message = new Message
            {
                Vector = &vector,
                VectorCount = 1,
                Control = control,
                ControlLength = (nuint)ControlSpace(MaximumDescriptors),
            };
            var count = ReceiveMessage(checked((int)socket.SafeHandle.DangerousGetHandle()), &message, CloseOnExec);
            if (count < 0)
                throw new IOException("The descriptor transfer failed.", new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
            var remaining = checked((int)message.ControlLength);
            if (remaining > ControlSpace(MaximumDescriptors)) throw new InvalidDataException("Invalid descriptor control length.");
            var offset = 0;
            var invalid = false;
            while (remaining >= sizeof(ControlHeader))
            {
                var header = (ControlHeader*)(control + offset);
                var length = checked((int)header->Length);
                if (length < sizeof(ControlHeader) || length > remaining)
                {
                    invalid = true;
                    break;
                }
                if (header->Level == SocketLevel && header->Type == Rights)
                {
                    var values = (int*)(control + offset + sizeof(ControlHeader));
                    var actual = (length - sizeof(ControlHeader)) / sizeof(int);
                    invalid |= (length - sizeof(ControlHeader)) % sizeof(int) != 0;
                    for (var index = 0; index < actual; index++)
                    {
                        if (values[index] < 0) invalid = true;
                        else received.Add(new SafeFileHandle((IntPtr)values[index], ownsHandle: true));
                    }
                }
                else invalid = true;
                var consumed = Align(length);
                if (consumed > remaining) break;
                offset += consumed;
                remaining -= consumed;
            }
            if (count != 1 || payload != Marker || invalid || (message.Flags & ~CloseOnExec) != 0 || received.Count != expectedCount)
                throw new InvalidDataException("The descriptor transfer was incomplete.");
            return [.. received];
        }
        catch
        {
            foreach (var descriptor in received) descriptor.Dispose();
            throw;
        }
        finally
        {
            if (socketReference) socket.SafeHandle.DangerousRelease();
        }
    }

    private static int Align(int length) => (length + sizeof(long) - 1) & ~(sizeof(long) - 1);

    private static int ControlSpace(int descriptors) => sizeof(ControlHeader) + Align(descriptors * sizeof(int));

    [StructLayout(LayoutKind.Sequential)]
    private struct Vector
    {
        internal void* Base;
        internal nuint Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Message
    {
        internal void* Name;
        internal uint NameLength;
        internal Vector* Vector;
        internal nuint VectorCount;
        internal void* Control;
        internal nuint ControlLength;
        internal int Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ControlHeader
    {
        internal nuint Length;
        internal int Level;
        internal int Type;
    }

    [LibraryImport("libc", EntryPoint = "sendmsg", SetLastError = true)]
    private static partial nint SendMessage(int socket, Message* message, int flags);

    [LibraryImport("libc", EntryPoint = "recvmsg", SetLastError = true)]
    private static partial nint ReceiveMessage(int socket, Message* message, int flags);
}
