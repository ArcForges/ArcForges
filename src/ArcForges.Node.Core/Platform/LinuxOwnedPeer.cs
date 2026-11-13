// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// A one-use transport to the exact live child that connected and proved a private random challenge. This alone does not
/// authenticate a worker executable or grant a file effect: the later controller must bind the parent, command, caller,
/// policy, exact object identities, deadline, journal and worker lifecycle before authorizing any effect.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class LinuxPeerChallenge : IDisposable
{
    private readonly byte[] _secret = RandomNumberGenerator.GetBytes(32);
    private LinuxOwnedProcessIdentity? _issuedTo;
    private int _issued;
    private int _consumed;

    internal void DeliverTo(Process child)
    {
        ArgumentNullException.ThrowIfNull(child);
        if (Interlocked.Exchange(ref _issued, 1) != 0) throw new InvalidOperationException("The challenge was already issued.");
        _issuedTo = LinuxOwnedProcessIdentity.CaptureChild(child);
        child.StandardInput.BaseStream.Write(_secret);
        child.StandardInput.BaseStream.Flush();
    }

    internal bool IsAvailableFor(LinuxOwnedProcessIdentity identity) =>
        _issuedTo == identity && Volatile.Read(ref _consumed) == 0;

    internal bool Consume(LinuxOwnedProcessIdentity identity, ReadOnlySpan<byte> supplied)
    {
        if (_issuedTo != identity || Interlocked.Exchange(ref _consumed, 1) != 0) return false;
        try { return CryptographicOperations.FixedTimeEquals(_secret, supplied); }
        finally { CryptographicOperations.ZeroMemory(_secret); }
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(_secret);
}

[SupportedOSPlatform("linux")]
internal sealed partial class LinuxOwnedPeer
{
    private readonly Socket _socket;
    private readonly Process _child;
    private readonly LinuxOwnedProcessIdentity _identity;
    private int _sent;
    private int _received;

    internal LinuxOwnedProcessIdentity ProcessIdentity => _identity;

    private LinuxOwnedPeer(Socket socket, Process child, LinuxOwnedProcessIdentity identity)
    {
        _socket = socket;
        _child = child;
        _identity = identity;
    }

    internal static LinuxOwnedPeer Authenticate(Socket socket, Process child, LinuxPeerChallenge challenge)
    {
        ArgumentNullException.ThrowIfNull(socket);
        ArgumentNullException.ThrowIfNull(child);
        ArgumentNullException.ThrowIfNull(challenge);
        var identity = LinuxOwnedProcessIdentity.CaptureChild(child);
        var peer = LinuxPeerCredentialReader.Read(socket);
        if (peer.ProcessId != identity.ProcessId || peer.UserId != GetEffectiveUserId() || !challenge.IsAvailableFor(identity) ||
            identity.Observe() != LinuxProcessObservation.Alive)
            throw new InvalidOperationException("The connected peer is not the expected live owned child.");

        // The socket is private to this single operation; its native receive timeout bounds incomplete peers.
        socket.ReceiveTimeout = 5000;
        Span<byte> supplied = stackalloc byte[32];
        try
        {
            var offset = 0;
            while (offset < supplied.Length)
            {
                var count = socket.Receive(supplied[offset..]);
                if (count <= 0) throw new IOException("The worker challenge ended early.");
                offset += count;
            }
            if (!challenge.Consume(identity, supplied) || child.HasExited ||
                identity.Observe() != LinuxProcessObservation.Alive)
                throw new InvalidOperationException("The owned peer did not prove its challenge.");
            return new LinuxOwnedPeer(socket, child, identity);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(supplied);
        }
    }

    /// <summary>One transfer only. The receiving child still has no authority to perform a target effect.</summary>
    internal void SendDescriptorsOnce(IReadOnlyList<SafeFileHandle> descriptors)
    {
        if (Interlocked.Exchange(ref _sent, 1) != 0) throw new InvalidOperationException("The peer transfer was already used.");
        var peer = LinuxPeerCredentialReader.Read(_socket);
        if (_child.HasExited || peer.ProcessId != _identity.ProcessId || peer.UserId != GetEffectiveUserId() ||
            _identity.Observe() != LinuxProcessObservation.Alive)
            throw new InvalidOperationException("The original owned peer is no longer available.");
        LinuxDescriptorTransfer.Send(_socket, descriptors);
    }

    /// <summary>Checks the same challenge-sealed child; process exit or identity reuse invalidates the capability.</summary>
    internal void RequireOriginalLivePeer()
    {
        var peer = LinuxPeerCredentialReader.Read(_socket);
        if (_child.HasExited || peer.ProcessId != _identity.ProcessId || peer.UserId != GetEffectiveUserId() ||
            _identity.Observe() != LinuxProcessObservation.Alive)
            throw new InvalidOperationException("The original owned peer is no longer available.");
    }

    /// <summary>Receives one exact returned description, once, while that original child is still live.</summary>
    internal SafeFileHandle ReceiveReturnedDescriptorOnce()
    {
        if (Interlocked.Exchange(ref _received, 1) != 0)
            throw new InvalidOperationException("The peer return was already used.");
        RequireOriginalLivePeer();
        var descriptors = LinuxDescriptorTransfer.Receive(_socket, 1);
        try
        {
            RequireOriginalLivePeer();
            return descriptors[0];
        }
        catch
        {
            descriptors[0].Dispose();
            throw;
        }
    }

    [LibraryImport("libc", EntryPoint = "geteuid")]
    private static partial uint GetEffectiveUserId();
}
