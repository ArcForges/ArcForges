// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// An owned child PID descriptor. It is not permitted to signal until the connected child proves a challenge sent
/// after this descriptor was opened. This transport is not an authorization for a file effect.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed unsafe partial class LinuxOwnedPidfd : IDisposable
{
    private readonly SafeFileHandle _pidfd;
    private readonly Process _child;
    private readonly LinuxOwnedProcessIdentity _identity;
    private int _state; // 0 pending, 1 authenticating, 2 sealed, 3 failed

    private LinuxOwnedPidfd(SafeFileHandle pidfd, Process child, LinuxOwnedProcessIdentity identity)
    {
        _pidfd = pidfd;
        _child = child;
        _identity = identity;
    }

    /// <summary>Opens but does not yet trust or signal a pidfd for the connecting child.</summary>
    internal static LinuxOwnedPidfd OpenPending(Socket peer, Process child)
    {
        ArgumentNullException.ThrowIfNull(peer);
        ArgumentNullException.ThrowIfNull(child);
        var identity = LinuxOwnedProcessIdentity.CaptureChild(child);
        var credentials = LinuxPeerCredentialReader.Read(peer);
        if (credentials.ProcessId != identity.ProcessId || identity.Observe() != LinuxProcessObservation.Alive)
            throw new InvalidOperationException("The peer is not the expected live child.");
        var result = PidfdOpen(434, identity.ProcessId, 0);
        if (result < 0) throw new IOException("The child process descriptor is unavailable.", new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
        var handle = new SafeFileHandle((IntPtr)result, ownsHandle: true);
        try
        {
            var owned = new LinuxOwnedPidfd(handle, child, identity);
            if (!owned.IsRunning()) throw new InvalidOperationException("The child process descriptor is not live.");
            return owned;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    /// <summary>Seals only after the private challenge has been sent to and returned by the same still-live child.</summary>
    internal LinuxOwnedPeer AuthenticateAndSeal(Socket peer, LinuxPeerChallenge challenge)
    {
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
            throw new InvalidOperationException("The child process descriptor was already used.");
        try
        {
            if (!IsRunning() || _child.HasExited || _identity.Observe() != LinuxProcessObservation.Alive)
                throw new InvalidOperationException("The owned child is unavailable.");
            challenge.DeliverTo(_child); // No challenge is sent before the pidfd has been opened.
            var authenticated = LinuxOwnedPeer.Authenticate(peer, _child, challenge);
            if (!IsRunning() || _child.HasExited || _identity.Observe() != LinuxProcessObservation.Alive)
                throw new InvalidOperationException("The owned child ended during authentication.");
            Volatile.Write(ref _state, 2);
            return authenticated;
        }
        catch
        {
            Volatile.Write(ref _state, 3);
            throw;
        }
    }

    /// <summary>Returns the actual authenticated identity only while its sealed pidfd and owned child remain live.</summary>
    internal LinuxOwnedProcessIdentity SealedIdentity()
    {
        if (Volatile.Read(ref _state) != 2 || !IsRunning() || _child.HasExited ||
            _identity.Observe() != LinuxProcessObservation.Alive)
            throw new InvalidOperationException("The sealed worker is unavailable.");
        return _identity;
    }

    /// <summary>Sends SIGKILL only through the sealed kernel process descriptor, never to a PID or process group.</summary>
    internal void StopSealedChild() => SignalSealedChild(9);

    // No-effect test-only coordination; the only target is this sealed pidfd.
    internal void PauseSealedChildForTests() => SignalSealedChild(19);

    internal bool ObserveStoppedForTests()
    {
        if (Volatile.Read(ref _state) != 2) throw new InvalidOperationException("An unverified process descriptor cannot be observed.");
        var retained = false;
        try
        {
            _pidfd.DangerousAddRef(ref retained);
            byte* information = stackalloc byte[128];
            new Span<byte>(information, 128).Clear();
            // P_PIDFD, WSTOPPED|WEXITED|WNOWAIT: preserve the exit for the owned Process waiter.
            return WaitId(3, checked((uint)_pidfd.DangerousGetHandle()), information, 2 | 4 | 0x01000000) == 0 &&
                *(int*)(information + 8) == 5 && *(int*)(information + 16) == _identity.ProcessId &&
                *(int*)(information + 24) == 19; // CLD_STOPPED, SIGSTOP
        }
        finally
        {
            if (retained) _pidfd.DangerousRelease();
        }
    }

    private void SignalSealedChild(int signal)
    {
        if (Volatile.Read(ref _state) != 2) throw new InvalidOperationException("An unverified process descriptor cannot be signalled.");
        var retained = false;
        try
        {
            _pidfd.DangerousAddRef(ref retained);
            if (PidfdSendSignal(424, checked((int)_pidfd.DangerousGetHandle()), signal, 0, 0) < 0 &&
                Marshal.GetLastPInvokeError() != 3)
                throw new IOException("The owned child could not be signalled.", new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
        }
        finally
        {
            if (retained) _pidfd.DangerousRelease();
        }
    }

    private bool IsRunning()
    {
        var retained = false;
        try
        {
            _pidfd.DangerousAddRef(ref retained);
            var poll = new PollDescriptor { FileDescriptor = checked((int)_pidfd.DangerousGetHandle()), Events = 1 };
            return Poll(&poll, 1, 0) == 0;
        }
        finally
        {
            if (retained) _pidfd.DangerousRelease();
        }
    }

    public void Dispose() => _pidfd.Dispose();

    [StructLayout(LayoutKind.Sequential)]
    private struct PollDescriptor
    {
        internal int FileDescriptor;
        internal short Events;
        internal short Revents;
    }

    [LibraryImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static partial nint PidfdOpen(nint number, int pid, uint flags);

    [LibraryImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static partial nint PidfdSendSignal(nint number, int pidfd, int signal, nint info, uint flags);

    [LibraryImport("libc", EntryPoint = "waitid", SetLastError = true)]
    private static partial int WaitId(int kind, uint id, byte* information, int options);

    [LibraryImport("libc", EntryPoint = "poll", SetLastError = true)]
    private static partial int Poll(PollDescriptor* descriptors, nuint count, int milliseconds);
}
