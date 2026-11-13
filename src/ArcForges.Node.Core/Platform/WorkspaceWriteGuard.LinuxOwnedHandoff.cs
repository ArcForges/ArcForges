// SPDX-License-Identifier: AGPL-3.0-only
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspaceWriteGuard
{
    /// <summary>
    /// Adopts the same open description returned by the original authenticated live child. Its existing write lease
    /// stays installed: changing notification ownership never releases or regrants it. The operation's original
    /// native deadline remains in force. The coordinator still binds the exact intent, names, result and settlement.
    /// </summary>
    internal static WorkspaceWriteGuard AdoptLinuxReturnedFile(SafeFileHandle file, LinuxOwnedPeer peer,
        WorkspaceObjectIdentity expectedIdentity, long deadlineNanoseconds, bool privateStage = false,
        Action<SafeFileHandle>? verifyPrivateSecurity = null)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(peer);
        if (!OperatingSystem.IsLinux() || deadlineNanoseconds <= LinuxFatalDeadline.MonotonicNanoseconds() ||
            privateStage && verifyPrivateSecurity is null)
            throw new WorkspacePathException("file_guard_unavailable");
        peer.RequireOriginalLivePeer();
        var expectedWorker = peer.ProcessIdentity;
        var identity = WorkspacePath.Identity(file);
        if (!identity.IsFile || identity.Links != 1 || !expectedIdentity.SameObject(identity) ||
            privateStage && (identity.Mode & 0x3f) != 0)
            throw new WorkspacePathException("file_identity_changed");
        verifyPrivateSecurity?.Invoke(file);
        WorkspacePath.RequireLinuxLeaseBreakTime();
        var descriptor = checked((int)file.DangerousGetHandle());
        if (LinuxLeaseNative.Control(descriptor, 9, 0) != expectedWorker.ProcessId ||
            LinuxLeaseNative.Control(descriptor, 11, 0) != 9 ||
            LinuxLeaseNative.Control(descriptor, 1025, 0) != 1)
            throw new WorkspacePathException("file_guard_breaking");

        // The child's SIGIO disposition is fatal. Downgrade SIGKILL while it still owns notifications: a break
        // in this interval can end only that child, never the node. Only then redirect SIGIO to our blocked TID.
        if (LinuxLeaseNative.Control(descriptor, 10, 29) < 0 ||
            LinuxLeaseNative.Control(descriptor, 11, 0) != 29)
            throw new WorkspacePathException("file_guard_unavailable");
        var owner = new LinuxLeaseNative.Owner { Type = 0, ProcessId = LinuxLeaseNotifications.Owner };
        if (LinuxLeaseNative.SetOwner(descriptor, 15, ref owner) < 0 ||
            LinuxLeaseNative.GetOwner(descriptor, 16, out var actualOwner) < 0 ||
            actualOwner.Type != owner.Type || actualOwner.ProcessId != owner.ProcessId ||
            LinuxLeaseNative.Control(descriptor, 11, 0) != 29 ||
            LinuxLeaseNative.Control(descriptor, 1025, 0) != 1)
            throw new WorkspacePathException("file_guard_breaking");
        peer.RequireOriginalLivePeer();
        if (LinuxFatalDeadline.MonotonicNanoseconds() >= deadlineNanoseconds)
            throw new WorkspacePathException("file_guard_expired");

        var guard = new WorkspaceWriteGuard(file, identity, linux: true, privateStage, expectedLinks: 1,
            verifyPrivateSecurity, deadlineNanoseconds);
        try
        {
            LinuxLeaseNotifications.Register(guard);
            guard.CheckIntact();
            return guard;
        }
        catch
        {
            guard.Dispose();
            throw;
        }
    }
}
