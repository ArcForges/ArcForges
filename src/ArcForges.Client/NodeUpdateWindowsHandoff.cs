// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;

namespace ArcForges.Client;

/// <summary>Preserves and temporarily unnames a drained, verified legacy Windows installation.</summary>
public static class NodeUpdateWindowsHandoff
{
    private const string LockName = ".windows-update-install.lock";

    /// <summary>Reports whether the exact verified version has been parked by the offline updater.</summary>
    public static bool IsParked(string appRoot, string archiveSha256)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        var canonical = NodeVersionSelection.InstallationDirectory(appRoot, archiveSha256);
        var parked = NodeVersionSelection.WindowsParkedDirectory(canonical);
        if (NodeVersionSelection.Attributes(canonical) is not null || NodeVersionSelection.Attributes(parked) is null)
        {
            return false;
        }

        NodeVersionSelection.RequireDirectory(parked, create: false);
        return true;
    }

    /// <summary>Finds the one physical location of a recorded previous installation.</summary>
    public static NodeUpdateInstallation ResolvePrevious(string appRoot, NodeUpdateInstallation previous)
    {
        if (!OperatingSystem.IsWindows())
        {
            return previous;
        }

        var canonical = RequireCanonical(appRoot, previous);
        var parked = NodeVersionSelection.WindowsParkedDirectory(canonical);
        var canonicalExists = NodeVersionSelection.Attributes(canonical) is not null;
        var parkedExists = NodeVersionSelection.Attributes(parked) is not null;
        if (canonicalExists == parkedExists)
        {
            throw new IOException("node_update_windows_previous_installation_custody_ambiguous");
        }

        var actual = canonicalExists ? canonical : parked;
        NodeVersionSelection.RequireDirectory(actual, create: false);
        return previous with { Root = actual };
    }

    /// <summary>Moves a verified previous cohort after the caller has recorded intent and owns the inactive Node lease.</summary>
    public static void Park(string appRoot, NodeUpdateInstallation previous, bool testMode) => Move(appRoot, previous, testMode, park: true);

    /// <summary>Restores the exact previous path while the caller owns the inactive Node lease.</summary>
    public static void Restore(string appRoot, NodeUpdateInstallation previous, bool testMode) => Move(appRoot, previous, testMode, park: false);

    internal static IDisposable? EnterStaging(string destination)
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        var parent = Path.GetDirectoryName(destination)!;
        if (!string.Equals(Path.GetFileName(parent), "versions", StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("node_update_windows_managed_installation_required");
        }

        var lease = Acquire(parent);
        try
        {
            if (NodeVersionSelection.Attributes(NodeVersionSelection.WindowsParkedDirectory(destination)) is not null)
            {
                throw new IOException("node_update_windows_previous_installation_parked_use_resume_or_rollback");
            }

            return lease;
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    private static void Move(string appRoot, NodeUpdateInstallation previous, bool testMode, bool park)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("node_update_windows_previous_installation_required");
        }

        if (testMode && NodeLocations.EndpointOverride(testMode) is null)
        {
            throw new IOException("node_update_windows_handoff_test_endpoint_required");
        }

        var canonical = RequireCanonical(appRoot, previous);
        using var exclusion = Acquire(Path.GetDirectoryName(canonical)!);
        var target = park ? NodeVersionSelection.WindowsParkedDirectory(canonical) : canonical;
        var source = ResolvePrevious(appRoot, previous);
        NodeUpdateLauncher.RequireTrustedManifest(source);
        RequireExecutable(NodeUpdateLauncher.Executable(source.Root));
        RequireExecutable(Path.Combine(source.Root, NodeAutoStart.SupervisorFileName));
        if (string.Equals(source.Root, target, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        using var holder = new Mutex(initiallyOwned: false, NodeLocations.WindowsSupervisorMutexName(NodeLocations.InstanceKey(testMode)));
        if (!WaitForHolder(holder))
        {
            throw new IOException("node_update_windows_previous_holder_still_live");
        }

        try
        {
            const uint WriteThrough = 8;
            for (int attempt = 0; ; attempt++)
            {
                if (NodeVersionSelection.MoveFileEx(source.Root, target, WriteThrough))
                {
                    return;
                }

                int error = Marshal.GetLastPInvokeError();
                if (attempt == 10 || error is not (5 or 32 or 33))
                {
                    throw new IOException("node_update_windows_previous_installation_move_refused:" + error);
                }

                Thread.Sleep(100);
            }
        }
        finally
        {
            holder.ReleaseMutex();
        }
    }

    private static bool WaitForHolder(Mutex holder)
    {
        try
        {
            return holder.WaitOne(TimeSpan.FromSeconds(10));
        }
        catch (AbandonedMutexException)
        {
            return true;
        }
    }

    private static FileStream Acquire(string parent)
    {
        NodeVersionSelection.RequireDirectory(parent, create: false);
        var path = Path.Combine(parent, LockName);
        if (NodeVersionSelection.Attributes(path) is { } attributes && (attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new IOException("node_update_windows_installation_lock_untrusted");
        }

        return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }

    private static string RequireCanonical(string appRoot, NodeUpdateInstallation previous)
    {
        var canonical = NodeVersionSelection.InstallationDirectory(appRoot, previous.ArchiveSha256);
        if (!string.Equals(canonical, previous.Root, StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("node_update_windows_previous_installation_not_canonical");
        }

        return canonical;
    }

    private static void RequireExecutable(string path)
    {
        if ((File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new IOException("node_update_windows_previous_executable_untrusted");
        }
    }
}
