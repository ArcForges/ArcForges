// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using ArcForges.Client;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store.Migrations;

namespace ArcForges.Node.Core.Updates;

/// <summary>Observes launchers already in flight after the exact predecessor's normal startup paths have been closed.</summary>
internal static class NodeUpdatePendingPredecessor
{
    private const string LegacyShellCommand = "exec \"$0\" -f \"$@\" </dev/null >/dev/null 2>&1";
    private const int MaxArgumentsBytes = 16 * 1024;

    /// <summary>The caller must own the inactive Node lease and have already parked the verified predecessor.</summary>
    [SupportedOSPlatform("linux")]
    internal static void RequireNoPendingPredecessor(string appRoot, NodeUpdateInstallation previous)
    {
        if (!LinuxOwnedProcessIdentity.HasMatchingProcView() || !CompleteOwnerProcView())
            throw Refused("proc_view_unconfirmed");

        string parked = RequireParked(appRoot, previous);
        var identity = ContractionPaths.NamedRegularIdentity(parked);
        string canonical = NodeUpdateLauncher.Executable(previous.Root);
        string managedPath = NodeUpdateLauncher.Executable(Path.Combine(appRoot, "current"));
        string shell = File.ResolveLinkTarget("/bin/sh", returnFinalTarget: true)?.Name ?? "sh";
        uint user = EffectiveUid("/proc/self/status", out _);
        foreach (string process in Directory.EnumerateDirectories("/proc"))
        {
            if (!int.TryParse(Path.GetFileName(process), NumberStyles.None, CultureInfo.InvariantCulture, out int pid) ||
                pid <= 1 || pid == Environment.ProcessId)
                continue;

            ObserveProcess(process, user, shell, canonical, parked, managedPath);
        }

        if (RequireParked(appRoot, previous) != parked || ContractionPaths.NamedRegularIdentity(parked) != identity)
            throw Refused("installation_changed");
    }

    private static string RequireParked(string appRoot, NodeUpdateInstallation previous)
    {
        if (NodeVersionSelection.ReadIdentity(appRoot) != previous.ArchiveSha256 ||
            !NodeUpdateInstallationCustody.IsParked(appRoot, previous.ArchiveSha256))
            throw Refused("installation_custody_unconfirmed");

        return NodeUpdateLauncher.Executable(NodeUpdateInstallationCustody.ResolvePrevious(appRoot, previous).Root);
    }

    private static void ObserveProcess(string process, uint user, string shell, string canonical, string parked, string managedPath)
    {
        try
        {
            // Filter the kernel's process name before opening any arguments. No unrelated command lines are collected.
            string name = File.ReadAllText(Path.Combine(process, "comm")).TrimEnd('\n');
            if (name != "arcforges" && name != "setsid" && name != shell && name != "sh")
                return;

            string status = Path.Combine(process, "status");
            if (!IsLiveOwner(status, user))
                return;

            string[]? arguments = null;
            if (name != "arcforges")
                arguments = ReadArguments(Path.Combine(process, "cmdline"));

            // The launcher can exec between the comm and argv reads. Inspect the resulting kernel image even if argv changed shape.
            string? image = new FileInfo(Path.Combine(process, "exe")).LinkTarget;
            if (image is null)
            {
                if (IsLiveOwner(status, user))
                    throw Refused("process_image_unconfirmed");
                return;
            }

            if (image.EndsWith(" (deleted)", StringComparison.Ordinal))
                image = image[..^" (deleted)".Length];
            if (image == canonical || image == parked || image == managedPath)
                throw Refused("previous_image_still_loaded");
            if (arguments is not null && IsPredecessorLauncher(image, shell, arguments, canonical, parked, managedPath))
                throw Refused("previous_launcher_still_pending");
            if (arguments is { Length: 0 } && (IsSetsid(image) || IsSystemBinary(image, shell) || IsSystemBinary(image, "sh")) &&
                IsLiveOwner(status, user))
                throw Refused("launcher_observation_unconfirmed");
        }
        catch (FileNotFoundException)
        {
            // procfs removed the process while it was being observed.
        }
        catch (DirectoryNotFoundException)
        {
        }
    }

    internal static bool IsPredecessorLauncher(string image, string shell, string[] args, string canonical, string parked, string managedPath)
    {
        bool TargetsPredecessor(string value) => value == canonical || value == parked || value == managedPath;
        if (IsSetsid(image))
            return args.Length is 5 or 6 && IsSetsid(args[0]) && args[1] == "-f" && TargetsPredecessor(args[2]) &&
                args[3] == "node" && args[4] == "run" && (args.Length == 5 || args[5] == NodeLocations.TestModeOption);

        return (IsSystemBinary(image, shell) || IsSystemBinary(image, "sh")) &&
            args.Length is 7 or 8 && args[0] == "/bin/sh" && args[1] == "-c" && args[2] == LegacyShellCommand &&
            IsSetsid(args[3]) && TargetsPredecessor(args[4]) && args[5] == "node" && args[6] == "run" &&
            (args.Length == 7 || args[7] == NodeLocations.TestModeOption);
    }

    private static bool IsSetsid(string path) => IsSystemBinary(path, "setsid");

    private static bool IsSystemBinary(string path, string name) => path == "/usr/bin/" + name || path == "/bin/" + name;

    private static string[]? ReadArguments(string path)
    {
        using var file = File.OpenRead(path);
        byte[] bytes = new byte[MaxArgumentsBytes + 1];
        int length = file.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
        if (length == 0)
            return [];
        if (length > MaxArgumentsBytes)
            return null; // Too long to be the bounded built-in launcher.
        if (bytes[length - 1] != 0)
            throw Refused("launcher_arguments_unconfirmed");
        return Encoding.UTF8.GetString(bytes, 0, length - 1).Split('\0');
    }

    private static bool IsLiveOwner(string status, uint owner) =>
        EffectiveUid(status, out var state) == owner && state is not ('Z' or 'X' or 'x');

    private static uint EffectiveUid(string path, out char state)
    {
        state = '\0';
        foreach (string line in File.ReadLines(path))
        {
            if (line.StartsWith("State:", StringComparison.Ordinal))
            {
                var value = line.AsSpan("State:".Length).TrimStart();
                if (!value.IsEmpty)
                    state = value[0];
            }
            else if (line.StartsWith("Uid:", StringComparison.Ordinal))
            {
                string[] values = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (state != '\0' && values.Length == 5 &&
                    uint.TryParse(values[2], NumberStyles.None, CultureInfo.InvariantCulture, out uint uid))
                    return uid;
                break;
            }
        }
        throw Refused("process_owner_unconfirmed");
    }

    private static bool CompleteOwnerProcView()
    {
        foreach (string line in File.ReadLines("/proc/self/mountinfo"))
        {
            string[] entries = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (entries.Length < 10 || entries[4] != "/proc")
                continue;
            int separator = Array.IndexOf(entries, "-", 6);
            if (separator < 0 || separator + 3 >= entries.Length || entries[separator + 1] != "proc")
                return false;
            return !entries[separator + 3].Split(',').Any(option => option is "hidepid=4" or "hidepid=ptraceable");
        }
        return false;
    }

    private static IOException Refused(string reason) => new("native_update_linux_pending_predecessor_" + reason);
}
