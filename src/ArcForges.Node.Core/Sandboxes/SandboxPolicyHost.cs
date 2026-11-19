// SPDX-License-Identifier: AGPL-3.0-only

using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform.Capabilities;

namespace ArcForges.Node.Core.Sandboxes;

internal static class SandboxPolicyHost
{
    private const int ManifestBytes = 65_536;
    private const long NativeMemberBytes = 512L * 1024 * 1024;
    private static readonly string[] SystemDirectories = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

    internal static string InstallationRoot => Path.Combine(AppContext.BaseDirectory, "mxc");

    internal static MxcHostFacts? Read(string dataRoot, string installationRoot)
    {
        var windows = OperatingSystem.IsWindows();
        if (!windows && !OperatingSystem.IsLinux())
        {
            return null;
        }

        try
        {
            var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(installationRoot));
            using var installed = WorkspacePath.OpenRoot(root);
            WorkspacePath.CheckMxcTrustedObject(installed.RootHandle);
            for (var parent = Directory.GetParent(root); parent is not null; parent = parent.Parent)
            {
                using var ancestor = WorkspacePath.OpenRoot(parent.FullName);
                WorkspacePath.CheckMxcTrustedObject(ancestor.RootHandle, ancestor: true);
            }

            var control = ControlPathsVerified(dataRoot);
            var flags = MxcPrerequisites.ProtectedInstallation;
            if (control)
            {
                flags |= MxcPrerequisites.PrivateControlPaths;
            }

            using var manifestStream = OpenMember(installed, "mxc-manifest.json", ManifestBytes);
            using var manifest = JsonDocument.Parse(manifestStream);
            var metadata = manifest.RootElement;
            var manifestMembers = metadata.GetProperty("files").EnumerateArray()
                .ToDictionary(entry => String(entry, "path"), entry => String(entry, "sha256"), StringComparer.Ordinal);
            var nativeHashes = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var name in MxcProfileAdmission.NativeMemberNames(windows))
            {
                var hash = HashInstalledMember(installed, name);
                if (!manifestMembers.TryGetValue(name, out var expected) || !StringComparer.Ordinal.Equals(expected, hash))
                {
                    flags &= ~MxcPrerequisites.ProtectedInstallation;
                }

                nativeHashes.Add(name, hash);
            }

            var rid = RuntimeInformation.RuntimeIdentifier;
            if (!string.Equals(String(metadata, "rid"), rid, StringComparison.Ordinal)
                || !MxcProfileAdmission.MatchesNativeMembers(windows, nativeHashes))
            {
                flags &= ~MxcPrerequisites.ProtectedInstallation;
            }

            var version = String(metadata, "version");
            var schema = String(metadata, "schema");
            var source = String(metadata, "source");
            var package = String(metadata, "packageSha256");
            var release = String(metadata, "releaseSha256");
            if (OperatingSystem.IsWindows())
            {
                if ((flags & MxcPrerequisites.ProtectedInstallation) != 0)
                {
                    flags |= SandboxPolicyWindows.Discover(installed.RootPath);
                }

                return new MxcHostFacts(rid, Environment.OSVersion.Version.ToString(4), null, null, version, schema, source,
                    package, release, "process-container/base-container", nativeHashes, flags);
            }

            if (OperatingSystem.IsLinux())
            {
                var (linuxFlags, systemd, helperHashes) = ReadLinuxPrerequisites();
                return new MxcHostFacts(rid, LinuxOsIdentity(), ReadOne("/proc/sys/kernel/osrelease"),
                    ReadOne("/proc/sys/kernel/version"), version, schema, source, package, release, "bubblewrap",
                    nativeHashes, flags | linuxFlags, systemd, helperHashes);
            }

            return null;
        }
        catch (Exception error) when (IsDiscoveryFailure(error))
        {
            return null;
        }
    }

    internal static bool IsDiscoveryFailure(Exception error) => error is IOException or InvalidDataException or UnauthorizedAccessException
        or JsonException or KeyNotFoundException or FormatException or InvalidOperationException or ArgumentException
        or Win32Exception or OperationCanceledException;

    private static bool ControlPathsVerified(string dataRoot)
    {
        try
        {
            new SandboxPrivateRoots(dataRoot).ValidateControlPaths();
            return true;
        }
        catch (Exception error) when (IsDiscoveryFailure(error))
        {
            return false;
        }
    }

    private static string HashInstalledMember(WorkspacePath installed, string name)
    {
        // WorkspacePath owns this bound read handle through the native discovery probes. On Windows
        // that also denies a concurrent writer/deleter while the executor image may be opened.
        var handle = installed.OpenRead(name);
        WorkspacePath.CheckMxcTrustedObject(handle);
        var before = WorkspacePath.FileStamp(handle);
        if (before.Size is <= 0 or > NativeMemberBytes)
        {
            throw new InvalidDataException("Invalid protected MXC member size.");
        }

        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[65_536];
        long offset = 0;
        while (offset < before.Size)
        {
            var count = RandomAccess.Read(handle, buffer.AsSpan(0, (int)Math.Min(before.Size - offset, buffer.Length)), offset);
            if (count == 0)
            {
                throw new InvalidDataException("Installed MXC member changed while reading.");
            }

            digest.AppendData(buffer.AsSpan(0, count));
            offset += count;
        }

        if (WorkspacePath.FileStamp(handle) != before)
        {
            throw new InvalidDataException("Installed MXC member changed while reading.");
        }

        return Convert.ToHexStringLower(digest.GetHashAndReset());
    }

    private static FileStream OpenMember(WorkspacePath installed, string name, long maxBytes)
    {
        var handle = installed.OpenRead(name);
        WorkspacePath.CheckMxcTrustedObject(handle);
        var stream = new FileStream(handle, FileAccess.Read);
        if (stream.Length is <= 0 || stream.Length > maxBytes)
        {
            stream.Dispose();
            throw new InvalidDataException("Invalid protected MXC member size.");
        }

        return stream;
    }

    private static string String(JsonElement parent, string property) =>
        parent.GetProperty(property).GetString() ?? throw new InvalidDataException("Invalid MXC manifest.");

    private static string LinuxOsIdentity()
    {
        var fields = File.ReadLines("/etc/os-release")
            .Select(line => line.Split('=', 2))
            .Where(parts => parts.Length == 2 && parts[0] is "ID" or "VERSION_ID")
            .ToDictionary(parts => parts[0], parts => parts[1].Trim('"'), StringComparer.Ordinal);
        return fields["ID"] + "/" + fields["VERSION_ID"];
    }

    private static string ReadOne(string path) => File.ReadAllText(path).Trim();

    [SupportedOSPlatform("linux")]
    private static (MxcPrerequisites Flags, string? Systemd, IReadOnlyDictionary<string, string> Helpers) ReadLinuxPrerequisites()
    {
        var hashes = new Dictionary<string, string>(StringComparer.Ordinal);
        var paths = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var name in MxcProfileAdmission.LinuxHelperNames())
        {
            var first = SystemDirectories.Select(parent => Path.Combine(parent, name)).FirstOrDefault(File.Exists);
            if (first is null)
            {
                continue;
            }

            // Distribution aliases (e.g. /usr/sbin/iptables via /etc/alternatives) are resolved before
            // hashing the final immutable system-owned file. No helper is discovered on a caller PATH.
            try
            {
                var final = File.ResolveLinkTarget(first, returnFinalTarget: true)?.FullName ?? first;
                using var directory = WorkspacePath.OpenRoot(Path.GetDirectoryName(final)!);
                WorkspacePath.CheckMxcTrustedObject(directory.RootHandle, systemOnly: true);
                using var handle = directory.OpenRead(Path.GetFileName(final));
                WorkspacePath.CheckMxcTrustedObject(handle, systemOnly: true);
                using var stream = new FileStream(handle, FileAccess.Read);
                if (stream.Length is > 0 and <= NativeMemberBytes)
                {
                    hashes.Add(name, Convert.ToHexStringLower(SHA256.HashData(stream)));
                    paths.Add(name, final);
                }
            }
            catch (Exception error) when (IsDiscoveryFailure(error))
            {
                // One missing helper affects only requests depending on that helper.
            }
        }

        var flags = MxcPrerequisites.None;
        if (MxcProfileAdmission.MatchesLinuxBaseHelpers(hashes))
        {
            flags |= MxcPrerequisites.LinuxBubblewrap;
            // The probe runs only a fixed system utility under the pinned official backend. Its
            // namespace setup exercises host policy without running any submitted executable.
            if (Run(paths["bwrap"], "/", ["--unshare-all", "--ro-bind", "/usr", "/usr", "--symlink",
                    "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--", "/usr/bin/true"], null) is not null)
            {
                flags |= MxcPrerequisites.LinuxNamespaces;
            }
        }

        if (MxcProfileAdmission.MatchesLinuxNetworkHelpers(hashes))
        {
            flags |= MxcPrerequisites.LinuxSelectedNetworkHelpers;
        }

        if (SandboxPolicyLinux.ProbePty())
        {
            flags |= MxcPrerequisites.LinuxPty;
        }

        var userRun = "/run/user/" + WorkspacePath.MxcEffectiveUserId().ToString(CultureInfo.InvariantCulture);
        string? systemd = null;
        if (File.Exists(userRun + "/bus") && Run("/usr/bin/systemctl", "/", ["--user", "show", "--property=Version",
                "--property=ControlGroup"], new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + userRun + "/bus",
                    ["XDG_RUNTIME_DIR"] = userRun,
                }) is { } manager)
        {
            var properties = manager.Split('\n')
                .Select(line => line.TrimEnd('\r').Split('=', 2))
                .Where(parts => parts.Length == 2)
                .ToDictionary(parts => parts[0], parts => parts[1], StringComparer.Ordinal);
            if (properties.TryGetValue("Version", out systemd) && !string.IsNullOrWhiteSpace(systemd))
            {
                flags |= MxcPrerequisites.LinuxUserManager;
            }

            if (properties.TryGetValue("ControlGroup", out var group)
                && group.Length > 1 && group[0] == '/'
                && !group.Split('/').Skip(1).Any(part => part is "" or "." or "..")
                && File.Exists("/sys/fs/cgroup/cgroup.controllers"))
            {
                var scope = "/sys/fs/cgroup" + group;
                flags |= MxcPrerequisites.LinuxCgroupV2;
                var controllers = ReadControllers(scope + "/cgroup.controllers");
                controllers.IntersectWith(ReadControllers(scope + "/cgroup.subtree_control"));
                if (controllers.Contains("cpu")) flags |= MxcPrerequisites.LinuxCpuController;
                if (controllers.Contains("memory")) flags |= MxcPrerequisites.LinuxMemoryController;
                if (controllers.Contains("pids")) flags |= MxcPrerequisites.LinuxPidsController;
            }
        }

        return (flags, systemd, hashes);
    }

    private static HashSet<string> ReadControllers(string path) => new(
        File.Exists(path) ? ReadOne(path).Split(' ', StringSplitOptions.RemoveEmptyEntries) : [], StringComparer.Ordinal);

    // Only fixed absolute executables and fixed discovery arguments reach this method.
    internal static string? Run(string executable, string workingDirectory, IReadOnlyList<string> arguments,
        IReadOnlyDictionary<string, string>? environment)
    {
        var start = new ProcessStartInfo(executable)
        {
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        start.Environment.Clear();
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        if (environment is not null)
        {
            foreach (var (key, value) in environment)
            {
                start.Environment.Add(key, value);
            }
        }

        try
        {
            using var process = Process.Start(start);
            if (process is null)
            {
                return null;
            }

            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            try
            {
                var output = ReadOutput(process.StandardOutput, deadline.Token);
                var error = ReadOutput(process.StandardError, deadline.Token);
                Task.WhenAll(output, error, process.WaitForExitAsync(deadline.Token)).GetAwaiter().GetResult();
                return process.ExitCode == 0 ? output.Result : null;
            }
            finally
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    _ = process.WaitForExit(2_000);
                }
            }
        }
        catch (Exception error) when (IsDiscoveryFailure(error))
        {
            return null;
        }
    }

    private static async Task<string> ReadOutput(StreamReader reader, CancellationToken cancellationToken)
    {
        var buffer = new char[4096];
        var text = new System.Text.StringBuilder();
        int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (text.Length + count > ManifestBytes)
            {
                throw new InvalidDataException("MXC host probe output exceeds the bound.");
            }

            text.Append(buffer, 0, count);
        }

        return text.ToString();
    }
}
