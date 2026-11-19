// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using ArcForges.Node.Platform.Capabilities;
using ArcForges.RunSupervisor.Protocol;

namespace ArcForges.Node.Platform.Linux.Mxc;

[SupportedOSPlatform("linux")]
internal static class LinuxRunMxcAssets
{
    private static readonly string[] s_toolDirectories = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

    internal static void VerifySupervisor(RunLaunchSpec spec) =>
        RequireSupervisorHash(spec, Hash(spec.SupervisorPath, rootOnly: false, executable: true));

    internal static void VerifyRunningSupervisor(RunLaunchSpec spec, int pid, long startTicks)
    {
        // The caller already checked the socket's native UID, PID and executable path.
        // This descriptor identifies the actual image, even if the installed name changes.
        using var image = File.OpenRead("/proc/" + pid.ToString(CultureInfo.InvariantCulture) + "/exe");
        RequireSupervisorHash(spec, Hash(image));
        if (ProcFs.Stat(pid) is not { State: not ('Z' or 'X') } current || current.StartTicks != startTicks)
        {
            throw new RunNativeException("verify_linux_supervisor", "linux_supervisor_image_owner_changed", payloadNotStarted: true);
        }
    }

    private static void RequireSupervisorHash(RunLaunchSpec spec, string observed)
    {
        if (observed != spec.SupervisorSha256)
        {
            throw new RunNativeException("verify_linux_supervisor", "linux_supervisor_image_hash_mismatch", payloadNotStarted: true);
        }
    }

    internal static void Verify(RunLaunchSpec spec)
    {
        if (spec.ProfileId != "linux-bubblewrap-sdk-v1" || spec.ProfileVersion != "linux-bubblewrap-sdk-v1" ||
            Path.GetDirectoryName(spec.SupervisorPath) != spec.InstallationRoot)
        {
            throw new RunNativeException("linux_mxc_profile", "official_bubblewrap_profile_mismatch", payloadNotStarted: true);
        }

        const string nativeMember = "libmxc_ffi.so";
        var nativeHash = Hash(Path.Combine(spec.InstallationRoot, nativeMember), rootOnly: false, executable: false);
        if (!MxcProfileAdmission.MatchesNativeMembers(false, new Dictionary<string, string>(StringComparer.Ordinal)
        { [nativeMember] = nativeHash }))
        {
            throw new RunNativeException("linux_mxc_profile", "pinned_sdk_native_member_mismatch", payloadNotStarted: true);
        }

        string? bubblewrap = null;
        var helpers = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var name in MxcProfileAdmission.LinuxHelperNames())
        {
            var discovered = s_toolDirectories.Select(directory => Path.Combine(directory, name)).FirstOrDefault(File.Exists);
            if (discovered is null)
            {
                continue;
            }

            try
            {
                var canonical = File.ResolveLinkTarget(discovered, returnFinalTarget: true)?.FullName ?? discovered;
                var hash = Hash(canonical, rootOnly: true, executable: true);
                helpers.Add(name, hash);
                if (name == "bwrap")
                {
                    bubblewrap = canonical;
                }
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                // The profile check below determines whether this request requires that helper.
            }
        }

        if (!MxcProfileAdmission.MatchesLinuxBaseHelpers(helpers) || spec.BubblewrapPath != bubblewrap ||
            !helpers.TryGetValue("bwrap", out var observed) || observed != spec.BubblewrapIdentity)
        {
            throw new RunNativeException("linux_mxc_profile", "official_bubblewrap_helper_mismatch", payloadNotStarted: true);
        }

        if (spec.Network.Destinations.Length > 0 && !MxcProfileAdmission.MatchesLinuxNetworkHelpers(helpers))
        {
            throw new RunNativeException("linux_mxc_profile", "official_selected_egress_helper_mismatch", payloadNotStarted: true);
        }
    }

    private static string Hash(string path, bool rootOnly, bool executable)
    {
        using var handle = LinuxRunCgroup.OpenTrustedFile(path, rootOnly, executable);
        using var stream = new FileStream(handle, FileAccess.Read);
        return Hash(stream);
    }

    private static string Hash(Stream stream) => stream.Length is > 0 and <= 128 * 1024 * 1024
        ? Convert.ToHexStringLower(SHA256.HashData(stream)) : throw new IOException("A protected MXC asset exceeds its bound.");
}
