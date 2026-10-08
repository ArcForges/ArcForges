// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.ContentSandbox.Native;
using ArcForges.LocalRpc;

namespace ArcForges.ContentSandbox.Host;

/// <summary>
/// Brings the operating-system profile of the helper into force and checks it before any parser runs. On Windows the parent has already
/// created the process in its AppContainer and Job Object, so the helper only verifies by attempting what the profile must deny. On Linux the
/// helper applies no_new_privs, resource limits, Landlock and seccomp to itself first, then verifies by the same kind of attempt. A check that
/// does not come out as denied is a refusal to run: the helper never falls back to full trust.
/// </summary>
internal static class ProfileEnforcement
{
    /// <summary>
    /// The profile family of the operating system this process runs on. It is null where no restricted profile exists (macOS and every other
    /// operating system), so no launch frame matches it and HelperEntry refuses the frame with the isolation-unavailable exit.
    /// </summary>
    internal static ContentSandboxProfileKind? ThisPlatform =>
        OperatingSystem.IsWindows() ? ContentSandboxProfileKind.WindowsAppContainerJob
        : OperatingSystem.IsLinux() ? ContentSandboxProfileKind.LinuxLandlockSeccomp
        : null;

    /// <summary>Applies and verifies the profile; false means the helper must not run a parser.</summary>
    [SuppressMessage("Design", "CA1031", Justification = "Any failure of enforcement or verification is a refusal to run.")]
    internal static bool TryApplyAndVerify(ContentSandboxLaunchFrame frame, LocalRpcProcessIdentity parent)
    {
        ArgumentNullException.ThrowIfNull(frame);
        try
        {
            if (OperatingSystem.IsWindows())
            {
                var allowed = WindowsProbes.FirstAllowed(parent);
                if (allowed is not null)
                {
                    Console.Error.WriteLine("isolation: " + allowed + " was not denied");
                }

                return allowed is null;
            }

            if (OperatingSystem.IsLinux())
            {
                return LinuxEnforcement.ApplyAndVerify(frame);
            }

            return false;
        }
        catch (Exception exception) when (exception is InvalidOperationException or PlatformNotSupportedException or IOException
            or UnauthorizedAccessException or System.ComponentModel.Win32Exception or DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
    }

    /// <summary>
    /// The Windows self-check. Each attempt must be denied by the operating system: a handle on the parent process and a listing of the user
    /// profile. They are attempts to use an ambient authority, not proof of the whole profile. Network denial is not probed here: a connection
    /// attempt cannot tell a blocked path from a closed port without a listener, so the parent verifies the token (an AppContainer holding no capability)
    /// before it resumes the helper, and the opt-in tests connect to real listeners.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static class WindowsProbes
    {
        /// <summary>Names the first attempt that was not denied, or null when every one was.</summary>
        internal static string? FirstAllowed(LocalRpcProcessIdentity parent) =>
            !ParentProcessDenied(parent) ? "parent-process" : !UserProfileDenied() ? "user-profile" : null;

        private static bool ParentProcessDenied(LocalRpcProcessIdentity parent)
        {
            try
            {
                using var process = Process.GetProcessById(parent.ProcessId);
                _ = process.Handle;
                return false;
            }
            catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException or ArgumentException)
            {
                return true;
            }
        }

        private static bool UserProfileDenied()
        {
            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (string.IsNullOrEmpty(profile))
            {
                return true;
            }

            try
            {
                using var entries = Directory.EnumerateFileSystemEntries(profile).GetEnumerator();
                _ = entries.MoveNext();
                return false;
            }
            catch (Exception exception) when (exception is UnauthorizedAccessException or IOException)
            {
                return true;
            }
        }
    }
}
