// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
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
    /// <summary>The profile family of the operating system this process runs on, or macOS/unsupported values the launch frame never matches.</summary>
    internal static ContentSandboxProfileKind ThisPlatform =>
        OperatingSystem.IsWindows() ? ContentSandboxProfileKind.WindowsAppContainerJob
        : OperatingSystem.IsLinux() ? ContentSandboxProfileKind.LinuxLandlockSeccomp
        : ContentSandboxProfileKind.MacOsAppSandboxXpc;

    /// <summary>Applies and verifies the profile; false means the helper must not run a parser.</summary>
    [SuppressMessage("Design", "CA1031", Justification = "Any failure of enforcement or verification is a refusal to run.")]
    internal static bool TryApplyAndVerify(ContentSandboxLaunchFrame frame, LocalRpcProcessIdentity parent)
    {
        ArgumentNullException.ThrowIfNull(frame);
        try
        {
            if (OperatingSystem.IsWindows())
            {
                return WindowsProbes.AllDenied(parent);
            }

            if (OperatingSystem.IsLinux())
            {
                return LinuxEnforcement.ApplyAndVerify(frame);
            }

            return false;
        }
        catch (Exception exception) when (exception is InvalidOperationException or PlatformNotSupportedException or IOException
            or UnauthorizedAccessException or SocketException or System.ComponentModel.Win32Exception or DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
    }

    /// <summary>
    /// The Windows self-check. Each attempt must be denied by the operating system: a connection to the loopback address, a handle on the
    /// parent process, and a listing of the user profile. They are attempts to use an ambient authority, not proof of the whole profile.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static class WindowsProbes
    {
        internal static bool AllDenied(LocalRpcProcessIdentity parent) => NetworkDenied() && ParentProcessDenied(parent) && UserProfileDenied();

        private static bool NetworkDenied()
        {
            try
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                socket.Connect(new IPEndPoint(IPAddress.Loopback, 9));
                return false;
            }
            catch (SocketException exception)
            {
                return exception.SocketErrorCode == SocketError.AccessDenied;
            }
        }

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
