// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace ArcForges.Supervisor;

/// <summary>
/// The logon autostart of the supervisor (13 section 3.1; AD-0003 section 1): the value
/// <c>HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ArcForgesNode</c> = <c>"&lt;...&gt;\arcforges-supervisor.exe"</c>. The installer
/// (AF-DIST-01) registers it on the user's profile; tests use a key path of their own (the setup program's
/// <c>--test-registry-key</c>), so the user's real Run key is never touched.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class AutostartRegistration
{
    /// <summary>The Run key under HKEY_CURRENT_USER.</summary>
    public const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";

    /// <summary>The value name.</summary>
    public const string ValueName = "ArcForgesNode";

    /// <summary>The value data: the quoted supervisor path, as Explorer runs it at logon.</summary>
    public static string Command(string supervisorPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(supervisorPath);
        if (!Path.IsPathFullyQualified(supervisorPath))
        {
            throw new ArgumentException("The supervisor path must be absolute.", nameof(supervisorPath));
        }

        return "\"" + supervisorPath + "\"";
    }

    /// <summary>Writes the autostart value (REG_SZ) under <c>HKCU\&lt;keyPath&gt;</c>.</summary>
    public static void Register(string supervisorPath, string keyPath = RunKey, string valueName = ValueName)
    {
        using var key = Registry.CurrentUser.CreateSubKey(keyPath, writable: true);
        key.SetValue(valueName, Command(supervisorPath), RegistryValueKind.String);
    }

    /// <summary>The registered command, or <see langword="null"/>.</summary>
    public static string? Read(string keyPath = RunKey, string valueName = ValueName)
    {
        using var key = Registry.CurrentUser.OpenSubKey(keyPath, writable: false);
        return key?.GetValue(valueName) as string;
    }

    /// <summary>Removes the autostart value; returns whether it existed.</summary>
    public static bool Unregister(string keyPath = RunKey, string valueName = ValueName)
    {
        using var key = Registry.CurrentUser.OpenSubKey(keyPath, writable: true);
        if (key?.GetValue(valueName) is null)
        {
            return false;
        }

        key.DeleteValue(valueName, throwOnMissingValue: false);
        return true;
    }
}
