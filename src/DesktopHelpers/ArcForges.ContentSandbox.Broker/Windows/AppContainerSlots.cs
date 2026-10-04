// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using ArcForges.ContentSandbox.Broker.Native;

namespace ArcForges.ContentSandbox.Broker.Windows;

/// <summary>
/// One AppContainer identity held exclusively for the life of one helper. The container is the package identity of the child:
/// a fresh identity per concurrent helper means the helpers cannot reach one another through the shared package SID.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class AppContainerLease : IDisposable
{
    private readonly FileStream _lock;
    private nint _sid;

    internal AppContainerLease(string name, nint sid, FileStream slotLock)
    {
        Name = name;
        _sid = sid;
        _lock = slotLock;
    }

    /// <summary>The AppContainer name (for example <c>ArcForges.ContentSandbox.3</c>).</summary>
    internal string Name { get; }

    /// <summary>The package SID. Valid until <see cref="Dispose"/>.</summary>
    internal nint Sid => _sid == 0 ? throw new ObjectDisposedException(nameof(AppContainerLease)) : _sid;

    public void Dispose()
    {
        var sid = Interlocked.Exchange(ref _sid, 0);
        if (sid != 0)
        {
            _ = WindowsNative.FreeSid(sid);
            _lock.Dispose();
        }
    }
}

/// <summary>
/// A bounded pool of AppContainer identities. Creating a profile writes per-user registry state, so a profile is created once and kept:
/// at most eight exist (the session bound), they are named, and one is leased to a helper at a time. The lease is a lock file opened without
/// sharing, so it is released by the operating system when its owner ends, however it ends, and works across processes of the same user.
/// </summary>
[SupportedOSPlatform("windows")]
internal static partial class AppContainerSlots
{
    internal const int SlotCount = 8;
    private const string Description = "ArcForges restricted content helper";

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,50}$", RegexOptions.CultureInvariant)]
    private static partial Regex NamePattern();

    internal static string DefaultLockDirectory() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ArcForges", "ContentSandbox", "slots");

    /// <summary>Leases a free identity, or throws <see cref="ContentSandboxLaunchException"/> when every identity is in use or none can be made.</summary>
    internal static AppContainerLease Acquire(string prefix, string lockDirectory)
    {
        if (!NamePattern().IsMatch(prefix))
        {
            throw new ArgumentException("The AppContainer name prefix is not a valid name.", nameof(prefix));
        }

        _ = Directory.CreateDirectory(lockDirectory);
        for (var index = 0; index < SlotCount; index++)
        {
            FileStream slotLock;
            try
            {
                slotLock = new FileStream(
                    Path.Combine(lockDirectory, $"slot-{index}.lock"),
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    1,
                    FileOptions.None);
            }
            catch (IOException)
            {
                continue;
            }

            try
            {
                return new AppContainerLease($"{prefix}.{index}", EnsureProfile($"{prefix}.{index}"), slotLock);
            }
            catch
            {
                slotLock.Dispose();
                throw;
            }
        }

        throw new ContentSandboxLaunchException("capacity.busy", "Every restricted identity is in use.");
    }

    private static nint EnsureProfile(string name)
    {
        var result = WindowsNative.CreateAppContainerProfile(name, name, Description, 0, 0, out var sid);
        if (result == 0)
        {
            return sid;
        }

        if (result == WindowsNative.ErrorAlreadyExists)
        {
            result = WindowsNative.DeriveAppContainerSidFromAppContainerName(name, out sid);
            if (result == 0)
            {
                return sid;
            }
        }

        throw new ContentSandboxLaunchException(
            "security.isolation_unavailable",
            "The AppContainer identity could not be created.",
            new Win32Exception(result & 0xFFFF));
    }
}
