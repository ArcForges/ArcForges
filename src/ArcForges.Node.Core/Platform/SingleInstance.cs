// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using ArcForges.Client;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// The node's single-instance guard (architecture 02 section 2 step 2): on Windows the named mutex
/// <c>Local\ArcForges.Node.&lt;user-sid-hash&gt;</c>, on Linux an exclusive <c>flock</c> on <c>&lt;data root&gt;/node.lock</c>. The guard
/// is held for the life of the node process; the operating system releases it when the process exits, however it exits.
/// </summary>
public sealed partial class SingleInstance : IDisposable
{
    private const int LockExclusive = 2;
    private const int LockNonBlocking = 4;
    private const int WouldBlock = 11;

    private readonly Mutex? _mutex;
    private readonly SafeFileHandle? _lock;

    private SingleInstance(Mutex? mutex, SafeFileHandle? lockFile, string name)
    {
        _mutex = mutex;
        _lock = lockFile;
        Name = name;
    }

    /// <summary>The mutex name or the lock file path.</summary>
    public string Name { get; }

    /// <summary>Acquires the guard, or returns <see langword="null"/> when another node instance holds it.</summary>
    public static SingleInstance? TryAcquire(string instanceKey, string dataRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(instanceKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        if (OperatingSystem.IsWindows())
        {
            var name = NodeLocations.NodeMutexName(instanceKey);
            var mutex = new Mutex(initiallyOwned: true, name, out var created);
            if (created)
            {
                return new SingleInstance(mutex, null, name);
            }

            try
            {
                if (mutex.WaitOne(0))
                {
                    return new SingleInstance(mutex, null, name);
                }
            }
            catch (AbandonedMutexException)
            {
                // The previous holder exited without releasing it (a crash); this process owns it now.
                return new SingleInstance(mutex, null, name);
            }

            mutex.Dispose();
            return null;
        }

        var path = NodeLocations.NodeLockFile(dataRoot);
        SafeFileHandle handle;
        try
        {
            // FileShare.None makes the runtime take flock(LOCK_EX | LOCK_NB) as it opens; the explicit flock below holds the lock
            // even where the runtime's advisory locking is switched off (DOTNET_SYSTEM_IO_DISABLEFILELOCKING).
            handle = File.OpenHandle(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, FileOptions.None, preallocationSize: 0);
        }
        catch (IOException)
        {
            return null;
        }

        if (OperatingSystem.IsLinux() || OperatingSystem.IsFreeBSD())
        {
            File.SetUnixFileMode(handle, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        if (Flock((int)handle.DangerousGetHandle(), LockExclusive | LockNonBlocking) != 0)
        {
            var error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            if (error == WouldBlock)
            {
                return null;
            }

            throw new IOException($"flock on {path} failed (errno {error}).");
        }

        return new SingleInstance(null, handle, path);
    }

    /// <summary>Releases the guard (the process exit releases it as well).</summary>
    public void Dispose()
    {
        // The mutex is not released from this thread (it may not own it); closing the last handle abandons it, and the next
        // node takes it over. The flock ends with the file descriptor.
        _mutex?.Dispose();
        _lock?.Dispose();
    }

    [LibraryImport("libc", EntryPoint = "flock", SetLastError = true)]
    private static partial int Flock(int fileDescriptor, int operation);
}
