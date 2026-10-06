// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;
using ArcForges.ContentSandbox.Broker.Native;

namespace ArcForges.ContentSandbox.Broker.Windows;

/// <summary>An exclusively held identity. Dispose only after its child has actually terminated.</summary>
[SupportedOSPlatform("windows")]
internal sealed class AppContainerLease(string name, nint sid, IReadOnlyList<FileStream> locks) : IDisposable
{
    private long _sid = sid;
    private FileStream Canonical => locks[0];
    private int _launchState;

    internal string Name { get; } = name;

    internal nint Sid
    {
        get
        {
            var value = Interlocked.Read(ref _sid);
            return value == 0 ? throw new ObjectDisposedException(nameof(AppContainerLease)) : (nint)value;
        }
    }

    internal void BeginLaunch()
    {
        _launchState = 1;
        AppContainerSlots.WriteLifetime(Canonical,
            new AppContainerSlots.LifetimeRecord(1, "pending", 0, 0, new SecurityIdentifier(Sid).Value));
    }

    internal void RecordChild(Process process)
    {
        AppContainerSlots.WriteLifetime(Canonical,
            new AppContainerSlots.LifetimeRecord(1, "active", process.Id, process.StartTime.ToUniversalTime().Ticks, new SecurityIdentifier(Sid).Value));
        _launchState = 2;
    }

    // Only the launcher, after its actual retained kernel exit wait or proof that no child was created.
    internal void ConfirmExit() => _launchState = 3;

    [SuppressMessage("Design", "CA1031", Justification = "Every identity lock must be released after verified child exit even if profile deletion or another lock release fails.")]
    public void Dispose()
    {
        var value = Interlocked.Exchange(ref _sid, 0);
        if (value == 0)
        {
            return;
        }

        var failures = new List<Exception>();
        try
        {
            if (_launchState is 1 or 2)
            {
                throw new ContentSandboxLaunchException("resource.unavailable", "The unconfirmed helper lifetime remains durably quarantined.");
            }

            AppContainerSlots.RemoveProfile(Name, (nint)value);
            AppContainerSlots.WriteLifetime(Canonical, null);
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }
        finally
        {
            _ = WindowsNative.FreeSid((nint)value);
            foreach (var slotLock in locks)
            {
                try
                {
                    slotLock.Dispose();
                }
                catch (Exception exception)
                {
                    failures.Add(exception);
                }
            }
        }

        if (failures.Count != 0)
        {
            throw new ContentSandboxLaunchException("security.isolation_unavailable", "The previous AppContainer identity could not be completely cleaned.", new AggregateException(failures));
        }
    }

}

/// <summary>Eight bounded identities, held by crash-releasing canonical per-user file locks and recreated fresh for every helper.</summary>
[SupportedOSPlatform("windows")]
internal static partial class AppContainerSlots
{
    internal const int SlotCount = 8;
    private const string Description = "ArcForges restricted content helper";

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,50}$", RegexOptions.CultureInvariant)]
    private static partial Regex NamePattern();

    internal static string DefaultLockDirectory() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ArcForges", "ContentSandbox", "slots");

    internal static AppContainerLease Acquire(string prefix, string lockDirectory)
    {
        if (!NamePattern().IsMatch(prefix))
        {
            throw new ArgumentException("The AppContainer name prefix is not a valid name.", nameof(prefix));
        }

        var canonicalDirectory = Path.Combine(DefaultLockDirectory(), prefix);
        var additionalDirectory = Path.Combine(Path.GetFullPath(lockDirectory), prefix);
        _ = Directory.CreateDirectory(canonicalDirectory);
        _ = Directory.CreateDirectory(additionalDirectory);
        for (var index = 0; index < SlotCount; index++)
        {
            var locks = new List<FileStream>(2);
            try
            {
                locks.Add(OpenLock(canonicalDirectory, index));
                if (!string.Equals(canonicalDirectory, additionalDirectory, StringComparison.OrdinalIgnoreCase))
                {
                    locks.Add(OpenLock(additionalDirectory, index));
                }
            }
            catch (IOException)
            {
                foreach (var held in locks)
                {
                    held.Dispose();
                }

                continue;
            }
            catch
            {
                foreach (var held in locks)
                {
                    held.Dispose();
                }

                throw;
            }

            try
            {
                var name = $"{prefix}.{index}";
                if (!PriorLifetimeEnded(locks[0], name))
                {
                    foreach (var held in locks)
                    {
                        held.Dispose();
                    }

                    continue;
                }

                return new AppContainerLease(name, CreateFreshProfile(name), locks);
            }
            catch
            {
                foreach (var held in locks)
                {
                    held.Dispose();
                }

                throw;
            }
        }

        throw new ContentSandboxLaunchException("capacity.busy", "Every restricted identity is in use.");
    }

    internal sealed record LifetimeRecord(int SchemaVersion, string State, int ProcessId, long CreatedUtcTicks, string Sid);

    internal static void WriteLifetime(FileStream stream, LifetimeRecord? record)
    {
        var bytes = record is null ? [] : EncodeLifetime(record);
        stream.Position = 0;
        if (record is not null)
        {
            // Preserve the durable pending sentinel during replacement. A partial write must remain
            // non-empty and quarantined, never look like a clean identity while its child still lives.
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }

        // Only remove an old tail after the replacement bytes are durable. Clearing is called only
        // after verified exit and complete profile removal, so an empty record is safe at this point.
        stream.SetLength(bytes.Length);
        stream.Flush(flushToDisk: true);
    }

    private static byte[] EncodeLifetime(LifetimeRecord record)
    {
        using var bytes = new MemoryStream();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", record.SchemaVersion);
            writer.WriteString("state", record.State);
            writer.WriteNumber("processId", record.ProcessId);
            writer.WriteNumber("createdUtcTicks", record.CreatedUtcTicks);
            writer.WriteString("sid", record.Sid);
            writer.WriteEndObject();
        }

        return bytes.ToArray();
    }

    internal static bool PriorLifetimeEnded(FileStream stream, string name)
    {
        if (stream.Length == 0)
        {
            return true;
        }

        if (stream.Length > 2048)
        {
            return false;
        }

        stream.Position = 0;
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        LifetimeRecord record;
        try
        {
            using var document = JsonDocument.Parse(bytes);
            var root = document.RootElement;
            record = new LifetimeRecord(root.GetProperty("schemaVersion").GetInt32(), root.GetProperty("state").GetString()!,
                root.GetProperty("processId").GetInt32(), root.GetProperty("createdUtcTicks").GetInt64(), root.GetProperty("sid").GetString()!);
        }
        catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            return false;
        }

        if (record.SchemaVersion != 1 || record.State != "active"
            || record.ProcessId <= 0 || record.CreatedUtcTicks <= 0 || record.CreatedUtcTicks > DateTime.MaxValue.Ticks
            || !bytes.AsSpan().SequenceEqual(EncodeLifetime(record)))
        {
            // The bounded pending/crash-before-instance-record window has no trustworthy child identity.
            // Malformed/unknown state is equally quarantined; a new Job namespace cannot prove exit.
            return false;
        }

        var result = WindowsNative.DeriveAppContainerSidFromAppContainerName(name, out var sid);
        if (result != 0)
        {
            throw Unavailable("The prior AppContainer identity could not be derived.", result);
        }

        try
        {
            if (record.Sid != new SecurityIdentifier(sid).Value)
            {
                return false;
            }

            Process process;
            try
            {
                process = Process.GetProcessById(record.ProcessId);
            }
            catch (ArgumentException)
            {
                return true; // The exact prior PID no longer exists. No process is terminated here.
            }

            using (process)
            {
                try
                {
                    if (process.HasExited || process.StartTime.ToUniversalTime().Ticks != record.CreatedUtcTicks)
                    {
                        return true; // PID reuse proves the original instance exited; never touch the replacement.
                    }

                    return !HasExpectedContainer(process.Handle, sid) ? false : process.WaitForExit(0);
                }
                catch (Exception exception) when (exception is InvalidOperationException or Win32Exception)
                {
                    return false; // Access failure or racing instance information is not exit evidence.
                }
            }
        }
        finally
        {
            _ = WindowsNative.FreeSid(sid);
        }
    }

    private static unsafe bool HasExpectedContainer(nint process, nint expectedSid)
    {
        if (!WindowsNative.OpenProcessToken(process, WindowsNative.TokenQueryAccess, out var token))
        {
            return false;
        }

        try
        {
            _ = WindowsNative.GetTokenInformation(token, WindowsNative.TokenAppContainerSid, 0, 0, out var needed);
            if (needed is 0 or > 4096)
            {
                return false;
            }

            var buffer = (nint)NativeMemory.Alloc(needed);
            try
            {
                return WindowsNative.GetTokenInformation(token, WindowsNative.TokenAppContainerSid, buffer, needed, out _)
                    && *(nint*)buffer != 0 && WindowsNative.EqualSid(*(nint*)buffer, expectedSid);
            }
            finally
            {
                NativeMemory.Free((void*)buffer);
            }
        }
        finally
        {
            _ = WindowsNative.CloseHandle(token);
        }
    }

    private static FileStream OpenLock(string directory, int index) => new(
        Path.Combine(directory, $"slot-{index}.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.None);

    private static nint CreateFreshProfile(string name)
    {
        var result = WindowsNative.DeriveAppContainerSidFromAppContainerName(name, out var oldSid);
        if (result != 0)
        {
            throw Unavailable("The AppContainer identity could not be derived.", result);
        }

        try
        {
            RemoveProfile(name, oldSid);
        }
        finally
        {
            _ = WindowsNative.FreeSid(oldSid);
        }

        result = WindowsNative.CreateAppContainerProfile(name, name, Description, 0, 0, out var sid);
        if (result != 0)
        {
            // Existing profiles are never adopted: their storage may belong to another helper lifetime.
            throw Unavailable("A fresh AppContainer identity could not be created.", result);
        }

        return sid;
    }

    internal static string ProfileStorage(nint sid) => ReadProfileStorage(sid)
        ?? throw new ContentSandboxLaunchException("security.isolation_unavailable", "The AppContainer profile storage is absent.");

    private static string? ReadProfileStorage(nint sid)
    {
        var result = WindowsNative.GetAppContainerFolderPath(new SecurityIdentifier(sid).Value, out var value);
        try
        {
            if (result is unchecked((int)0x80070002) or unchecked((int)0x80070003))
            {
                // A newly derived SID need not have a profile, and deletion may already have removed its registry mapping.
                return null;
            }

            if (result != 0)
            {
                throw Unavailable("The AppContainer storage path could not be verified.", result);
            }

            var path = Path.GetFullPath(Marshal.PtrToStringUni(value) ?? throw new ContentSandboxLaunchException("security.isolation_unavailable", "The AppContainer storage path is absent."));
            var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Packages") + Path.DirectorySeparatorChar;
            if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase) || path.Length <= root.Length)
            {
                throw new ContentSandboxLaunchException("security.isolation_unavailable", "The AppContainer storage path is outside its per-user package root.");
            }

            return path;
        }
        finally
        {
            Marshal.FreeCoTaskMem(value);
        }
    }

    internal static void RemoveProfile(string name, nint sid)
    {
        var path = ReadProfileStorage(sid);
        var package = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Packages", name);
        if (path is not null && !string.Equals(path, Path.Combine(package, "AC"), StringComparison.OrdinalIgnoreCase))
        {
            throw new ContentSandboxLaunchException("security.isolation_unavailable", "The AppContainer storage path does not match its bounded named profile.");
        }

        var result = WindowsNative.DeleteAppContainerProfile(name);
        if (result != 0)
        {
            throw Unavailable("The previous AppContainer profile could not be deleted.", result);
        }

        try
        {
            _ = File.GetAttributes(package);
        }
        catch (FileNotFoundException)
        {
            return;
        }
        catch (DirectoryNotFoundException)
        {
            return;
        }

        // S_OK is insufficient: open storage handles may leave the old directory behind. Never recursively delete it ourselves.
        throw new ContentSandboxLaunchException("security.isolation_unavailable", "The previous AppContainer storage remains; this identity cannot be reused.");
    }

    private static ContentSandboxLaunchException Unavailable(string message, int result) =>
        new("security.isolation_unavailable", message, new Win32Exception(result & 0xFFFF));
}
