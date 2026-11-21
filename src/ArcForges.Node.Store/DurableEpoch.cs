// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;

namespace ArcForges.Node.Store;

/// <summary>Fixed refusal codes for incomplete protected authority, never secret-store exception details.</summary>
public sealed class DurableStoreMaintenanceException : InvalidOperationException
{
    /// <summary>Creates a fail-closed maintenance refusal.</summary>
    public DurableStoreMaintenanceException() : base("The owner store requires reconciliation before admitting durable work.") { }
}

// An admission/effect-history witness outside SQLite. A snapshot cannot use its own old witness
// as proof that no later admission or effect observation exists. Preparing the next witness before
// the FULL transaction makes an interrupted boundary maintenance, never permission to execute again.
internal sealed record DurableEpochFence(string Owner, byte[] Epoch, string KeyReference, long Sequence, byte[] History)
{
    private const int Format = 1;

    internal static string PathFor(string dataRoot, string owner) => Path.Combine(dataRoot, "store",
        "v2-owner-" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(owner))) + ".fence");

    // Serializes namespace creation with complete catalogue backup/restore inspection.
    // Per-owner locks continue to protect admission and effect observations.
    internal static FileStream OpenCatalogueLock(string dataRoot, bool existingOnly = false) =>
        OpenPrivate(Path.Combine(dataRoot, "store", "v2-owner-catalogue.lock"), existingOnly ? FileMode.Open : FileMode.OpenOrCreate);

    internal byte[] Encode(ReadOnlySpan<byte> key)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(Format);
            writer.Write(Owner);
            writer.Write(Epoch);
            writer.Write(KeyReference);
            writer.Write(Sequence);
            writer.Write(History);
        }
        byte[] body = stream.ToArray();
        return [.. body, .. HMACSHA256.HashData(key, body)];
    }

    internal static DurableEpochFence Read(string path, ReadOnlySpan<byte> key)
    {
        try
        {
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (file.Length < 8) throw new DurableStoreMaintenanceException();
            using var frame = new BinaryReader(file, Encoding.UTF8, leaveOpen: true);
            file.Seek(-4, SeekOrigin.End);
            int length = frame.ReadInt32();
            if (length is < 104 or > 4096 || file.Length < length + 8) throw new DurableStoreMaintenanceException();
            file.Seek(-length - 8, SeekOrigin.End);
            if (frame.ReadInt32() != length) throw new DurableStoreMaintenanceException();
            byte[] bytes = frame.ReadBytes(length);
            if (bytes.Length != length || !CryptographicOperations.FixedTimeEquals(
                HMACSHA256.HashData(key, bytes.AsSpan(0, bytes.Length - 32)), bytes.AsSpan(bytes.Length - 32)))
                throw new DurableStoreMaintenanceException();
            using var stream = new MemoryStream(bytes, 0, bytes.Length - 32, writable: false);
            using var reader = new BinaryReader(stream, Encoding.UTF8);
            if (reader.ReadInt32() != Format) throw new DurableStoreMaintenanceException();
            string owner = reader.ReadString();
            byte[] epoch = reader.ReadBytes(16);
            string reference = reader.ReadString();
            long sequence = reader.ReadInt64();
            byte[] history = reader.ReadBytes(32);
            if (epoch.Length != 16 || history.Length != 32 || sequence < 0 || stream.Position != stream.Length)
                throw new DurableStoreMaintenanceException();
            return new(owner, epoch, reference, sequence, history);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            throw new DurableStoreMaintenanceException();
        }
    }

    internal void Write(string path, ReadOnlySpan<byte> key)
    {
        // Append and fsync the existing inode before the SQLite FULL commit. A torn final
        // frame is maintenance; never fall back to an older valid authority observation.
        byte[] bytes = Encode(key);
        using var stream = OpenPrivate(path, FileMode.OpenOrCreate);
        stream.Seek(0, SeekOrigin.End);
        using var frame = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        frame.Write(bytes.Length);
        frame.Write(bytes);
        frame.Write(bytes.Length);
        stream.Flush(flushToDisk: true);
    }

    internal static void WritePrivate(string path, ReadOnlySpan<byte> bytes)
    {
        StorePaths.CreatePrivateDirectory(Path.GetDirectoryName(path)!);
        string temporary = path + "." + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8)) + ".partial";
        try
        {
            using (var stream = OpenPrivate(temporary, FileMode.CreateNew))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            File.Delete(temporary);
        }
    }

    internal static FileStream OpenPrivate(string path, FileMode mode)
    {
        var options = new FileStreamOptions { Mode = mode, Access = FileAccess.ReadWrite, Share = FileShare.None };
        if (!OperatingSystem.IsWindows() && mode is FileMode.Create or FileMode.CreateNew or FileMode.OpenOrCreate)
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        return new FileStream(path, options);
    }
}
