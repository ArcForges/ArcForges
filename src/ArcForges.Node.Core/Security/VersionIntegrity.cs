// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text.Json;

namespace ArcForges.Node.Core.Security;

/// <summary>What <see cref="VersionIntegrity.Check"/> found in a version directory.</summary>
/// <param name="Fact">The capability fact <c>version_integrity</c>: <c>verified</c>, <c>mismatch: &lt;n&gt; files</c> or <c>not checked: ...</c>.</param>
/// <param name="Missing">Listed files that are not in the directory (relative paths, <c>/</c> separators).</param>
/// <param name="Changed">Listed files whose SHA-256 differs (or that could not be read, or whose entry is not a valid relative path).</param>
/// <param name="Unlisted">Files in the directory the manifest does not list.</param>
/// <param name="MadeReadOnly">Files this check made read-only (they were writable).</param>
/// <param name="NotReadOnly">Files that could not be made read-only.</param>
/// <param name="Problem">Why the manifest itself could not be used, or <see langword="null"/>.</param>
public sealed record VersionIntegrityReport(string Fact, IReadOnlyList<string> Missing, IReadOnlyList<string> Changed, IReadOnlyList<string> Unlisted,
    int MadeReadOnly, IReadOnlyList<string> NotReadOnly, string? Problem)
{
    /// <summary>The files that do not match the manifest (with an unusable manifest every file is unlisted, and at least one counts).</summary>
    public int Mismatches => Math.Max(Missing.Count + Changed.Count + Unlisted.Count, Problem is null ? 0 : 1);

    /// <summary>True when a manifest was present (the directory was checked).</summary>
    public bool Checked => !string.Equals(Fact, VersionIntegrity.NotChecked, StringComparison.Ordinal);
}

/// <summary>
/// Read-only version directories with digest checks (AD-0007 section 8; 11 section 1, the tamper finding): the packaging step writes
/// <c>digests.json</c> (<c>{"version": "&lt;v&gt;", "files": {"&lt;relative path, / separators&gt;": "&lt;sha256 hex&gt;"}}</c>, every file except
/// itself) into each version directory. A node running from a version directory that holds the manifest makes every file in it read-only
/// (Windows <c>FILE_ATTRIBUTE_READONLY</c>; elsewhere the write bits are removed) and verifies every listed file's SHA-256, reporting the
/// files that are missing, changed or unlisted. The node runs this after it is ready, on a background thread (never on the startup path).
/// Without a manifest (development builds, tests running from their build output) nothing is checked, and that is never reported as
/// verified. This is GUARDRAIL hardening against accidental or careless modification: same-user code can still change the files back.
/// </summary>
public static class VersionIntegrity
{
    /// <summary>The manifest's file name in a version directory.</summary>
    public const string ManifestName = "digests.json";

    /// <summary>The capability fact's name.</summary>
    public const string FactName = "version_integrity";

    /// <summary>The fact without a manifest.</summary>
    public const string NotChecked = "not checked: no digest manifest";

    /// <summary>The fact once every listed file matched and no file was unlisted.</summary>
    public const string Verified = "verified";

    /// <summary>The fact while the check runs.</summary>
    public const string Checking = "not checked yet: the check runs after startup";

    /// <summary>True when <paramref name="directory"/> holds a digest manifest.</summary>
    public static bool HasManifest(string directory) => File.Exists(Path.Combine(directory, ManifestName));

    /// <summary>The fact to report before the check finished.</summary>
    public static string InitialFact(string directory) => HasManifest(directory) ? Checking : NotChecked;

    /// <summary>The fact of a finished check.</summary>
    public static string FactOf(int mismatches) => mismatches == 0 ? Verified : $"mismatch: {mismatches} files";

    /// <summary>
    /// Makes the files of <paramref name="directory"/> read-only and verifies them against its manifest. Without a manifest nothing is
    /// changed and the report says <see cref="NotChecked"/>.
    /// </summary>
    public static VersionIntegrityReport Check(string directory, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        var manifestPath = Path.Combine(directory, ManifestName);
        if (!File.Exists(manifestPath))
        {
            return new VersionIntegrityReport(NotChecked, [], [], [], 0, [], null);
        }

        var comparer = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        var onDisk = Directory.EnumerateFiles(directory, "*", new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = 0, IgnoreInaccessible = true })
            .Select(path => Path.GetRelativePath(directory, path).Replace('\\', '/'))
            .Where(path => !comparer.Equals(path, ManifestName))
            .Order(StringComparer.Ordinal)
            .ToList();

        // 1. Every file read-only (the manifest too).
        var madeReadOnly = 0;
        var notReadOnly = new List<string>();
        foreach (var relative in onDisk.Append(ManifestName))
        {
            cancellationToken.ThrowIfCancellationRequested();
            switch (MakeReadOnly(Path.Combine(directory, relative)))
            {
                case true:
                    madeReadOnly++;
                    break;
                case null:
                    notReadOnly.Add(relative);
                    break;
            }
        }

        // 2. The digests.
        var problem = ReadManifest(manifestPath, comparer, out var listed);
        var missing = new List<string>();
        var changed = new List<string>();
        foreach (var (relative, digest) in listed)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!ValidRelative(relative))
            {
                changed.Add(relative);
                continue;
            }

            var path = Path.Combine(directory, relative.Replace('/', Path.DirectorySeparatorChar));
            if (!File.Exists(path))
            {
                missing.Add(relative);
                continue;
            }

            if (!string.Equals(Sha256(path), digest, StringComparison.OrdinalIgnoreCase))
            {
                changed.Add(relative);
            }
        }

        var unlisted = onDisk.Where(path => !listed.ContainsKey(path)).ToList();
        var mismatches = Math.Max(missing.Count + changed.Count + unlisted.Count, problem is null ? 0 : 1);
        return new VersionIntegrityReport(FactOf(mismatches), missing, changed, unlisted, madeReadOnly, notReadOnly, problem);
    }

    /// <summary>
    /// Makes a file read-only: true when it was writable and now is not, false when it already was read-only, null when it could not be
    /// changed.
    /// </summary>
    public static bool? MakeReadOnly(string path)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                var attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.ReadOnly) != 0)
                {
                    return false;
                }

                File.SetAttributes(path, attributes | FileAttributes.ReadOnly);
                return true;
            }

            const UnixFileMode Write = UnixFileMode.UserWrite | UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;
            var mode = File.GetUnixFileMode(path);
            if ((mode & Write) == 0)
            {
                return false;
            }

            File.SetUnixFileMode(path, mode & ~Write);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>True when the file can no longer be written through its permissions (the read-only attribute, or no write bit).</summary>
    public static bool IsReadOnly(string path) => OperatingSystem.IsWindows()
        ? (File.GetAttributes(path) & FileAttributes.ReadOnly) != 0
        : (File.GetUnixFileMode(path) & (UnixFileMode.UserWrite | UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) == 0;

    /// <summary>The lowercase hex SHA-256 of a file, or an empty string when it cannot be read.</summary>
    public static string Sha256(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
            return Convert.ToHexStringLower(SHA256.HashData(stream));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return string.Empty;
        }
    }

    private static string? ReadManifest(string path, StringComparer comparer, out Dictionary<string, string> listed)
    {
        listed = new Dictionary<string, string>(comparer);
        try
        {
            var bytes = File.ReadAllBytes(path);
            var start = bytes.AsSpan().StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]) ? 3 : 0;
            using var document = JsonDocument.Parse(bytes.AsMemory(start));
            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !document.RootElement.TryGetProperty("files", out var files) || files.ValueKind != JsonValueKind.Object)
            {
                return "digests.json has no \"files\" object";
            }

            foreach (var file in files.EnumerateObject())
            {
                if (file.Value.ValueKind != JsonValueKind.String || file.Value.GetString() is not { Length: 64 } digest)
                {
                    return $"digests.json: the entry {file.Name} is not a SHA-256 hex digest";
                }

                listed[file.Name] = digest;
            }

            return null;
        }
        catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException)
        {
            return "digests.json cannot be read: " + exception.Message;
        }
    }

    private static bool ValidRelative(string relative) =>
        relative.Length > 0 && !Path.IsPathRooted(relative) && !relative.Contains('\\', StringComparison.Ordinal)
        && relative.Split('/').All(segment => segment is { Length: > 0 } and not "." and not "..");
}
