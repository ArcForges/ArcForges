// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text.Json;

namespace ArcForges.Node.Core.Security;

/// <summary>What <see cref="VersionIntegrity.Check"/> found in a version directory.</summary>
/// <param name="Fact">The capability fact <c>version_integrity</c>: <c>verified</c>, <c>mismatch: &lt;n&gt; files</c> or <c>not checked: ...</c>.</param>
/// <param name="Missing">Listed files that are not in the directory (relative paths, <c>/</c> separators).</param>
/// <param name="Changed">Listed files whose SHA-256 differs (or that could not be read).</param>
/// <param name="Unlisted">Files in the directory the manifest does not list.</param>
/// <param name="Links">Symbolic links and other reparse points in the directory: never followed, never changed, each a mismatch.</param>
/// <param name="Invalid">Manifest entries that are not a plain relative path inside the directory (absolute, <c>..</c>, empty segments): never read.</param>
/// <param name="HardLinks">Regular files (listed or not) with more than one hard link, or whose link count cannot be read: they share their data
/// and permissions with a name elsewhere, so they are never made read-only and never hashed; each is a mismatch.</param>
/// <param name="MadeReadOnly">Files this check made read-only (they were writable).</param>
/// <param name="NotReadOnly">Files that could not be made read-only.</param>
/// <param name="Problem">Why the manifest itself could not be used, or <see langword="null"/>.</param>
public sealed record VersionIntegrityReport(string Fact, IReadOnlyList<string> Missing, IReadOnlyList<string> Changed, IReadOnlyList<string> Unlisted,
    IReadOnlyList<string> Links, IReadOnlyList<string> Invalid, IReadOnlyList<string> HardLinks, int MadeReadOnly, IReadOnlyList<string> NotReadOnly,
    string? Problem)
{
    /// <summary>The entries that do not match the manifest (with an unusable manifest every file is unlisted, and at least one counts).</summary>
    public int Mismatches => Math.Max(Missing.Count + Changed.Count + Unlisted.Count + Links.Count + Invalid.Count + HardLinks.Count, Problem is null ? 0 : 1);

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
    /// Verifies <paramref name="directory"/> against its manifest and makes the listed files read-only. Without a manifest nothing is
    /// changed and the report says <see cref="NotChecked"/>. The walk never follows a link: a symbolic link or other reparse point inside the
    /// directory is a mismatch and neither it nor its target is changed or read; a manifest entry that is not a plain relative path inside
    /// the directory is a mismatch and is never read; a file with more than one hard link is a mismatch and is never changed or hashed; only
    /// listed files with a valid path and a single link are hashed and made read-only, and unlisted files are never touched.
    /// </summary>
    public static VersionIntegrityReport Check(string directory, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        var manifestPath = Path.Combine(directory, ManifestName);
        if (!File.Exists(manifestPath))
        {
            return new VersionIntegrityReport(NotChecked, [], [], [], [], [], [], 0, [], null);
        }

        var comparer = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        var files = new Dictionary<string, string>(comparer);
        var links = new List<string>();
        Walk(directory, directory, files, links, cancellationToken);
        var manifestIsLink = links.Contains(ManifestName, comparer);
        files.Remove(ManifestName);
        var onDisk = files.Keys.Order(StringComparer.Ordinal).ToList();

        // Review round 2: the manifest is read and validated first, and only what it lists is ever changed. A file with more than one hard
        // link shares its inode (data, mode, attributes) with a name outside the directory: it is a mismatch, never made read-only, never hashed.
        static bool Single(string path) => Platform.FileLinks.Count(path) == 1;
        Dictionary<string, string> listed;
        var problem = manifestIsLink
            ? Fail("digests.json is a link; it is not followed", comparer, out listed)
            : !Single(manifestPath)
                ? Fail("digests.json has more than one hard link; it is not used", comparer, out listed)
                : ReadManifest(manifestPath, comparer, out listed);
        var missing = new List<string>();
        var changed = new List<string>();
        var invalid = new List<string>();
        var hardLinks = new List<string>();
        var protect = new List<string>();
        foreach (var (relative, digest) in listed)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Inside(directory, relative))
            {
                invalid.Add(relative);
            }
            else if (files.TryGetValue(relative, out var path))
            {
                if (!Single(path))
                {
                    hardLinks.Add(relative);
                    continue;
                }

                protect.Add(relative);
                if (!string.Equals(Sha256(path), digest, StringComparison.OrdinalIgnoreCase))
                {
                    changed.Add(relative);
                }
            }
            else if (!links.Contains(relative, comparer))
            {
                // A listed path under a link, or absent: never read through the link (the link itself is reported).
                missing.Add(relative);
            }
        }

        // Unlisted files are never touched; one with several links is reported as a hard link.
        var unlisted = new List<string>();
        foreach (var relative in onDisk.Where(path => !listed.ContainsKey(path)))
        {
            (Single(files[relative]) ? unlisted : hardLinks).Add(relative);
        }

        // Only listed files with a valid path and a single link are made read-only (and the manifest, once it was usable).
        var madeReadOnly = 0;
        var notReadOnly = new List<string>();
        foreach (var relative in problem is null ? protect.Append(ManifestName) : protect)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var path = Path.Combine(directory, relative.Replace('/', Path.DirectorySeparatorChar));
            switch (Single(path) ? MakeReadOnly(path) : null)
            {
                case true:
                    madeReadOnly++;
                    break;
                case null:
                    notReadOnly.Add(relative);
                    break;
            }
        }

        var report = new VersionIntegrityReport(string.Empty, missing, changed, unlisted, links, invalid, hardLinks, madeReadOnly, notReadOnly, problem);
        return report with { Fact = FactOf(report.Mismatches) };
    }

    /// <summary>True when <paramref name="info"/> is a symbolic link, a junction or another reparse point (never followed).</summary>
    public static bool IsLink(FileSystemInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);
        return info.LinkTarget is not null || (info.Attributes & FileAttributes.ReparsePoint) != 0;
    }

    private static void Walk(string root, string directory, Dictionary<string, string> files, List<string> links, CancellationToken cancellationToken)
    {
        IEnumerable<FileSystemInfo> entries;
        try
        {
            entries = new DirectoryInfo(directory).EnumerateFileSystemInfos("*", new EnumerationOptions { RecurseSubdirectories = false, AttributesToSkip = 0, IgnoreInaccessible = true });
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return;
        }

        foreach (var entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relative = Path.GetRelativePath(root, entry.FullName).Replace('\\', '/');
            if (IsLink(entry))
            {
                links.Add(relative);
            }
            else if (entry is DirectoryInfo)
            {
                Walk(root, entry.FullName, files, links, cancellationToken);
            }
            else
            {
                files[relative] = entry.FullName;
            }
        }
    }

    private static string Fail(string problem, StringComparer comparer, out Dictionary<string, string> listed)
    {
        listed = new Dictionary<string, string>(comparer);
        return problem;
    }

    /// <summary>True when a manifest entry is a plain relative path (no root, no <c>..</c>, <c>.</c> or empty segment) that stays inside the directory.</summary>
    private static bool Inside(string directory, string relative)
    {
        if (relative.Length == 0 || Path.IsPathRooted(relative) || relative.Contains('\\', StringComparison.Ordinal) || relative.Contains(':', StringComparison.Ordinal)
            || !relative.Split('/').All(segment => segment is { Length: > 0 } and not "." and not ".."))
        {
            return false;
        }

        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory)) + Path.DirectorySeparatorChar;
        var full = Path.GetFullPath(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));
        return full.StartsWith(root, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
    }

    /// <summary>
    /// Makes a file read-only: true when it was writable and now is not, false when it already was read-only, null when it could not be
    /// changed.
    /// </summary>
    public static bool? MakeReadOnly(string path)
    {
        try
        {
            if (IsLink(new FileInfo(path)))
            {
                // Never through a link: File.SetUnixFileMode and File.SetAttributes would change its target.
                return null;
            }

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
            if (IsLink(new FileInfo(path)))
            {
                return string.Empty;
            }

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

}
