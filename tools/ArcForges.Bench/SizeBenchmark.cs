// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Bench;

/// <summary>A size target of 15-performance-targets section 1 (1 MB = 1,000,000 bytes).</summary>
internal sealed record SizeTarget(string Name, bool IsDirectory, long LimitBytes, IReadOnlyList<string> ExcludedPrefixes);

/// <summary>
/// <c>size</c>: the file size of a published binary, or the size of a publish directory. Debug
/// symbols are never counted (they are not shipped); the Desktop target also excludes the native
/// Skia and HarfBuzz libraries, as its target states.
/// </summary>
internal static class SizeBenchmark
{
    public const long Megabyte = 1_000_000;

    public static readonly IReadOnlyDictionary<string, SizeTarget> Targets = new Dictionary<string, SizeTarget>(StringComparer.Ordinal)
    {
        ["arcforges"] = new("arcforges", IsDirectory: false, 45 * Megabyte, []),
        ["arcforges-supervisor"] = new("arcforges-supervisor", IsDirectory: false, 4 * Megabyte, []),
        ["arcforges-desktop"] = new("arcforges-desktop", IsDirectory: true, 60 * Megabyte, ["libSkiaSharp.", "libHarfBuzzSharp."]),
    };

    private static readonly string[] SymbolExtensions = [".pdb", ".dbg", ".dSYM"];

    public static SizeResult Run(BenchOptions options)
    {
        var path = options.GetRequired("path");
        var targetName = options.GetString("target");
        var maxMegabytes = options.GetDouble("max-mb", 0.001, 100_000);
        var name = options.GetString("name");
        options.GetString("output");
        options.EnsureAllUsed();

        SizeTarget target;
        if (targetName is not null)
        {
            if (!Targets.TryGetValue(targetName, out var known))
            {
                throw new UsageException($"Unknown size target '{targetName}'; known: {string.Join(", ", Targets.Keys)}.");
            }

            target = maxMegabytes is null ? known : known with { LimitBytes = (long)(maxMegabytes.Value * Megabyte) };
        }
        else if (maxMegabytes is not null)
        {
            target = new SizeTarget(name ?? Path.GetFileName(Path.TrimEndingDirectorySeparator(path)), Directory.Exists(path), (long)(maxMegabytes.Value * Megabyte), []);
        }
        else
        {
            throw new UsageException("Give --target or --max-mb.");
        }

        var (bytes, excluded) = Measure(path, target);
        return new SizeResult
        {
            Name = name ?? target.Name,
            Measurement = target.IsDirectory ? "directory" : "file",
            Bytes = bytes,
            LimitBytes = target.LimitBytes,
            Excluded = excluded,
            Pass = bytes <= target.LimitBytes,
            Environment = BenchEnvironment.Current(),
        };
    }

    public static (long Bytes, IReadOnlyList<string> Excluded) Measure(string path, SizeTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (!target.IsDirectory)
        {
            var file = new FileInfo(path);
            if (!file.Exists)
            {
                throw new FileNotFoundException($"'{path}' is not a file.", path);
            }

            return (file.Length, []);
        }

        var directory = new DirectoryInfo(path);
        if (!directory.Exists)
        {
            throw new DirectoryNotFoundException($"'{path}' is not a directory.");
        }

        long total = 0;
        var excluded = new List<string>();
        foreach (var file in directory.EnumerateFiles("*", SearchOption.AllDirectories).OrderBy(file => file.FullName, StringComparer.Ordinal))
        {
            var relative = Path.GetRelativePath(directory.FullName, file.FullName).Replace('\\', '/');
            if (SymbolExtensions.Contains(file.Extension, StringComparer.OrdinalIgnoreCase)
                || target.ExcludedPrefixes.Any(prefix => file.Name.StartsWith(prefix, StringComparison.Ordinal))
                || relative.Contains(".dSYM/", StringComparison.Ordinal))
            {
                excluded.Add(relative);
                continue;
            }

            total += file.Length;
        }

        return (total, excluded);
    }
}
