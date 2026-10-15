// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Platform.Windows;

/// <summary>
/// Windows program lookup (architecture 04 section 2): a program named with a directory part resolves against the working directory;
/// a bare name searches the <c>PATH</c> of the resolved environment, never the current directory (as with
/// <c>NoDefaultCurrentDirectoryInExePath</c>). In each place the name is tried as given when it has an extension, then with every
/// <c>PATHEXT</c> extension in order (default <c>.COM;.EXE;.BAT;.CMD</c>).
/// </summary>
public static class WindowsProgramResolver
{
    /// <summary>PATHEXT when the environment has none.</summary>
    public const string DefaultPathExt = ".COM;.EXE;.BAT;.CMD";

    /// <summary>Resolves <paramref name="program"/>, or returns <see langword="null"/>.</summary>
    public static string? Resolve(string program, string workingDirectory, IReadOnlyDictionary<string, string> environment)
    {
        ArgumentException.ThrowIfNullOrEmpty(program);
        ArgumentNullException.ThrowIfNull(workingDirectory);
        ArgumentNullException.ThrowIfNull(environment);
        var extensions = Value(environment, "PATHEXT") is { Length: > 0 } pathExt ? pathExt : DefaultPathExt;
        var suffixes = extensions.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(extension => extension.StartsWith('.'))
            .ToList();
        if (program.AsSpan().IndexOfAny('/', '\\') >= 0 || Path.IsPathRooted(program))
        {
            var candidate = Path.IsPathFullyQualified(program) ? program : Path.GetFullPath(Path.Combine(workingDirectory, program));
            return Probe(candidate, suffixes);
        }

        foreach (var directory in (Value(environment, "PATH") ?? string.Empty).Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var unquoted = directory.Trim('"');
            if (unquoted.Length == 0 || !Path.IsPathFullyQualified(unquoted))
            {
                // Relative PATH entries would search relative to the node's directory; they are skipped.
                continue;
            }

            string candidate;
            try
            {
                candidate = Path.Combine(unquoted, program);
            }
            catch (ArgumentException)
            {
                continue;
            }

            if (Probe(candidate, suffixes) is { } found)
            {
                return found;
            }
        }

        return null;
    }

    /// <summary>True for <c>.bat</c> and <c>.cmd</c> files, which run through cmd.exe.</summary>
    public static bool IsBatch(string path) =>
        Path.GetExtension(path) is { } extension
        && (extension.Equals(".bat", StringComparison.OrdinalIgnoreCase) || extension.Equals(".cmd", StringComparison.OrdinalIgnoreCase));

    /// <summary>A variable's value with Windows' case-insensitive names.</summary>
    public static string? Value(IReadOnlyDictionary<string, string> environment, string name)
    {
        ArgumentNullException.ThrowIfNull(environment);
        if (environment.TryGetValue(name, out var exact))
        {
            return exact;
        }

        foreach (var (key, value) in environment)
        {
            if (string.Equals(key, name, StringComparison.OrdinalIgnoreCase))
            {
                return value;
            }
        }

        return null;
    }

    private static string? Probe(string candidate, List<string> suffixes)
    {
        if (Path.HasExtension(candidate) && File.Exists(candidate))
        {
            return Path.GetFullPath(candidate);
        }

        foreach (var suffix in suffixes)
        {
            var withExtension = candidate + suffix.ToLowerInvariant();
            if (File.Exists(withExtension))
            {
                return Path.GetFullPath(withExtension);
            }
        }

        return null;
    }
}
