// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using System.Xml.Linq;

namespace ArcForges.Repository.Tests;

/// <summary>Reads the checked-in repository files that the policy tests examine.</summary>
internal static class RepositoryFiles
{
    public static string Root { get; } = FindRoot();

    public static string PathOf(string relative) => Path.Combine(Root, relative);

    public static IReadOnlyList<string> Projects(params string[] directories) =>
        directories
            .Select(PathOf)
            .Where(Directory.Exists)
            .SelectMany(directory => Directory.EnumerateFiles(directory, "*.csproj", SearchOption.AllDirectories))
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                && !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Select(path => Path.GetRelativePath(Root, path).Replace('\\', '/'))
            .Order(StringComparer.Ordinal)
            .ToList();

    public static XDocument Xml(string relative) => XDocument.Load(PathOf(relative));

    public static JsonDocument Json(string relative) => JsonDocument.Parse(File.ReadAllBytes(PathOf(relative)));

    /// <summary>The value of a property set unconditionally in the project file.</summary>
    public static string? Property(string project, string name) =>
        Xml(project).Descendants(name).LastOrDefault(element => element.Parent?.Attribute("Condition") is null)?.Value;

    public static IReadOnlyDictionary<string, string> CentralVersions() =>
        Xml("Directory.Packages.props").Descendants("PackageVersion")
            .ToDictionary(element => (string)element.Attribute("Include")!, element => (string)element.Attribute("Version")!, StringComparer.Ordinal);

    private static string FindRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "ArcForges.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new DirectoryNotFoundException("The repository root (ArcForges.slnx) was not found above the test output.");
    }
}
