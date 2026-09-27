// SPDX-License-Identifier: AGPL-3.0-only

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

namespace ArcForges.Tests.ArchitectureTests;

public sealed class RepositoryPolicyTests
{
    private static readonly string Root = FindRoot();

    [Xunit.Fact]
    public void SolutionsContainOnlyExistingOwnedProjects()
    {
        foreach (string name in new[] { "DesktopPlatform.slnx", "win.slnx" })
        {
            var solution = XDocument.Load(Path.Combine(Root, name));
            foreach (var reference in solution.Descendants("Project"))
            {
                string path = reference.Attribute("Path")!.Value;
                Xunit.Assert.True(File.Exists(Path.Combine(Root, path)), path);
            }
        }

        foreach (string name in new[] { "ArcChat", "ArcNotes", "ArcScope", "ArcSlate", "Cloud", "Web", "Mobile", "Contracts", "SDK" })
        {
            Xunit.Assert.False(Directory.Exists(Path.Combine(Root, "src", name)), name);
        }

        Xunit.Assert.False(File.Exists(Path.Combine(Root, ".gitmodules")));
        Xunit.Assert.False(Directory.Exists(Path.Combine(Root, "native", "arcscope-mdf-abi")));
    }

    [Xunit.Fact]
    public void ProjectReferencesStayInsideThisRepository()
    {
        foreach (string file in Files("*.csproj"))
        {
            foreach (var reference in XDocument.Load(file).Descendants("ProjectReference"))
            {
                string relative = reference.Attribute("Include")!.Value.Replace('\\', Path.DirectorySeparatorChar);
                string target = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(file)!, relative));
                Xunit.Assert.StartsWith(Root + Path.DirectorySeparatorChar, target, StringComparison.OrdinalIgnoreCase);
                Xunit.Assert.True(File.Exists(target), target);
            }
        }
    }

    [Xunit.Fact]
    public void ProductionNativeBindingsHaveOneCapabilityOwner()
    {
        var owners = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["ArcImageNative"] = "ArcForges.Native.Image",
        };
        var exports = new HashSet<string>(StringComparer.Ordinal);
        foreach (string file in Files("*.cs").Where(file => Path.GetRelativePath(Root, file)
            .Replace('\\', '/').StartsWith("src/", StringComparison.Ordinal)))
        {
            string source = File.ReadAllText(file);
            Xunit.Assert.DoesNotMatch(@"\bDllImport\s*\(", source);
            int declarations = System.Text.RegularExpressions.Regex.Count(source, @"\bLibraryImport\s*\(");
            int matched = 0;
            foreach (System.Text.RegularExpressions.Match match in System.Text.RegularExpressions.Regex.Matches(
                source, """LibraryImport\("([^"]+)", EntryPoint = "([^"]+)"\)"""))
            {
                matched++;
                string library = match.Groups[1].Value;
                Xunit.Assert.True(owners.TryGetValue(library, out string? owner), library);
                Xunit.Assert.Equal(Path.Combine(Root, "src", "Native", owner!), Path.GetDirectoryName(file));
                Xunit.Assert.True(exports.Add(library + ":" + match.Groups[2].Value), "Duplicate production binding: " + match.Value);
            }

            Xunit.Assert.Equal(declarations, matched);
        }

        string[] expectedExports =
        [
            "ArcImageNative:arc_image_get_abi_version",
            "ArcImageNative:arc_image_get_build_info",
            "ArcImageNative:arc_image_get_last_error",
        ];
        Xunit.Assert.Equal(expectedExports, exports.OrderBy(value => value, StringComparer.Ordinal));
        foreach (string file in Files("*.csproj").Where(file => Path.GetRelativePath(Root, file)
            .Replace('\\', '/').StartsWith("src/", StringComparison.Ordinal)))
        {
            foreach (var reference in XDocument.Load(file).Descendants("ProjectReference"))
            {
                string target = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(file)!,
                    reference.Attribute("Include")!.Value.Replace('\\', Path.DirectorySeparatorChar)));
                Xunit.Assert.StartsWith(Path.Combine(Root, "src") + Path.DirectorySeparatorChar, target, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    [Xunit.Fact]
    public void PublishedProjectsAreExplicitAndContainNoPlaceholders()
    {
        using var manifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "eng", "packaging", "packages.json")));
        var allowed = manifest.RootElement.GetProperty("packages").EnumerateArray()
            .Select(package => Path.GetFullPath(Path.Combine(Root, package.GetProperty("project").GetString()!)))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        Xunit.Assert.NotEmpty(allowed);
        foreach (string file in Files("*.csproj"))
        {
            bool packable = XDocument.Load(file).Descendants("IsPackable").Any(value => value.Value == "true");
            Xunit.Assert.Equal(allowed.Contains(file), packable);
            if (packable)
            {
                Xunit.Assert.Empty(Directory.EnumerateFiles(Path.GetDirectoryName(file)!, "*Placeholder.cs", SearchOption.AllDirectories));
            }
        }
    }

    [Xunit.Fact]
    public void SourceHeadersAndLicenceArePreserved()
    {
        string[] extensions = [".cs", ".csproj", ".cpp", ".h", ".mm", ".props", ".targets", ".vcxproj", ".cmake", ".py"];
        foreach (string file in Files("*").Where(file => extensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase)
            || Path.GetFileName(file) == "CMakeLists.txt"))
        {
            Xunit.Assert.Contains(File.ReadLines(file).Take(5), line => line.Contains("SPDX-License-Identifier:", StringComparison.Ordinal));
        }

        string license = File.ReadAllText(Path.Combine(Root, "LICENSE")).Replace("\r\n", "\n", StringComparison.Ordinal);
        Xunit.Assert.Equal("8486A10C4393CEE1C25392769DDD3B2D6C242D6EC7928E1414EFFF7DFB2F07EF",
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(license))));
    }

    private static IEnumerable<string> Files(string pattern) =>
        Directory.EnumerateFiles(Root, pattern, SearchOption.AllDirectories).Where(path =>
            !Path.GetRelativePath(Root, path).Split(Path.DirectorySeparatorChar)
                .Any(part => part is ".git" or ".worktree" or "artifacts" or "bin" or "obj"));

    private static string FindRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "DesktopPlatform.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("DesktopPlatform root not found.");
    }
}
