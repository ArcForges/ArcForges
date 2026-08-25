// SPDX-License-Identifier: AGPL-3.0-only

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

namespace ArcForges.Tests.ArchitectureTests;

public sealed class RepositoryPolicyTests
{
    private const string LicenseSha256 = "8486A10C4393CEE1C25392769DDD3B2D6C242D6EC7928E1414EFFF7DFB2F07EF";
    private static readonly Lazy<string> RepositoryRoot = new(FindRepositoryRoot);

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void RepositoryLayoutMatchesFoundationContract()
    {
        var root = RepositoryRoot.Value;
        string[] required =
        [
            "global.json", "Directory.Build.props", "Directory.Build.targets", "Directory.Packages.props",
            "NuGet.config", "ArcForges.slnx", "win.slnx", "CMakeLists.txt", "CMakePresets.json",
            ".editorconfig", ".gitignore", ".gitattributes", "LICENSE", "README.md", "NOTICE.md",
            "eng", "src", "native", "tests", "docs", ".github",
        ];

        var missing = required.Where(path => !Path.Exists(Path.Combine(root, path))).ToArray();
        Xunit.Assert.True(missing.Length == 0, $"Missing repository entries: {string.Join(", ", missing)}");

        var managed = EnumerateRepositoryFiles("*.csproj").Count();
        var native = Directory.EnumerateFiles(Path.Combine(root, "native"), "*.vcxproj", SearchOption.AllDirectories).Count();
        var shims = Directory.EnumerateDirectories(Path.Combine(root, "native"), "*-abi", SearchOption.TopDirectoryOnly).Count();
        Xunit.Assert.Equal(166, managed);
        Xunit.Assert.Equal(5, native);
        Xunit.Assert.Equal(6, shims);
        Xunit.Assert.False(File.Exists(Path.Combine(root, "vcpkg.json")), "Native dependencies use the documented classic vcpkg installation.");

        var nativeProjects = Directory.EnumerateFiles(Path.Combine(root, "native"), "*.vcxproj", SearchOption.AllDirectories);
        foreach (var project in nativeProjects)
        {
            var xml = File.ReadAllText(project);
            Xunit.Assert.DoesNotMatch("<(ClCompile|ClInclude)\\s+Include=\"[^\"]*[?*]", xml);
        }

        var nativeBuildFiles = EnumerateRepositoryFiles("*")
            .Where(path => Path.GetFileName(path) == "CMakeLists.txt"
                || Path.GetExtension(path) is ".cmake" or ".vcxproj"
                || Path.GetFileName(path) == ".clangd");
        foreach (var file in nativeBuildFiles)
        {
            var content = File.ReadAllText(file);
            Xunit.Assert.DoesNotContain("c++23", content, StringComparison.OrdinalIgnoreCase);
            Xunit.Assert.DoesNotContain("std:c++latest", content, StringComparison.OrdinalIgnoreCase);
            Xunit.Assert.DoesNotContain("c++2b", content, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ManagedTestsUseTheMicrosoftTestingPlatformContract()
    {
        using var globalJson = JsonDocument.Parse(File.ReadAllText(Path.Combine(RepositoryRoot.Value, "global.json")));
        var runner = globalJson.RootElement
            .GetProperty("test")
            .GetProperty("runner")
            .GetString();
        Xunit.Assert.Equal("Microsoft.Testing.Platform", runner);

        var pullRequestGate = File.ReadAllText(Path.Combine(RepositoryRoot.Value, ".github", "workflows", "pr-gate.yml"));
        Xunit.Assert.DoesNotContain("--filter ", pullRequestGate, StringComparison.Ordinal);
        Xunit.Assert.DoesNotContain("--ignore-exit-code 8", pullRequestGate, StringComparison.Ordinal);
        Xunit.Assert.Contains("dotnet test --solution ArcForges.slnx", pullRequestGate, StringComparison.Ordinal);
        Xunit.Assert.Contains("-p:ArcForgesManagedTestTaxonomy=true", pullRequestGate, StringComparison.Ordinal);
        Xunit.Assert.Contains("--filter-trait Category=Unit", pullRequestGate, StringComparison.Ordinal);
        Xunit.Assert.Contains("dotnet test --project tests/Web/ArcForges.Web.BrowserTests", pullRequestGate, StringComparison.Ordinal);
        Xunit.Assert.Contains("--filter-trait Category=Browser", pullRequestGate, StringComparison.Ordinal);

        string[] separatelyGatedProjects =
        [
            Path.Combine("tests", "NativeAbiTests", "ArcForges.Tests.NativeAbiTests.csproj"),
            Path.Combine("tests", "Web", "ArcForges.Web.BrowserTests", "ArcForges.Web.BrowserTests.csproj"),
        ];
        foreach (var project in separatelyGatedProjects)
        {
            var content = File.ReadAllText(Path.Combine(RepositoryRoot.Value, project));
            Xunit.Assert.Contains("Condition=\"'$(ArcForgesManagedTestTaxonomy)' == 'true'\"", content, StringComparison.Ordinal);
            Xunit.Assert.Contains("--ignore-exit-code 8", content, StringComparison.Ordinal);
        }
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void FirstPartySourceFilesDeclareSpdx()
    {
        string[] extensions = [".cs", ".cpp", ".cc", ".cxx", ".mm", ".h", ".hpp", ".cmake", ".props", ".targets", ".vcxproj"];
        var missing = EnumerateRepositoryFiles("*")
            .Where(path => extensions.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase)
                || Path.GetFileName(path) == "CMakeLists.txt")
            .Where(path => !File.ReadLines(path).Take(5).Any(line => line.Contains("SPDX-License-Identifier:", StringComparison.Ordinal)))
            .Select(path => Path.GetRelativePath(RepositoryRoot.Value, path))
            .ToArray();

        Xunit.Assert.True(missing.Length == 0, $"Missing SPDX header: {string.Join(", ", missing)}");
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void RootLicenseMatchesCanonicalAgplText()
    {
        var text = File.ReadAllText(Path.Combine(RepositoryRoot.Value, "LICENSE")).Replace("\r\n", "\n", StringComparison.Ordinal);
        var actual = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
        Xunit.Assert.Equal(LicenseSha256, actual);
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void LockedPackagesContainNoUnapprovedPreviewVersions()
    {
        const string allowedIdentity = "Xamarin.AndroidX.Security.SecurityCrypto/1.1.0.4-alpha07";
        var violations = new List<string>();
        foreach (var lockFile in EnumerateRepositoryFiles("packages*.lock.json"))
        {
            using var document = JsonDocument.Parse(File.ReadAllText(lockFile));
            foreach (var framework in document.RootElement.GetProperty("dependencies").EnumerateObject())
            {
                foreach (var package in framework.Value.EnumerateObject())
                {
                    var value = package.Value;
                    var type = value.GetProperty("type").GetString();
                    var resolved = value.TryGetProperty("resolved", out var resolvedElement) ? resolvedElement.GetString() : null;
                    var identity = $"{package.Name}/{resolved}";
                    if (!string.Equals(type, "Project", StringComparison.Ordinal)
                        && resolved?.Contains('-', StringComparison.Ordinal) == true
                        && !string.Equals(identity, allowedIdentity, StringComparison.Ordinal))
                    {
                        violations.Add($"{Path.GetRelativePath(RepositoryRoot.Value, lockFile)}: {identity}");
                    }
                }
            }
        }

        Xunit.Assert.True(violations.Count == 0, $"Unapproved preview packages: {string.Join(", ", violations)}");
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void TrimmingSuppressionsCarryReviewEvidence()
    {
        var unconditionalSuppression = "Unconditional" + "SuppressMessage";
        var requiresUnreferencedCode = "Requires" + "UnreferencedCode";
        var violations = new List<string>();
        foreach (var source in EnumerateRepositoryFiles("*.cs"))
        {
            var lineNumber = 0;
            foreach (var line in File.ReadLines(source))
            {
                lineNumber++;
                if (!line.Contains(unconditionalSuppression, StringComparison.Ordinal)
                    && !line.Contains(requiresUnreferencedCode, StringComparison.Ordinal))
                {
                    continue;
                }

                if (!line.Contains("reason:", StringComparison.OrdinalIgnoreCase)
                    || !line.Contains("evidence:", StringComparison.OrdinalIgnoreCase)
                    || !line.Contains("owner:", StringComparison.OrdinalIgnoreCase)
                    || !line.Contains("tracking:", StringComparison.OrdinalIgnoreCase)
                    || line.Contains("Scope = \"module\"", StringComparison.OrdinalIgnoreCase)
                    || line.Contains("Scope = \"assembly\"", StringComparison.OrdinalIgnoreCase))
                {
                    violations.Add($"{Path.GetRelativePath(RepositoryRoot.Value, source)}:{lineNumber}");
                }
            }
        }

        Xunit.Assert.True(violations.Count == 0, $"Unreviewed trimming suppressions: {string.Join(", ", violations)}");
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void VcpkgIntegrationUsesClassicInstalledPackagesWithoutRepositoryPaths()
    {
        var root = RepositoryRoot.Value;
        var nativeVcpkg = Path.Combine(root, "eng", "native", "vcpkg");
        Xunit.Assert.Empty(Directory.Exists(Path.Combine(nativeVcpkg, "manifests"))
            ? Directory.EnumerateFiles(Path.Combine(nativeVcpkg, "manifests"), "*", SearchOption.AllDirectories)
            : Enumerable.Empty<string>());
        Xunit.Assert.Empty(Directory.Exists(Path.Combine(nativeVcpkg, "triplets"))
            ? Directory.EnumerateFiles(Path.Combine(nativeVcpkg, "triplets"), "*", SearchOption.AllDirectories)
            : Enumerable.Empty<string>());
        Xunit.Assert.False(File.Exists(Path.Combine(nativeVcpkg, "registry.lock.v1.json")));

        var presets = File.ReadAllText(Path.Combine(root, "CMakePresets.json"));
        Xunit.Assert.Contains("$env{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake", presets, StringComparison.Ordinal);
        Xunit.Assert.DoesNotContain("VCPKG_MANIFEST", presets, StringComparison.Ordinal);
        Xunit.Assert.DoesNotContain("VCPKG_INSTALLED_DIR", presets, StringComparison.Ordinal);
        Xunit.Assert.DoesNotContain("arc-runtime-", presets, StringComparison.Ordinal);
        Xunit.Assert.DoesNotContain("arc-shim-", presets, StringComparison.Ordinal);

        var msbuild = File.ReadAllText(Path.Combine(root, "native", "windows", "ArcForges.Native.props"));
        Xunit.Assert.DoesNotContain("VcpkgRoot", msbuild, StringComparison.Ordinal);
        Xunit.Assert.DoesNotContain("VcpkgManifest", msbuild, StringComparison.Ordinal);
        Xunit.Assert.DoesNotContain("VcpkgInstalled", msbuild, StringComparison.Ordinal);
        Xunit.Assert.Contains("bcrypt.lib", msbuild, StringComparison.OrdinalIgnoreCase);

        var deployment = File.ReadAllText(Path.Combine(root, "deploy", "README.md"));
        Xunit.Assert.Matches("commit\\s+`[0-9a-f]{40}`", deployment);
        Xunit.Assert.Contains("vcpkg.exe integrate install", deployment, StringComparison.Ordinal);
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void WindowsNativeRuntimeIsDeployedAppLocalWithoutRuntimeEnvironmentOverrides()
    {
        var root = RepositoryRoot.Value;
        string prefix = "ARCFORGES_NATIVE_";
        string[] forbiddenVariables = [prefix + "BUILD_MODE", prefix + "DIR"];
        string[] textExtensions = [".cs", ".csproj", ".props", ".targets", ".yml", ".yaml", ".md"];
        var offenders = EnumerateRepositoryFiles("*")
            .Where(path => textExtensions.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase))
            .Where(path => forbiddenVariables.Any(variable => File.ReadAllText(path).Contains(variable, StringComparison.Ordinal)))
            .Select(path => Path.GetRelativePath(root, path))
            .ToArray();
        Xunit.Assert.Empty(offenders);

        var buildTargets = File.ReadAllText(Path.Combine(root, "Directory.Build.targets"));
        Xunit.Assert.Contains("CollectArcForgesWindowsNativeRuntime", buildTargets, StringComparison.Ordinal);
        Xunit.Assert.Contains("CopyToOutputDirectory", buildTargets, StringComparison.Ordinal);
        Xunit.Assert.Contains("CopyToPublishDirectory", buildTargets, StringComparison.Ordinal);

        var nativeAbiProject = File.ReadAllText(Path.Combine(root, "tests", "NativeAbiTests", "ArcForges.Tests.NativeAbiTests.csproj"));
        Xunit.Assert.Contains("ArcForgesDeployWindowsNativeRuntime", nativeAbiProject, StringComparison.Ordinal);

        var solution = XDocument.Load(Path.Combine(root, "win.slnx"));
        var testProject = solution.Descendants("Project").Single(element =>
            string.Equals(
                element.Attribute("Path")?.Value,
                "tests/NativeAbiTests/ArcForges.Tests.NativeAbiTests.csproj",
                StringComparison.Ordinal));
        var dependencies = testProject.Elements("BuildDependency")
            .Select(element => element.Attribute("Project")?.Value)
            .Where(path => path is not null)
            .Select(path => path!)
            .ToHashSet(StringComparer.Ordinal);
        string[] expectedDependencies =
        [
            "native/arcmedia-ffmpeg-abi/windows/arcmedia_ffmpeg_abi.vcxproj",
            "native/arcscope-mdf-abi/windows/arcscope_mdf_abi.vcxproj",
            "native/arcslate-otio-abi/windows/arcslate_otio_abi.vcxproj",
            "native/arcslate-color-abi/windows/arcslate_color_abi.vcxproj",
            "native/arcslate-image-abi/windows/arcslate_image_abi.vcxproj",
        ];
        Xunit.Assert.True(dependencies.SetEquals(expectedDependencies), "Native ABI test build dependencies are incomplete.");
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void NativeDirectDependenciesAreRegisteredAndSupplyChainGatesStayEnabled()
    {
        var root = RepositoryRoot.Value;
        var register = File.ReadAllText(Path.Combine(root, "docs", "compliance", "third-party-license-register.md"));
        var notice = File.ReadAllText(Path.Combine(root, "NOTICE.md"));
        var setup = File.ReadAllText(Path.Combine(root, "deploy", "README.md"));
        var inventory = string.Concat(register, Environment.NewLine, notice);
        var missing = new List<string>();

        string[] directNativeDependencies =
        {
            "ffmpeg", "libusb", "miniaudio", "opentimelineio", "opencolorio",
            "openimageio", "openexr", "imath", "mdflib",
        };
        foreach (var dependency in directNativeDependencies)
        {
            if (!inventory.Contains(dependency, StringComparison.OrdinalIgnoreCase)
                || !setup.Contains(dependency, StringComparison.OrdinalIgnoreCase))
            {
                missing.Add(dependency);
            }
        }

        Xunit.Assert.True(missing.Count == 0, $"Unregistered direct native dependencies: {string.Join(", ", missing.Distinct())}");

        var workflows = Directory.EnumerateFiles(Path.Combine(root, ".github", "workflows"), "*.yml")
            .Select(File.ReadAllText)
            .ToArray();
        Xunit.Assert.Contains(workflows, text => text.Contains("anchore/sbom-action@", StringComparison.Ordinal));
        Xunit.Assert.Contains(workflows, text => text.Contains("actions/dependency-review-action@", StringComparison.Ordinal));
        Xunit.Assert.Contains(workflows, text => text.Contains("ghcr.io/gitleaks/gitleaks:", StringComparison.Ordinal));
        Xunit.Assert.Contains(workflows, text => text.Contains("github/codeql-action/analyze@", StringComparison.Ordinal));
        Xunit.Assert.Contains(workflows, text => text.Contains("  ci:", StringComparison.Ordinal));

        var deepCheck = File.ReadAllText(Path.Combine(root, ".github", "workflows", "deep-check.yml"));
        Xunit.Assert.Contains("languages: csharp", deepCheck, StringComparison.Ordinal);
        Xunit.Assert.DoesNotContain("language: [csharp, cpp]", deepCheck, StringComparison.Ordinal);
        Xunit.Assert.Contains("-DCMAKE_CXX_CLANG_TIDY=clang-tidy", deepCheck, StringComparison.Ordinal);

        var pullRequestGate = File.ReadAllText(Path.Combine(root, ".github", "workflows", "pr-gate.yml"));
        var releaseTrain = File.ReadAllText(Path.Combine(root, ".github", "workflows", "release-train.yml"));
        foreach (var workflow in new[] { pullRequestGate, releaseTrain, deepCheck })
        {
            Xunit.Assert.Contains("steps.vcpkg-toolchain.outputs.fingerprint", workflow, StringComparison.Ordinal);
            Xunit.Assert.Contains("checkout --detach --force", workflow, StringComparison.Ordinal);
        }
        foreach (var workflow in new[] { pullRequestGate, releaseTrain })
        {
            Xunit.Assert.DoesNotContain("vcpkg-classic-Windows-x64-", workflow, StringComparison.Ordinal);
        }

        var hooks = File.ReadAllText(Path.Combine(root, ".pre-commit-config.yaml"));
        Xunit.Assert.Contains("pre-commit/mirrors-clang-format", hooks, StringComparison.Ordinal);
        Xunit.Assert.Contains("repository-hooks:", pullRequestGate, StringComparison.Ordinal);

        var helperScripts = EnumerateRepositoryFiles("*")
            .Where(path => Path.GetExtension(path) is ".ps1" or ".sh")
            .Select(path => Path.GetRelativePath(root, path))
            .ToArray();
        Xunit.Assert.True(helperScripts.Length == 0, $"Tracked helper scripts are forbidden: {string.Join(", ", helperScripts)}");
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void NativeBuildEntrypointsMatchOwnedSourcesHeadersExportsAndProfiles()
    {
        var nativeRoot = Path.Combine(RepositoryRoot.Value, "native");
        var solution = XDocument.Load(Path.Combine(RepositoryRoot.Value, "win.slnx"));
        var solutionProjects = solution.Descendants("Project")
            .Select(element => element.Attribute("Path")?.Value?.Replace('/', Path.DirectorySeparatorChar))
            .Where(path => path is not null)
            .Select(path => Path.GetFullPath(Path.Combine(RepositoryRoot.Value, path!)))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var project in Directory.EnumerateFiles(nativeRoot, "*.vcxproj", SearchOption.AllDirectories))
        {
            var shimRoot = Directory.GetParent(Path.GetDirectoryName(project)!)!.FullName;
            var document = XDocument.Load(project);
            Xunit.Assert.Contains(Path.GetFullPath(project), solutionProjects);

            var projectSources = document.Descendants()
                .Where(element => element.Name.LocalName == "ClCompile" && element.Attribute("Include") is not null)
                .Select(element => ResolveProjectItem(project, element.Attribute("Include")!.Value))
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            var ownedSources = Directory.EnumerateFiles(Path.Combine(shimRoot, "src"), "*", SearchOption.AllDirectories)
                .Where(path => Path.GetExtension(path) is ".cpp" or ".cc" or ".cxx")
                .Append(Path.Combine(nativeRoot, "shared", "src", "arc_native_abi.cpp"))
                .Select(Path.GetFullPath)
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            Xunit.Assert.True(
                ownedSources.SequenceEqual(projectSources, StringComparer.OrdinalIgnoreCase),
                $"{Path.GetRelativePath(RepositoryRoot.Value, project)} source list differs from its owned src tree.");

            var projectHeaders = document.Descendants()
                .Where(element => element.Name.LocalName == "ClInclude" && element.Attribute("Include") is not null)
                .Select(element => ResolveProjectItem(project, element.Attribute("Include")!.Value))
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            var ownedHeaders = Directory.EnumerateFiles(Path.Combine(shimRoot, "include"), "*.h", SearchOption.AllDirectories)
                .Append(Path.Combine(nativeRoot, "shared", "include", "arc", "arc_native_abi.h"))
                .Append(Path.Combine(nativeRoot, "shared", "src", "arc_native_abi_internal.hpp"))
                .Select(Path.GetFullPath)
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            Xunit.Assert.True(
                ownedHeaders.SequenceEqual(projectHeaders, StringComparer.OrdinalIgnoreCase),
                $"{Path.GetRelativePath(RepositoryRoot.Value, project)} header list differs from its owned include tree.");

            var headerExports = ownedHeaders
                .SelectMany(File.ReadLines)
                .Where(line => line.TrimStart().StartsWith("ARC_ABI_EXPORT ", StringComparison.Ordinal))
                .Select(ExtractExportName)
                .Where(name => name is not null)
                .Select(name => name!)
                .ToHashSet(StringComparer.Ordinal);
            var windowsExports = File.ReadLines(Path.Combine(shimRoot, "exports", "windows.def"))
                .Select(line => line.Trim())
                .Where(line => line.StartsWith("arc_", StringComparison.Ordinal))
                .ToHashSet(StringComparer.Ordinal);
            var macExports = File.ReadLines(Path.Combine(shimRoot, "exports", "macos.exports"))
                .Select(line => line.Trim().TrimStart('_'))
                .Where(line => line.StartsWith("arc_", StringComparison.Ordinal))
                .ToHashSet(StringComparer.Ordinal);
            var linuxExports = File.ReadAllText(Path.Combine(shimRoot, "exports", "linux.map"))
                .Split([';', '\r', '\n'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Where(line => line.StartsWith("arc_", StringComparison.Ordinal))
                .ToHashSet(StringComparer.Ordinal);
            Xunit.Assert.True(headerExports.SetEquals(windowsExports), $"{Path.GetFileName(shimRoot)} Windows export allowlist differs from its C header.");
            Xunit.Assert.True(headerExports.SetEquals(macExports), $"{Path.GetFileName(shimRoot)} macOS export allowlist differs from its C header.");
            Xunit.Assert.True(headerExports.SetEquals(linuxExports), $"{Path.GetFileName(shimRoot)} Linux export allowlist differs from its C header.");

            bool expectedStatic = Path.GetFileName(shimRoot) != "arcmedia-ffmpeg-abi";
            bool usesStatic = bool.Parse(document.Descendants().Single(element => element.Name.LocalName == "VcpkgUseStatic").Value);
            Xunit.Assert.Equal(expectedStatic, usesStatic);
        }

        var rootCmake = File.ReadAllText(Path.Combine(nativeRoot, "CMakeLists.txt"));
        foreach (string shim in Directory.EnumerateDirectories(nativeRoot, "*-abi").Select(Path.GetFileName)!)
        {
            Xunit.Assert.Contains($"add_subdirectory({shim})", rootCmake, StringComparison.Ordinal);
        }
    }

    private static string? ExtractExportName(string declaration)
    {
        int open = declaration.IndexOf('(', StringComparison.Ordinal);
        if (open < 0)
        {
            return null;
        }

        string prefix = declaration[..open].Trim();
        int separator = prefix.LastIndexOf(' ');
        return separator >= 0 ? prefix[(separator + 1)..] : null;
    }

    private static IEnumerable<string> EnumerateRepositoryFiles(string pattern) =>
        Directory.EnumerateFiles(RepositoryRoot.Value, pattern, SearchOption.AllDirectories)
            .Where(path => !IsGeneratedPath(path));

    private static bool IsGeneratedPath(string path)
    {
        var relative = Path.GetRelativePath(RepositoryRoot.Value, path);
        string[] generatedSegments = ["bin", "obj", "artifacts", ".packages", ".git", ".worktree"];
        return relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .Any(segment => generatedSegments.Contains(segment, StringComparer.OrdinalIgnoreCase));
    }

    private static string ResolveProjectItem(string project, string include)
    {
        var normalized = include.Replace('\\', Path.DirectorySeparatorChar).Replace('/', Path.DirectorySeparatorChar);
        return Path.GetFullPath(Path.Combine(Path.GetDirectoryName(project)!, normalized));
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "ArcForges.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("ArcForges repository root was not found.");
    }
}
