// SPDX-License-Identifier: AGPL-3.0-only

using System.Reflection;
using System.Runtime.CompilerServices;
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
    public void MandatedCiJobNamesArePresent()
    {
        // Step 01.06 fixes these names so every later step's completion gate can reference a gate by name.
        // Renaming one silently would break those references, so the names are asserted, not just written.
        (string Workflow, string[] Jobs)[] contracts =
        [
            ("pr-gate.yml",
            [
                "locked-restore", "format-analyzers", "build", "unit-tests", "integration-tests",
                "architecture-tests", "suppression-audit", "no-inline-versions", "dependency-audit",
                "secret-scan",
            ]),
            ("runtime-publish-smoke.yml", ["desktop-aot", "cloud-jit", "cloud-gc-baseline"]),
            ("release-train.yml",
            [
                "train-desktop-aot", "train-cloud-jit", "train-maui-android", "train-ios-build",
                "train-blazor-web", "train-native-abi-matrix", "train-install-upgrade-rollback",
            ]),
        ];

        foreach ((string workflow, string[] jobs) in contracts)
        {
            var path = Path.Combine(RepositoryRoot.Value, ".github", "workflows", workflow);
            Xunit.Assert.True(File.Exists(path), $"Missing required workflow {workflow}.");

            // Job ids sit at exactly one indent level below the `jobs:` mapping.
            var declared = File.ReadLines(path)
                .Select(line => System.Text.RegularExpressions.Regex.Match(line, "^  ([A-Za-z0-9_-]+):\\s*$"))
                .Where(match => match.Success)
                .Select(match => match.Groups[1].Value)
                .ToHashSet(StringComparer.Ordinal);

            var missing = jobs.Where(job => !declared.Contains(job)).ToArray();
            Xunit.Assert.True(missing.Length == 0, $"{workflow} is missing job(s): {string.Join(", ", missing)}");
        }
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void GatedReleaseTrainJobsDeclareOwnerAndTracking()
    {
        // A gated placeholder may exist, but it must never read as completed work: it has to state its skip
        // reason, its owning step and a tracking item in the job summary.
        var releaseTrain = File.ReadAllText(
            Path.Combine(RepositoryRoot.Value, ".github", "workflows", "release-train.yml"));

        foreach (var gated in new[] { "train-ios-build", "train-install-upgrade-rollback" })
        {
            var section = releaseTrain[releaseTrain.IndexOf($"  {gated}:", StringComparison.Ordinal)..];
            Xunit.Assert.Contains("NOT EXECUTED", section, StringComparison.Ordinal);
            Xunit.Assert.Contains("Skip reason", section, StringComparison.Ordinal);
            Xunit.Assert.Contains("Owning step", section, StringComparison.Ordinal);
            Xunit.Assert.Contains("Tracking", section, StringComparison.Ordinal);
            Xunit.Assert.Contains("GITHUB_STEP_SUMMARY", section, StringComparison.Ordinal);
        }
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void EveryCentralPackageIsRegistered()
    {
        // Step 01.06's dependency-audit gate must fail on an unregistered package. Repository policy
        // forbids tracked helper scripts, so the plan's check-licenses script lives here instead, and the
        // comparison is a set equality in both directions: an unregistered package and a stale row both fail.
        var central = System.Text.RegularExpressions.Regex
            .Matches(File.ReadAllText(Path.Combine(RepositoryRoot.Value, "Directory.Packages.props")),
                "PackageVersion Include=\"([^\"]+)\"")
            .Select(match => match.Groups[1].Value)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var registered = System.Text.RegularExpressions.Regex
            .Matches(File.ReadAllText(Path.Combine(RepositoryRoot.Value, "docs", "compliance", "third-party-license-register.md")),
                @"^\| `([^`]+)` \| ", System.Text.RegularExpressions.RegexOptions.Multiline)
            .Select(match => match.Groups[1].Value)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var unregistered = central.Except(registered, StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal).ToArray();
        var stale = registered.Except(central, StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal).ToArray();

        Xunit.Assert.True(
            unregistered.Length == 0,
            $"Packages missing from the third-party license register: {string.Join(", ", unregistered)}");
        Xunit.Assert.True(
            stale.Length == 0,
            $"Register rows with no central package: {string.Join(", ", stale)}");
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
    public void TrimmingSuppressionCountStaysAtTheStep0105Baseline()
    {
        // Step 01.05 sets the baseline at zero and forbids it rising without an approved ADR. Counting is
        // separate from TrimmingSuppressionsCarryReviewEvidence: a suppression can be perfectly documented
        // and still not belong here.
        const int baseline = 0;
        var unconditionalSuppression = "Unconditional" + "SuppressMessage";

        var suppressions = EnumerateRepositoryFiles("*.cs")
            .SelectMany(source => File.ReadLines(source)
                .Select((line, index) => (Source: source, Line: index + 1, Text: line))
                .Where(entry => entry.Text.Contains(unconditionalSuppression, StringComparison.Ordinal)))
            .Select(entry => $"{Path.GetRelativePath(RepositoryRoot.Value, entry.Source)}:{entry.Line}")
            .ToArray();

        Xunit.Assert.True(
            suppressions.Length == baseline,
            $"Trimming suppression count moved from {baseline} to {suppressions.Length}: {string.Join(", ", suppressions)}");
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void PublishModePropertiesEvaluateToTheirDeclaredValues()
    {
        // implementation-repository-layout.md §13 is explicit that a publish mode must be asserted from the
        // evaluated value, not from the text of a project file: an import, a condition or a Directory.Build
        // file can change the effective value without changing any single csproj. These are read back out of
        // MSBuild's own evaluation.
        (string Project, string Property, string Expected)[] expectations =
        [
            (Path.Combine("src", "ArcChat", "ArcChat.Desktop", "ArcChat.Desktop.csproj"), "PublishAot", "true"),
            (Path.Combine("src", "ArcChat", "ArcChat.Desktop", "ArcChat.Desktop.csproj"), "TrimMode", "full"),
            (Path.Combine("src", "DesktopHelpers", "ArcForges.ContentSandbox", "ArcForges.ContentSandbox.csproj"), "PublishAot", "true"),
            (Path.Combine("src", "Cloud", "ArcForges.Cloud.Host", "ArcForges.Cloud.Host.csproj"), "PublishAot", "false"),
            (Path.Combine("src", "Cloud", "ArcForges.Cloud.Host", "ArcForges.Cloud.Host.csproj"), "PublishTrimmed", "false"),
            (Path.Combine("src", "Web", "ArcForges.Web.App", "ArcForges.Web.App.csproj"), "RunAOTCompilation", "false"),
            (Path.Combine("src", "Web", "ArcForges.Web.App", "ArcForges.Web.App.csproj"), "PublishTrimmed", "true"),
        ];

        foreach ((string project, string property, string expected) in expectations)
        {
            var actual = EvaluateMsBuildProperty(Path.Combine(RepositoryRoot.Value, project), property);
            Xunit.Assert.Equal(expected, actual, StringComparer.OrdinalIgnoreCase);
        }
    }

    private static string EvaluateMsBuildProperty(string project, string property)
    {
        using var process = new System.Diagnostics.Process
        {
            StartInfo = new System.Diagnostics.ProcessStartInfo(
                "dotnet", $"msbuild \"{project}\" -nologo -getProperty:{property}")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                WorkingDirectory = RepositoryRoot.Value,
            },
        };

        process.Start();
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        Xunit.Assert.True(
            process.ExitCode == 0,
            $"Could not evaluate {property} for {project}:{Environment.NewLine}{output}{error}");

        return output.Trim();
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

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ContractProjectsMatchTheFixedReferenceGraph()
    {
        // implementation-repository-layout.md §3 fixes this graph and forbids any other
        // Contract-to-Contract edge. An extra edge and a missing edge both fail here.
        Dictionary<string, string[]> graph = new(StringComparer.Ordinal)
        {
            ["ArcForges.Contracts.Foundation"] = [],
            ["ArcForges.Contracts.Agent"] = ["ArcForges.Contracts.Foundation"],
            ["ArcForges.Contracts.Sync"] = ["ArcForges.Contracts.Foundation"],
            ["ArcForges.Contracts.LocalRpc"] = ["ArcForges.Contracts.Agent", "ArcForges.Contracts.Foundation"],
            ["ArcForges.Contracts.PublicApi"] =
                ["ArcForges.Contracts.Agent", "ArcForges.Contracts.Foundation", "ArcForges.Contracts.Sync"],
            ["ArcForges.Contracts.Realtime"] =
                ["ArcForges.Contracts.Agent", "ArcForges.Contracts.Foundation", "ArcForges.Contracts.Sync"],
            ["ArcForges.Contracts.Serialization"] =
            [
                "ArcForges.Contracts.Agent", "ArcForges.Contracts.Foundation", "ArcForges.Contracts.LocalRpc",
                "ArcForges.Contracts.PublicApi", "ArcForges.Contracts.Realtime", "ArcForges.Contracts.Sync",
            ],
        };

        var contractsRoot = Path.Combine(RepositoryRoot.Value, "src", "Contracts");
        var projects = Directory.EnumerateFiles(contractsRoot, "*.csproj", SearchOption.AllDirectories).ToArray();
        Xunit.Assert.Equal(graph.Count, projects.Length);

        foreach (var project in projects)
        {
            var name = Path.GetFileNameWithoutExtension(project);
            Xunit.Assert.True(graph.ContainsKey(name), $"{name} is not part of the layout §3 contract set.");

            var actual = XDocument.Load(project).Descendants("ProjectReference")
                .Select(element => element.Attribute("Include")?.Value)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => Path.GetFileNameWithoutExtension(value!.Replace('\\', Path.DirectorySeparatorChar)))
                .OrderBy(value => value, StringComparer.Ordinal)
                .ToArray();

            Xunit.Assert.Equal(graph[name], actual);
        }
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void ContractAssembliesGrantInternalsToTheContractTestProjects()
    {
        // Step 02's Required Inputs table names these four assemblies as the consumers of contract
        // internals: the partitioned JsonSerializerContext types are internal, so source-generation
        // coverage, old-vs-new compatibility and generated-only purity all have to reach them. The grant
        // is declared once in eng/build/contracts.props; this asserts the emitted metadata, per assembly.
        string[] grantees =
        [
            "ArcForges.Tests.ArchitectureTests",
            "ArcForges.Tests.ContractCompatibilityTests",
            "ArcForges.Tests.PublicApiContractTests",
            "ArcForges.Tests.RealtimeReconnectTests",
        ];

        string[] contracts =
        [
            "ArcForges.Contracts.Agent", "ArcForges.Contracts.Foundation", "ArcForges.Contracts.LocalRpc",
            "ArcForges.Contracts.PublicApi", "ArcForges.Contracts.Realtime", "ArcForges.Contracts.Serialization",
            "ArcForges.Contracts.Sync",
        ];

        foreach (var contract in contracts)
        {
            var assembly = Assembly.Load(contract);
            var granted = assembly.GetCustomAttributes<InternalsVisibleToAttribute>()
                .Select(attribute => attribute.AssemblyName)
                .OrderBy(value => value, StringComparer.Ordinal)
                .ToArray();

            Xunit.Assert.Equal(grantees.OrderBy(value => value, StringComparer.Ordinal).ToArray(), granted);
        }
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Architecture")]
    public void LayeredBuildPropertyFilesAreImportedByExactlyTheirDeclaredHosts()
    {
        // implementation-repository-layout.md §13 and Step 01.05 assign each property file to one
        // host set. Importing one anywhere else crosses the Native AOT / JIT / WASM boundaries the
        // release gates depend on, and importing it nowhere leaves the gate unattached.
        Dictionary<string, string[]> expected = new(StringComparer.Ordinal)
        {
            ["desktop-aot.props"] =
            [
                "ArcChat.Desktop", "ArcNotes.Desktop", "ArcScope.Desktop", "ArcSlate.Desktop",
                "ArcForges.ContentSandbox",
            ],
            ["desktop-rids.props"] =
            [
                "ArcChat.Desktop", "ArcNotes.Desktop", "ArcScope.Desktop", "ArcSlate.Desktop",
                "ArcForges.ContentSandbox",
            ],
            ["rpc-attach.props"] =
            [
                "ArcChat.Desktop", "ArcNotes.Desktop", "ArcScope.Desktop", "ArcSlate.Desktop",
                "ArcChat.LocalRpc", "ArcNotes.LocalRpc", "ArcScope.LocalRpc", "ArcSlate.LocalRpc",
                "ArcForges.Tests.LocalRpcAotTests",
            ],
            ["contracts.props"] =
            [
                "ArcForges.Contracts.Agent", "ArcForges.Contracts.Foundation",
                "ArcForges.Contracts.LocalRpc", "ArcForges.Contracts.PublicApi",
                "ArcForges.Contracts.Realtime", "ArcForges.Contracts.Serialization",
                "ArcForges.Contracts.Sync",
            ],
            ["cloud-jit.props"] = ["ArcForges.Cloud.Host"],
            ["web-wasm.props"] = ["ArcForges.Web.App"],
            ["mobile.props"] = ["ArcChat.Mobile"],
            ["Android.aot.props"] = ["ArcChat.Mobile"],
        };

        var projects = EnumerateRepositoryFiles("*.csproj").ToArray();
        foreach ((string propertyFile, string[] hosts) in expected)
        {
            var actual = projects
                .Where(project => File.ReadAllText(project).Contains(propertyFile, StringComparison.Ordinal))
                .Select(project => Path.GetFileNameWithoutExtension(project))
                .OrderBy(name => name, StringComparer.Ordinal)
                .ToArray();

            Xunit.Assert.Equal(hosts.OrderBy(name => name, StringComparer.Ordinal).ToArray(), actual);
        }

        // The desktop AOT posture must never reach the Cloud JIT host or the WASM head.
        string cloudHost = File.ReadAllText(Path.Combine(
            RepositoryRoot.Value, "src", "Cloud", "ArcForges.Cloud.Host", "ArcForges.Cloud.Host.csproj"));
        Xunit.Assert.DoesNotContain("desktop-aot.props", cloudHost, StringComparison.Ordinal);
        Xunit.Assert.DoesNotContain("<PublishAot>true</PublishAot>", cloudHost, StringComparison.Ordinal);

        string webApp = File.ReadAllText(Path.Combine(
            RepositoryRoot.Value, "src", "Web", "ArcForges.Web.App", "ArcForges.Web.App.csproj"));
        Xunit.Assert.DoesNotContain("desktop-aot.props", webApp, StringComparison.Ordinal);
        Xunit.Assert.DoesNotContain("<RunAOTCompilation>true</RunAOTCompilation>", webApp, StringComparison.Ordinal);
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
