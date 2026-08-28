// SPDX-License-Identifier: AGPL-3.0-only

using System.Diagnostics;

namespace ArcForges.Tests.ArchitectureTests;

/// <summary>
/// Compiles a violation fixture into a throwaway assembly so a rule can be asserted to fail on it.
/// </summary>
/// <remarks>
/// Step 01.04 requires the violation samples to be stored as <c>.cs.txt</c> (so they never participate in
/// this project's own compilation) and to be compiled dynamically at test time. The compilation runs
/// through the .NET SDK — that is, through Roslyn — on a generated project placed outside the repository,
/// with its own empty <c>Directory.Build.*</c> so none of the repository's analyzer, warning or AOT policy
/// applies to a deliberately broken sample.
///
/// The generated project carries no PackageReference. It instead takes a raw <c>Reference</c> to every
/// assembly already sitting in this test project's output directory, which is what lets a fixture bind to
/// real types such as <c>Microsoft.Data.Sqlite.SqliteConnection</c> without a second restore graph and
/// without adding a Roslyn package that <c>implementation-repository-layout.md</c> §12 does not list.
/// Platform types that no <c>net10.0</c> reference set can supply (Android, WebView, upstream native
/// structs) are declared as stubs inside the fixture itself; the rules match on namespace and type
/// identity, so a stub reproduces the violation faithfully.
/// </remarks>
internal static class FixtureCompiler
{
    private static readonly Dictionary<string, string> CompiledFixtures = new(StringComparer.Ordinal);
    private static readonly Lock Gate = new();

    /// <summary>
    /// Compiles <c>Fixtures/{id}Violation.cs.txt</c> into an assembly named <paramref name="assemblyName"/>
    /// and returns the path to it. Results are cached because several rules share a fixture.
    /// </summary>
    internal static string Compile(string repositoryRoot, string id, string assemblyName)
    {
        var key = $"{id}|{assemblyName}";
        lock (Gate)
        {
            if (CompiledFixtures.TryGetValue(key, out var cached))
            {
                return cached;
            }

            var source = Path.Combine(
                repositoryRoot, "tests", "ArchitectureTests", "Fixtures", $"{id.Replace("-", string.Empty, StringComparison.Ordinal)}Violation.cs.txt");
            if (!File.Exists(source))
            {
                throw new FileNotFoundException($"Violation fixture for {id} is missing.", source);
            }

            var workspace = Path.Combine(Path.GetTempPath(), "arcforges-architecture-fixtures", $"{id}-{Guid.NewGuid():N}");
            Directory.CreateDirectory(workspace);

            var referenceDirectory = AppContext.BaseDirectory;
            // Private=false keeps the compiler from copying the whole reference set into the fixture's
            // own output, which would otherwise be a few hundred files per fixture.
            var references = Directory.EnumerateFiles(referenceDirectory, "*.dll")
                .Select(path =>
                    $"    <Reference Include=\"{Path.GetFileNameWithoutExtension(path)}\">"
                    + $"<HintPath>{path}</HintPath><Private>false</Private></Reference>")
                .ToArray();

            File.WriteAllText(Path.Combine(workspace, "Directory.Build.props"), "<Project />");
            File.WriteAllText(Path.Combine(workspace, "Directory.Build.targets"), "<Project />");
            File.WriteAllText(Path.Combine(workspace, "Fixture.cs"), File.ReadAllText(source));
            File.WriteAllText(
                Path.Combine(workspace, "Fixture.csproj"),
                $"""
                 <Project Sdk="Microsoft.NET.Sdk">
                   <PropertyGroup>
                     <TargetFramework>net10.0</TargetFramework>
                     <AssemblyName>{assemblyName}</AssemblyName>
                     <RootNamespace>{assemblyName}</RootNamespace>
                     <Nullable>disable</Nullable>
                     <ImplicitUsings>disable</ImplicitUsings>
                     <EnableDefaultItems>false</EnableDefaultItems>
                     <GenerateDocumentationFile>false</GenerateDocumentationFile>
                     <NoWarn>$(NoWarn);CS0169;CS0649;CS8981</NoWarn>
                     <EnableNETAnalyzers>false</EnableNETAnalyzers>
                     <RestorePackagesWithLockFile>false</RestorePackagesWithLockFile>
                   </PropertyGroup>
                   <ItemGroup>
                     <Compile Include="Fixture.cs" />
                 {string.Join(Environment.NewLine, references)}
                   </ItemGroup>
                 </Project>
                 """);

            var output = Run("dotnet", $"build \"{Path.Combine(workspace, "Fixture.csproj")}\" -c Release -v quiet --nologo", workspace);

            // Only the real build output will do. obj/ also holds a reference assembly with the same file
            // name, and a metadata-only assembly makes the dependency rules silently find nothing.
            var assembly = Directory
                .EnumerateFiles(Path.Combine(workspace, "bin"), $"{assemblyName}.dll", SearchOption.AllDirectories)
                .FirstOrDefault()
                ?? throw new InvalidOperationException($"Fixture {id} did not compile:{Environment.NewLine}{output}");

            CompiledFixtures[key] = assembly;
            return assembly;
        }
    }

    private static string Run(string fileName, string arguments, string workingDirectory)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(fileName, arguments)
            {
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            },
        };

        process.Start();
        var standardOutput = process.StandardOutput.ReadToEnd();
        var standardError = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return standardOutput + standardError;
    }
}
