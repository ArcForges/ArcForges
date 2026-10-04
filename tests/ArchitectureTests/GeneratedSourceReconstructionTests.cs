// SPDX-License-Identifier: AGPL-3.0-only

using System.Diagnostics;
using ArcForges.Build.Policy.Architecture;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace ArcForges.Tests.ArchitectureTests;

/// <summary>
/// Proves that <see cref="ProjectGraph"/> reconstructs a project from the pinned SDK compiler's real source-generator
/// output. The subject is a tiny library whose only generator is the SDK's own regular-expression generator.
/// </summary>
public sealed class GeneratedSourceReconstructionTests
{
    private const string Project = """
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup>
            <TargetFramework>net10.0</TargetFramework>
            <OutputType>Library</OutputType>
            <AssemblyName>GeneratedRegexSubject</AssemblyName>
            <LangVersion>14</LangVersion>
            <Nullable>enable</Nullable>
            <ImplicitUsings>disable</ImplicitUsings>
            <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
          </PropertyGroup>
        </Project>
        """;

    private const string Source = """
        using System.Text.RegularExpressions;

        namespace Subject;

        public static partial class Patterns
        {
            [GeneratedRegex("^a+$")]
            public static partial Regex Letters();
        }
        """;

    private static readonly ProjectClassification Classification =
        new("Subject/Subject.csproj", ProjectRole.Foundation, "DesktopPlatform");

    [Xunit.Fact]
    public void GeneratedRegexPartialImplementationIsReconstructedFromTheSdkGeneratorOutput()
    {
        using var subject = Subject.Create(Source);
        var facts = subject.Evaluate();

        string generated = Xunit.Assert.Single(facts.Sources, path => IsGenerated(subject, path)
            && Path.GetFileName(path) == "RegexGenerator.g.cs");
        Xunit.Assert.Contains("partial global::System.Text.RegularExpressions.Regex Letters()", File.ReadAllText(generated), StringComparison.Ordinal);

        var compilation = ProjectGraph.ReadCompilation(facts);
        var declaration = compilation.SyntaxTrees.SelectMany(tree => tree.GetRoot(Xunit.TestContext.Current.CancellationToken).DescendantNodes().OfType<MethodDeclarationSyntax>())
            .Single(method => method.Identifier.ValueText == "Letters" && IsGenerated(subject, method.SyntaxTree.FilePath));
        var implementation = (IMethodSymbol)compilation.GetSemanticModel(declaration.SyntaxTree).GetDeclaredSymbol(declaration, Xunit.TestContext.Current.CancellationToken)!;
        Xunit.Assert.NotNull(implementation.PartialDefinitionPart);
        Xunit.Assert.Equal("System.Text.RegularExpressions.Regex", implementation.ReturnType.ToDisplayString());
    }

    [Xunit.Fact]
    public void ReconstructionStaysFailClosedWhenTheGeneratedImplementationIsAbsent()
    {
        using var subject = Subject.Create(Source);
        var facts = subject.Evaluate();
        var withoutGenerated = facts with { Sources = facts.Sources.Where(path => !IsGenerated(subject, path)).ToArray() };
        var failure = Xunit.Assert.Throws<InvalidOperationException>(() => ProjectGraph.ReadCompilation(withoutGenerated));
        Xunit.Assert.Contains("CS8795", failure.Message, StringComparison.Ordinal);
    }

    [Xunit.Fact]
    public void StaleOrForgedGeneratedFilesFromAnEarlierBuildAreNeverReused()
    {
        using var subject = Subject.Create(Source);
        _ = subject.Evaluate();

        // The second evaluation runs while the first one's compiler output is up to date, so only a forced real compile
        // can regenerate the sources. Anything left in the generator output directory beforehand must be discarded.
        string forged = Path.Combine(subject.GeneratedRoot, "Forged.g.cs");
        File.WriteAllText(forged, "namespace Subject { internal static class Forged { } }");
        var facts = subject.Evaluate();

        Xunit.Assert.DoesNotContain(facts.Sources, path => string.Equals(path, forged, StringComparison.OrdinalIgnoreCase));
        Xunit.Assert.Contains(facts.Sources, path => Path.GetFileName(path) == "RegexGenerator.g.cs");
        _ = ProjectGraph.ReadCompilation(facts);
    }

    [Xunit.Fact]
    public void CompilerErrorsInTheSelectedProjectFailTheEvaluation()
    {
        using var subject = Subject.Create(Source + Environment.NewLine + "public sealed class Broken : Missing { }");
        var failure = Xunit.Assert.Throws<InvalidOperationException>(subject.Evaluate);
        Xunit.Assert.Contains("CS0246", failure.Message, StringComparison.Ordinal);
    }

    private static bool IsGenerated(Subject subject, string path) =>
        path.StartsWith(subject.GeneratedRoot, StringComparison.OrdinalIgnoreCase);

    private sealed class Subject : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "arcforges-generated-" + Guid.NewGuid().ToString("N"));

        private Subject()
        {
        }

        public string GeneratedRoot => Path.Combine(_root, "Subject", "obj", "arcforges-policy", "Release", "generated");

        public static Subject Create(string source)
        {
            var subject = new Subject();
            _ = Directory.CreateDirectory(Path.Combine(subject._root, "Subject"));
            File.WriteAllText(Path.Combine(subject._root, "Subject", "Subject.csproj"), Project);
            File.WriteAllText(Path.Combine(subject._root, "Subject", "Patterns.cs"), source);
            // The subject compiles with the repository's pinned SDK unless the explicit local driver override is set.
            File.Copy(Path.Combine(FindRoot(), "global.json"), Path.Combine(subject._root, "global.json"));
            subject.Restore();
            return subject;
        }

        public ProjectFacts Evaluate() => ProjectGraph.Evaluate(_root, Classification,
            sdkDriver: Environment.GetEnvironmentVariable("ARCFORGES_LOCAL_SDK_DRIVER"),
            compatibilityTargets: Environment.GetEnvironmentVariable("ARCFORGES_LOCAL_COMPATIBILITY_TARGETS"));

        public void Dispose()
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }

        private void Restore()
        {
            var start = new ProcessStartInfo("dotnet")
            {
                WorkingDirectory = _root,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            if (Environment.GetEnvironmentVariable("ARCFORGES_LOCAL_SDK_DRIVER") is { } driver)
            {
                start.ArgumentList.Add(driver);
            }

            start.ArgumentList.Add("restore");
            start.ArgumentList.Add(Path.Combine(_root, "Subject", "Subject.csproj"));
            start.ArgumentList.Add("-nologo");
            using var process = Process.Start(start) ?? throw new InvalidOperationException("dotnet restore did not start.");
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(300_000))
            {
                process.Kill(entireProcessTree: true);
                throw new TimeoutException("The subject restore timed out.");
            }

            Xunit.Assert.True(process.ExitCode == 0, output.GetAwaiter().GetResult() + error.GetAwaiter().GetResult());
        }

        private static string FindRoot()
        {
            var directory = new DirectoryInfo(AppContext.BaseDirectory);
            while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "DesktopPlatform.slnx")))
            {
                directory = directory.Parent;
            }

            return directory?.FullName ?? throw new InvalidOperationException("Owning repository not found.");
        }
    }
}
