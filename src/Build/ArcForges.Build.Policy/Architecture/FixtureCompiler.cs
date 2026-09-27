// SPDX-License-Identifier: AGPL-3.0-only

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace ArcForges.Build.Policy.Architecture;

/// <summary>Compiles bounded offline fixtures; emitted code is never loaded or executed.</summary>
internal static class FixtureCompiler
{
    public static CSharpCompilation Create(
        string name,
        IReadOnlyDictionary<string, string> sources,
        IEnumerable<string>? references = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(sources);
        if (sources.Count == 0)
        {
            throw new ArgumentException("A fixture requires at least one source file.", nameof(sources));
        }

        var paths = ((string?)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES") ?? "")
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Concat(references ?? [])
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (paths.Length == 0 || paths.Any(path => !File.Exists(path)))
        {
            throw new InvalidOperationException("Compiler metadata references must be existing pinned build inputs.");
        }

        var trees = sources.Select(source => CSharpSyntaxTree.ParseText(source.Value,
            new CSharpParseOptions(LanguageVersion.CSharp14), source.Key));
        return CSharpCompilation.Create(name, trees,
            paths.Select(path => MetadataReference.CreateFromFile(path)),
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, allowUnsafe: true,
                nullableContextOptions: NullableContextOptions.Enable, deterministic: true));
    }

    public static CSharpCompilation Compile(
        string name,
        IReadOnlyDictionary<string, string> sources,
        IEnumerable<string>? references = null)
    {
        var compilation = Create(name, sources, references);
        using var stream = new MemoryStream();
        var result = compilation.Emit(stream);
        if (!result.Success)
        {
            throw new InvalidOperationException("Invalid policy fixture: " + string.Join(Environment.NewLine,
                result.Diagnostics.Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error)));
        }

        return compilation;
    }
}
