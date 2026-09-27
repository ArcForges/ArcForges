// SPDX-License-Identifier: AGPL-3.0-only

using System.Diagnostics;
using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace ArcForges.Build.Policy.Architecture;

/// <summary>Reads effective MSBuild inputs after the owning build. It never restores packages or builds references.</summary>
internal sealed class ProjectGraph
{
    private readonly IReadOnlyDictionary<string, ProjectFacts> _projects;

    public ProjectGraph(IEnumerable<ProjectFacts> projects)
    {
        ArgumentNullException.ThrowIfNull(projects);
        _projects = projects.ToDictionary(project => Normalize(project.Classification.Path), StringComparer.Ordinal);
        foreach (var project in _projects.Values)
        {
            foreach (string reference in project.ProjectReferences)
            {
                if (!_projects.ContainsKey(Normalize(reference)))
                {
                    throw new InvalidOperationException($"Unclassified project reference: {project.Classification.Path} -> {reference}");
                }
            }
        }

        foreach (string path in _projects.Keys)
        {
            Visit(path, [], []);
        }
    }

    public IReadOnlyCollection<ProjectFacts> Projects => _projects.Values.ToArray();

    public IEnumerable<ProjectFacts> Closure(string path)
    {
        var visited = new HashSet<string>(StringComparer.Ordinal);
        var pending = new Stack<string>(_projects[Normalize(path)].ProjectReferences.Select(Normalize));
        while (pending.TryPop(out string? current))
        {
            if (!visited.Add(current))
            {
                continue;
            }

            var project = _projects[current];
            yield return project;
            foreach (string reference in project.ProjectReferences)
            {
                pending.Push(Normalize(reference));
            }
        }
    }

    public static ProjectFacts Evaluate(string root, ProjectClassification classification,
        string configuration = "Release", string? sdkDriver = null, string? compatibilityTargets = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        ArgumentNullException.ThrowIfNull(classification);
        string projectPath = ContainedPath(root, classification.Path);
        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = root,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        if (sdkDriver is not null)
        {
            start.ArgumentList.Add(sdkDriver);
        }

        foreach (string argument in new[]
        {
            "msbuild", projectPath, "-nologo", "-target:GenerateGlobalUsings,ResolveReferences,BeforeCompile", "-p:BuildProjectReferences=false",
            "-p:Configuration=" + configuration,
            "-p:EmitCompilerGeneratedFiles=true",
            "-getProperty:TargetFramework,OutputType,PackageLicenseExpression,LicenceBoundary,IsAotCompatible,PublishAot,ManagePackageVersionsCentrally,RestorePackagesWithLockFile,NoWarn,SuppressTrimAnalysisWarnings,EnableTrimAnalyzer,EnableAotAnalyzer,MSBuildProjectFullPath,ProjectAssetsFile,DefineConstants,AssemblyName,CompilerGeneratedFilesOutputPath",
            "-getItem:Compile,ProjectReference,ReferencePath,PackageReference,PackageVersion",
        })
        {
            start.ArgumentList.Add(argument);
        }

        if (compatibilityTargets is not null)
        {
            start.ArgumentList.Add("-p:CustomAfterMicrosoftCommonTargets=" + compatibilityTargets);
        }

        using var process = Process.Start(start) ?? throw new InvalidOperationException("MSBuild did not start.");
        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(120_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("Bounded project evaluation timed out: " + classification.Path);
        }

        string output = outputTask.GetAwaiter().GetResult();
        string error = errorTask.GetAwaiter().GetResult();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"Project evaluation failed: {classification.Path}\n{output}\n{error}");
        }

        using var document = JsonDocument.Parse(output);
        var properties = document.RootElement.GetProperty("Properties").EnumerateObject()
            .ToDictionary(property => property.Name, property => property.Value.GetString() ?? "", StringComparer.Ordinal);
        var items = document.RootElement.GetProperty("Items");
        var versions = ReadItems(items, "PackageVersion").ToDictionary(item => Text(item, "Identity"),
            item => Text(item, "Version"), StringComparer.OrdinalIgnoreCase);
        var packages = ReadItems(items, "PackageReference").ToDictionary(item => Text(item, "Identity"), item =>
        {
            string version = Text(item, "Version");
            return version.Length > 0 ? version : versions.GetValueOrDefault(Text(item, "Identity"), "");
        }, StringComparer.OrdinalIgnoreCase);
        string assetsPath = properties["ProjectAssetsFile"];
        if (!File.Exists(assetsPath))
        {
            throw new InvalidOperationException("Locked restore assets are required before graph evaluation: " + classification.Path);
        }

        using var assets = JsonDocument.Parse(File.ReadAllText(assetsPath));
        foreach (var library in assets.RootElement.GetProperty("libraries").EnumerateObject())
        {
            if (library.Value.GetProperty("type").GetString() != "package")
            {
                continue;
            }

            int separator = library.Name.LastIndexOf('/');
            if (separator < 1)
            {
                throw new InvalidOperationException("Malformed resolved dependency identity: " + library.Name);
            }

            packages[library.Name[..separator]] = library.Name[(separator + 1)..];
        }
        string generated = Path.GetFullPath(properties["CompilerGeneratedFilesOutputPath"], Path.GetDirectoryName(projectPath)!);
        var generatedSources = Directory.Exists(generated) ? Directory.GetFiles(generated, "*.cs", SearchOption.AllDirectories) : [];
        return new ProjectFacts(classification, properties["TargetFramework"], properties["OutputType"],
            properties["PackageLicenseExpression"], properties["LicenceBoundary"],
            ReadItems(items, "ProjectReference").Select(item => Relative(root, Text(item, "FullPath"))).ToArray(),
            ReadItems(items, "Compile").Select(item => Text(item, "FullPath")).Concat(generatedSources).Distinct(StringComparer.Ordinal).ToArray(),
            ReadItems(items, "ReferencePath").Select(item => Text(item, "FullPath")).ToArray(), properties, packages);
    }

    /// <summary>Reconstructs the semantic input of the completed owning build without loading its assemblies.</summary>
    public static CSharpCompilation ReadCompilation(ProjectFacts project)
    {
        ArgumentNullException.ThrowIfNull(project);
        if (project.Sources.Count == 0 || project.AssemblyReferences.Count == 0
            || project.Sources.Concat(project.AssemblyReferences).Any(path => !File.Exists(path)))
        {
            throw new InvalidOperationException("Completed source/reference inputs are required: " + project.Classification.Path);
        }

        var options = new CSharpParseOptions(LanguageVersion.CSharp14,
            preprocessorSymbols: project.Properties.GetValueOrDefault("DefineConstants", "")
                .Split(';', StringSplitOptions.RemoveEmptyEntries));
        var output = project.OutputType switch
        {
            "Library" => OutputKind.DynamicallyLinkedLibrary,
            "Exe" => OutputKind.ConsoleApplication,
            "WinExe" => OutputKind.WindowsApplication,
            _ => throw new InvalidOperationException("Unsupported managed output kind: " + project.OutputType),
        };
        var compilation = CSharpCompilation.Create(project.Properties["AssemblyName"],
            project.Sources.Distinct(StringComparer.Ordinal).Select(path =>
                CSharpSyntaxTree.ParseText(File.ReadAllText(path), options, path)),
            project.AssemblyReferences.Distinct(StringComparer.Ordinal).Select(path => MetadataReference.CreateFromFile(path)),
            new CSharpCompilationOptions(output, allowUnsafe: true,
                nullableContextOptions: NullableContextOptions.Enable));
        var errors = compilation.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error).ToArray();
        if (errors.Length != 0)
        {
            throw new InvalidOperationException("Invalid owning compilation: " + project.Classification.Path + Environment.NewLine
                + string.Join(Environment.NewLine, errors.Select(error => error.ToString())));
        }

        return compilation;
    }

    public static string Normalize(string path) => path.Replace('\\', '/');

    public static string ContainedPath(string root, string relative)
    {
        string fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        string full = Path.GetFullPath(Path.Combine(fullRoot, relative));
        if (!full.StartsWith(fullRoot, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Project input escapes the owning repository: " + relative);
        }

        return full;
    }

    private static string Relative(string root, string full)
    {
        string relative = Normalize(Path.GetRelativePath(root, full));
        _ = ContainedPath(root, relative);
        return relative;
    }

    private static JsonElement.ArrayEnumerator ReadItems(JsonElement items, string name) =>
        items.GetProperty(name).EnumerateArray();

    private static string Text(JsonElement item, string name) =>
        item.TryGetProperty(name, out var value) ? value.GetString() ?? "" : "";

    private void Visit(string path, HashSet<string> active, HashSet<string> complete)
    {
        if (complete.Contains(path))
        {
            return;
        }

        if (!active.Add(path))
        {
            throw new InvalidOperationException("Project reference cycle at " + path);
        }

        foreach (string reference in _projects[path].ProjectReferences)
        {
            Visit(Normalize(reference), active, complete);
        }

        active.Remove(path);
        complete.Add(path);
    }
}
