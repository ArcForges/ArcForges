// SPDX-License-Identifier: AGPL-3.0-only

using System.Reflection;
using System.Text.Json;

namespace ArcForges.Testing;

public static class ReferencedModuleContract
{
    public static IReadOnlyList<string> Verify(Assembly testAssembly)
    {
        ArgumentNullException.ThrowIfNull(testAssembly);

        string assemblyPath = testAssembly.Location;
        string depsPath = Path.ChangeExtension(assemblyPath, ".deps.json");
        if (!File.Exists(depsPath))
        {
            throw new InvalidOperationException($"Dependency manifest is missing for {testAssembly.GetName().Name}.");
        }

        using FileStream stream = File.OpenRead(depsPath);
        using JsonDocument document = JsonDocument.Parse(stream);
        JsonElement targets = document.RootElement.GetProperty("targets");
        JsonElement target = targets.EnumerateObject().Single().Value;

        string testName = testAssembly.GetName().Name ?? string.Empty;
        List<string> verified = [];
        foreach (JsonProperty library in target.EnumerateObject())
        {
            string name = library.Name.Split('/')[0];
            if (!IsProductionAssembly(name, testName) || !library.Value.TryGetProperty("runtime", out _))
            {
                continue;
            }

            Assembly assembly = Assembly.Load(new AssemblyName(name));
            Type? identity = assembly.GetType($"{RootNamespace(name)}.AssemblyPlaceholder", throwOnError: false);
            if (identity is null)
            {
                continue;
            }

            object? declaredName = identity.GetField("Name", BindingFlags.Public | BindingFlags.Static)?.GetValue(null);
            if (!string.Equals(name, declaredName as string, StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"{name} did not execute a matching public AssemblyPlaceholder.Name contract.");
            }

            verified.Add(name);
        }

        if (verified.Count == 0)
        {
            throw new InvalidOperationException($"{testName} executes no referenced production module.");
        }

        verified.Sort(StringComparer.Ordinal);
        return verified;
    }

    private static bool IsProductionAssembly(string name, string testName) =>
        !string.Equals(name, testName, StringComparison.Ordinal) &&
        !name.Contains("Tests", StringComparison.Ordinal) &&
        (name.StartsWith("ArcForges.", StringComparison.Ordinal) ||
         name.StartsWith("ArcChat.", StringComparison.Ordinal) ||
         name.StartsWith("ArcNotes.", StringComparison.Ordinal) ||
         name.StartsWith("ArcScope.", StringComparison.Ordinal) ||
         name.StartsWith("ArcSlate.", StringComparison.Ordinal));

    private static string RootNamespace(string assemblyName)
    {
        int tests = assemblyName.IndexOf(".Tests", StringComparison.Ordinal);
        return tests >= 0 ? assemblyName[..tests] : assemblyName;
    }
}
