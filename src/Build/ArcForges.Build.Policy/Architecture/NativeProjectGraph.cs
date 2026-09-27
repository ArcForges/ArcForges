// SPDX-License-Identifier: AGPL-3.0-only

using System.Text.Json;

namespace ArcForges.Build.Policy.Architecture;

/// <summary>Consumes the existing owning CMake configure receipt; never configures or executes native code.</summary>
internal static class NativeProjectGraph
{
    public static IReadOnlyList<ProjectFacts> Read(string reportPath, string sourceCommit, string owner)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(reportPath));
        var report = document.RootElement;
        if (report.GetProperty("commit").GetString() != sourceCommit || report.GetProperty("dirty").GetBoolean()
            || report.GetProperty("result").GetString() != "passed"
            || report.GetProperty("evidenceClass").GetString() != "evaluated-cmake-target-declarations")
        {
            throw new InvalidOperationException("Missing or stale owning native target evidence.");
        }

        var targets = report.GetProperty("targets").EnumerateArray().ToArray();
        if (targets.Length == 0)
        {
            throw new InvalidOperationException("No native targets in owning configure receipt.");
        }

        var paths = targets.ToDictionary(target => target.GetProperty("target").GetString()!, target =>
            target.GetProperty("sourceDirectory").GetString() + "/CMakeLists.txt#" + target.GetProperty("target").GetString(), StringComparer.Ordinal);
        return targets.Select(target =>
        {
            string kind = target.GetProperty("targetType").GetString()!;
            var role = kind switch
            {
                "EXECUTABLE" => ProjectRole.NativeWorker,
                "SHARED_LIBRARY" or "STATIC_LIBRARY" or "MODULE_LIBRARY" or "OBJECT_LIBRARY" or "INTERFACE_LIBRARY" => ProjectRole.NativeLibrary,
                "UTILITY" => ProjectRole.BuildTool,
                _ => throw new InvalidOperationException("Unclassified native target kind: " + kind),
            };
            string path = paths[target.GetProperty("target").GetString()!];
            return new ProjectFacts(new ProjectClassification(path, role, owner, Production: !target.GetProperty("testOnly").GetBoolean()), "native", kind,
                target.GetProperty("spdxLicense").GetString()!, target.GetProperty("licenceBoundary").GetString()!,
                target.GetProperty("references").EnumerateArray().Select(reference => reference.GetString()!)
                    .Where(paths.ContainsKey).Select(reference => paths[reference]).Distinct(StringComparer.Ordinal).ToArray(),
                [], [], new Dictionary<string, string>(StringComparer.Ordinal), new Dictionary<string, string>(StringComparer.Ordinal));
        }).ToArray();
    }
}
