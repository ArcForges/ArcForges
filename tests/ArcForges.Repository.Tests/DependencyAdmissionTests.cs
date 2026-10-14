// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ArcForges.Repository.Tests;

/// <summary>Every central package version is admitted in eng/policy/dependency-admissions.json and pinned identically in every lock.</summary>
public sealed partial class DependencyAdmissionTests
{
    private const string Admissions = "eng/policy/dependency-admissions.json";

    [Fact]
    public void EveryCentralPackageVersionHasExactlyOneAdmissionAndViceVersa()
    {
        var central = RepositoryFiles.CentralVersions();
        var admitted = AdmittedPackages().ToList();

        Assert.Equal(admitted.Count, admitted.Select(package => package.Id).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(
            central.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => $"{pair.Key}@{pair.Value}"),
            admitted.OrderBy(package => package.Id, StringComparer.Ordinal).Select(package => $"{package.Id}@{package.Version}"));
    }

    [Fact]
    public void EveryLockRecordsTheAdmittedContentHash()
    {
        var admitted = AdmittedPackages().ToDictionary(package => package.Id, StringComparer.Ordinal);
        var checkedEntries = 0;

        foreach (var lockFile in LockFiles())
        {
            using var document = RepositoryFiles.Json(lockFile);
            foreach (var framework in document.RootElement.GetProperty("dependencies").EnumerateObject())
            {
                foreach (var dependency in framework.Value.EnumerateObject())
                {
                    if (!admitted.TryGetValue(dependency.Name, out var package))
                    {
                        continue;
                    }

                    Assert.Equal(package.Version, dependency.Value.GetProperty("resolved").GetString());
                    Assert.True(
                        package.ContentHash == dependency.Value.GetProperty("contentHash").GetString(),
                        $"{lockFile} records a different content hash for {package.Id}.");
                    checkedEntries++;
                }
            }
        }

        Assert.True(checkedEntries >= admitted.Count, "Every admitted package must appear in at least one lock.");
    }

    [Fact]
    public void NeverAdmittedVersionsAppearNowhere()
    {
        using var document = RepositoryFiles.Json(Admissions);
        var forbidden = document.RootElement.GetProperty("neverAdmit").EnumerateArray()
            .Select(entry => (Id: entry.GetProperty("id").GetString()!, Version: entry.GetProperty("version").GetString()!))
            .ToList();

        Assert.Contains(("ArcForges.Build.Policy", "1.0.0-ci.124.1"), forbidden);
        var central = RepositoryFiles.CentralVersions();
        foreach (var (id, version) in forbidden)
        {
            Assert.False(central.TryGetValue(id, out var pinned) && pinned == version, $"{id} {version} must never be pinned.");
            foreach (var lockFile in LockFiles())
            {
                using var lockDocument = RepositoryFiles.Json(lockFile);
                foreach (var framework in lockDocument.RootElement.GetProperty("dependencies").EnumerateObject())
                {
                    Assert.False(
                        framework.Value.TryGetProperty(id, out var entry) && entry.GetProperty("resolved").GetString() == version,
                        $"{lockFile} resolves the never-admitted {id} {version}.");
                }
            }
        }
    }

    [Fact]
    public void AdmissionsNameLicenceClassAndSourceCommit()
    {
        foreach (var package in AdmittedPackages())
        {
            Assert.Matches(Sha1(), package.SourceCommit);
            Assert.Contains(package.Class, (string[])["runtime", "build-only", "test"]);
            Assert.False(string.IsNullOrWhiteSpace(package.Licence), $"{package.Id} needs a licence.");
            Assert.False(string.IsNullOrWhiteSpace(package.Reason), $"{package.Id} needs a reason.");
        }
    }

    [Fact]
    public void TheBuildPolicyIsABuildOnlyReferenceOfEveryProject()
    {
        var reference = RepositoryFiles.Xml("Directory.Build.props").Descendants("PackageReference")
            .Single(element => (string?)element.Attribute("Include") == "ArcForges.Build.Policy");

        Assert.Equal("all", (string?)reference.Attribute("PrivateAssets"));
        foreach (var lockFile in LockFiles())
        {
            using var document = RepositoryFiles.Json(lockFile);
            var framework = document.RootElement.GetProperty("dependencies").GetProperty("net10.0");
            Assert.True(framework.TryGetProperty("ArcForges.Build.Policy", out var entry), $"{lockFile} must restore ArcForges.Build.Policy.");
            Assert.Equal("Direct", entry.GetProperty("type").GetString());
        }
    }

    private static IEnumerable<string> LockFiles() =>
        RepositoryFiles.Projects("src", "tools", "tests").Select(project => Path.Combine(Path.GetDirectoryName(project)!, "packages.lock.json"));

    private static List<AdmittedPackage> AdmittedPackages()
    {
        using var document = RepositoryFiles.Json(Admissions);
        return document.RootElement.GetProperty("packages").EnumerateArray().Select(entry => new AdmittedPackage(
            entry.GetProperty("id").GetString()!,
            entry.GetProperty("version").GetString()!,
            entry.GetProperty("contentHash").GetString()!,
            entry.GetProperty("licence").GetString()!,
            entry.GetProperty("class").GetString()!,
            entry.GetProperty("sourceCommit").GetString()!,
            entry.GetProperty("reason").GetString()!)).ToList();
    }

    [GeneratedRegex("^[0-9a-f]{40}$")]
    private static partial Regex Sha1();

    private sealed record AdmittedPackage(string Id, string Version, string ContentHash, string Licence, string Class, string SourceCommit, string Reason);
}
