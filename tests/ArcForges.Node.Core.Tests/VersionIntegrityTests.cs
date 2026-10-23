// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Security;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Read-only version directories with digest checks (AD-0007 section 8; 11 section 1, the tamper finding; AF-SEC-01): a version directory
/// with <c>digests.json</c> is made read-only and verified; an edited, an extra and a missing file are each a mismatch; without a manifest
/// nothing is checked or changed and the fact never says verified. At node level the check runs after startup: the fact
/// <c>version_integrity</c> becomes <c>verified</c> or <c>mismatch: &lt;n&gt; files</c>, a mismatch raises ENFORCEMENT_DEGRADED with the
/// paths, and the files are read-only.
/// </summary>
public sealed class VersionIntegrityTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 60_000)]
    public void AnIntactVersionDirectoryIsVerifiedAndMadeReadOnly()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var directory = CreateVersion();
        try
        {
            var report = VersionIntegrity.Check(directory, Ct);
            Assert.Equal(VersionIntegrity.Verified, report.Fact);
            Assert.Equal(0, report.Mismatches);
            Assert.Empty(report.NotReadOnly);
            Assert.Equal(4, report.MadeReadOnly);
            Assert.All(Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories), path => Assert.True(VersionIntegrity.IsReadOnly(path), path));

            // A second run finds them read-only already and still verified.
            var again = VersionIntegrity.Check(directory, Ct);
            Assert.Equal((VersionIntegrity.Verified, 0), (again.Fact, again.MadeReadOnly));
        }
        finally
        {
            Remove(directory);
        }
    }

    [Fact(Timeout = 60_000)]
    public void AnEditedAnExtraAndAMissingFileAreEachAMismatch()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var directory = CreateVersion();
        try
        {
            File.WriteAllText(Path.Combine(directory, "lib", "native.so"), "edited");
            File.WriteAllText(Path.Combine(directory, "extra.txt"), "not listed");
            File.Delete(Path.Combine(directory, "notes.txt"));
            var report = VersionIntegrity.Check(directory, Ct);
            Assert.Equal("mismatch: 3 files", report.Fact);
            Assert.Equal(["lib/native.so"], report.Changed);
            Assert.Equal(["extra.txt"], report.Unlisted);
            Assert.Equal(["notes.txt"], report.Missing);
            Assert.Null(report.Problem);
            Assert.True(VersionIntegrity.IsReadOnly(Path.Combine(directory, "extra.txt")), "Every file is made read-only, listed or not.");
        }
        finally
        {
            Remove(directory);
        }
    }

    [Fact(Timeout = 60_000)]
    public void WithoutAManifestNothingIsCheckedOrChangedAndAnUnusableOneIsAMismatch()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var directory = CreateVersion();
        try
        {
            File.Delete(Path.Combine(directory, VersionIntegrity.ManifestName));
            var report = VersionIntegrity.Check(directory, Ct);
            Assert.Equal(VersionIntegrity.NotChecked, report.Fact);
            Assert.False(report.Checked);
            Assert.Equal(VersionIntegrity.NotChecked, VersionIntegrity.InitialFact(directory));
            Assert.All(Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories), path => Assert.False(VersionIntegrity.IsReadOnly(path), path));

            File.WriteAllText(Path.Combine(directory, VersionIntegrity.ManifestName), "{ \"version\": \"1\" }");
            var unusable = VersionIntegrity.Check(directory, Ct);
            Assert.NotNull(unusable.Problem);
            Assert.Equal("mismatch: 3 files", unusable.Fact);
            Assert.NotEqual(VersionIntegrity.Verified, unusable.Fact);
        }
        finally
        {
            Remove(directory);
        }
    }

    /// <summary>
    /// At node level: the check runs after the node is ready. A tampered version directory raises ENFORCEMENT_DEGRADED with the paths and
    /// reports <c>mismatch: 2 files</c>; an intact one reports <c>verified</c> and raises nothing; a node without a manifest (the test
    /// build output) reports <c>not checked: no digest manifest</c>. The files are read-only after startup.
    /// </summary>
    [Fact(Timeout = 180_000)]
    public async Task TheNodeVerifiesItsVersionDirectoryAfterStartup()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var intact = CreateVersion();
        var tampered = CreateVersion();
        try
        {
            File.WriteAllText(Path.Combine(tampered, "notes.txt"), "edited after installation");
            File.WriteAllText(Path.Combine(tampered, "lib", "dropped.dll"), "not listed");

            await using (var node = InProcessNode.Create())
            {
                node.VersionDirectory = tampered;
                await node.StartAsync();
                await using var channel = await node.ChannelAsync();
                Assert.Equal("mismatch: 2 files", await FinalFactAsync(channel));
                var finding = Assert.Single(node.Runtime.Store.Read(reader => ExecutionFindings.OpenFor(reader, "node", node.Runtime.NodeId.Span)),
                    item => item.Kind == FindingKind.EnforcementDegraded);
                Assert.Equal(Severity.Error, finding.Severity);
                Assert.Contains(finding.Evidence, item => item.Name == "changed" && item.Value == "notes.txt");
                Assert.Contains(finding.Evidence, item => item.Name == "unlisted" && item.Value == "lib/dropped.dll");
                Assert.Contains(finding.Evidence, item => item.Name == "missing" && item.Value == "-");
                Assert.All(Directory.EnumerateFiles(tampered, "*", SearchOption.AllDirectories), path => Assert.True(VersionIntegrity.IsReadOnly(path), path));
            }

            await using (var node = InProcessNode.Create())
            {
                node.VersionDirectory = intact;
                await node.StartAsync();
                await using var channel = await node.ChannelAsync();
                Assert.Equal(VersionIntegrity.Verified, await FinalFactAsync(channel));
                Assert.DoesNotContain(node.Runtime.Store.Read(reader => ExecutionFindings.OpenFor(reader, "node", node.Runtime.NodeId.Span)),
                    item => item.Kind == FindingKind.EnforcementDegraded);
                Assert.All(Directory.EnumerateFiles(intact, "*", SearchOption.AllDirectories), path => Assert.True(VersionIntegrity.IsReadOnly(path), path));
            }

            await using (var node = await InProcessNode.Create().StartAsync())
            {
                await using var channel = await node.ChannelAsync();
                Assert.Equal(VersionIntegrity.NotChecked, await FinalFactAsync(channel));
            }
        }
        finally
        {
            Remove(intact);
            Remove(tampered);
        }
    }

    /// <summary>The fact <c>version_integrity</c> once the check finished (bounded).</summary>
    private static async Task<string> FinalFactAsync(ArcForges.Client.NodeChannel channel)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (true)
        {
            var response = await channel.Node.GetCapabilitiesAsync(new NodeServiceGetCapabilitiesRequest { Meta = new RequestMeta() }, deadline: DateTime.UtcNow.AddSeconds(10),
                cancellationToken: Ct);
            Assert.Null(response.Error);
            var fact = Assert.Single(response.Value.Capabilities.PlatformFacts, item => item.Name == VersionIntegrity.FactName).Value;
            if (fact != VersionIntegrity.Checking || DateTime.UtcNow > deadline)
            {
                return fact;
            }

            await Task.Delay(100, Ct);
        }
    }

    /// <summary>A version directory of four files (one in a subdirectory) and its <c>digests.json</c> in the packaging step's format.</summary>
    internal static string CreateVersion()
    {
        var directory = Directory.CreateTempSubdirectory("arcforges-version-").FullName;
        Directory.CreateDirectory(Path.Combine(directory, "lib"));
        var files = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["arcforges.bin"] = "the node",
            ["notes.txt"] = "notes",
            ["lib/native.so"] = "a native library",
        };
        foreach (var (relative, content) in files)
        {
            File.WriteAllText(Path.Combine(directory, relative.Replace('/', Path.DirectorySeparatorChar)), content);
        }

        var manifest = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var relative in files.Keys)
        {
            manifest[relative] = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(files[relative])));
        }

        using var stream = File.Create(Path.Combine(directory, VersionIntegrity.ManifestName));
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
        writer.WriteStartObject();
        writer.WriteString("version", "0.0.0-test");
        writer.WriteStartObject("files");
        foreach (var (relative, digest) in manifest)
        {
            writer.WriteString(relative, digest);
        }

        writer.WriteEndObject();
        writer.WriteEndObject();
        return directory;
    }

    /// <summary>Makes the files writable again (a read-only file cannot be deleted on Windows) and removes the directory.</summary>
    internal static void Remove(string directory)
    {
        if (!Directory.Exists(directory))
        {
            return;
        }

        foreach (var path in Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories))
        {
            if (OperatingSystem.IsWindows())
            {
                File.SetAttributes(path, File.GetAttributes(path) & ~FileAttributes.ReadOnly);
            }
            else
            {
                File.SetUnixFileMode(path, File.GetUnixFileMode(path) | UnixFileMode.UserWrite);
            }
        }

        Directory.Delete(directory, recursive: true);
    }
}
