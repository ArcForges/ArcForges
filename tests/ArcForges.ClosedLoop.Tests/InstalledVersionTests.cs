// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Security;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// Read-only version directories with digest checks (AD-0007 section 8; AF-SEC-01), end to end: the built <c>arcforges</c> is copied into a
/// temporary version directory with a <c>digests.json</c> in the packaging step's format, and runs from there as the node. After startup
/// the node reports <c>version_integrity</c> <c>verified</c> and every file in the directory is read-only. After an edited listed file and an
/// extra file, the next start reports <c>mismatch: 2 files</c> and raises ENFORCEMENT_DEGRADED (the tamper finding of 11 section 1) with
/// the paths. A node running from the build output (no manifest) reports <c>not checked: no digest manifest</c>.
/// </summary>
public sealed class InstalledVersionTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 300_000)]
    public async Task TheNodeVerifiesTheVersionDirectoryItRunsFrom()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = TestNode.Create();
        var version = Path.Combine(node.Root, "app", "0.0.0-test");
        try
        {
            Copy(Path.GetDirectoryName(Path.GetFullPath(TestNode.Host))!, version);
            File.WriteAllText(Path.Combine(version, "notes.txt"), "installed");
            WriteManifest(version);
            node.NodeExecutable = Path.Combine(version, Path.GetFileName(TestNode.Host));

            var started = Stopwatch.StartNew();
            await node.StartNodeAsync();
            var ready = started.Elapsed;
            await using (var channel = await node.HumanChannelAsync())
            {
                Assert.Equal(VersionIntegrity.Verified, await FinalFactAsync(channel));
            }

            Assert.All(Directory.EnumerateFiles(version, "*", SearchOption.AllDirectories), path => Assert.True(VersionIntegrity.IsReadOnly(path), path));
            await node.StopNodeAsync();
            TestContext.Current.TestOutputHelper?.WriteLine($"ready after {ready.TotalMilliseconds:0} ms from a version directory with digests.json");

            // Tampering: a listed file edited, a file added.
            MakeWritable(Path.Combine(version, "notes.txt"));
            File.WriteAllText(Path.Combine(version, "notes.txt"), "edited after installation");
            File.WriteAllText(Path.Combine(version, "extra.txt"), "not listed");
            await node.StartNodeAsync();
            await using (var channel = await node.HumanChannelAsync())
            {
                Assert.Equal("mismatch: 2 files", await FinalFactAsync(channel));
            }

            await node.StopNodeAsync();
            using var store = ArcForges.Node.Store.NodeStore.Open(new ArcForges.Node.Store.NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = "integrity" });
            var finding = Assert.Single(store.Read(reader => ExecutionFindings.OpenFor(reader, "node", store.Metadata.NodeId.Span)),
                item => item.Kind == FindingKind.EnforcementDegraded);
            Assert.Contains(finding.Evidence, item => item.Name == "changed" && item.Value == "notes.txt");
            Assert.Contains(finding.Evidence, item => item.Name == "unlisted" && item.Value == "extra.txt");

            // The build output has no manifest: nothing is checked, and that is never reported as verified.
            node.NodeExecutable = TestNode.Host;
            await node.StartNodeAsync();
            await using (var channel = await node.HumanChannelAsync())
            {
                Assert.Equal(VersionIntegrity.NotChecked, await FinalFactAsync(channel));
            }

            await node.StopNodeAsync();
        }
        finally
        {
            if (Directory.Exists(version))
            {
                foreach (var path in Directory.EnumerateFiles(version, "*", SearchOption.AllDirectories))
                {
                    MakeWritable(path);
                }
            }
        }
    }

    /// <summary>
    /// category=perf, isolation=exclusive (timing and CPU): the check costs no startup time (it runs after the node is ready) and no idle
    /// CPU (it runs once). The same version directory is started alternately with and without its manifest; each run records the time
    /// until the node answers and the node's CPU time over 10 s once the check finished.
    /// </summary>
    [Fact(Timeout = 900_000, DisableParallelization = true)]
    [Trait("category", "perf")]
    [Trait("isolation", "exclusive")]
    public async Task TheVersionCheckCostsNoStartupTimeAndNoIdleCpu()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        const int Runs = 5;
        await using var node = TestNode.Create();
        var version = Path.Combine(node.Root, "app", "0.0.0-test");
        try
        {
            Copy(Path.GetDirectoryName(Path.GetFullPath(TestNode.Host))!, version);
            WriteManifest(version);
            node.NodeExecutable = Path.Combine(version, Path.GetFileName(TestNode.Host));
            var manifest = Path.Combine(version, VersionIntegrity.ManifestName);
            var results = new Dictionary<bool, List<(double ReadyMs, double IdleCpuMs)>> { [true] = [], [false] = [] };
            for (var run = 0; run < Runs * 2; run++)
            {
                var withManifest = run % 2 == 0;
                if (withManifest != File.Exists(manifest))
                {
                    File.Move(withManifest ? manifest + ".off" : manifest, withManifest ? manifest : manifest + ".off");
                }

                var watch = Stopwatch.StartNew();
                var process = await node.StartNodeAsync();
                var ready = watch.Elapsed.TotalMilliseconds;
                await using (var channel = await node.HumanChannelAsync())
                {
                    Assert.Equal(withManifest ? VersionIntegrity.Verified : VersionIntegrity.NotChecked, await FinalFactAsync(channel));
                }

                process.Refresh();
                var before = process.TotalProcessorTime;
                await Task.Delay(TimeSpan.FromSeconds(10), Ct);
                process.Refresh();
                results[withManifest].Add((ready, (process.TotalProcessorTime - before).TotalMilliseconds));
                await node.StopNodeAsync();
            }

            static double Median(IEnumerable<double> values) => values.Order().ElementAt(Runs / 2);
            var (readyWith, readyWithout) = (Median(results[true].Select(item => item.ReadyMs)), Median(results[false].Select(item => item.ReadyMs)));
            var (cpuWith, cpuWithout) = (Median(results[true].Select(item => item.IdleCpuMs)), Median(results[false].Select(item => item.IdleCpuMs)));
            TestContext.Current.TestOutputHelper?.WriteLine(string.Create(System.Globalization.CultureInfo.InvariantCulture,
                $"median ready: {readyWith:0} ms with digests.json, {readyWithout:0} ms without; median node CPU over 10 s idle: {cpuWith:0} ms with, {cpuWithout:0} ms without"));
            foreach (var (withManifest, list) in results)
            {
                TestContext.Current.TestOutputHelper?.WriteLine((withManifest ? "with:    " : "without: ")
                    + string.Join("; ", list.Select(item => string.Create(System.Globalization.CultureInfo.InvariantCulture, $"ready {item.ReadyMs:0} ms, idle CPU {item.IdleCpuMs:0} ms"))));
            }

            var summary = new System.Text.Json.Nodes.JsonObject
            {
                ["name"] = "version-check-cost",
                ["runs"] = Runs,
                ["readyMedianMsWithManifest"] = Math.Round(readyWith),
                ["readyMedianMsWithoutManifest"] = Math.Round(readyWithout),
                ["idleCpuMedianMsPer10sWithManifest"] = Math.Round(cpuWith),
                ["idleCpuMedianMsPer10sWithoutManifest"] = Math.Round(cpuWithout),
                ["host"] = TestNode.Host,
            };
            if (Environment.GetEnvironmentVariable("ARCFORGES_BENCH_OUTPUT") is { Length: > 0 } output)
            {
                Directory.CreateDirectory(output);
                File.WriteAllText(Path.Combine(output, "version-check-cost-" + (OperatingSystem.IsWindows() ? "windows" : "linux") + ".json"),
                    summary.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            }

            Assert.True(readyWith <= (readyWithout * 1.2) + 50, $"startup got slower: {readyWith:0} ms with the manifest, {readyWithout:0} ms without");
            Assert.True(cpuWith <= (cpuWithout * 1.5) + 20, $"idle CPU grew: {cpuWith:0} ms with the manifest, {cpuWithout:0} ms without");
        }
        finally
        {
            if (Directory.Exists(version))
            {
                foreach (var path in Directory.EnumerateFiles(version, "*", SearchOption.AllDirectories))
                {
                    MakeWritable(path);
                }
            }
        }
    }

    private static async Task<string> FinalFactAsync(NodeChannel channel)
    {
        var deadline = DateTime.UtcNow.AddSeconds(60);
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

            await Task.Delay(200, Ct);
        }
    }

    /// <summary>Copies the build output (without the data roots other tests may have created beside it).</summary>
    private static void Copy(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var file in Directory.EnumerateFiles(source))
        {
            File.Copy(file, Path.Combine(destination, Path.GetFileName(file)));
        }

        foreach (var directory in Directory.EnumerateDirectories(source).Where(path => !Path.GetFileName(path).StartsWith("arcforges-", StringComparison.Ordinal)))
        {
            Copy(directory, Path.Combine(destination, Path.GetFileName(directory)));
        }

        if (!OperatingSystem.IsWindows())
        {
            foreach (var file in Directory.EnumerateFiles(destination))
            {
                var mode = File.GetUnixFileMode(Path.Combine(source, Path.GetFileName(file)));
                File.SetUnixFileMode(file, mode);
            }
        }
    }

    /// <summary>Writes <c>digests.json</c> as the packaging step does: every file except itself, relative paths with / separators.</summary>
    private static void WriteManifest(string version)
    {
        using var stream = File.Create(Path.Combine(version, VersionIntegrity.ManifestName));
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
        writer.WriteStartObject();
        writer.WriteString("version", "0.0.0-test");
        writer.WriteStartObject("files");
        foreach (var path in Directory.EnumerateFiles(version, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            var relative = Path.GetRelativePath(version, path).Replace('\\', '/');
            if (relative != VersionIntegrity.ManifestName)
            {
                writer.WriteString(relative, VersionIntegrity.Sha256(path));
            }
        }

        writer.WriteEndObject();
        writer.WriteEndObject();
    }

    private static void MakeWritable(string path)
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
}
