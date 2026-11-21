// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;

namespace ArcForges.Node.Core.Tests;

/// <summary>Linux observation of the filesystem that contains owner data.</summary>
[Trait("env", "linux-real")]
[SupportedOSPlatform("linux")]
public sealed class LinuxDataRootObservationTests
{
    [Fact(Timeout = 120_000)]
    public async Task AnInMemoryDataRootIsReportedAndADiskOneIsNot()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        // tmpfs (/dev/shm, and /tmp in WSL Debian) keeps captured output in memory charged to the attempts: a capability fact and a log
        // warning say so; a disk-backed root (the test binaries' directory) reports "disk".
        Assert.SkipUnless(OperatingSystem.IsLinux() && Directory.Exists("/dev/shm"), "Linux tmpfs.");
        Assert.Equal("tmpfs", Core.Platform.MemoryFileSystems.KindOf("/dev/shm"));
        Assert.Null(Core.Platform.MemoryFileSystems.KindOf(AppContext.BaseDirectory));
        TestContext.Current.TestOutputHelper?.WriteLine($"/tmp: {Core.Platform.MemoryFileSystems.KindOf("/tmp") ?? "disk"}");

        await using (var inMemory = await InProcessNode.Create(parent: "/dev/shm").StartAsync())
        {
            var fact = inMemory.Runtime.Capabilities.PlatformFacts.Single(item => item.Name == "data_root_filesystem").Value;
            Assert.StartsWith("tmpfs (" + inMemory.DataRoot + ")", fact, StringComparison.Ordinal);
            Assert.Contains("node.data_root_in_memory", File.ReadAllText(Path.Combine(inMemory.DataRoot, "logs", "node", "node.log")), StringComparison.Ordinal);
        }

        await using var onDisk = await InProcessNode.Create(parent: AppContext.BaseDirectory).StartAsync();
        Assert.Equal("disk", onDisk.Runtime.Capabilities.PlatformFacts.Single(item => item.Name == "data_root_filesystem").Value);
    }
}
