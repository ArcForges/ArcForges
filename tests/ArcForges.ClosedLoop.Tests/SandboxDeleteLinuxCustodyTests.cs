// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Platform;

namespace ArcForges.ClosedLoop.Tests;

public sealed class SandboxDeleteLinuxCustodyTests
{
    private const string LinuxDeleteCustodyRunIdVariable = "ARCFORGES_MXC_DELETE_CUSTODY_RUN_ID";

    [Fact(Timeout = 145_000, DisableParallelization = true)]
    public async Task InstalledSandboxDeletePreservesSiblingAndHostGrantInLinuxCustody()
    {
        var runId = RequireLinuxDeleteCustodyRun();
        var dataRoot = RequireEmptyLinuxDeleteCustodyDataRoot(runId, "normal");
        await MxcRunServiceTests.VerifyInstalledDeleteAfterManagedUseAsync(dataRoot, TestContext.Current.CancellationToken);
    }

    [Fact(Timeout = 300_000, DisableParallelization = true)]
    public async Task InstalledSandboxDeleteReconcilesInterruptedOwnedBoundariesInLinuxCustody()
    {
        var runId = RequireLinuxDeleteCustodyRun();
        const string faultPrefix = "hold-delete-";
        await MxcRunServiceTests.VerifyInstalledDeleteRecoveryAsync(TestContext.Current.CancellationToken,
            checkpoint => RequireEmptyLinuxDeleteCustodyDataRoot(runId, checkpoint[faultPrefix.Length..]));
    }

    [Fact(Timeout = 60_000, DisableParallelization = true)]
    public async Task InstalledNodeRefusesMissingLinuxCustodyBeforeCreatingState()
    {
        var runId = RequireLinuxDeleteCustodyRun();
        var token = TestContext.Current.CancellationToken;
        var instance = $"/var/lib/arcforges/file02-{runId}-unprovisioned";
        var dataRoot = Path.Combine(instance, "data");
        Assert.False(Path.Exists(instance));
        await using var fixture = TestNode.Create();
        fixture.Environment[LinuxSandboxDeletionAuthority.SelectionVariable] = "1";
        var config = Path.Combine(fixture.ConfigDirectory, "node.json");
        await File.WriteAllTextAsync(config, "{ \"dataRoot\": " + JsonSerializer.Serialize(dataRoot) + " }", token);

        using var process = fixture.StartProduct(["node", "run", NodeLocations.TestModeOption]);
        var result = await TestNode.CompleteAsync(process, TimeSpan.FromSeconds(25));
        Assert.Equal(NodeExitCodes.Failure, result.ExitCode);
        Assert.Contains("the node cannot start: native_2", result.Error, StringComparison.Ordinal);
        Assert.False(Path.Exists(instance));
        Assert.False(Path.Exists(fixture.Endpoint));
        Assert.Null(EndpointDescriptor.TryRead(NodeLocations.EndpointDescriptorFile(dataRoot)));
    }

    private static string RequireLinuxDeleteCustodyRun()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux protected storage requires native Linux.");
        var runId = Environment.GetEnvironmentVariable(LinuxDeleteCustodyRunIdVariable);
        Assert.SkipUnless(runId is not null, $"{LinuxDeleteCustodyRunIdVariable} selects fresh Linux custody fixtures for this native run.");
        Assert.Matches("\\A[0-9a-f]{32}\\z", runId);
        Assert.Equal("1", Environment.GetEnvironmentVariable("ARCFORGES_MXC_PACKAGE_TESTS"));
        Assert.Equal(Environment.GetEnvironmentVariable("ARCFORGES_HOST_PATH"), TestNode.Host);
        Assert.Equal("1", Environment.GetEnvironmentVariable(LinuxSandboxDeletionAuthority.SelectionVariable));
        return runId;
    }

    private static string RequireEmptyLinuxDeleteCustodyDataRoot(string runId, string scenario)
    {
        // The selected service UID runs this test, the installed Node and the CLI. The administrator
        // provisions every case independently. The test creates no users, mounts, or custody records.
        var dataRoot = $"/var/lib/arcforges/file02-{runId}-{scenario}/data";
        Assert.NotNull(LinuxSandboxDeletionAuthority.OpenIfProvisioned(dataRoot));
        Assert.Equal(Path.Combine(dataRoot, "node.lock"), Assert.Single(Directory.EnumerateFileSystemEntries(dataRoot)));
        return dataRoot;
    }
}
