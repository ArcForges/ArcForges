// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;

namespace ArcForges.Repository.Tests;

/// <summary>Checks the current source boundary after legacy execution and routing withdrawal.</summary>
public sealed partial class RoutedDispatchPolicyTests
{
    private static IEnumerable<string> Sources() =>
        Directory.EnumerateFiles(RepositoryFiles.PathOf("src"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                && !path.Contains(Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar, StringComparison.Ordinal));

    [Fact]
    public void NoSourceWritesRemoteCommandLog()
    {
        foreach (var path in Sources())
        {
            Assert.DoesNotMatch(RemoteCommandLogWrite(), File.ReadAllText(path));
        }
    }

    [Fact]
    public void NoProductionSourceCanRequestLegacyScriptAdmissionFromTheEnvironment()
    {
        foreach (var path in Sources())
        {
            Assert.DoesNotContain("ARCFORGES_TEST_ALLOW_LOCAL_SCRIPT_SUBMIT", File.ReadAllText(path), StringComparison.Ordinal);
        }
    }

    [Fact]
    public void TheListenerRegistersTypedSandboxRunResourceAndDataHandlers()
    {
        var source = File.ReadAllText(RepositoryFiles.PathOf("src/ArcForges.Node.Api/NodeApiServer.cs"));
        foreach (var handler in new[] { "SandboxNodeServiceHandler", "SandboxServiceHandler", "RunServiceHandler",
            "SandboxResourceServiceHandler", "DataServiceHandler", "CenterControlServiceHandler" })
        {
            Assert.Contains(handler, source, StringComparison.Ordinal);
        }

        foreach (var handler in new[] { "TaskServiceHandler", "QueueServiceHandler", "PolicyServiceHandler",
            "WorkspaceServiceHandler", "LocalFileOperationHandler", "FleetServiceHandler" })
        {
            Assert.DoesNotContain("new " + handler + "(", source, StringComparison.Ordinal);
        }
    }

    [GeneratedRegex(@"(INSERT INTO|UPDATE|DELETE FROM)\s+remote_command_log\b", RegexOptions.IgnoreCase)]
    private static partial Regex RemoteCommandLogWrite();
}
