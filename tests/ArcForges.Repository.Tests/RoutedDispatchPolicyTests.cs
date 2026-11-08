// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;

namespace ArcForges.Repository.Tests;

/// <summary>
/// AF-CTR-05 part N2b, source rules:
/// <list type="bullet">
/// <item>routed calls are recorded in <c>routed_call_log</c> only; <c>remote_command_log</c> (schema step 1) stays for the unserved command
/// kinds, and no source writes it (decisions Q1);</item>
/// <item>the local-submission allowance is derived only from <c>--test-mode</c> and the exact variable (<c>LocalSubmission.ScriptAllowed</c>),
/// and only the host derives it (CTR5-NODE-14: production ignores the variable);</item>
/// <item><c>ExecutionSupervisor.BindingOf</c> is read only by tests (N2a review N-5);</item>
/// <item>every AGENT-only rule of the TaskService bodies reads the caller's cells origin, so a relayed AGENT gets it (decisions B-4).</item>
/// </list>
/// </summary>
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
    public void TheLocalScriptAllowanceIsDerivedOnlyByTheHostFromTestModeAndTheVariable()
    {
        var derivations = Sources().Where(path => File.ReadAllText(path).Contains("LocalSubmission.ScriptAllowed(", StringComparison.Ordinal)).ToList();
        Assert.Equal("NodeHost.cs", Path.GetFileName(Assert.Single(derivations)));
        Assert.Contains("LocalSubmission.ScriptAllowed(options.TestMode, Environment.GetEnvironmentVariable(LocalSubmission.Variable))",
            File.ReadAllText(derivations[0]), StringComparison.Ordinal);
        var readers = Sources().Where(path => File.ReadAllText(path).Contains("ARCFORGES_TEST_ALLOW_LOCAL_SCRIPT_SUBMIT", StringComparison.Ordinal)).ToList();
        Assert.Equal("LocalSubmission.cs", Path.GetFileName(Assert.Single(readers)));
        Assert.Contains("testMode && string.Equals(value, \"1\", StringComparison.Ordinal)",
            File.ReadAllText(readers[0]), StringComparison.Ordinal);
    }

    [Fact]
    public void OnlyTestsReadACallersBinding()
    {
        foreach (var path in Sources())
        {
            var text = File.ReadAllText(path);
            var uses = Regex.Count(text, @"\bBindingOf\(");
            Assert.True(uses == 0 || (Path.GetFileName(path) == "ExecutionSupervisor.cs" && uses == 1), $"{path} reads BindingOf");
        }
    }

    [Fact]
    public void EveryAgentRuleOfTheTaskServiceReadsTheCellsOrigin()
    {
        var text = File.ReadAllText(RepositoryFiles.PathOf("src/ArcForges.Node.Api/TaskServiceHandler.cs"));
        Assert.DoesNotMatch(@"\borigin == Origin\.Agent\b", text);
        Assert.Equal(2, Regex.Count(text, @"caller\.CellsOrigin == Origin\.Agent"));
    }

    [GeneratedRegex(@"(INSERT INTO|UPDATE|DELETE FROM)\s+remote_command_log\b", RegexOptions.IgnoreCase)]
    private static partial Regex RemoteCommandLogWrite();
}
