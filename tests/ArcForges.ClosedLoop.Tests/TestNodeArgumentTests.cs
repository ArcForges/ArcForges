// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.ClosedLoop.Tests;

/// <summary>Local-only fixtures must not mistake option values or process arguments for the CLI root command.</summary>
public sealed class TestNodeArgumentTests
{
    public static TheoryData<string[], string[]> Arguments => new()
    {
        { ["events", "--topic", "tasks", "--topic", "node", "--test-mode"], ["events", "--topic", "tasks", "--topic", "node", "--test-mode"] },
        { ["events", "--topic", "run"], ["events", "--topic", "run"] },
        { ["--timeout", "run", "events", "--topic", "node"], ["--timeout", "run", "events", "--topic", "node"] },
        { ["--wait-approval", "output", "events"], ["--wait-approval", "output", "events"] },
        { ["--timeout", "tasks", "run", "--", "output"], ["--timeout", "tasks", "run", "--local", "--", "output"] },
        { ["--test-mode", "--timeout=1s", "run", "--", "tasks"], ["--test-mode", "--timeout=1s", "run", "--local", "--", "tasks"] },
        { ["run", "--node=remote", "--", "x"], ["run", "--node=remote", "--", "x"] },
        { ["run", "--local=true", "--", "x"], ["run", "--local=true", "--", "x"] },
        { ["--json", "tasks", "--verbose", "wait", "id"], ["--json", "tasks", "--verbose", "wait", "--local", "id"] },
        { ["tasks", "attach", "id"], ["tasks", "attach", "id"] },
        { ["node", "run", "--test-mode"], ["node", "run", "--test-mode"] },
        { ["run", "--", "--node"], ["run", "--local", "--", "--node"] },
        { ["--json=true", "run", "--", "x"], ["--json=true", "run", "--local", "--", "x"] },
        { ["--verbose=false", "tasks", "list"], ["--verbose=false", "tasks", "list", "--local"] },
        { ["tasks", "--timeout", "1s", "wait", "id"], ["tasks", "--timeout", "1s", "wait", "--local", "id"] },
        { ["--unknown", "run"], ["--unknown", "run"] },
        { ["--timeout"], ["--timeout"] },
        { ["events", "--topic=tasks"], ["events", "--topic=tasks"] },
        { ["run", "--json", "start", "sandbox", "--", "--local"], ["run", "--json", "start", "sandbox", "--", "--local"] },
        { ["run", "stop", "run-id"], ["run", "stop", "run-id"] },
    };

    [Theory]
    [MemberData(nameof(Arguments))]
    public void LocalDiagnosticIsInsertedOnlyForTheActualRoutedCommand(string[] input, string[] expected)
    {
        var actual = input.ToList();
        TestNode.AddLocalDiagnosticOption(actual);
        Assert.Equal(expected, actual);
    }

    public static TheoryData<string[], bool> ExecutableSelection => new()
    {
        { ["--test-mode", "run", "--", "start"], true },
        { ["--test-mode", "run", "--json", "start", "sandbox", "--", "tasks", "--local"], false },
        { ["run", "list", "--sandbox", "sandbox"], false },
        { ["run", "inspect", "run-id"], false },
        { ["run", "stop", "run-id"], false },
        { ["resources", "--watch"], true },
        { ["resources", "--json", "watch", "--scope", "node"], false },
        { ["resources", "show"], false },
        { ["resources", "set"], false },
        { ["--timeout", "run", "sandbox", "inspect", "sandbox"], false },
        { ["tasks", "list"], true },
        { ["queue", "list"], true },
        { ["jobs", "list"], true },
        { ["samples", "--scope", "machine"], true },
        { ["workspace", "list"], false },
        { ["file-operation", "show"], false },
        { ["login"], true },
        { ["events", "--topic", "tasks"], false },
        { ["node", "run", "--test-mode"], false },
        { ["node", "wait-ready", "--test-mode"], false },
        { ["node", "stop", "--test-mode"], false },
        { ["--help"], false },
    };

    [Theory]
    [MemberData(nameof(ExecutableSelection))]
    public void LegacySelectionUsesTheCommandAndKeepsTheV2HostRoute(string[] input, bool expected) =>
        Assert.Equal(expected, TestNode.UsesLegacyCli(input.ToList()));
}
