// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;

namespace ArcForges.Repository.Tests;

/// <summary>
/// AF-CTR-05 part N2a (CTR5-NODE-08, the refactor half): the TaskService gRPC methods are thin wrappers. Each unary method builds its caller
/// with <c>CallerOf(context)</c> and passes it, the request and the call's cancellation to its operation body unchanged; <c>CallerOf</c> is the
/// service's only read of the connection's session (<c>ApiCommands.CallerOf</c>, which is <c>Caller.OfConnection</c> of the session); the
/// operation bodies never see the <c>ServerCallContext</c>; the two output streams read no caller.
/// </summary>
public sealed partial class TaskServiceCallerPolicyTests
{
    private const string Handler = "src/ArcForges.Node.Api/TaskServiceHandler.cs";
    private const string Commands = "src/ArcForges.Node.Api/ApiCommands.cs";

    /// <summary>The streams bound to the local stream transport (no routed counterpart; they read no caller).</summary>
    private static readonly string[] Streams = ["AttachTask", "WatchTaskOutput"];

    private static string Text(string relative) => File.ReadAllText(RepositoryFiles.PathOf(relative)).ReplaceLineEndings("\n");

    [Fact]
    public void EveryUnaryTaskServiceMethodIsAWrapperThatBuildsItsCallerWithCallerOf()
    {
        var text = Text(Handler);
        var overrides = Override().Matches(text).Select(match => match.Groups["name"].Value).ToList();
        var wrappers = Wrapper().Matches(text).Select(match => match.Groups["name"].Value).ToList();
        Assert.Equal(Streams, overrides.Where(name => !wrappers.Contains(name)).Order(StringComparer.Ordinal));
        Assert.Equal(17, wrappers.Count);
        Assert.Equal(wrappers.Count, wrappers.Distinct(StringComparer.Ordinal).Count());
        foreach (var name in wrappers)
        {
            // The operation body of each wrapper takes the caller first, then the request and the cancellation.
            Assert.Matches(new Regex(@"internal (async )?Task<TaskService" + name + @"Response> " + name + @"\(Caller caller, TaskService" + name
                + @"Request request, CancellationToken cancellationToken\)"), text);
        }
    }

    [Fact]
    public void OnlyTheWrapperLayerReadsTheConnectionsSession()
    {
        var text = Text(Handler);
        Assert.DoesNotContain("OriginOf(", text, StringComparison.Ordinal);
        Assert.DoesNotContain("SessionOf(", text, StringComparison.Ordinal);
        Assert.DoesNotContain("_sessions", text, StringComparison.Ordinal);

        // CallerOf(context) appears only in the unary wrappers and in its own definition.
        var wrappers = Wrapper().Count(text);
        Assert.Equal(wrappers, Regex.Count(text, @"CallerOf\(context\), request, context\.CancellationToken\)"));
        Assert.Equal(wrappers + 2, Regex.Count(text, @"CallerOf\("));
        Assert.Contains("private Caller CallerOf(ServerCallContext context) => _api.CallerOf(context ?? throw new ArgumentNullException(nameof(context)));", text,
            StringComparison.Ordinal);
        Assert.Contains("public Caller CallerOf(ServerCallContext context) => Caller.OfConnection(sessions.SessionOf(context));", Text(Commands), StringComparison.Ordinal);

        // A ServerCallContext appears only in the wrappers, CallerOf and the two streams.
        Assert.Equal(wrappers + 1 + Streams.Length, Regex.Count(text, @"ServerCallContext context\)"));
        foreach (var stream in Streams)
        {
            var start = text.IndexOf("public override async Task " + stream + "(", StringComparison.Ordinal);
            Assert.True(start >= 0, stream);
            var end = text.IndexOf("\n    }\n", start, StringComparison.Ordinal);
            Assert.DoesNotContain("aller", text[start..end], StringComparison.Ordinal);
        }
    }

    [GeneratedRegex(@"public override (async )?Task(<\w+>)? (?<name>\w+)\(")]
    private static partial Regex Override();

    [GeneratedRegex(@"public override Task<TaskService(?<name>\w+)Response> \k<name>\(TaskService\k<name>Request request, ServerCallContext context\) =>\n        \k<name>\(CallerOf\(context\), request, context\.CancellationToken\);\n")]
    private static partial Regex Wrapper();
}
