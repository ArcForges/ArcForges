// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Scheduling;

namespace ArcForges.Node.Core.Tests;

/// <summary>Feasibility explanations and concurrency-key compatibility for retained Tasks.</summary>
/// <remarks>The original admission passes and their tests remain at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.</remarks>
public sealed class AdmissionEngineTests
{
    private const long GiB = 1024L * 1024 * 1024;

    [Theory]
    [InlineData(8 * GiB, 12 * GiB, 8 * GiB, 16 * GiB, Feasibility.Feasible)]
    [InlineData(9 * GiB, 12 * GiB, 8 * GiB, 16 * GiB, Feasibility.ExceedsBudget)]
    [InlineData(12 * GiB, 12 * GiB, 8 * GiB, 16 * GiB, Feasibility.ExceedsBudget)]
    [InlineData(13 * GiB, 12 * GiB, 20 * GiB, 16 * GiB, Feasibility.ExceedsCapacity)]
    [InlineData(13 * GiB, 20 * GiB, 20 * GiB, 12 * GiB, Feasibility.ExceedsCapacity)]
    [InlineData(12 * GiB, 20 * GiB, 20 * GiB, 12 * GiB, Feasibility.Feasible)]
    public void ClassifyUsesTheIdleBudgetAndBothCapacityBoundaries(long expectedBytes, long shareLimit, long idleBudget, long taskLimit,
        Feasibility expected)
    {
        Assert.Equal(expected, AdmissionEngine.Classify(expectedBytes, shareLimit, idleBudget, taskLimit));
    }

    [Fact]
    public void TheKeyOverlapRuleCoversAncestorsPurposesToolsTheWorkspaceKeyAndNames()
    {
        static bool Overlap(string left, string right) => ConcurrencyKey.Parse(left).Overlaps(ConcurrencyKey.Parse(right));

        Assert.True(Overlap("ws:W/a", "ws:W/a"));
        Assert.True(Overlap("ws:W/a", "ws:W/a/b"));
        Assert.True(Overlap("ws:W/a/b", "ws:W/a"));
        Assert.False(Overlap("ws:W/a", "ws:W/ab"));
        Assert.False(Overlap("ws:W/a", "ws:V/a"));

        // Purposes separate two uses of a directory only when both keys carry one and they differ.
        Assert.False(Overlap("ws:W/pkg:deps", "ws:W/pkg:build"));
        Assert.True(Overlap("ws:W/pkg:deps", "ws:W/pkg:deps"));
        Assert.True(Overlap("ws:W/pkg:deps", "ws:W/pkg"));
        Assert.True(Overlap("ws:W/pkg:deps", "ws:W/pkg/sub"));

        // Tool keys overlap only the same tool key; the workspace key overlaps everything of its workspace, tool keys in it included.
        Assert.True(Overlap("tool:dotnet:W", "tool:dotnet:W"));
        Assert.False(Overlap("tool:dotnet:W", "tool:cargo:W"));
        Assert.False(Overlap("tool:dotnet:W", "ws:W/src"));
        Assert.True(Overlap("ws:W", "tool:dotnet:W"));
        Assert.True(Overlap("ws:W", "tool:git:W/sub"));
        Assert.True(Overlap("ws:W", "ws:W/deep/dir:deps"));
        Assert.False(Overlap("ws:W", "tool:dotnet:V"));
        Assert.False(Overlap("ws:W", "name:W"));
        Assert.True(Overlap("name:x", "name:x"));
        Assert.False(Overlap("name:x", "name:y"));

        // A tool key scoped by an absolute path inside the workspace's root.
        Assert.True(ConcurrencyKey.Parse("ws:W").Overlaps(ConcurrencyKey.Parse("tool:cargo:/work/repo/target"), workspace => workspace == "W" ? "/work/repo" : null));

        // Parsing: canonical text, and refused shapes.
        Assert.Equal("ws:W/a/b:deps", ConcurrencyKey.Parse(@"ws:W\a\.\b:deps").Text);
        Assert.Equal(KeyKind.Workspace, ConcurrencyKey.Parse("ws:W/").Kind);
        foreach (var bad in new[] { "", "ws:", "ws:W/../x", "ws:W/a:", "tool:dotnet", "tool::x", "name:", "other:x", new string('x', 201) })
        {
            Assert.False(ConcurrencyKey.TryParse(bad, out _, out _), bad);
        }

        Assert.NotNull(KeyHolders.FromSpec([.. Enumerable.Range(0, 17).Select(index => "name:" + index)], []).Error);
        Assert.NotNull(KeyHolders.FromSpec(["name:a", "name:a"], []).Error);
        Assert.Null(KeyHolders.FromSpec(["name:a"], ["ws:W"]).Error);
    }
}
