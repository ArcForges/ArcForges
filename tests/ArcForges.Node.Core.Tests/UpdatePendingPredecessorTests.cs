// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Updates;

namespace ArcForges.Node.Core.Tests;

public sealed class UpdatePendingPredecessorTests
{
    private const string Canonical = "/fixture/app/versions/accepted/arcforges";
    private const string Parked = "/fixture/app/versions/.parked-accepted/arcforges";
    private const string Managed = "/fixture/app/current/arcforges";

    [Theory]
    [InlineData(Canonical)]
    [InlineData(Parked)]
    [InlineData(Managed)]
    public void RecognizesTheExactLegacySetsidTarget(string target)
    {
        Assert.True(NodeUpdatePendingPredecessor.IsPredecessorLauncher("/usr/bin/setsid", "dash",
            ["/bin/setsid", "-f", target, "node", "run", "--test-mode"], Canonical, Parked, Managed));
        Assert.False(NodeUpdatePendingPredecessor.IsPredecessorLauncher("/tmp/setsid", "dash",
            ["/bin/setsid", "-f", target, "node", "run", "--test-mode"], Canonical, Parked, Managed));
        Assert.False(NodeUpdatePendingPredecessor.IsPredecessorLauncher("/usr/bin/setsid", "dash",
            ["/bin/setsid", "-f", target, "node", "status"], Canonical, Parked, Managed));
    }

    [Fact]
    public void TheNormalShellWrapperIsMatchedWithoutAcceptingOtherShellCommands()
    {
        string[] launcher = ["/bin/sh", "-c", "exec \"$0\" -f \"$@\" </dev/null >/dev/null 2>&1",
            "/usr/bin/setsid", Canonical, "node", "run"];
        Assert.True(NodeUpdatePendingPredecessor.IsPredecessorLauncher("/usr/bin/dash", "dash", launcher, Canonical, Parked, Managed));
        launcher[4] = "/fixture/app/versions/another-cohort/arcforges";
        Assert.False(NodeUpdatePendingPredecessor.IsPredecessorLauncher("/usr/bin/dash", "dash", launcher, Canonical, Parked, Managed));
    }
}
