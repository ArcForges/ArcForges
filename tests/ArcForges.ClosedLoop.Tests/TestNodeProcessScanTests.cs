// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.ClosedLoop.Tests;

public sealed class TestNodeProcessScanTests
{
    [Fact]
    public async Task OnlyTheSameStillUninspectableProcessIsReportedAfterARescan()
    {
        // These are fake identities: one remains, one exited, one PID was reused, and one newly appeared.
        var first = new List<string> { "pid 42 start A", "pid 43 start B", "pid 44 start C" };
        var second = new List<string> { "pid 42 start A", "pid 44 start NEW", "pid 45 start D" };
        var scans = 0;
        Task<List<string>> Scan()
        {
            scans++;
            return Task.FromResult(second);
        }

        Assert.Equal("pid 42 start A", Assert.Single(await TestNode.PersistentlyUninspectableAsync(first, Scan)));
        Assert.Equal(1, scans);
        Assert.Empty(await TestNode.PersistentlyUninspectableAsync([], Scan));
        Assert.Equal(1, scans);
    }
}
