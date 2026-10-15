// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Tests;

namespace ArcForges.Tools.Tests;

/// <summary>
/// Recorded processes are identified by ID and creation (tests/Shared/ProcessIdentity.cs): a process that now holds a recorded ID but
/// was created after the recorded process was alive is another process (the ID was reused) and is neither reported running nor killed;
/// the recorded process itself is. Real processes on the current OS.
/// </summary>
public sealed class ProcessIdentityTests
{
    [Fact(Timeout = 60_000)]
    public async Task AReusedIdIsAnotherProcessAndTheRecordedOneStillCounts()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var (pid, run) = ToolProcess.Start(ToolProcess.TestLoad, ["fork", "--width", "1", "--depth", "1", "--hold-ms", "30000"], TestContext.Current.CancellationToken);
        try
        {
            var exact = ProcessIdentity.Capture(pid);
            Assert.NotNull(exact);
            Assert.True(exact.Value.IsRunning(), "The captured process runs.");
            Assert.True(ProcessIdentity.CreatedNoLaterThan(pid, DateTimeOffset.UtcNow).IsRunning(), "Alive now, so created no later than now.");

            // The same ID recorded for a process alive one minute ago: the running process was created later, so it is another one.
            var reused = ProcessIdentity.CreatedNoLaterThan(pid, DateTimeOffset.UtcNow - TimeSpan.FromMinutes(1));
            Assert.False(reused.IsRunning());
            Assert.False(reused.Kill(), "A process that reused a recorded ID is never killed.");
            Assert.True(exact.Value.IsRunning());

            Assert.True(exact.Value.Kill(), "The recorded process itself is killed.");
            Assert.False(exact.Value.IsRunning());
        }
        finally
        {
            await run;
        }
    }
}
