// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using ArcForges.Tests;

namespace ArcForges.Node.Platform.Linux.Tests;

/// <summary>
/// A wait for a user manager job never misses the job's end (04 section 3: the node waits for the job's <c>JobRemoved</c>, result
/// <c>done</c>). MR-92: on a Linux verification leg an adoption scope started at once, yet <c>Adopt</c>'s 10 s wait missed its
/// <c>JobRemoved</c>. The signal's handler had looked for a waiter before the wait registered, and recorded the result after the wait had read
/// the record. The jobs here are synthetic paths the manager never uses, handled as their signal would be; the connection is real.
/// </summary>
[Trait("env", "linux-real")]
[SupportedOSPlatform("linux")]
public sealed class JobWaitTests
{
    private const string Unit = "arcforges-x-jobwait.scope";

    [Fact(Timeout = 60_000)]
    public async Task AJobThatEndsWhileItsWaitBeginsEndsTheWait()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        using var manager = SystemdManager.Connect(SystemdManager.DefaultAddress()!, TimeSpan.FromSeconds(5));

        // The wait begins on the signal's own thread between the two steps of its handling, so the rest of the handling cannot run before the
        // wait ends: the wait gets the result only if the handling already made it visible to a wait that begins now.
        var job = NewJob();
        string? during = "the handler did not reach the seam";
        manager.JobRemovedRecorded = removed =>
        {
            if (removed == job)
            {
                during = manager.WaitJob(job, TimeSpan.FromSeconds(2));
            }
        };
        manager.OnJobRemoved(job, Unit, "done");
        manager.JobRemovedRecorded = null;
        Assert.Equal("done", during);

        // A job that ended before its wait began, and one whose wait may begin before or after its end: each wait gets its result.
        var before = NewJob();
        manager.OnJobRemoved(before, Unit, "failed");
        Assert.Equal("failed", manager.WaitJob(before, TimeSpan.FromSeconds(2)));

        var racing = NewJob();
        var waiting = Task.Run(() => manager.WaitJob(racing, TimeSpan.FromSeconds(30)), TestContext.Current.CancellationToken);
        manager.OnJobRemoved(racing, Unit, "done");
        Assert.Equal("done", await waiting);
    }

    private static string NewJob() => "/org/freedesktop/systemd1/job/arcforges_test_" + Guid.NewGuid().ToString("N");
}
