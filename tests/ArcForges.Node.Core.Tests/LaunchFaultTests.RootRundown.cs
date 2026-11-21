// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Tests;

public sealed partial class LaunchFaultTests
{
    // Windows debugger-held Task root run-down, including the successful root's end-step ordering,
    // remains executable at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a. The V2 force/final observations
    // and exact owned-scope drain are covered by RecoveryNativeDispatchMxcRunServiceTests and RecoveryFinalMxcRunServiceTests.

    [Fact(Timeout = 30_000)]
    public async Task ARecoveredLegacyStopForcesItsLateStartAndLaterMemberBeforeAcknowledgingTheOriginalExit()
    {
        var ct = TestContext.Current.CancellationToken;
        await UseRecoveredAttemptAsync(AttemptState.Stopping, startedInGap: false, configure: null, async fixture =>
        {
            var handle = fixture.Handle;
            await handle.WaitForTerminationsAsync(1);
            Assert.Equal(1, handle.Terminations);
            Assert.Equal(AttemptState.Stopping, fixture.ReadAttempt().State);
            Assert.Null(fixture.ReadAttempt().RootPid);

            handle.ReportOriginalRoot();
            await handle.WaitForTerminationsAsync(2);
            Assert.Equal(2, handle.Terminations);

            handle.ReportLaterMember();
            await handle.WaitForTerminationsAsync(3);
            Assert.Equal(3, handle.Terminations);
            await handle.ObservePassesAsync();

            // The simulated container is empty. Its original effect still waits for the original holder's exit record.
            Assert.Equal(0, handle.Accounting().ActiveProcesses);
            Assert.Equal(AttemptState.Stopping, fixture.ReadAttempt().State);
            Assert.Equal(TerminationReason.Cancelled, fixture.ReadAttempt().Reason);
            Assert.False(handle.Acknowledged.IsCompleted);

            handle.ReportOriginalExit();
            await handle.Acknowledged.WaitAsync(TimeSpan.FromSeconds(5), ct);
            fixture.AssertFinished(TaskState.Cancelled, TerminationReason.Cancelled);
        }, ct);
    }
}
