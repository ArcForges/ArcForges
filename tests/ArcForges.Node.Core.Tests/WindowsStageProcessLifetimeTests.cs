// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

public sealed class WindowsStageBootEvidenceTests
{
    [Fact]
    public void OnlyTheRecordedWindowsBootCanQueryTheRecordedProcess()
    {
        const string machine = "af01ef4b-ebac-4958-8613-8cb936658a30";
        const string boot = "windows:" + machine + ":100";
        const int processId = 42;
        const long creationTime = 1_000_000_001;
        var unknown = WindowsStageProcessObservation.Unknown;
        var cases = new (string Recorded, string? Current, WindowsStageProcessObservation Expected)[]
        {
            (boot, "windows:" + machine + ":200", WindowsStageProcessObservation.Ended),
            (boot, "windows:4287aee6-1317-4dc8-a002-7a4fa68f94fb:200", unknown),
            (boot, "windows:unknown:200", unknown),
            ("windows:unknown:100", boot, unknown),
            ("windows:00000000-0000-0000-0000-000000000000:100", boot, unknown),
            ("windows:" + machine + ":0", boot, unknown),
            ("windows:" + machine + ":9223372036854775807", boot, unknown),
            ("windows:" + machine + ":+100", boot, unknown),
            (boot + "\0", boot, unknown),
            (boot, "windows:" + machine + ":200\0", unknown),
            (boot + "\0", boot + "\0", unknown),
            ("linux:" + machine, boot, unknown),
            (boot, null, unknown),
        };

        static WindowsStageProcessObservation UnexpectedLookup(int _, long __) =>
            throw new NotSupportedException("An unproved or earlier boot cannot query this process.");

        foreach (var (recorded, current, expected) in cases)
        {
            var historical = new WindowsOwnedStageIdentity(recorded, processId, creationTime);
            Assert.Equal(expected, historical.Observe(() => current, UnexpectedLookup));
        }

        var owned = new WindowsOwnedStageIdentity(boot, processId, creationTime);
        Assert.Equal(unknown, owned.Observe(() => throw new UnauthorizedAccessException(), UnexpectedLookup));
        Assert.Equal(unknown, (owned with { ProcessId = 0 }).Observe(() => boot, UnexpectedLookup));
        Assert.Equal(unknown, (owned with { CreationTime = 0 }).Observe(() => boot, UnexpectedLookup));
        foreach (var expected in Enum.GetValues<WindowsStageProcessObservation>())
        {
            var calls = 0;
            Assert.Equal(expected, owned.Observe(() => boot, (pid, created) =>
            {
                Assert.Equal((processId, creationTime), (pid, created));
                calls++;
                return expected;
            }));
            Assert.Equal(1, calls);
        }
    }
}
