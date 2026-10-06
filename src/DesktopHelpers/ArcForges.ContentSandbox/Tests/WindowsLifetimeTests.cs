// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Principal;
using ArcForges.ContentSandbox.Broker;
using ArcForges.ContentSandbox.Broker.Windows;
using Xunit;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>Actual cleanup coordination; injected outcomes cover unavailable process/diagnostic faults, never OS isolation.</summary>
public sealed class WindowsLifetimeTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("fault")]
    [InlineData("cancel")]
    [InlineData("timeout")]
    public async Task DiagnosticFailureStillReleasesAllRealResourcesAndIdentity(string outcome)
    {
        var directory = Path.Combine(Path.GetTempPath(), "ArcForges-Lifetime-" + Guid.NewGuid().ToString("N"));
        _ = Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "held.lock");
        await using var held = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        var released = 0;
        var stopped = 0;
        var boundary = 0;
        var diagnostics = outcome switch
        {
            "fault" => Task.FromException(new IOException("diagnostic failure")),
            "cancel" => Task.FromCanceled(new CancellationToken(canceled: true)),
            _ => new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously).Task,
        };
        var lifetime = new HelperResourceLifetime(
            () => Interlocked.Increment(ref stopped),
            () => Interlocked.Increment(ref boundary),
            Task.CompletedTask,
            () => new ValueTask(diagnostics),
            [() => held.DisposeAsync()],
            () => Interlocked.Increment(ref released),
            TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(30));
        try
        {
            var attempts = Enumerable.Range(0, 12).Select(_ => lifetime.DisposeAsync().AsTask()).ToArray();
            foreach (var attempt in attempts)
            {
                Assert.Equal("resource.unavailable", (await Assert.ThrowsAsync<ContentSandboxLaunchException>(() => attempt)).ReasonCode);
            }

            await lifetime.Released.WaitAsync(TimeSpan.FromSeconds(2), Ct);
            Assert.Equal(1, stopped);
            Assert.Equal(1, boundary);
            Assert.Equal(1, released);
            await using var reopened = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        }
        finally
        {
            await held.DisposeAsync();
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task AStalledResourceCannotSkipLaterResourcesOrIdentityCleanup()
    {
        var late = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var count = 0;
        var lifetime = new HelperResourceLifetime(
            () => { }, () => { }, Task.CompletedTask, () => ValueTask.CompletedTask,
            [() => new ValueTask(late.Task), () => { Interlocked.Increment(ref count); return ValueTask.CompletedTask; }],
            () => Interlocked.Increment(ref count), TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(30));
        var error = await Assert.ThrowsAsync<ContentSandboxLaunchException>(() => lifetime.DisposeAsync().AsTask()).WaitAsync(TimeSpan.FromSeconds(2), Ct);
        Assert.IsType<TimeoutException>(Assert.Single(((AggregateException)error.InnerException!).InnerExceptions));
        await lifetime.Released.WaitAsync(TimeSpan.FromSeconds(2), Ct);
        Assert.Equal(2, count);
        late.SetException(new IOException("observed late release failure"));
        _ = await Assert.ThrowsAsync<IOException>(() => late.Task);
        _ = await Assert.ThrowsAsync<ContentSandboxLaunchException>(() => lifetime.DisposeAsync().AsTask());
        Assert.Equal(2, count);
    }

    [Fact]
    public async Task UnconfirmedExitQuarantinesIdentityUntilTheActualSignalDespiteResourceFaults()
    {
        var exit = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var released = 0;
        var resources = 0;
        var lifetime = new HelperResourceLifetime(
            () => throw new IOException("terminate failed"),
            () => Interlocked.Increment(ref resources),
            exit.Task,
            () => ValueTask.CompletedTask,
            [() => throw new IOException("one resource failed"), () => { Interlocked.Increment(ref resources); return ValueTask.CompletedTask; }],
            () => Interlocked.Increment(ref released),
            TimeSpan.FromMilliseconds(30), TimeSpan.FromSeconds(1));
        var error = await Assert.ThrowsAsync<ContentSandboxLaunchException>(() => lifetime.DisposeAsync().AsTask());
        Assert.Contains("quarantined", error.Message, StringComparison.Ordinal);
        Assert.Equal(2, resources);
        Assert.Equal(0, released);
        Assert.False(lifetime.Released.IsCompleted);
        exit.SetResult();
        await lifetime.Released.WaitAsync(TimeSpan.FromSeconds(2), Ct);
        Assert.Equal(1, released);
        _ = await Assert.ThrowsAsync<ContentSandboxLaunchException>(() => lifetime.DisposeAsync().AsTask());
        Assert.Equal(1, released);
    }

    [Fact]
    public async Task SuccessfulConcurrentDisposalCompletesOneCleanupAndReportsIdentityFailure()
    {
        var count = 0;
        var lifetime = new HelperResourceLifetime(
            () => { }, () => { }, Task.CompletedTask, () => ValueTask.CompletedTask, [],
            () => Interlocked.Increment(ref count), TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
        await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => lifetime.DisposeAsync().AsTask())).WaitAsync(TimeSpan.FromSeconds(2), Ct);
        Assert.Equal(1, count);
        await lifetime.Released;
        var bad = new HelperResourceLifetime(
            () => { }, () => { }, Task.CompletedTask, () => ValueTask.CompletedTask, [],
            () => throw new IOException("profile deletion failed"), TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
        _ = await Assert.ThrowsAsync<ContentSandboxLaunchException>(() => bad.DisposeAsync().AsTask());
        _ = await Assert.ThrowsAsync<IOException>(() => bad.Released);
    }

    [Theory]
    [InlineData("pending")]
    [InlineData("malformed")]
    [InlineData("foreign")]
    [SupportedOSPlatform("windows")]
    public async Task UnverifiableCrashRecordsQuarantineTheIdentityWithoutDeletingItsStorageOrKillingAProcess(string state)
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Actual Userenv component requires Windows.");
        var prefix = "ArcForges.Crash." + Guid.NewGuid().ToString("N")[..24];
        var directory = Path.Combine(Path.GetTempPath(), prefix);
        var canonical = Path.Combine(AppContainerSlots.DefaultLockDirectory(), prefix, "slot-0.lock");
        using var current = Process.GetCurrentProcess();
        string marker;
        using (var initial = AppContainerSlots.Acquire(prefix, directory))
        {
            marker = Path.Combine(AppContainerSlots.ProfileStorage(initial.Sid), "old-secret.bin");
            _ = Directory.CreateDirectory(Path.GetDirectoryName(marker)!);
            await File.WriteAllTextAsync(marker, "old secret", Ct);
            initial.BeginLaunch();
            if (state == "foreign")
            {
                initial.RecordChild(current); // A real foreign current process cannot satisfy the container SID check.
            }

            _ = Assert.Throws<ContentSandboxLaunchException>(initial.Dispose);
        }

        if (state == "malformed")
        {
            await File.WriteAllTextAsync(canonical, "{truncated", Ct);
        }

        try
        {
            using var next = AppContainerSlots.Acquire(prefix, Path.Combine(directory, "other"));
            Assert.Equal(prefix + ".1", next.Name);
            Assert.True(File.Exists(marker));
            Assert.False(current.HasExited);
        }
        finally
        {
            // The test owns the seeded, child-free record and profile. Production never clears unknown pending records.
            await File.WriteAllBytesAsync(canonical, [], Ct);
            using var clean = AppContainerSlots.Acquire(prefix, directory);
            Assert.Equal(prefix + ".0", clean.Name);
            Assert.False(File.Exists(marker));
        }
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void EveryInterruptedActiveRecordWriteRetainsQuarantineInsteadOfAnEmptySafeRecord()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Actual Userenv component requires Windows.");
        var prefix = "ArcForges.Record." + Guid.NewGuid().ToString("N")[..24];
        var directory = Path.Combine(Path.GetTempPath(), prefix);
        using var current = Process.GetCurrentProcess();
        using var lease = AppContainerSlots.Acquire(prefix, directory);
        var sid = new SecurityIdentifier(lease.Sid).Value;
        var path = Path.Combine(directory, "transition.lock");
        var pending = new AppContainerSlots.LifetimeRecord(1, "pending", 0, 0, sid);
        var active = new AppContainerSlots.LifetimeRecord(1, "active", current.Id, current.StartTime.ToUniversalTime().Ticks, sid);
        try
        {
            long length;
            using (var stream = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            {
                AppContainerSlots.WriteLifetime(stream, active);
                length = stream.Length;
            }

            for (var cut = 0; cut <= length; cut++)
            {
                using (var stream = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
                {
                    AppContainerSlots.WriteLifetime(stream, pending);
                }

                using (var stream = new InterruptedRecordStream(path, cut))
                {
                    _ = Assert.Throws<IOException>(() => AppContainerSlots.WriteLifetime(stream, active));
                }

                using var reopened = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                Assert.True(reopened.Length > 0);
                // Fully written active bytes still describe a real foreign live process, not exit.
                Assert.False(AppContainerSlots.PriorLifetimeEnded(reopened, lease.Name));
                Assert.False(current.HasExited);
            }
        }
        finally
        {
            File.Delete(path);
        }
    }

    private sealed class InterruptedRecordStream(string path, int cut)
        : FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None)
    {
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            base.Write(buffer[..Math.Min(cut, buffer.Length)]);
            base.Flush(flushToDisk: true);
            throw new IOException("Injected crash cut after persisting the selected replacement prefix.");
        }
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task AReusedPidRecordCannotKillTheRealReplacementAndAllowsFreshProfileReuse()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Actual Userenv component requires Windows.");
        var prefix = "ArcForges.Reused." + Guid.NewGuid().ToString("N")[..24];
        var directory = Path.Combine(Path.GetTempPath(), prefix);
        var canonical = Path.Combine(AppContainerSlots.DefaultLockDirectory(), prefix, "slot-0.lock");
        using var current = Process.GetCurrentProcess();
        string sid;
        using (var initial = AppContainerSlots.Acquire(prefix, directory))
        {
            sid = new SecurityIdentifier(initial.Sid).Value;
        }

        await using (var stream = new FileStream(canonical, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            AppContainerSlots.WriteLifetime(stream,
                new AppContainerSlots.LifetimeRecord(1, "active", current.Id, current.StartTime.ToUniversalTime().Ticks - 1, sid));
        }

        using var next = AppContainerSlots.Acquire(prefix, directory);
        Assert.Equal(prefix + ".0", next.Name);
        Assert.False(current.HasExited);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void ActualPoolIsExclusiveAcrossCallerDirectoriesAndPlantedStorageIsRemovedBeforeReuse()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Actual Userenv component requires Windows.");
        var prefix = "ArcForges.Lifetime." + Guid.NewGuid().ToString("N")[..24];
        var directory = Path.Combine(Path.GetTempPath(), prefix);
        var leases = new List<AppContainerLease>();
        try
        {
            var first = AppContainerSlots.Acquire(prefix, Path.Combine(directory, "first"));
            leases.Add(first);
            var storage = AppContainerSlots.ProfileStorage(first.Sid);
            var planted = Path.Combine(storage, "previous-private-input.bin");
            _ = Directory.CreateDirectory(storage);
            File.WriteAllText(planted, "private previous lifetime");
            for (var index = 1; index < AppContainerSlots.SlotCount; index++)
            {
                leases.Add(AppContainerSlots.Acquire(prefix, Path.Combine(directory, "second")));
            }

            Assert.Equal(AppContainerSlots.SlotCount, leases.Select(lease => lease.Name).Distinct().Count());
            Assert.Equal("capacity.busy", Assert.Throws<ContentSandboxLaunchException>(() => AppContainerSlots.Acquire(prefix, Path.Combine(directory, "third"))).ReasonCode);
            var name = first.Name;
            first.Dispose();
            Assert.False(File.Exists(planted));
            using var fresh = AppContainerSlots.Acquire(prefix, Path.Combine(directory, "third"));
            Assert.Equal(name, fresh.Name);
            Assert.False(File.Exists(Path.Combine(AppContainerSlots.ProfileStorage(fresh.Sid), "previous-private-input.bin")));
        }
        finally
        {
            foreach (var lease in leases)
            {
                lease.Dispose();
            }

            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }
}
