// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace ArcForges.LocalRpc.Tests;

/// <summary>A clock a test advances by hand.</summary>
internal sealed class ManualClock(DateTimeOffset start) : TimeProvider
{
    private long _ticks = start.UtcTicks;

    public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref _ticks), TimeSpan.Zero);

    internal void Advance(TimeSpan by) => Interlocked.Add(ref _ticks, by.Ticks);
}

/// <summary>A process table a test controls: unlisted processes are dead.</summary>
internal sealed class FakeProcesses
{
    private readonly ConcurrentDictionary<int, (long Start, ProcessLiveness State)> _table = new();

    internal void Set(LocalRpcProcessIdentity identity, ProcessLiveness state) => _table[identity.ProcessId] = (identity.StartTimeUtcTicks, state);

    internal ProcessLiveness Probe(LocalRpcProcessIdentity identity) =>
        _table.TryGetValue(identity.ProcessId, out var entry) && Math.Abs(entry.Start - identity.StartTimeUtcTicks) <= LocalRpcProcessIdentity.StartTimeTolerance.Ticks
            ? entry.State
            : ProcessLiveness.Dead;
}

/// <summary>A fake parent process, clock and process table plus a private runtime root, removed on dispose.</summary>
internal sealed class LaunchWorld : IDisposable
{
    private readonly DateTimeOffset _start = DateTimeOffset.UtcNow;
    private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("afrpc-");

    internal LaunchWorld()
    {
        Clock = new ManualClock(_start);
        Processes = new FakeProcesses();
        Parent = new LocalRpcProcessIdentity(4242, _start.UtcTicks);
        Processes.Set(Parent, ProcessLiveness.Live);
        Root = Path.Combine(_directory.FullName, "rt");
    }

    internal ManualClock Clock { get; }

    internal FakeProcesses Processes { get; }

    internal LocalRpcProcessIdentity Parent { get; }

    internal string Root { get; }

    internal LaunchEnvironment Environment(LocalRpcProcessIdentity? parent = null, bool unixSocket = true) => new()
    {
        Clock = Clock,
        Probe = Processes.Probe,
        Parent = parent ?? Parent,
        ForceUnixSocket = unixSocket,
    };

    internal LocalRpcLaunchAuthority Authority(LocalRpcProcessIdentity? parent = null, bool unixSocket = true, TimeSpan? window = null) =>
        LocalRpcLaunchAuthority.Create(Root, window, Environment(parent, unixSocket));

    internal LocalRpcProcessIdentity SpawnFake(int processId, ProcessLiveness state = ProcessLiveness.Live)
    {
        var identity = new LocalRpcProcessIdentity(processId, _start.UtcTicks + processId);
        Processes.Set(identity, state);
        return identity;
    }

    public void Dispose()
    {
        try
        {
            _directory.Delete(recursive: true);
        }
        catch (IOException)
        {
            // A bound AF_UNIX socket file can outlive a test on Windows; the temporary directory is disposable.
        }
        catch (UnauthorizedAccessException)
        {
            // Same: disposable temporary state.
        }
    }
}

internal static class Launches
{
    internal static byte[] Bytes(byte fill, int length = 32) => Enumerable.Repeat(fill, length).ToArray();

    internal static LocalRpcLaunchIdentity Identity(
        LocalRpcChildKind kind = LocalRpcChildKind.ContentSandbox,
        string build = "contentsandbox-1.0.0",
        byte buildFill = 0x11,
        uint protocol = 1,
        byte contractFill = 0x22) =>
        new(kind, build, Bytes(buildFill), protocol, Bytes(contractFill));

    internal static byte[] Flip(ReadOnlyMemory<byte> bytes, int index = 0)
    {
        var copy = bytes.ToArray();
        copy[index] ^= 0x01;
        return copy;
    }

    internal static LocalRpcLaunchClaim ClaimFrom(LocalRpcLaunchClaim claim, Guid? launchId = null, string? slot = null, ulong? epoch = null,
        byte[]? nonce = null, LocalRpcLaunchIdentity? identity = null) =>
        new(launchId ?? claim.LaunchId, slot ?? claim.Slot, epoch ?? claim.Epoch, nonce ?? claim.Nonce.ToArray(), identity ?? claim.Identity);

    /// <summary>A descriptor outside any authority, for codec and forged-parent fixtures.</summary>
    internal static LocalRpcLaunchDescriptor Descriptor(
        LocalRpcEndpoint? endpoint = null,
        ulong epoch = 3,
        LocalRpcProcessIdentity? parent = null,
        LocalRpcLaunchIdentity? identity = null) =>
        new(
            Guid.NewGuid(),
            "slot-a",
            epoch,
            endpoint,
            parent ?? new LocalRpcProcessIdentity(4242, new DateTime(2026, 10, 2, 12, 0, 0, DateTimeKind.Utc).Ticks),
            identity ?? Identity(),
            RandomNumberGenerator.GetBytes(LocalRpcLaunchDescriptor.NonceLength),
            new DateTimeOffset(2026, 10, 2, 12, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 10, 2, 12, 0, 30, TimeSpan.Zero));
}
