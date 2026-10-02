// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// Offline fixtures for the parent-owned launch identity: descriptor, nonce, build/protocol, epoch fencing, the one-use
/// secret and the connection decision. A fake process table and clock stand in for the OS; the OS-level behavior of launch
/// directories and real processes is checked by the directory tests and the opt-in process checks.
/// </summary>
public sealed class LocalRpcLaunchTests
{
    private static readonly LocalRpcLaunchIdentity Standard = Launches.Identity();

    // ---- descriptor codec ----

    [Fact]
    public void ADescriptorRoundTripsEveryFieldIncludingEachEndpointKind()
    {
        var socket = LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.UnixDomainSocket, Path.Combine(Path.GetFullPath(Path.GetTempPath()), "a", "s"));
        var pipe = LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.NamedPipe, "afl-0123456789abcdef");
        foreach (var endpoint in new LocalRpcEndpoint?[] { null, pipe, socket })
        {
            var original = Launches.Descriptor(endpoint, epoch: ulong.MaxValue);

            var decoded = LocalRpcLaunchDescriptor.Decode(original.Encode());

            Assert.Equal(original.LaunchId, decoded.LaunchId);
            Assert.Equal(original.Slot, decoded.Slot);
            Assert.Equal(ulong.MaxValue, decoded.Epoch);
            Assert.Equal(original.Parent, decoded.Parent);
            Assert.Equal(original.IssuedAtUtc, decoded.IssuedAtUtc);
            Assert.Equal(original.BootstrapDeadlineUtc, decoded.BootstrapDeadlineUtc);
            Assert.Equal(original.Nonce.ToArray(), decoded.Nonce.ToArray());
            Assert.Equal(original.Identity.ChildKind, decoded.Identity.ChildKind);
            Assert.Equal(original.Identity.BuildId, decoded.Identity.BuildId);
            Assert.Equal(original.Identity.BuildDigest.ToArray(), decoded.Identity.BuildDigest.ToArray());
            Assert.Equal(original.Identity.ProtocolVersion, decoded.Identity.ProtocolVersion);
            Assert.Equal(original.Identity.ContractSetDigest.ToArray(), decoded.Identity.ContractSetDigest.ToArray());
            Assert.Equal(endpoint?.Transport, decoded.Endpoint?.Transport);
            Assert.Equal(endpoint?.Address, decoded.Endpoint?.Address);
            Assert.Equal(original.Encode(), decoded.Encode());
        }
    }

    [Fact]
    public void ADescriptorClaimCarriesExactlyTheDescriptorIdentity()
    {
        var descriptor = Launches.Descriptor();

        var claim = descriptor.ToClaim();

        Assert.Equal(descriptor.LaunchId, claim.LaunchId);
        Assert.Equal(descriptor.Slot, claim.Slot);
        Assert.Equal(descriptor.Epoch, claim.Epoch);
        Assert.Equal(descriptor.Nonce.ToArray(), claim.Nonce.ToArray());
        Assert.Same(descriptor.Identity, claim.Identity);
    }

    [Fact]
    public void EveryTruncationAndEveryTrailingByteOfADescriptorIsRefused()
    {
        var encoded = Launches.Descriptor(LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.NamedPipe, "afl-abc")).Encode();

        for (var length = 0; length < encoded.Length; length++)
        {
            Assert.Throws<FormatException>(() => LocalRpcLaunchDescriptor.Decode(encoded.AsSpan(0, length)));
        }

        Assert.Throws<FormatException>(() => LocalRpcLaunchDescriptor.Decode([.. encoded, 0]));
        _ = LocalRpcLaunchDescriptor.Decode(encoded);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public void AForeignOrFutureDescriptorFormatIsRefused(int offset)
    {
        var encoded = Launches.Descriptor().Encode();
        encoded[offset] ^= 0xFF;

        Assert.Throws<FormatException>(() => LocalRpcLaunchDescriptor.Decode(encoded));
    }

    [Fact]
    public void MalformedDescriptorValuesAreRefusedAsFormatErrors()
    {
        var baseline = Launches.Descriptor(LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.NamedPipe, "afl-abc")).Encode();
        // Offsets: magic 0-3, version 4-5, id 6-21, epoch 22-29, pid 30-33, start 34-41, issued 42-49, deadline 50-57, kind 58, protocol 59-62, slot length 63.
        var mutations = new (string Name, Action<byte[]> Apply)[]
        {
            ("nil id", bytes => Array.Clear(bytes, 6, 16)),
            ("zero epoch", bytes => Array.Clear(bytes, 22, 8)),
            ("zero parent", bytes => Array.Clear(bytes, 30, 4)),
            ("deadline before issue", bytes => Array.Clear(bytes, 50, 8)),
            ("out of range time", bytes => bytes.AsSpan(42, 8).Fill(0xFF)),
            ("kind none", bytes => bytes[58] = 0),
            ("kind unknown", bytes => bytes[58] = 9),
            ("protocol zero", bytes => Array.Clear(bytes, 59, 4)),
            ("empty slot", bytes => bytes[63] = 0),
            ("long slot", bytes => bytes[63] = 200),
        };
        foreach (var (name, apply) in mutations)
        {
            var mutated = (byte[])baseline.Clone();
            apply(mutated);

            var error = Record.Exception(() => LocalRpcLaunchDescriptor.Decode(mutated));

            Assert.True(error is FormatException, name);
        }
    }

    [Fact]
    public void ABadSlotCharacterAnEndpointWithoutTransportAndAnUnknownTransportAreRefused()
    {
        var encoded = Launches.Descriptor().Encode();
        var slotStart = 64;
        var bad = (byte[])encoded.Clone();
        bad[slotStart] = (byte)'/';
        Assert.Throws<FormatException>(() => LocalRpcLaunchDescriptor.Decode(bad));

        var withAddress = Launches.Descriptor(LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.NamedPipe, "afl-abc")).Encode();
        var transportOffset = withAddress.Length - 2 - "afl-abc".Length - 1;
        var noTransport = (byte[])withAddress.Clone();
        noTransport[transportOffset] = 0;
        Assert.Throws<FormatException>(() => LocalRpcLaunchDescriptor.Decode(noTransport));
        var unknownTransport = (byte[])withAddress.Clone();
        unknownTransport[transportOffset] = 7;
        Assert.Throws<FormatException>(() => LocalRpcLaunchDescriptor.Decode(unknownTransport));
        var badAddress = (byte[])withAddress.Clone();
        badAddress[^1] = (byte)'/';
        Assert.Throws<FormatException>(() => LocalRpcLaunchDescriptor.Decode(badAddress));
    }

    [Fact]
    public void ABootstrapResourceIsTheDescriptorFollowedByExactlyTheSecret()
    {
        var descriptor = Launches.Descriptor();
        var secret = Launches.Bytes(0x5A);
        byte[] resource = [.. descriptor.Encode(), .. secret];
        var destination = new byte[LocalRpcLaunchDescriptor.SecretLength];

        var decoded = LocalRpcLaunchDescriptor.DecodeBootstrapResource(resource, destination);

        Assert.Equal(descriptor.LaunchId, decoded.LaunchId);
        Assert.Equal(secret, destination);
        Assert.Throws<FormatException>(() => LocalRpcLaunchDescriptor.DecodeBootstrapResource(resource.AsSpan(0, resource.Length - 1), destination));
        Assert.Throws<FormatException>(() => LocalRpcLaunchDescriptor.DecodeBootstrapResource([.. resource, 0], destination));
        Assert.Throws<FormatException>(() => LocalRpcLaunchDescriptor.DecodeBootstrapResource(descriptor.Encode(), destination));
        Assert.Throws<ArgumentException>(() => LocalRpcLaunchDescriptor.DecodeBootstrapResource(resource, new byte[31]));
        Assert.Throws<ArgumentException>(() => LocalRpcLaunchDescriptor.DecodeBootstrapResource(resource, new byte[33]));
    }

    [Fact]
    public void IdentityClaimAndDescriptorConstructionRefuseInvalidValues()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcLaunchIdentity(LocalRpcChildKind.None, "b", Launches.Bytes(1), 1, Launches.Bytes(2)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcLaunchIdentity((LocalRpcChildKind)42, "b", Launches.Bytes(1), 1, Launches.Bytes(2)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcLaunchIdentity(LocalRpcChildKind.Connector, "b", Launches.Bytes(1), 0, Launches.Bytes(2)));
        Assert.Throws<ArgumentException>(() => new LocalRpcLaunchIdentity(LocalRpcChildKind.Connector, "b", Launches.Bytes(1, 31), 1, Launches.Bytes(2)));
        Assert.Throws<ArgumentException>(() => new LocalRpcLaunchIdentity(LocalRpcChildKind.Connector, "b", Launches.Bytes(1), 1, Launches.Bytes(2, 33)));
        Assert.Throws<ArgumentNullException>(() => new LocalRpcLaunchIdentity(LocalRpcChildKind.Connector, null!, Launches.Bytes(1), 1, Launches.Bytes(2)));
        foreach (var token in new[] { string.Empty, "-leading", ".leading", "has space", "slash/x", "café", new string('a', 65) })
        {
            Assert.Throws<ArgumentException>(() => new LocalRpcLaunchIdentity(LocalRpcChildKind.Connector, token, Launches.Bytes(1), 1, Launches.Bytes(2)));
            Assert.Throws<ArgumentException>(() => new LocalRpcLaunchClaim(Guid.NewGuid(), token, 1, Launches.Bytes(3), Standard));
        }

        _ = new LocalRpcLaunchIdentity(LocalRpcChildKind.Connector, new string('a', 64), Launches.Bytes(1), 1, Launches.Bytes(2));
        _ = new LocalRpcLaunchIdentity(LocalRpcChildKind.ExecutableExtension, "a.b_c-d+e", Launches.Bytes(1), 1, Launches.Bytes(2));
        Assert.Throws<ArgumentException>(() => new LocalRpcLaunchClaim(Guid.NewGuid(), "slot", 1, Launches.Bytes(3, 31), Standard));
        Assert.Throws<ArgumentNullException>(() => new LocalRpcLaunchClaim(Guid.NewGuid(), "slot", 1, Launches.Bytes(3), null!));
        var parent = new LocalRpcProcessIdentity(1, 1);
        var nonce = Launches.Bytes(4);
        var issued = DateTimeOffset.UnixEpoch;
        Assert.Throws<ArgumentException>(() => new LocalRpcLaunchDescriptor(Guid.Empty, "s", 1, null, parent, Standard, nonce, issued, issued.AddSeconds(1)));
        Assert.Throws<ArgumentException>(() => new LocalRpcLaunchDescriptor(Guid.NewGuid(), "s", 0, null, parent, Standard, nonce, issued, issued.AddSeconds(1)));
        Assert.Throws<ArgumentException>(() => new LocalRpcLaunchDescriptor(Guid.NewGuid(), "s", 1, null, new LocalRpcProcessIdentity(0, 1), Standard, nonce, issued, issued.AddSeconds(1)));
        Assert.Throws<ArgumentException>(() => new LocalRpcLaunchDescriptor(Guid.NewGuid(), "s", 1, null, parent, Standard, Launches.Bytes(4, 31), issued, issued.AddSeconds(1)));
        Assert.Throws<ArgumentException>(() => new LocalRpcLaunchDescriptor(Guid.NewGuid(), "s", 1, null, parent, Standard, nonce, issued, issued));
        _ = new LocalRpcLaunchDescriptor(Guid.NewGuid(), "s", 1, null, parent, Standard, nonce, issued, issued.AddTicks(1));
    }

    [Fact]
    public void IdentityAndClaimCopyTheirByteInputs()
    {
        var digest = Launches.Bytes(9);
        var identity = new LocalRpcLaunchIdentity(LocalRpcChildKind.Connector, "b", digest, 1, digest);
        var nonce = Launches.Bytes(8);
        var claim = new LocalRpcLaunchClaim(Guid.NewGuid(), "s", 1, nonce, identity);

        digest[0] = 0;
        nonce[0] = 0;

        Assert.Equal(9, identity.BuildDigest.Span[0]);
        Assert.Equal(9, identity.ContractSetDigest.Span[0]);
        Assert.Equal(8, claim.Nonce.Span[0]);
    }

    // ---- process identity ----

    [Fact]
    public void ProcessIdentitiesMatchOnIdAndStartTimeWithinTheToleranceOnly()
    {
        var baseline = new LocalRpcProcessIdentity(77, 1_000_000_000_000);
        var tolerance = LocalRpcProcessIdentity.StartTimeTolerance.Ticks;

        Assert.True(baseline.Names(baseline with { StartTimeUtcTicks = baseline.StartTimeUtcTicks + tolerance }));
        Assert.True(baseline.Names(baseline with { StartTimeUtcTicks = baseline.StartTimeUtcTicks - tolerance }));
        Assert.False(baseline.Names(baseline with { StartTimeUtcTicks = baseline.StartTimeUtcTicks + tolerance + 1 }));
        Assert.False(baseline.Names(baseline with { StartTimeUtcTicks = baseline.StartTimeUtcTicks - tolerance - 1 }));
        Assert.False(baseline.Names(baseline with { ProcessId = 78 }));
        Assert.False(new LocalRpcProcessIdentity(0, 5).Names(new LocalRpcProcessIdentity(0, 5)));
        Assert.False(new LocalRpcProcessIdentity(-1, 5).Names(new LocalRpcProcessIdentity(-1, 5)));
    }

    [Fact]
    public void TheRealProbeSeesTheRunningProcessAndRefusesARecycledIdOrAMissingProcess()
    {
        var current = LocalRpcProcessIdentity.Current;
        using var self = Process.GetCurrentProcess();

        Assert.Equal(Environment.ProcessId, current.ProcessId);
        Assert.Equal(current, LocalRpcProcessIdentity.FromProcess(self));
        Assert.Equal(ProcessLiveness.Live, ProcessProbe.Probe(current));
        Assert.Equal(ProcessLiveness.Dead, ProcessProbe.Probe(current with { StartTimeUtcTicks = current.StartTimeUtcTicks + TimeSpan.FromHours(1).Ticks }));
        Assert.Equal(ProcessLiveness.Dead, ProcessProbe.Probe(current with { StartTimeUtcTicks = current.StartTimeUtcTicks - TimeSpan.FromHours(1).Ticks }));
        Assert.Equal(ProcessLiveness.Dead, ProcessProbe.Probe(new LocalRpcProcessIdentity(int.MaxValue, current.StartTimeUtcTicks)));
        Assert.Equal(ProcessLiveness.Dead, ProcessProbe.Probe(new LocalRpcProcessIdentity(0, current.StartTimeUtcTicks)));
        Assert.Equal(ProcessLiveness.Dead, ProcessProbe.Probe(new LocalRpcProcessIdentity(-5, current.StartTimeUtcTicks)));
        Assert.Throws<ArgumentNullException>(() => LocalRpcProcessIdentity.FromProcess(null!));
    }

    // ---- authority: epochs, fencing, claims ----

    [Fact]
    public async Task EpochsIncreaseWithinASlotAndAreIndependentAcrossSlots()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();

        var first = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        var other = authority.Launch("slot-b", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        var second = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);

        Assert.Equal(1UL, first.Descriptor.Epoch);
        Assert.Equal(1UL, other.Descriptor.Epoch);
        Assert.Equal(2UL, second.Descriptor.Epoch);
        Assert.Equal(LocalRpcLaunchRefusal.None, other.Status());
        Assert.Equal(world.Parent, second.Descriptor.Parent);
        Assert.NotEqual(first.Descriptor.LaunchId, second.Descriptor.LaunchId);
        Assert.NotEqual(first.Descriptor.Nonce.ToArray(), second.Descriptor.Nonce.ToArray());
        Assert.Equal(world.Clock.GetUtcNow(), second.Descriptor.IssuedAtUtc);
        Assert.Equal(world.Clock.GetUtcNow() + TimeSpan.FromSeconds(30), second.Descriptor.BootstrapDeadlineUtc);
    }

    [Fact]
    public async Task ANewerLaunchRevokesTheOlderAndTheOlderDescriptorNeverAuthorizesAgain()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var old = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        var oldClaim = old.Descriptor.ToClaim();
        Assert.Equal(LocalRpcLaunchRefusal.None, authority.Verify(oldClaim));

        var current = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);

        Assert.True(old.Revoked.IsCancellationRequested);
        Assert.False(current.Revoked.IsCancellationRequested);
        Assert.Equal(LocalRpcLaunchRefusal.StaleEpoch, authority.Verify(oldClaim));
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, old.Verify(oldClaim));
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, old.Status());
        Assert.True(old.SecretIsZeroed());
        Assert.Equal(LocalRpcLaunchRefusal.None, authority.Verify(current.Descriptor.ToClaim()));
        // A forged claim that reuses the old epoch's nonce with the new epoch number is a different claim and fails too.
        Assert.Equal(LocalRpcLaunchRefusal.NonceMismatch, authority.Verify(Launches.ClaimFrom(oldClaim, launchId: current.Descriptor.LaunchId, epoch: 2)));
    }

    [Fact]
    public async Task UnknownSlotsFutureEpochsAndForeignLaunchIdsAreRefused()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        var claim = launch.Descriptor.ToClaim();

        Assert.Equal(LocalRpcLaunchRefusal.UnknownSlot, authority.Verify(Launches.ClaimFrom(claim, slot: "slot-z")));
        Assert.Equal(LocalRpcLaunchRefusal.UnknownLaunch, authority.Verify(Launches.ClaimFrom(claim, epoch: 2)));
        Assert.Equal(LocalRpcLaunchRefusal.UnknownLaunch, authority.Verify(Launches.ClaimFrom(claim, launchId: Guid.NewGuid())));
        Assert.Equal(LocalRpcLaunchRefusal.UnknownLaunch, launch.Verify(Launches.ClaimFrom(claim, slot: "slot-z")));
        Assert.Equal(LocalRpcLaunchRefusal.UnknownLaunch, launch.Verify(Launches.ClaimFrom(claim, epoch: 9)));
        Assert.Equal(LocalRpcLaunchRefusal.None, authority.Verify(claim));
        Assert.Throws<ArgumentNullException>(() => authority.Verify(null!));
        Assert.Throws<ArgumentNullException>(() => launch.Verify(null!));
    }

    [Fact]
    public async Task AForgedNonceIsRefusedWhateverElseIsCorrect()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        var claim = launch.Descriptor.ToClaim();

        for (var index = 0; index < LocalRpcLaunchDescriptor.NonceLength; index++)
        {
            Assert.Equal(
                LocalRpcLaunchRefusal.NonceMismatch,
                authority.Verify(Launches.ClaimFrom(claim, nonce: Launches.Flip(claim.Nonce, index))));
        }

        Assert.Equal(LocalRpcLaunchRefusal.NonceMismatch, launch.Verify(Launches.ClaimFrom(claim, nonce: new byte[LocalRpcLaunchDescriptor.NonceLength])));
        Assert.Equal(LocalRpcLaunchRefusal.None, launch.Verify(claim));
    }

    [Fact]
    public async Task AForgedBuildKindOrProtocolIsRefusedWhateverElseIsCorrect()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        var claim = launch.Descriptor.ToClaim();

        var build = new (LocalRpcLaunchIdentity Forged, string Why)[]
        {
            (Launches.Identity(kind: LocalRpcChildKind.Connector), "kind"),
            (Launches.Identity(build: "contentsandbox-1.0.1"), "build id"),
            (Launches.Identity(buildFill: 0x12), "build digest"),
        };
        foreach (var (forged, why) in build)
        {
            Assert.True(
                LocalRpcLaunchRefusal.BuildMismatch == authority.Verify(Launches.ClaimFrom(claim, identity: forged)),
                why);
        }

        var protocol = new (LocalRpcLaunchIdentity Forged, string Why)[]
        {
            (Launches.Identity(protocol: 2), "protocol version"),
            (Launches.Identity(contractFill: 0x23), "contract-set digest"),
        };
        foreach (var (forged, why) in protocol)
        {
            Assert.True(
                LocalRpcLaunchRefusal.ProtocolMismatch == authority.Verify(Launches.ClaimFrom(claim, identity: forged)),
                why);
        }

        var oneBitOff = Launches.Flip(Standard.BuildDigest, 31);
        var oneBitIdentity = new LocalRpcLaunchIdentity(Standard.ChildKind, Standard.BuildId, oneBitOff, 1, Standard.ContractSetDigest.Span);
        Assert.Equal(LocalRpcLaunchRefusal.BuildMismatch, authority.Verify(Launches.ClaimFrom(claim, identity: oneBitIdentity)));
        var oneBitContract = new LocalRpcLaunchIdentity(Standard.ChildKind, Standard.BuildId, Standard.BuildDigest.Span, 1, Launches.Flip(Standard.ContractSetDigest, 31));
        Assert.Equal(LocalRpcLaunchRefusal.ProtocolMismatch, authority.Verify(Launches.ClaimFrom(claim, identity: oneBitContract)));
        Assert.Equal(LocalRpcLaunchRefusal.None, authority.Verify(Launches.ClaimFrom(claim, identity: Launches.Identity())));
    }

    [Fact]
    public async Task AnUnbootstrappedLaunchExpiresAtItsDeadlineAndABootstrappedOneDoesNot()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority(window: TimeSpan.FromSeconds(10));
        var waiting = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        var bootstrapped = authority.Launch("slot-b", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        Assert.Equal(1, bootstrapped.ConsumeSecret(1, static (state, _) => state));

        world.Clock.Advance(TimeSpan.FromSeconds(10) - TimeSpan.FromTicks(1));
        Assert.Equal(LocalRpcLaunchRefusal.None, waiting.Status());
        Assert.Equal(LocalRpcLaunchRefusal.None, authority.Verify(waiting.Descriptor.ToClaim()));
        world.Clock.Advance(TimeSpan.FromTicks(1));

        Assert.Equal(LocalRpcLaunchRefusal.Expired, waiting.Status());
        Assert.Equal(LocalRpcLaunchRefusal.Expired, authority.Verify(waiting.Descriptor.ToClaim()));
        Assert.False(await waiting.AuthorizeConnectionAsync(new LocalRpcConnectionInfo(LocalRpcTransport.NamedPipe, 1), CancellationToken.None));
        world.Clock.Advance(TimeSpan.FromHours(1));
        Assert.Equal(LocalRpcLaunchRefusal.None, bootstrapped.Status());
        Assert.Equal(LocalRpcLaunchRefusal.None, authority.Verify(bootstrapped.Descriptor.ToClaim()));
    }

    [Fact]
    public async Task ALaunchIssuedByAnotherOrAVanishedParentNeverAuthorizes()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);

        world.Processes.Set(world.Parent, ProcessLiveness.Dead);
        Assert.Equal(LocalRpcLaunchRefusal.ParentMismatch, launch.Status());
        Assert.Equal(LocalRpcLaunchRefusal.ParentMismatch, authority.Verify(launch.Descriptor.ToClaim()));
        world.Processes.Set(world.Parent, ProcessLiveness.Unknown);
        Assert.Equal(LocalRpcLaunchRefusal.ParentMismatch, launch.Status());
        world.Processes.Set(world.Parent, ProcessLiveness.Live);
        Assert.Equal(LocalRpcLaunchRefusal.None, launch.Status());

        // A descriptor naming a different (live) parent than the verifying process: a descriptor of another parent or a forged copy.
        var foreign = world.SpawnFake(9001);
        await using var forged = new LocalRpcLaunch(Launches.Descriptor(parent: foreign), null, world.Environment());
        Assert.Equal(LocalRpcLaunchRefusal.ParentMismatch, forged.Status());
        Assert.Equal(LocalRpcLaunchRefusal.ParentMismatch, forged.Verify(forged.Descriptor.ToClaim()));
    }

    [Fact]
    public async Task ABoundChildIsRequiredToKeepRunning()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        var child = world.SpawnFake(5150);

        launch.BindChild(child);

        Assert.Equal(LocalRpcLaunchRefusal.None, launch.Status());
        Assert.Equal(LocalRpcLaunchRefusal.None, authority.Verify(launch.Descriptor.ToClaim()));
        world.Processes.Set(child, ProcessLiveness.Unknown);
        Assert.Equal(LocalRpcLaunchRefusal.ChildGone, launch.Status());
        world.Processes.Set(child, ProcessLiveness.Dead);
        Assert.Equal(LocalRpcLaunchRefusal.ChildGone, authority.Verify(launch.Descriptor.ToClaim()));
        Assert.False(await launch.AuthorizeConnectionAsync(new LocalRpcConnectionInfo(LocalRpcTransport.NamedPipe, 1), CancellationToken.None));
        world.Processes.Set(child, ProcessLiveness.Live);
        Assert.Equal(LocalRpcLaunchRefusal.None, launch.Status());
    }

    [Fact]
    public async Task BindingAChildRefusesTheParentANonRunningProcessADoubleBindAndARevokedLaunch()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);

        Assert.Throws<ArgumentException>(() => launch.BindChild(world.Parent));
        Assert.Throws<ArgumentException>(() => launch.BindChild(new LocalRpcProcessIdentity(0, 1)));
        Assert.Throws<ArgumentException>(() => launch.BindChild(new LocalRpcProcessIdentity(-3, 1)));
        Assert.Throws<InvalidOperationException>(() => launch.BindChild(world.SpawnFake(6001, ProcessLiveness.Dead)));
        Assert.Throws<InvalidOperationException>(() => launch.BindChild(world.SpawnFake(6002, ProcessLiveness.Unknown)));
        launch.BindChild(world.SpawnFake(6003));
        Assert.Throws<InvalidOperationException>(() => launch.BindChild(world.SpawnFake(6004)));
        var second = authority.Launch("slot-b", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        second.Revoke();
        Assert.Throws<InvalidOperationException>(() => second.BindChild(world.SpawnFake(6005)));
    }

    // ---- one-use secret and handoff ----

    [Fact]
    public async Task TheBootstrapResourceIsHandedOffOnceAndCarriesTheDescriptorAndTheSecret()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);

        var resource = launch.HandoffBootstrapResource();
        var secret = new byte[LocalRpcLaunchDescriptor.SecretLength];
        var decoded = LocalRpcLaunchDescriptor.DecodeBootstrapResource(resource, secret);

        Assert.Equal(launch.Descriptor.LaunchId, decoded.LaunchId);
        Assert.Equal(launch.Descriptor.Nonce.ToArray(), decoded.Nonce.ToArray());
        Assert.NotEqual(new byte[32], secret);
        var seen = launch.ConsumeSecret(secret.ToArray(), static (expected, actual) => actual.SequenceEqual(expected));
        Assert.True(seen);
        Assert.Throws<InvalidOperationException>(launch.HandoffBootstrapResource);
        var other = authority.Launch("slot-b", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        _ = other.HandoffBootstrapResource();
        Assert.Throws<InvalidOperationException>(other.HandoffBootstrapResource);
    }

    [Fact]
    public async Task EveryLaunchHasItsOwnSecretAndNonce()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var secrets = new HashSet<string>(StringComparer.Ordinal);
        var nonces = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < 20; index++)
        {
            var launch = authority.Launch("slot-" + index, Standard, LocalRpcLaunchTransport.SuppliedStreams);
            var secret = new byte[LocalRpcLaunchDescriptor.SecretLength];
            _ = LocalRpcLaunchDescriptor.DecodeBootstrapResource(launch.HandoffBootstrapResource(), secret);
            Assert.True(secrets.Add(Convert.ToHexString(secret)));
            Assert.True(nonces.Add(Convert.ToHexString(launch.Descriptor.Nonce.Span)));
            Assert.NotEqual(launch.Descriptor.Nonce.ToArray(), secret);
        }
    }

    [Fact]
    public async Task TheSecretIsConsumedOnceAndDestroyedWhateverTheOutcome()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        Assert.False(launch.SecretIsZeroed());

        var length = launch.ConsumeSecret(0, static (_, secret) => secret.Length);

        Assert.Equal(LocalRpcLaunchDescriptor.SecretLength, length);
        Assert.True(launch.SecretIsZeroed());
        Assert.Throws<InvalidOperationException>(() => launch.ConsumeSecret(0, static (_, secret) => secret.Length));
        Assert.Throws<ArgumentNullException>(() => launch.ConsumeSecret<int, int>(0, null!));

        var failing = authority.Launch("slot-b", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        Assert.Throws<InvalidOperationException>(() => failing.ConsumeSecret<int, int>(0, static (_, _) => throw new InvalidOperationException("proof rejected")));
        Assert.True(failing.SecretIsZeroed());
        Assert.Throws<InvalidOperationException>(() => failing.ConsumeSecret(0, static (_, secret) => secret.Length));
    }

    [Fact]
    public async Task ARevokedLaunchHasNoSecretLeft()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);

        launch.Revoke();
        launch.Revoke();

        Assert.True(launch.SecretIsZeroed());
        Assert.True(launch.Revoked.IsCancellationRequested);
        Assert.Throws<InvalidOperationException>(launch.HandoffBootstrapResource);
        Assert.Throws<InvalidOperationException>(() => launch.ConsumeSecret(0, static (_, secret) => secret.Length));
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, launch.Status());
    }

    // ---- connection decision ----

    [Fact]
    public async Task ASuppliedStreamLaunchAdmitsOnlyConnectionsWithoutAnEndpoint()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        var foreign = LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.NamedPipe, "afl-foreign");

        Assert.Null(launch.Endpoint);
        Assert.True(await launch.AuthorizeConnectionAsync(new LocalRpcConnectionInfo(LocalRpcTransport.NamedPipe, 1), CancellationToken.None));
        Assert.False(await launch.AuthorizeConnectionAsync(new LocalRpcConnectionInfo(LocalRpcTransport.NamedPipe, 2, foreign), CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await launch.AuthorizeConnectionAsync(null!, CancellationToken.None));
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await launch.AuthorizeConnectionAsync(new LocalRpcConnectionInfo(LocalRpcTransport.NamedPipe, 3), cancelled.Token));
        launch.Revoke();
        Assert.False(await launch.AuthorizeConnectionAsync(new LocalRpcConnectionInfo(LocalRpcTransport.NamedPipe, 4), CancellationToken.None));
    }

    [Fact]
    public async Task AnEndpointLaunchAdmitsOnlyConnectionsOnItsOwnEndpoint()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var launch = authority.Launch("slot-a", Standard);
        var endpoint = launch.Endpoint;
        Assert.NotNull(endpoint);
        var otherAddress = LocalRpcEndpoint.CreateForVerification(endpoint.Transport, endpoint.Address[..^1] + "x");
        var otherTransport = LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.NamedPipe, "afl-" + Guid.NewGuid().ToString("N"));

        Assert.True(await launch.AuthorizeConnectionAsync(new LocalRpcConnectionInfo(endpoint.Transport, 1, endpoint), CancellationToken.None));
        Assert.False(await launch.AuthorizeConnectionAsync(new LocalRpcConnectionInfo(endpoint.Transport, 2, otherAddress), CancellationToken.None));
        Assert.False(await launch.AuthorizeConnectionAsync(new LocalRpcConnectionInfo(endpoint.Transport, 3, otherTransport), CancellationToken.None));
        Assert.False(await launch.AuthorizeConnectionAsync(new LocalRpcConnectionInfo(endpoint.Transport, 4), CancellationToken.None));
        launch.Revoke();
        Assert.False(await launch.AuthorizeConnectionAsync(new LocalRpcConnectionInfo(endpoint.Transport, 5, endpoint), CancellationToken.None));
    }

    // ---- authority lifecycle ----

    [Fact]
    public async Task TheAuthorityRefusesBadArgumentsAndIsDisposedOnce()
    {
        using var world = new LaunchWorld();
        Assert.Throws<ArgumentOutOfRangeException>(() => world.Authority(window: TimeSpan.FromMilliseconds(999)));
        Assert.Throws<ArgumentOutOfRangeException>(() => world.Authority(window: TimeSpan.FromMinutes(5) + TimeSpan.FromTicks(1)));
        await using (world.Authority(window: TimeSpan.FromSeconds(1)))
        {
        }

        await using (world.Authority(window: TimeSpan.FromMinutes(5)))
        {
        }

        await using var authority = world.Authority();
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);

        Assert.Throws<ArgumentException>(() => authority.Launch("bad slot", Standard));
        Assert.Throws<ArgumentNullException>(() => authority.Launch("slot-a", null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => authority.Launch("slot-a", Standard, (LocalRpcLaunchTransport)9));
        await authority.DisposeAsync();
        await authority.DisposeAsync();

        Assert.Equal(0, authority.IssuedCount);
        Assert.True(launch.Revoked.IsCancellationRequested);
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, launch.Status());
        Assert.Throws<ObjectDisposedException>(() => authority.Launch("slot-a", Standard));
        Assert.Throws<ObjectDisposedException>(() => authority.SweepStale());
    }

    [Fact]
    public async Task SixtyFourConcurrentLaunchesGetUniqueIdentitiesAndGaplessEpochsWithOneCurrentLaunchPerSlot()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        const int slots = 8;
        const int perSlot = 8;

        var launches = await Task.WhenAll(Enumerable.Range(0, slots * perSlot).Select(index => Task.Run(() =>
            authority.Launch("slot-" + (index % slots), Standard))));

        Assert.Equal(slots * perSlot, launches.Select(launch => launch.Descriptor.LaunchId).Distinct().Count());
        Assert.Equal(slots * perSlot, launches.Select(launch => Convert.ToHexString(launch.Descriptor.Nonce.Span)).Distinct().Count());
        Assert.Equal(slots * perSlot, launches.Select(launch => launch.Endpoint!.Address).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(slots * perSlot, launches.Select(launch => launch.DirectoryPath!).Distinct(StringComparer.Ordinal).Count());
        Assert.All(launches, launch => Assert.True(Directory.Exists(launch.DirectoryPath)));
        foreach (var group in launches.GroupBy(launch => launch.Descriptor.Slot))
        {
            Assert.Equal(Enumerable.Range(1, perSlot).Select(epoch => (ulong)epoch), group.Select(launch => launch.Descriptor.Epoch).Order());
            var current = group.Single(launch => launch.Descriptor.Epoch == perSlot);
            Assert.Equal(LocalRpcLaunchRefusal.None, authority.Verify(current.Descriptor.ToClaim()));
            Assert.All(group.Where(launch => launch != current), stale =>
            {
                Assert.Equal(LocalRpcLaunchRefusal.StaleEpoch, authority.Verify(stale.Descriptor.ToClaim()));
                Assert.True(stale.Revoked.IsCancellationRequested);
            });
        }

        foreach (var launch in launches)
        {
            await launch.DisposeAsync();
        }

        Assert.Empty(Directory.EnumerateFileSystemEntries(world.Root));
    }

    [Fact]
    public async Task TheAuthorityForgetsALaunchOnceItIsDisposed()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var launches = Enumerable.Range(0, 3).Select(index => authority.Launch("slot-" + index, Standard, LocalRpcLaunchTransport.SuppliedStreams)).ToArray();

        Assert.Equal(3, authority.IssuedCount);
        await launches[0].DisposeAsync();
        await launches[0].DisposeAsync();
        await launches[1].DisposeAsync();

        Assert.Equal(1, authority.IssuedCount);
    }

    [Fact]
    public async Task AFailedLaunchLeavesNoDirectoryAndNoEpochBehind()
    {
        using var world = new LaunchWorld();
        await using var broken = world.Authority(parent: new LocalRpcProcessIdentity(0, 0));

        Assert.Throws<ArgumentException>(() => broken.Launch("slot-a", Standard));

        Assert.Empty(Directory.EnumerateFileSystemEntries(world.Root));
        await using var healthy = world.Authority();
        Assert.Equal(1UL, healthy.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams).Descriptor.Epoch);
    }


    // ---- secret consumption is gated by the launch status (review finding 1)

    [Fact]
    public async Task AnExpiredLaunchCannotConsumeItsSecretAndStaysExpired()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority(window: TimeSpan.FromSeconds(10));
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        var ran = false;
        world.Clock.Advance(TimeSpan.FromSeconds(11));
        Assert.Equal(LocalRpcLaunchRefusal.Expired, launch.Status());

        var error = Assert.Throws<InvalidOperationException>(() => launch.ConsumeSecret(0, (_, _) =>
        {
            ran = true;
            return 0;
        }));

        Assert.Contains("Expired", error.Message, StringComparison.Ordinal);
        Assert.False(ran);
        Assert.True(launch.SecretIsZeroed());
        Assert.Equal(LocalRpcLaunchRefusal.Expired, launch.Status());
        Assert.Equal(LocalRpcLaunchRefusal.Expired, authority.Verify(launch.Descriptor.ToClaim()));
        Assert.False(await launch.AuthorizeConnectionAsync(new LocalRpcConnectionInfo(LocalRpcTransport.NamedPipe, 1), CancellationToken.None));
        Assert.Throws<InvalidOperationException>(launch.HandoffBootstrapResource);
    }

    [Fact]
    public async Task ALaunchWhoseChildOrParentIsGoneCannotConsumeItsSecret()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var orphaned = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        var child = world.SpawnFake(5301);
        orphaned.BindChild(child);
        world.Processes.Set(child, ProcessLiveness.Dead);
        var ran = false;

        var gone = Assert.Throws<InvalidOperationException>(() => orphaned.ConsumeSecret(0, (_, _) => ran = true));

        Assert.Contains("ChildGone", gone.Message, StringComparison.Ordinal);
        Assert.False(ran);
        Assert.True(orphaned.SecretIsZeroed());
        var parentless = authority.Launch("slot-b", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        world.Processes.Set(world.Parent, ProcessLiveness.Dead);
        var parent = Assert.Throws<InvalidOperationException>(() => parentless.ConsumeSecret(0, (_, _) => ran = true));
        Assert.Contains("ParentMismatch", parent.Message, StringComparison.Ordinal);
        Assert.False(ran);
    }

    [Fact]
    public async Task AProofThatFinishesAfterTheDeadlineDoesNotExtendTheLaunch()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority(window: TimeSpan.FromSeconds(10));
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);

        var late = Assert.Throws<InvalidOperationException>(() => launch.ConsumeSecret(0, (_, _) =>
        {
            world.Clock.Advance(TimeSpan.FromSeconds(11));
            return 1;
        }));

        Assert.Contains("Expired", late.Message, StringComparison.Ordinal);
        Assert.Equal(LocalRpcLaunchRefusal.Expired, launch.Status());
        world.Clock.Advance(TimeSpan.FromHours(1));
        Assert.Equal(LocalRpcLaunchRefusal.Expired, authority.Verify(launch.Descriptor.ToClaim()));
    }

    [Fact]
    public async Task ARejectedProofSpendsTheSecretAndLeavesTheLaunchToExpire()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority(window: TimeSpan.FromSeconds(10));
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);

        Assert.Throws<FormatException>(() => launch.ConsumeSecret<int, int>(0, (_, _) => throw new FormatException("proof rejected")));

        Assert.Equal(LocalRpcLaunchRefusal.None, launch.Status());
        world.Clock.Advance(TimeSpan.FromSeconds(11));
        Assert.Equal(LocalRpcLaunchRefusal.Expired, launch.Status());
    }

    [Fact]
    public async Task TheSecretCallbackRunsOutsideTheLaunchLock()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var consuming = Task.Run(() => launch.ConsumeSecret(0, (_, _) =>
        {
            entered.Set();
            return release.Wait(TimeSpan.FromSeconds(30));
        }), TestContext.Current.CancellationToken);
        Assert.True(entered.Wait(TimeSpan.FromSeconds(20), TestContext.Current.CancellationToken));

        var decision = Task.Run(async () => await launch.AuthorizeConnectionAsync(new LocalRpcConnectionInfo(LocalRpcTransport.NamedPipe, 1), CancellationToken.None), TestContext.Current.CancellationToken);
        var status = Task.Run(launch.Status, TestContext.Current.CancellationToken);
        var finishedWhileTheCallbackBlocks = true;
        try
        {
            await Task.WhenAll(decision, status).WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        }
        catch (TimeoutException)
        {
            finishedWhileTheCallbackBlocks = false;
        }

        release.Set();

        Assert.True(finishedWhileTheCallbackBlocks, "a blocked secret callback must not stall connection decisions");
        Assert.True(await consuming);
        Assert.True(await decision);
        Assert.Equal(LocalRpcLaunchRefusal.None, await status);
    }

    [Fact]
    public async Task RevokedCallbacksRunOutsideTheAuthorityLock()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var old = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        var claim = old.Descriptor.ToClaim();
        var completed = false;
        using var registration = old.Revoked.Register(() => completed = Task.Run(() => authority.Verify(claim)).Wait(TimeSpan.FromSeconds(10)));

        _ = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);

        Assert.True(completed, "a Revoked callback that uses the authority must not deadlock with the launch that revoked it");
    }

    [Fact]
    public void ARealProcessProbeAgreesWithItselfAcrossPlatforms()
    {
        using var self = Process.GetCurrentProcess();
        var identity = LocalRpcProcessIdentity.FromProcess(self);

        Assert.Equal(ProcessLiveness.Live, ProcessProbe.Probe(identity));
        Assert.Equal(identity, LocalRpcProcessIdentity.Current);
        Assert.True(identity.StartTimeUtcTicks > 0);
    }

    [Theory]
    [InlineData("4242 (bash) S", 1234L, 'S')]
    [InlineData("4242 (we ird) name) R", 99L, 'R')]
    [InlineData("1 (a b c d) Z", 7L, 'Z')]
    public void ALinuxStatLineGivesItsStateAndStartTicksWhateverTheCommandName(string head, long ticks, char state)
    {
        // Fields 4..52 follow the state; the start time is field 22 and every other field here is a distinct decoy.
        var fields = Enumerable.Range(4, 49).Select(number => number == 22 ? ticks.ToString(System.Globalization.CultureInfo.InvariantCulture) : (1000 + number).ToString(System.Globalization.CultureInfo.InvariantCulture));
        var line = head + " " + string.Join(' ', fields) + "\n";

        Assert.True(ProcessStart.TryParseLinuxStat(line, out var parsedState, out var parsedTicks));

        Assert.Equal(state, parsedState);
        Assert.Equal(ticks, parsedTicks);
    }

    [Theory]
    [InlineData("")]
    [InlineData("4242 bash S 1 2 3")]
    [InlineData("4242 (bash)")]
    [InlineData("4242 (bash) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 x")]
    [InlineData("4242 (bash) SS 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19")]
    [InlineData("4242 (bash) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18")]
    [InlineData("4242 (bash) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 -5")]
    [InlineData("4242 (bash) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99999999999999999999")]
    [InlineData("4242 (bash) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 9223372036854775807")]
    public void AMalformedLinuxStatLineIsRefused(string line)
    {
        Assert.False(ProcessStart.TryParseLinuxStat(line, out _, out _));
    }


    [Fact]
    public async Task ABootstrapResourceCannotBeHandedOffOnceTheSecretIsSpentOrTheLaunchNoLongerAuthorizes()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority(window: TimeSpan.FromSeconds(10));

        var consumed = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        Assert.Equal(1, consumed.ConsumeSecret(1, static (state, _) => state));
        Assert.Throws<InvalidOperationException>(consumed.HandoffBootstrapResource);

        var revoked = authority.Launch("slot-b", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        revoked.Revoke();
        Assert.Throws<InvalidOperationException>(revoked.HandoffBootstrapResource);

        var childless = authority.Launch("slot-c", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        var child = world.SpawnFake(5401);
        childless.BindChild(child);
        world.Processes.Set(child, ProcessLiveness.Dead);
        Assert.Throws<InvalidOperationException>(childless.HandoffBootstrapResource);

        var parentless = authority.Launch("slot-d", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        world.Processes.Set(world.Parent, ProcessLiveness.Dead);
        Assert.Throws<InvalidOperationException>(parentless.HandoffBootstrapResource);
        world.Processes.Set(world.Parent, ProcessLiveness.Live);

        var expired = authority.Launch("slot-e", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        world.Clock.Advance(TimeSpan.FromSeconds(11));
        Assert.Throws<InvalidOperationException>(expired.HandoffBootstrapResource);
        Assert.True(expired.SecretIsZeroed());
    }


    // ---- the callback's copy of the secret, the clocks, and a throwing Revoked callback (re-review)

    [Fact]
    public async Task TheSecretCopyTheCallbackReceivedIsZeroedWhenTheCallbackReturnsOrThrows()
    {
        using var world = new LaunchWorld();
        var released = new List<byte[]>();
        await using var authority = LocalRpcLaunchAuthority.Create(world.Root, null, world.Environment() with { SecretCopyReleased = released.Add });
        var returning = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        var resource = returning.HandoffBootstrapResource();
        var handedOver = resource[^LocalRpcLaunchDescriptor.SecretLength..];
        var seen = Array.Empty<byte>();

        _ = returning.ConsumeSecret(0, (_, secret) =>
        {
            seen = secret.ToArray();
            return 0;
        });

        Assert.Equal(handedOver, seen);
        Assert.NotEqual(new byte[LocalRpcLaunchDescriptor.SecretLength], seen);
        var copy = Assert.Single(released);
        Assert.Equal(new byte[LocalRpcLaunchDescriptor.SecretLength], copy);

        var throwing = authority.Launch("slot-b", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        Assert.Throws<FormatException>(() => throwing.ConsumeSecret<int, int>(0, (_, secret) =>
        {
            seen = secret.ToArray();
            throw new FormatException("proof rejected");
        }));
        Assert.NotEqual(new byte[LocalRpcLaunchDescriptor.SecretLength], seen);
        Assert.Equal(2, released.Count);
        Assert.Equal(new byte[LocalRpcLaunchDescriptor.SecretLength], released[1]);
    }

    [Fact]
    public async Task TheSecretCopyIsZeroedWhenTheLaunchRefusesTheConsumption()
    {
        using var world = new LaunchWorld();
        var released = new List<byte[]>();
        await using var authority = LocalRpcLaunchAuthority.Create(world.Root, null, world.Environment() with { SecretCopyReleased = released.Add });
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        var child = world.SpawnFake(5501);
        launch.BindChild(child);
        world.Processes.Set(child, ProcessLiveness.Dead);

        Assert.Throws<InvalidOperationException>(() => launch.ConsumeSecret(0, (_, _) => 0));

        var copy = Assert.Single(released);
        Assert.Equal(new byte[LocalRpcLaunchDescriptor.SecretLength], copy);
        Assert.True(launch.SecretIsZeroed());
    }

    [Fact]
    public async Task ASecretCopyTheCallbackSawIsNotLeftBehindWhenTheCallbackRevokesTheLaunch()
    {
        using var world = new LaunchWorld();
        var released = new List<byte[]>();
        await using var authority = LocalRpcLaunchAuthority.Create(world.Root, null, world.Environment() with { SecretCopyReleased = released.Add });
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);

        var error = Assert.Throws<InvalidOperationException>(() => launch.ConsumeSecret(0, (_, _) =>
        {
            launch.Revoke();
            return 0;
        }));

        Assert.Contains("Revoked", error.Message, StringComparison.Ordinal);
        Assert.Equal(new byte[LocalRpcLaunchDescriptor.SecretLength], Assert.Single(released));
    }

    [Fact]
    public async Task AWallClockStepBackwardCannotExtendTheBootstrapWindowAndAStepForwardShortensIt()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority(window: TimeSpan.FromSeconds(10));
        var stepped = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        var forward = authority.Launch("slot-b", Standard, LocalRpcLaunchTransport.SuppliedStreams);

        world.Clock.Advance(TimeSpan.FromSeconds(6));
        world.Clock.StepWallClock(TimeSpan.FromHours(-1));
        Assert.Equal(LocalRpcLaunchRefusal.None, stepped.Status());
        world.Clock.Advance(TimeSpan.FromSeconds(5));
        Assert.Equal(LocalRpcLaunchRefusal.Expired, stepped.Status());
        Assert.Equal(LocalRpcLaunchRefusal.Expired, authority.Verify(stepped.Descriptor.ToClaim()));
        Assert.Equal(LocalRpcLaunchRefusal.Expired, forward.Status());

        using var second = new LaunchWorld();
        await using var other = second.Authority(window: TimeSpan.FromSeconds(10));
        var launch = other.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        second.Clock.StepWallClock(TimeSpan.FromSeconds(11));
        Assert.Equal(LocalRpcLaunchRefusal.Expired, launch.Status());
    }

    [Fact]
    public async Task TheMonotonicWindowEndsExactlyAtItsLengthWithoutHelpFromTheWallClock()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority(window: TimeSpan.FromSeconds(10));
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);

        world.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(10) - TimeSpan.FromTicks(1));
        Assert.Equal(LocalRpcLaunchRefusal.None, launch.Status());
        world.Clock.AdvanceMonotonic(TimeSpan.FromTicks(1));

        Assert.Equal(LocalRpcLaunchRefusal.Expired, launch.Status());
    }

    [Fact]
    public async Task ExpiryOnceSeenIsLatchedEvenIfTheWallClockLaterStepsBack()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority(window: TimeSpan.FromSeconds(10));
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        world.Clock.StepWallClock(TimeSpan.FromSeconds(11));
        Assert.Equal(LocalRpcLaunchRefusal.Expired, launch.Status());

        world.Clock.StepWallClock(TimeSpan.FromHours(-2));

        Assert.Equal(LocalRpcLaunchRefusal.Expired, launch.Status());
        Assert.Equal(LocalRpcLaunchRefusal.Expired, authority.Verify(launch.Descriptor.ToClaim()));
    }

    [Fact]
    public async Task AnExpiredLaunchDestroysItsStoredSecretAsSoonAsExpiryIsSeen()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority(window: TimeSpan.FromSeconds(10));
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        Assert.False(launch.SecretIsZeroed());

        world.Clock.Advance(TimeSpan.FromSeconds(11));
        Assert.False(launch.SecretIsZeroed());
        Assert.Equal(LocalRpcLaunchRefusal.Expired, launch.Status());

        Assert.True(launch.SecretIsZeroed());
    }

    [Fact]
    public async Task ARevokedCallbackThatThrowsNeitherUndoesTheRevocationNorFailsTheCallerThatCausedIt()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var old = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        var ran = 0;
        using var first = old.Revoked.Register(() =>
        {
            ran++;
            throw new InvalidOperationException("the owner's callback failed");
        });
        using var second = old.Revoked.Register(() => ran++);

        var current = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);

        Assert.Equal(2UL, current.Descriptor.Epoch);
        Assert.Equal(2, ran);
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, old.Status());
        Assert.Equal(LocalRpcLaunchRefusal.None, authority.Verify(current.Descriptor.ToClaim()));
        old.Revoke();

        var direct = authority.Launch("slot-b", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        using var third = direct.Revoked.Register(() => throw new InvalidOperationException("again"));
        direct.Revoke();
        Assert.True(direct.Revoked.IsCancellationRequested);
        await direct.DisposeAsync();
    }
}
