// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.ContentSandbox.Broker;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.LocalRpc.Sandbox.V1;
using ArcForges.LocalRpc;
using Xunit;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>The thin facade: the fixed contract facts, the launch frame, the record mapping and the budget. Offline; no process is started.</summary>
public sealed class ContractFacadeTests
{
    private static ContentSandboxLaunchFrame Frame(Action<List<ContentSandboxHandleEntry>>? handles = null, string profile = "hostile-test-parser", byte[]? bootstrap = null, ContentSandboxLimits? limits = null, ulong inputLength = 100, IReadOnlyList<ulong>? slots = null, byte[]? nativeBootstrap = null)
    {
        var list = new List<ContentSandboxHandleEntry>
        {
            new(ContentSandboxHandleRole.Control, 10),
            new(ContentSandboxHandleRole.Service, 11),
            new(ContentSandboxHandleRole.Input, 12),
            new(ContentSandboxHandleRole.Slot0, 13),
            new(ContentSandboxHandleRole.Slot1, 14),
        };
        handles?.Invoke(list);
        return new ContentSandboxLaunchFrame(
            ContentSandboxProfileKind.WindowsAppContainerJob,
            Guid.NewGuid(),
            Guid.NewGuid(),
            1,
            Guid.NewGuid(),
            inputLength,
            SHA256.HashData("input"u8),
            slots ?? [1024, 2048],
            limits ?? new ContentSandboxLimits(),
            list,
            profile,
            bootstrap ?? [1, 2, 3, 4], nativeBootstrap);
    }

    [Fact]
    public void TheFactsOfTheContractAreTheGeneratedOnesAndTheDigestIsStable()
    {
        Assert.Equal("arcforges.local.sandbox.v1.ContentSandboxService", ContentSandboxContract.ServiceName);
        Assert.Equal(32, ContentSandboxContract.ContractSetDigest.Length);
        Assert.True(ContentSandboxContract.ContractSetDigest.Span.SequenceEqual(ContentSandboxContract.ContractSetDigest.Span));
        Assert.Contains(ContentSandboxService.Descriptor.Methods, method => method.Name == ContentSandboxContract.RenewSessionMethod);
        Assert.Contains(ContentSandboxService.Descriptor.Methods, method => method.Name == ContentSandboxContract.CancelSessionMethod);
        Assert.Equal(15, ContentSandboxService.Descriptor.Methods.Count);
        Assert.Equal(3, ContentSandboxContract.MaxSlots);
        Assert.Equal(64L * 1024 * 1024, ContentSandboxContract.MaxSlotBytes);
    }

    [Fact]
    public void AFrameRoundTripsExactlyAndTheFrameClearsItsSecret()
    {
        using var original = Frame();
        var encoded = original.Encode();
        using var decoded = ContentSandboxLaunchFrame.Decode(encoded.AsSpan(4));
        Assert.Equal(original.InvocationId, decoded.InvocationId);
        Assert.Equal(original.LeaseId, decoded.LeaseId);
        Assert.Equal(original.InputId, decoded.InputId);
        Assert.Equal(original.InputLength, decoded.InputLength);
        Assert.Equal(original.InputDigest, decoded.InputDigest);
        Assert.Equal(original.SlotCapacities, decoded.SlotCapacities);
        Assert.Equal(original.Limits, decoded.Limits);
        Assert.Equal(original.ParserProfile, decoded.ParserProfile);
        Assert.Equal(original.BootstrapResource, decoded.BootstrapResource);
        Assert.Equal(original.Handles, decoded.Handles);
        Assert.True(decoded.TryGetHandle(ContentSandboxHandleRole.Slot1, out var slot1) && slot1 == 14);
        Assert.False(decoded.TryGetHandle(ContentSandboxHandleRole.Slot2, out _));
        decoded.Dispose();
        Assert.All(decoded.BootstrapResource, value => Assert.Equal(0, value));
    }

    [Fact]
    public void ReleaseNativeBootstrapRoundTripsInVersionTwoWithoutChangingHistoricalVersionOne()
    {
        byte[] release = "{\"fixture\":true}"u8.ToArray();
        using var current = Frame(nativeBootstrap: release);
        var encoded = current.Encode();
        using var decoded = ContentSandboxLaunchFrame.Decode(encoded.AsSpan(4));
        Assert.Equal(release, decoded.NativeBootstrap);
        Assert.Equal((byte)2, encoded[13]);
        using var previous = Frame();
        Assert.Equal((byte)1, previous.Encode()[13]);
        var oversized = encoded.ToArray();
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(oversized.AsSpan(oversized.Length - release.Length - 4), ContentSandboxLaunchFrame.MaxNativeBootstrapBytes + 1);
        _ = Assert.Throws<FormatException>(() => ContentSandboxLaunchFrame.Decode(oversized.AsSpan(4)));
        _ = Assert.Throws<ArgumentException>(() => Frame(nativeBootstrap: new byte[ContentSandboxLaunchFrame.MaxNativeBootstrapBytes + 1]));
    }

    [Theory]
    [InlineData("magic")]
    [InlineData("trailing")]
    [InlineData("truncated")]
    [InlineData("duplicate-role")]
    [InlineData("zero-handle")]
    [InlineData("missing-slot")]
    [InlineData("missing-control")]
    [InlineData("extra-handle")]
    [InlineData("zero-slot")]
    [InlineData("huge-slot")]
    [InlineData("zero-limit")]
    [InlineData("limit-over-profile")]
    [InlineData("bad-profile")]
    [InlineData("empty-bootstrap")]
    [InlineData("big-bootstrap")]
    [InlineData("input-over-budget")]
    [InlineData("zero-input")]
    public void AMalformedFrameIsRefused(string mutation)
    {
        ContentSandboxLaunchFrame frame = mutation switch
        {
            "duplicate-role" => Frame(h => h[4] = new ContentSandboxHandleEntry(ContentSandboxHandleRole.Slot0, 99)),
            "zero-handle" => Frame(h => h[0] = new ContentSandboxHandleEntry(ContentSandboxHandleRole.Control, 0)),
            "missing-slot" => Frame(h => h[4] = new ContentSandboxHandleEntry(ContentSandboxHandleRole.Slot2, 99)),
            "missing-control" => Frame(h => h[0] = new ContentSandboxHandleEntry(ContentSandboxHandleRole.Slot2, 99)),
            "extra-handle" => Frame(h => h.Add(new ContentSandboxHandleEntry(ContentSandboxHandleRole.Slot2, 99))),
            "zero-slot" => Frame(slots: [0, 10]),
            "huge-slot" => Frame(slots: [(ulong)ContentSandboxContract.MaxSlotBytes + 1, 10]),
            "zero-limit" => Frame(limits: new ContentSandboxLimits { MaxItems = 0 }),
            "limit-over-profile" => Frame(limits: new ContentSandboxLimits { TimeoutMs = ContentSandboxLimits.ProfileMaxTimeoutMs + 1 }),
            "bad-profile" => Frame(profile: "has space"),
            "empty-bootstrap" => Frame(bootstrap: []),
            "big-bootstrap" => Frame(bootstrap: new byte[ContentSandboxLaunchFrame.MaxBootstrapBytes + 1]),
            "input-over-budget" => Frame(inputLength: new ContentSandboxLimits().MaxInputBytes + 1),
            "zero-input" => Frame(inputLength: 0),
            _ => Frame(),
        };
        var encoded = frame.Encode();
        var body = encoded.AsSpan(4).ToArray();
        switch (mutation)
        {
            case "magic":
                body[0] ^= 0xFF;
                break;
            case "trailing":
                body = [.. body, 0];
                break;
            case "truncated":
                body = body[..^3];
                break;
            default:
                break;
        }

        _ = Assert.Throws<FormatException>(() => ContentSandboxLaunchFrame.Decode(body));
    }

    [Fact]
    public async Task AFrameReadFromAStreamIsBoundedByItsLengthPrefix()
    {
        var ct = Xunit.TestContext.Current.CancellationToken;
        using var frame = Frame();
        var encoded = frame.Encode();
        using (var good = new MemoryStream(encoded))
        {
            using var read = await ContentSandboxLaunchFrame.ReadAsync(good, ct);
            Assert.Equal(frame.InvocationId, read.InvocationId);
        }

        foreach (var prefix in new byte[][] { [0, 0, 0, 0], [0, 0, 0xFF, 0xFF], [0, 0, 0x40, 0x01] })
        {
            using var bad = new MemoryStream([.. prefix, 1, 2, 3]);
            _ = await Assert.ThrowsAsync<FormatException>(async () => await ContentSandboxLaunchFrame.ReadAsync(bad, ct));
        }

        using var truncated = new MemoryStream(encoded[..^5]);
        _ = await Assert.ThrowsAsync<EndOfStreamException>(async () => await ContentSandboxLaunchFrame.ReadAsync(truncated, ct));
    }

    [Theory]
    [InlineData("hostile-test-parser", true)]
    [InlineData("a.b_c-9", true)]
    [InlineData("", false)]
    [InlineData("has space", false)]
    [InlineData("slash/", false)]
    [InlineData("é", false)]
    public void AParserProfileIsADashedToken(string value, bool expected) =>
        Assert.Equal(expected, ContentSandboxLaunchFrame.IsParserProfile(value));

    [Fact]
    public void ALongParserProfileIsRefused() =>
        Assert.False(ContentSandboxLaunchFrame.IsParserProfile(new string('a', ContentSandboxContract.MaxParserProfileLength + 1)));

    [Fact]
    public void TheBudgetIsPositiveAndWithinTheProfileAndARequestMayOnlyLowerIt()
    {
        var budget = new ContentSandboxLimits();
        Assert.True(budget.IsWithinProfile());
        Assert.False((budget with { MaxInputBytes = 0 }).IsWithinProfile());
        Assert.False((budget with { MaxMemoryBytes = ContentSandboxLimits.ProfileMaxMemoryBytes + 1 }).IsWithinProfile());
        Assert.False((budget with { MaxWidth = ContentSandboxLimits.ProfileMaxDimension + 1 }).IsWithinProfile());
        Assert.False((budget with { TimeoutMs = 0 }).IsWithinProfile());
        Assert.True((budget with { TimeoutMs = budget.TimeoutMs - 1 }).FitsWithin(budget));
        Assert.False((budget with { TimeoutMs = budget.TimeoutMs + 1 }).FitsWithin(budget));
        Assert.True(ContentSandboxLimits.TryFromWire(budget.ToWire(), out var back));
        Assert.Equal(budget, back);
        Assert.False(ContentSandboxLimits.TryFromWire(null, out _));
        Assert.False(ContentSandboxLimits.TryFromWire(new SandboxLimits { MaxInputBytes = 1 }, out _));
        var zero = budget.ToWire();
        zero.MaxItems = 0;
        Assert.False(ContentSandboxLimits.TryFromWire(zero, out _));
    }

    [Fact]
    public void IdentifiersAreSixteenCanonicalBigEndianBytesAndNeverZero()
    {
        var id = Guid.NewGuid();
        var wire = SandboxRecords.ToWireId(id);
        Assert.Equal(16, wire.Value.Length);
        Assert.True(SandboxRecords.TryReadId(wire, out var back));
        Assert.Equal(id, back);
        Assert.Equal(id.ToByteArray(bigEndian: true), wire.Value.ToByteArray());
        Assert.False(SandboxRecords.TryReadId(null, out _));
        Assert.False(SandboxRecords.TryReadId(new Id(), out _));
        Assert.False(SandboxRecords.TryReadId(new Id { Value = Google.Protobuf.ByteString.CopyFrom(new byte[16]) }, out _));
        Assert.False(SandboxRecords.TryReadId(new Id { Value = Google.Protobuf.ByteString.CopyFrom(new byte[15]) }, out _));
        var instant = SandboxRecords.ToInstant(new DateTimeOffset(2026, 10, 4, 1, 2, 3, TimeSpan.Zero).AddTicks(1234));
        Assert.Equal(new DateTimeOffset(2026, 10, 4, 1, 2, 3, TimeSpan.Zero).AddTicks(1234), SandboxRecords.FromInstant(instant));
    }

    [Fact]
    public void ASlotGrantAnAckAndASealMapOntoTheBrokeredRecordsAndBack()
    {
        var grant = new LocalRpcSlotGrant(2, 7, 4096);
        Assert.True(SandboxRecords.TryReadGrant(SandboxRecords.ToWire(grant), out var grantBack));
        Assert.Equal(grant, grantBack);
        Assert.False(SandboxRecords.TryReadGrant(new SandboxSlotGrant { SlotId = 1 }, out _));
        Assert.False(SandboxRecords.TryReadGrant(null, out _));

        var digest = LocalRpcDigest.Compute("tile"u8);
        var ack = new LocalRpcBufferAck(Guid.NewGuid(), Guid.NewGuid(), 3, 1, 9, digest);
        Assert.True(SandboxRecords.TryReadAck(SandboxRecords.ToWire(ack), out var ackBack));
        Assert.Equal(ack.InvocationId, ackBack.InvocationId);
        Assert.Equal(ack.LeaseId, ackBack.LeaseId);
        Assert.Equal((ack.Generation, ack.SlotId, ack.Sequence), (ackBack.Generation, ackBack.SlotId, ackBack.Sequence));
        Assert.Equal(digest, ackBack.Digest);
        var upper = SandboxRecords.ToWire(ack);
        upper.Digest = upper.Digest.ToUpperInvariant();
        Assert.False(SandboxRecords.TryReadAck(upper, out _));
        Assert.False(SandboxRecords.TryReadAck(new SandboxBufferAck(), out _));

        var geometry = new TileGeometry(1, 100, 80, 10, 20, 16, 8);
        var seal = new LocalRpcBufferSeal(Guid.NewGuid(), Guid.NewGuid(), 3, 1, 9, 0, 512, digest, 64);
        var wire = SandboxRecords.ToWire(seal, geometry);
        Assert.Equal(1u, wire.Kind);
        Assert.True(SandboxRecords.TryReadSeal(wire, out var sealBack, out var geometryBack));
        Assert.Equal(seal.Digest, sealBack.Digest);
        Assert.Equal((seal.Offset, seal.Length, seal.RowStride, seal.Sequence), (sealBack.Offset, sealBack.Length, sealBack.RowStride, sealBack.Sequence));
        Assert.Equal(geometry, geometryBack);
        Assert.Equal(new LocalRpcBufferLayout(8, 64), geometry.Layout());
        Assert.Null(new TileGeometry(9, 1, 1, 0, 0, 1, 1).Layout());
        Assert.Null(new TileGeometry(1, 1, 1, 0, 0, 0, 1).Layout());
    }

    [Theory]
    [InlineData("version")]
    [InlineData("kind")]
    [InlineData("digest")]
    [InlineData("lease")]
    [InlineData("stride")]
    public void AMalformedSealDescriptorIsRefused(string mutation)
    {
        var seal = new LocalRpcBufferSeal(Guid.NewGuid(), Guid.NewGuid(), 1, 0, 1, 0, 16, LocalRpcDigest.Compute("x"u8), 16);
        var wire = SandboxRecords.ToWire(seal, new TileGeometry(1, 4, 4, 0, 0, 4, 1));
        switch (mutation)
        {
            case "version":
                wire.Version = 2;
                break;
            case "kind":
                wire.Kind = 2;
                break;
            case "digest":
                wire.Sha256 = "abc";
                break;
            case "lease":
                wire.LeaseId = new Id();
                break;
            default:
                wire.ClearRowStride();
                break;
        }

        Assert.False(SandboxRecords.TryReadSeal(wire, out _, out _));
    }

    [Fact]
    public void ALaunchRefusesOptionsOutsideTheProfileBeforeAnythingIsStarted()
    {
        var good = Fixtures.Options();
        _ = new ContentSandboxLauncher(good, profileOverride: ContentSandboxProfile.Unsupported, launcherOverride: null);
        Assert.Throws<ArgumentException>(() => new ContentSandboxLauncher(good with { HelperPath = "relative.exe" }, ContentSandboxProfile.Unsupported, null));
        Assert.Throws<ArgumentException>(() => new ContentSandboxLauncher(good with { HelperSha256 = new byte[5] }, ContentSandboxProfile.Unsupported, null));
        Assert.Throws<ArgumentException>(() => new ContentSandboxLauncher(good with { ParserProfile = "no good" }, ContentSandboxProfile.Unsupported, null));
        Assert.Throws<ArgumentException>(() => new ContentSandboxLauncher(good with { RuntimeRoot = "relative" }, ContentSandboxProfile.Unsupported, null));
        Assert.Throws<ArgumentException>(() => new ContentSandboxLauncher(good with { Limits = new ContentSandboxLimits { MaxItems = 0 } }, ContentSandboxProfile.Unsupported, null));
        Assert.Throws<ArgumentException>(() => new ContentSandboxLauncher(good with { SlotCount = 4 }, ContentSandboxProfile.Unsupported, null));
        Assert.Throws<ArgumentException>(() => new ContentSandboxLauncher(good with { SlotCapacityBytes = ContentSandboxContract.MaxSlotBytes + 1 }, ContentSandboxProfile.Unsupported, null));
        Assert.Throws<ArgumentException>(() => new ContentSandboxLauncher(good with { LaunchTimeout = TimeSpan.Zero }, ContentSandboxProfile.Unsupported, null));
        Assert.Throws<ArgumentException>(() => new ContentSandboxLauncher(good with { BuildId = new string('x', 65) }, ContentSandboxProfile.Unsupported, null));
    }

    [Theory]
    [InlineData(ContentSandboxProfile.Unsupported)]
    [InlineData(ContentSandboxProfile.MacOsAppSandboxXpc)]
    [InlineData(ContentSandboxProfile.LinuxLandlockSeccomp)]
    [InlineData(ContentSandboxProfile.WindowsAppContainerJob)]
    public async Task AProfileWithoutALauncherFailsClosedWithoutStartingAnything(ContentSandboxProfile profile)
    {
        var options = Fixtures.Options();
        await using var launcher = new ContentSandboxLauncher(options, profile, launcherOverride: null);
        var result = await launcher.LaunchAsync("data"u8.ToArray(), Xunit.TestContext.Current.CancellationToken);
        Assert.False(result.IsSuccess);
        Assert.Equal("security.isolation_unavailable", result.Failure!.Code);
        Assert.False(Directory.Exists(options.RuntimeRoot));
    }

    [Fact]
    public void TheProfileOfThisPlatformIsReportedWithoutLaunchingAnything()
    {
        var status = ContentSandboxLauncher.ProbeProfile();
        Assert.Equal(OperatingSystem.IsWindows(), status.Profile == ContentSandboxProfile.WindowsAppContainerJob);
        Assert.Equal(OperatingSystem.IsLinux(), status.Profile == ContentSandboxProfile.LinuxLandlockSeccomp);
        if (OperatingSystem.IsMacOS())
        {
            Assert.False(status.IsAvailable);
            Assert.NotEmpty(status.Reason);
        }
    }

    [Fact]
    public async Task AnInputOutsideTheBudgetIsRefusedBeforeALaunch()
    {
        var stand = new InProcessHelperLauncher(Fixtures.Hostile());
        await using var launcher = new ContentSandboxLauncher(Fixtures.Options(), profileOverride: null, launcherOverride: stand);
        var empty = await launcher.LaunchAsync(ReadOnlyMemory<byte>.Empty, Xunit.TestContext.Current.CancellationToken);
        Assert.Equal("validation.invalid_request", empty.Failure!.Code);
        var big = await launcher.LaunchAsync(new byte[(int)new ContentSandboxLimits().MaxInputBytes + 1], Xunit.TestContext.Current.CancellationToken);
        Assert.Equal("validation.invalid_request", big.Failure!.Code);
        Assert.Empty(stand.Started);
    }

    [Fact]
    public async Task AHelperThatIsNotThePinnedBuildIsRefusedByTheRealLauncherBeforeAnyProcessExists()
    {
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux())
        {
            return;
        }

        var directory = Path.Combine(Path.GetTempPath(), "arcforges-cs-pin-" + Guid.NewGuid().ToString("N")[..8]);
        _ = Directory.CreateDirectory(directory);
        try
        {
            var helper = Path.Combine(directory, "helper.bin");
            await File.WriteAllBytesAsync(helper, "not a program"u8.ToArray(), Xunit.TestContext.Current.CancellationToken);
            var options = Fixtures.Options() with { HelperPath = helper, HelperSha256 = SHA256.HashData("a different build"u8) };
            await using var launcher = new ContentSandboxLauncher(options);
            var result = await launcher.LaunchAsync("data"u8.ToArray(), Xunit.TestContext.Current.CancellationToken);
            Assert.False(result.IsSuccess);
            Assert.Equal("resource.integrity_failed", result.Failure!.Code);

            // The refused file is still the file that was checked: nothing renamed or deleted it, and no launch record was left behind.
            Assert.True(File.Exists(helper));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void AReapedChildIsNeverSignalledAgainBecauseItsIdMayBeRecycled()
    {
        var signalled = new List<int>();
        int? exit = null;
        var guard = new ChildProcessGuard(4242, _ => exit, signalled.Add);
        Assert.True(guard.IsLive);
        Assert.Null(guard.TryReap());
        guard.Kill();
        Assert.Equal([4242], signalled);

        exit = 9;
        Assert.Equal(9, guard.TryReap());
        Assert.False(guard.IsLive);
        guard.Kill();
        Assert.Null(guard.TryReap());
        Assert.Equal([4242], signalled);
    }

    [Fact]
    public void HelperOutputInADiagnosticNoteIsBoundedAndPrintable()
    {
        var hostile = new string('A', 5000) + "\u0000\u001b[31m\r\nend\u00e9";
        var note = HelperText.Sanitise(hostile);
        Assert.True(note.Length <= HelperText.MaxChars);
        Assert.All(note, character => Assert.InRange(character, ' ', '~'));
        Assert.EndsWith("end ", note, StringComparison.Ordinal);
        Assert.Equal(string.Empty, HelperText.Sanitise(null));
        Assert.Equal(200, HelperText.MaxChars);
        Assert.Equal(HelperText.MaxChars, HelperText.Sanitise(new string('B', 201)).Length);
        Assert.Equal(new string('B', 3), HelperText.Sanitise("BBB"));
    }

    [Fact]
    public void ALaunchExceptionCarriesARegisteredReasonCode()
    {
        var failure = new ContentSandboxLaunchException();
        Assert.Equal("resource.unavailable", failure.ReasonCode);
        Assert.Equal("resource.unavailable", new ContentSandboxLaunchException("x").ReasonCode);
        Assert.Equal("resource.unavailable", new ContentSandboxLaunchException("x", new InvalidOperationException()).ReasonCode);
    }
}
