// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.ContentSandbox.Host;
using ArcForges.Contracts.LocalRpc.Sandbox.V1;
using ArcForges.LocalRpc;
using ArcForges.Native.Abstractions;
using ArcForges.Native.Image;
using Xunit;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>Scripted native reader below the production adapter. This parses no image and is never native or OS evidence.</summary>
internal sealed class ScriptedImageReader : IImageReader
{
    public ImageMetadata Metadata { get; internal set; } = new(32, 24, 1, 1, 0, 0, ImagePixelFormat.Rgba8, "png", "linear", true,
        [new("R", "uint16", 16), new("G", "uint16", 16), new("B", "uint16", 16), new("A", "uint16", 16)]);

    internal int? ForcedSize { get; set; }

    internal bool ThrowNative { get; set; }

    internal bool WaitForCancellation { get; set; }

    internal Action? BeforeRead { get; set; }

    internal int Disposed { get; private set; }

    internal int Calls { get; private set; }

    internal (uint X, uint Y, uint Width, uint Height, ulong Stride)? LastTile { get; private set; }

    public int ReadRegion(uint x, uint y, uint width, uint height, ulong rowStride, Span<byte> destination, CancellationToken cancellation)
    {
        Calls++;
        LastTile = (x, y, width, height, rowStride);
        BeforeRead?.Invoke();
        cancellation.ThrowIfCancellationRequested();
        while (WaitForCancellation)
        {
            cancellation.ThrowIfCancellationRequested();
            Thread.Sleep(1);
        }

        destination.Fill(17);
        if (ThrowNative)
        {
            throw new ImageNativeException(NativeStatus.Corrupt, "Untrusted codec diagnostic text.");
        }

        return ForcedSize ?? destination.Length;
    }

    public ValueTask<int> ReadRegionAsync(uint x, uint y, uint width, uint height, ulong rowStride, Memory<byte> destination, CancellationToken cancellation) =>
        ValueTask.FromResult(ReadRegion(x, y, width, height, rowStride, destination.Span, cancellation));

    public void Dispose() => Disposed++;

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }
}

public sealed class ImageMetadataContractTests
{
    private const string Valid = "{\"version\":1,\"width\":32,\"height\":24,\"subimages\":1,\"mips\":1,\"subimage\":0,\"mip\":0,\"format\":1,\"codec\":\"png\",\"sourceColorSpace\":\"gamma2.200000\",\"conversionLoss\":true,\"channels\":[{\"name\":\"R\",\"type\":\"uint16\",\"bits\":16}]}";
    private static readonly ImageLimits Limits = new(64 * 1024 * 1024, 512 * 1024 * 1024, 64 * 1024 * 1024, 4096, 4096, 1024, 5000);

    [Fact]
    public void TheBoundedMetadataPreservesSourcePrecisionTransferAndLoss()
    {
        var parsed = ImageMetadataJson.Parse(Encoding.UTF8.GetBytes(Valid), Limits, 0, 0, ImagePixelFormat.Rgba8);
        Assert.Equal((32u, 24u, "png", "gamma2.200000", true), (parsed.Width, parsed.Height, parsed.Codec, parsed.SourceColorSpace, parsed.ConversionLoss));
        Assert.Equal(new ImageChannel("R", "uint16", 16), Assert.Single(parsed.Channels));
    }

    [Theory]
    [InlineData("version", "1", "2")]
    [InlineData("width", "32", "0")]
    [InlineData("width", "32", "4097")]
    [InlineData("subimages", "1", "0")]
    [InlineData("subimage", "0", "1")]
    [InlineData("mip", "0", "1")]
    [InlineData("format", "1", "2")]
    [InlineData("bits", "16", "0")]
    [InlineData("bits", "16", "65")]
    [InlineData("codec", "\"png\"", "\"unadmitted\"")]
    [InlineData("sourceColorSpace", "\"gamma2.200000\"", "null")]
    public void ContradictoryResultsRefuseAsAWhole(string key, string from, string to)
    {
        var invalid = Valid.Replace("\"" + key + "\":" + from, "\"" + key + "\":" + to, StringComparison.Ordinal);
        _ = Assert.Throws<InvalidDataException>(() => ImageMetadataJson.Parse(Encoding.UTF8.GetBytes(invalid), Limits, 0, 0, ImagePixelFormat.Rgba8));
    }

    [Fact]
    public void DuplicateUnknownMissingFieldsAndEmptyChannelsRefuse()
    {
        foreach (var invalid in new[] { Valid.Insert(1, "\"version\":1,"), Valid.Insert(1, "\"unknown\":1,"),
            Valid.Replace("\"version\":1,", string.Empty, StringComparison.Ordinal),
            Valid.Replace("[{\"name\":\"R\",\"type\":\"uint16\",\"bits\":16}]", "[]", StringComparison.Ordinal), "[]", "", Valid + " trailing" })
        {
            _ = Assert.Throws<InvalidDataException>(() => ImageMetadataJson.Parse(Encoding.UTF8.GetBytes(invalid), Limits, 0, 0, ImagePixelFormat.Rgba8));
        }
    }
}

public sealed class NativeImageAdapterTests
{
    private static ParserContext Context(CancellationToken cancellation = default) => new(new ContentSandboxLimits(), cancellation);

    private static ParserInput Input() => new(new Mapping(new byte[16]), 16);

    private sealed class Mapping(byte[] bytes) : ILocalRpcBufferMapping
    {
        public long Length => bytes.Length;

        public int Read(long offset, Span<byte> destination)
        {
            bytes.AsSpan((int)offset, destination.Length).CopyTo(destination);
            return destination.Length;
        }

        public void Dispose()
        {
        }
    }

    [Fact]
    public void OpenUsesImmutableBrokeredInputAndOneTileBudgetAndPreservesPrecision()
    {
        var reader = new ScriptedImageReader();
        ImageLimits? admitted = null;
        using var parser = new NativeImageParser((input, limits, _, _, _, _) =>
        {
            Assert.Equal(16, input.Length);
            Assert.Equal(4, input.ReadAt(12, new byte[8]));
            _ = Assert.Throws<ArgumentOutOfRangeException>(() => input.ReadAt(-1, new byte[4]));
            admitted = limits;
            return reader;
        });
        var info = parser.Open(Input(), 0, 0, 1, Context());
        Assert.Equal(64UL * 1024 * 1024, admitted!.MaxOutputBytes);
        Assert.Equal((32u, 24u, 4), (info.Width, info.Height, info.Channels.Count));
        Assert.Equal("uint16", info.Channels[0].SampleType);
        Assert.Contains(info.Tags, tag => tag.Key == "channel.0.bits" && tag.Value == "16");
        Assert.Contains("image.conversion_loss", info.Warnings);
        _ = Assert.Throws<ContentParserException>(() => parser.Open(Input(), 0, 0, 1, Context()));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65)]
    public void TileSizeMustBeExactAndNotPartialOrBeyondTheDestination(int reported)
    {
        var reader = new ScriptedImageReader { ForcedSize = reported };
        using var parser = new NativeImageParser((_, _, _, _, _, _) => reader);
        _ = parser.Open(Input(), 0, 0, 1, Context());
        _ = Assert.Throws<ContentParserException>(() => parser.ReadTile(new SandboxRegion { Width = 4, Height = 4, RowStride = 16 }, 1, new byte[64], Context()));
    }

    [Fact]
    public void InvalidFormatBoundsStrideOrBudgetNeverReachTheNativeReader()
    {
        var reader = new ScriptedImageReader();
        using var parser = new NativeImageParser((_, _, _, _, _, _) => reader);
        _ = parser.Open(Input(), 0, 0, 1, Context());
        foreach (var region in new[] { new SandboxRegion { X = 31, Width = 2, Height = 1, RowStride = 8 },
            new SandboxRegion { Width = 2, Height = 1, RowStride = 7 }, new SandboxRegion { Width = 2, Height = 1, RowStride = ulong.MaxValue },
            new SandboxRegion { Width = 2, Height = 1, RowStride = 8, FirstSample = 1 } })
        {
            _ = Assert.Throws<ContentParserException>(() => parser.ReadTile(region, 1, new byte[64], Context()));
        }

        var valid = new SandboxRegion { Width = 2, Height = 1, RowStride = 8 };
        _ = Assert.Throws<ContentParserException>(() => parser.ReadTile(valid, 2, new byte[64], Context()));
        _ = Assert.Throws<ContentParserException>(() => parser.ReadTile(valid, 1, new byte[7], Context()));
        var limited = new ParserContext(new ContentSandboxLimits { MaxOutputBytes = 7 }, CancellationToken.None);
        _ = Assert.Throws<ContentParserException>(() => parser.ReadTile(valid, 1, new byte[64], limited));
        Assert.Equal(0, reader.Calls);
    }

    [Fact]
    public void InvalidMetadataClosesTheOwnedReaderAndLoaderOrNativeFailureIsTyped()
    {
        var reader = new ScriptedImageReader();
        reader.Metadata = reader.Metadata with { Width = 0 };
        using var parser = new NativeImageParser((_, _, _, _, _, _) => reader);
        _ = Assert.Throws<ContentParserException>(() => parser.Open(Input(), 0, 0, 1, Context()));
        Assert.Equal(1, reader.Disposed);
        using var unavailable = new NativeImageParser((_, _, _, _, _, _) => throw new DllNotFoundException("not sent"));
        _ = Assert.Throws<ContentParserException>(() => unavailable.Open(Input(), 0, 0, 1, Context()));
    }

    [Fact]
    public void NativeDecodeFailureHasASafeProtocolMessage()
    {
        var reader = new ScriptedImageReader { ThrowNative = true };
        using var parser = new NativeImageParser((_, _, _, _, _, _) => reader);
        _ = parser.Open(Input(), 0, 0, 1, Context());
        var failure = Assert.Throws<ContentParserException>(() => parser.ReadTile(new SandboxRegion { Width = 2, Height = 1, RowStride = 8 }, 1, new byte[8], Context()));
        Assert.Equal("The native image decode failed.", failure.Message);
        Assert.IsType<ImageNativeException>(failure.InnerException);
    }

    [Fact]
    public async Task CloseDrainsTheBorrowedReadBeforeReleasingTheNativeReader()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        using var closing = new ManualResetEventSlim();
        var cancellation = Xunit.TestContext.Current.CancellationToken;
        var reader = new ScriptedImageReader { BeforeRead = () => { entered.Set(); release.Wait(cancellation); } };
        using var parser = new NativeImageParser((_, _, _, _, _, _) => reader);
        _ = parser.Open(Input(), 0, 0, 1, Context());
        var read = Task.Run(() => parser.ReadTile(new SandboxRegion { Width = 2, Height = 1, RowStride = 8 }, 1, new byte[8], Context(cancellation)), cancellation);
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5), cancellation));
        var close = Task.Run(() => { closing.Set(); parser.Dispose(); }, cancellation);
        Assert.True(closing.Wait(TimeSpan.FromSeconds(5), cancellation));
        try
        {
            Assert.Equal(0, reader.Disposed);
            Assert.False(close.IsCompleted);
        }
        finally
        {
            release.Set();
        }

        Assert.Equal(8, await read.WaitAsync(TimeSpan.FromSeconds(5), cancellation));
        await close.WaitAsync(TimeSpan.FromSeconds(5), cancellation);
        Assert.Equal(1, reader.Disposed);
    }

    [Fact]
    public void CancellationPropagatesAndCloseIsIdempotentAndFinal()
    {
        var reader = new ScriptedImageReader { WaitForCancellation = true };
        var parser = new NativeImageParser((_, _, _, _, _, _) => reader);
        _ = parser.Open(Input(), 0, 0, 1, Context());
        using var cancellation = new CancellationTokenSource();
        cancellation.CancelAfter(30);
        _ = Assert.ThrowsAny<OperationCanceledException>(() => parser.ReadTile(new SandboxRegion { Width = 2, Height = 1, RowStride = 8 }, 1, new byte[8], Context(cancellation.Token)));
        parser.Dispose();
        parser.Dispose();
        Assert.Equal(1, reader.Disposed);
        _ = Assert.Throws<ContentParserException>(() => parser.Open(Input(), 0, 0, 1, Context()));
    }

    [Fact]
    public void PreparationChecksTheExactImageFunctionalProfile()
    {
        const string good = "abi=1.1;openimageio=3.1.14.0;formats=png,tiff,exr;rgba8;rgba32fLinearPremultiplied;maxTileBytes=67108864;maxHandles=64";
        ProductionParserProfile.VerifyImageLibrary(new NativeAbiVersion(1, 1), good);
        foreach (var invalid in new[] { string.Empty, good.Replace("formats=png,tiff,exr", "formats=png", StringComparison.Ordinal),
            good.Replace("openimageio=3.1.14.0", "openimageio=caller", StringComparison.Ordinal), good.Replace(";rgba8;", ";", StringComparison.Ordinal) })
        {
            _ = Assert.Throws<ContentParserException>(() => ProductionParserProfile.VerifyImageLibrary(new NativeAbiVersion(1, 1), invalid));
        }

        _ = Assert.Throws<ContentParserException>(() => ProductionParserProfile.VerifyImageLibrary(new NativeAbiVersion(1, 0), good));
        _ = Assert.Throws<ContentParserException>(() => ProductionParserProfile.VerifyImageLibrary(new NativeAbiVersion(1, 2), good));
        _ = Assert.Throws<ContentParserException>(() => ProductionParserProfile.VerifyImageLibrary(new NativeAbiVersion(2, 1), good));
    }
}

public sealed class ProductionImageCompositionTests
{
    [Fact]
    public async Task ProductionImageAdapterComposesWithTheActualHostBrokerGrantSealAndAcknowledgment()
    {
        var reader = new ScriptedImageReader();
        var profile = new ProductionParserProfile(prepare: () => { }, imageOpener: (_, _, _, _, _, _) => reader);
        var launcher = new InProcessHelperLauncher(new ParserProfiles([profile]));
        var (sandbox, _, invocation) = await Fixtures.LaunchAsync(new byte[16], Fixtures.Options(parser: ProductionParserProfile.ProfileId), launcher);
        await using var _sandbox = sandbox;
        await using var _invocation = invocation;
        var cancellation = Xunit.TestContext.Current.CancellationToken;
        var opened = await invocation.OpenImageAsync(0, 0, 1, cancellation);
        Assert.True(opened.IsSuccess, opened.Failure?.Code);
        var info = (await invocation.GetImageInfoAsync(opened.Value, cancellation)).Value!;
        Assert.Equal("uint16", info.Channels[0].SampleType);
        using (var tile = (await invocation.ReadImageTileAsync(opened.Value, 7, 8, 4, 4, cancellation)).Value!)
        {
            Assert.Equal((4u, 4u), (tile.Width, tile.Height));
            Assert.Equal((7u, 8u, 4u, 4u), (reader.LastTile!.Value.X, reader.LastTile.Value.Y, reader.LastTile.Value.Width, reader.LastTile.Value.Height));
        }

        Assert.True((await invocation.CloseImageAsync(opened.Value, cancellation)).IsSuccess);
        Assert.Equal(1, reader.Disposed);
        // The native reader is scripted. This proves the real adapter/host/broker composition only; actual codecs are tested separately.
    }
}
