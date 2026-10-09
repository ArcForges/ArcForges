// SPDX-License-Identifier: AGPL-3.0-only

using ArcForges.Native.Abstractions;
using ArcForges.Native.Image;
using Xunit;

namespace ArcForges.Tests.NativeAbiTests;

// Runtime behaviour of the functional image exports through the managed binding. These tests load the
// staged ArcImageNative.dll app-locally, so they belong to the explicit NativeAbi opt-in suite.
[Trait("Category", "NativeAbi")]
public sealed class ImageReaderTests
{
    private const int Width = 3;
    private const int Height = 2;

    // Straight-alpha pixels with alpha 0, partial and full coverage. Exact output proves no premultiply round trip.
    private static readonly byte[] StraightRgba =
    [
        10, 50, 200, 0,
        20, 51, 199, 60,
        30, 52, 198, 128,
        40, 53, 197, 255,
        50, 54, 196, 200,
        60, 55, 195, 17,
    ];

    [Fact]
    public async Task PngRgba8StraightAlphaRoundTripsByteExactAndCompletes()
    {
        byte[] file = ImageFixtures.PngRgba8(Width, Height, StraightRgba);
        using var stream = new MemoryStream(file);
        await using ImageReader reader = await ImageReader.OpenAsync(ImageByteSource.FromStream(stream));

        Assert.Equal(ImageSourceFormat.Png, reader.Metadata.Format);
        Assert.Equal((uint)Width, reader.Metadata.Width);
        Assert.Equal((uint)Height, reader.Metadata.Height);
        Assert.Equal(ImageAlphaKind.Straight, reader.Metadata.Alpha);
        Assert.Equal(ImageOutputFormat.Rgba8, reader.Metadata.OutputFormat);
        Assert.Equal(4u, reader.Metadata.BytesPerPixel);

        ImagePixelRegion region = await reader.ReadRegionAsync(new ImageRegion(0, 0, Width, Height));
        Assert.Equal(StraightRgba, region.Pixels.ToArray());

        ImageCompletion completion = await reader.CompleteAsync();
        Assert.Equal((ulong)(Width * Height), completion.CoveredPixels);
        Assert.Equal(1u, completion.RegionCount);
    }

    [Fact]
    public async Task TiffRgba8UnassociatedAlphaRoundTripsByteExact()
    {
        byte[] file = ImageFixtures.TiffRgba8(Width, Height, StraightRgba);
        using var stream = new MemoryStream(file);
        ImageMetadata metadata = await ImageReader.ProbeAsync(ImageByteSource.FromStream(stream));

        Assert.Equal(ImageSourceFormat.Tiff, metadata.Format);
        Assert.Equal(ImageAlphaKind.Straight, metadata.Alpha);
        Assert.Equal(4u, metadata.OutputChannels);
        Assert.Empty(metadata.Losses);

        stream.Position = 0;
        await using ImageReader reader = await ImageReader.OpenAsync(ImageByteSource.FromStream(stream));
        ImagePixelRegion region = await reader.ReadRegionAsync(new ImageRegion(0, 0, Width, Height));
        Assert.Equal(StraightRgba, region.Pixels.ToArray());
    }

    [Fact]
    public async Task FloatOutputPremultipliesStraightColourOnRead()
    {
        byte[] file = ImageFixtures.PngRgba8(Width, Height, StraightRgba);
        using var stream = new MemoryStream(file);
        var options = new ImageOpenOptions { Format = ImageOutputFormat.Rgba32fLinearPremultiplied };
        await using ImageReader reader = await ImageReader.OpenAsync(ImageByteSource.FromStream(stream), options);
        Assert.Equal(16u, reader.Metadata.BytesPerPixel);

        ImagePixelRegion region = await reader.ReadRegionAsync(new ImageRegion(0, 0, Width, Height));
        ReadOnlyMemory<byte> bytes = region.Pixels;
        for (int pixel = 0; pixel < Width * Height; pixel++)
        {
            float alpha = StraightRgba[(pixel * 4) + 3] / 255f;
            for (int channel = 0; channel < 3; channel++)
            {
                float expected = StraightRgba[(pixel * 4) + channel] / 255f * alpha;
                float actual = BitConverter.ToSingle(bytes.Span.Slice((pixel * 16) + (channel * 4), 4));
                Assert.InRange(actual, expected - 1e-4f, expected + 1e-4f);
            }

            float actualAlpha = BitConverter.ToSingle(bytes.Span.Slice((pixel * 16) + 12, 4));
            Assert.InRange(actualAlpha, alpha - 1e-4f, alpha + 1e-4f);
        }
    }

    [Fact]
    public async Task RegionsCoverEveryPixelOnlyWhenEveryBandIsRead()
    {
        byte[] file = ImageFixtures.PngRgba8(Width, Height, StraightRgba);
        using var stream = new MemoryStream(file);
        await using ImageReader reader = await ImageReader.OpenAsync(ImageByteSource.FromStream(stream));

        await reader.ReadRegionAsync(new ImageRegion(0, 0, Width, 1));
        ImageCoverageIncompleteException missing = await Assert.ThrowsAsync<ImageCoverageIncompleteException>(
            () => reader.CompleteAsync());
        Assert.Equal((ulong)Width, missing.CoveredPixels);
        Assert.Equal((ulong)(Width * Height), missing.TotalPixels);

        await reader.ReadRegionAsync(new ImageRegion(0, 1, Width, 1));
        ImageCompletion completion = await reader.CompleteAsync();
        Assert.Equal((ulong)(Width * Height), completion.CoveredPixels);
        Assert.Equal(2u, completion.RegionCount);
    }

    [Fact]
    public async Task OverlappingAndOutOfOrderRegionsAreRefusedWithoutStateChange()
    {
        byte[] file = ImageFixtures.PngRgba8(Width, Height, StraightRgba);
        using var stream = new MemoryStream(file);
        await using ImageReader reader = await ImageReader.OpenAsync(ImageByteSource.FromStream(stream));

        await reader.ReadRegionAsync(new ImageRegion(0, 0, Width, 1));
        ImageNativeException overlap = await Assert.ThrowsAsync<ImageNativeException>(
            () => reader.ReadRegionAsync(new ImageRegion(0, 0, 1, 1)));
        Assert.Equal(NativeStatus.InvalidArgument, overlap.Status);

        await reader.ReadRegionAsync(new ImageRegion(0, 1, Width, 1));
        ImageCompletion completion = await reader.CompleteAsync();
        Assert.Equal((ulong)(Width * Height), completion.CoveredPixels);
    }

    [Fact]
    public async Task OutOfRasterOrderRegionIsRefusedWithoutStateChange()
    {
        byte[] file = ImageFixtures.PngRgba8(Width, Height, StraightRgba);
        using var stream = new MemoryStream(file);
        await using ImageReader reader = await ImageReader.OpenAsync(ImageByteSource.FromStream(stream));

        // The first region must start at the first uncovered pixel in raster order, so a row-1 read is refused.
        ImageNativeException firstRead = await Assert.ThrowsAsync<ImageNativeException>(
            () => reader.ReadRegionAsync(new ImageRegion(0, 1, Width, 1)));
        Assert.Equal(NativeStatus.InvalidArgument, firstRead.Status);

        await reader.ReadRegionAsync(new ImageRegion(0, 0, 1, 1));
        ImageNativeException early = await Assert.ThrowsAsync<ImageNativeException>(
            () => reader.ReadRegionAsync(new ImageRegion(0, 1, Width, 1)));
        Assert.Equal(NativeStatus.InvalidArgument, early.Status);

        await reader.ReadRegionAsync(new ImageRegion(1, 0, Width - 1, 1));
        await reader.ReadRegionAsync(new ImageRegion(0, 1, Width, 1));
        ImageCompletion completion = await reader.CompleteAsync();
        Assert.Equal((ulong)(Width * Height), completion.CoveredPixels);
        Assert.Equal(3u, completion.RegionCount);
    }

    [Fact]
    public async Task CorruptHeaderIsRefusedAtOpen()
    {
        byte[] file = ImageFixtures.PngRgba8(Width, Height, StraightRgba);
        file[29] ^= 0xFF; // first byte of the IHDR CRC
        using var stream = new MemoryStream(file);

        ImageNativeException corrupt = await Assert.ThrowsAsync<ImageNativeException>(
            () => ImageReader.OpenAsync(ImageByteSource.FromStream(stream)));
        Assert.Equal(NativeStatus.Corrupt, corrupt.Status);
    }

    [Fact]
    public async Task UnsupportedContentIsRefusedByContentNotName()
    {
        // GIF89a header and trailer only: the content is recognised as a format the reader does not decode.
        byte[] gif = [0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x3B];
        using var stream = new MemoryStream(gif);

        ImageNativeException unsupported = await Assert.ThrowsAsync<ImageNativeException>(
            () => ImageReader.OpenAsync(ImageByteSource.FromStream(stream)));
        Assert.Equal(NativeStatus.Unsupported, unsupported.Status);
    }

    [Fact]
    public async Task CancelledReadConsumesNoCoverageAndCanBeRetried()
    {
        byte[] file = ImageFixtures.PngRgba8(Width, Height, StraightRgba);
        using var stream = new MemoryStream(file);
        await using ImageReader reader = await ImageReader.OpenAsync(ImageByteSource.FromStream(stream));
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => reader.ReadRegionAsync(new ImageRegion(0, 0, Width, Height), cancellation.Token));
        ImageCoverageIncompleteException missing = await Assert.ThrowsAsync<ImageCoverageIncompleteException>(
            () => reader.CompleteAsync());
        Assert.Equal(0UL, missing.CoveredPixels);

        ImagePixelRegion region = await reader.ReadRegionAsync(new ImageRegion(0, 0, Width, Height));
        Assert.Equal(StraightRgba, region.Pixels.ToArray());
        ImageCompletion completion = await reader.CompleteAsync();
        Assert.Equal((ulong)(Width * Height), completion.CoveredPixels);
    }

    // Cancellation requested from inside a source callback may or may not be observed by native code, depending on
    // how the codec batches its input. Either way, coverage must match the outcome the caller saw.
    [Fact]
    public async Task CancellationDuringNativeReadKeepsCoverageConsistentWithOutcome()
    {
        byte[] file = ImageFixtures.PngRgba8(Width, Height, StraightRgba);
        using var stream = new MemoryStream(file);
        using var cancellation = new CancellationTokenSource();
        var source = new ArmableSource(ImageByteSource.FromStream(stream), () => cancellation.Cancel());
        await using ImageReader reader = await ImageReader.OpenAsync(source);

        source.Arm();
        bool completed = true;
        try
        {
            await reader.ReadRegionAsync(new ImageRegion(0, 0, Width, Height), cancellation.Token);
        }
        catch (OperationCanceledException)
        {
            completed = false;
        }

        source.Disarm();
        if (!completed)
        {
            ImageCoverageIncompleteException missing = await Assert.ThrowsAsync<ImageCoverageIncompleteException>(
                () => reader.CompleteAsync());
            Assert.Equal(0UL, missing.CoveredPixels);
            await reader.ReadRegionAsync(new ImageRegion(0, 0, Width, Height));
        }

        ImageCompletion completion = await reader.CompleteAsync();
        Assert.Equal((ulong)(Width * Height), completion.CoveredPixels);
    }

    [Fact]
    public async Task PreCancelledOpenDoesNotReachNative()
    {
        byte[] file = ImageFixtures.PngRgba8(Width, Height, StraightRgba);
        using var stream = new MemoryStream(file);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ImageReader.OpenAsync(ImageByteSource.FromStream(stream), cancellationToken: cancellation.Token));
    }

    [Fact]
    public async Task DisposeAsyncClosesTheHandleAndRefusesFurtherUse()
    {
        byte[] file = ImageFixtures.PngRgba8(Width, Height, StraightRgba);
        using var stream = new MemoryStream(file);
        ImageReader reader = await ImageReader.OpenAsync(ImageByteSource.FromStream(stream));

        await reader.DisposeAsync();
        await reader.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => reader.ReadRegionAsync(new ImageRegion(0, 0, Width, Height)));
    }

    [Fact]
    public async Task InvalidRegionsAndOptionsAreRefusedBeforeNativeCalls()
    {
        byte[] file = ImageFixtures.PngRgba8(Width, Height, StraightRgba);
        using var stream = new MemoryStream(file);
        await using ImageReader reader = await ImageReader.OpenAsync(ImageByteSource.FromStream(stream));

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => reader.ReadRegionAsync(new ImageRegion(0, 0, 0, 1)));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => reader.ReadRegionAsync(new ImageRegion(2, 0, 2, 1)));

        var options = new ImageOpenOptions { Limits = new ImageLimits { MaxOutputBytes = 0 } };
        using var second = new MemoryStream(file);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => ImageReader.OpenAsync(ImageByteSource.FromStream(second), options));
    }

    [Fact]
    public async Task RegionLargerThanOutputLimitIsRefusedBeforeAnyRead()
    {
        byte[] file = ImageFixtures.PngRgba8(Width, Height, StraightRgba);
        using var stream = new MemoryStream(file);
        var options = new ImageOpenOptions { Limits = new ImageLimits { MaxOutputBytes = 8 } };
        await using ImageReader reader = await ImageReader.OpenAsync(ImageByteSource.FromStream(stream), options);

        ImageNativeException refused = await Assert.ThrowsAsync<ImageNativeException>(
            () => reader.ReadRegionAsync(new ImageRegion(0, 0, Width, Height)));
        Assert.Equal(NativeStatus.ResourceLimit, refused.Status);

        ImageCoverageIncompleteException missing = await Assert.ThrowsAsync<ImageCoverageIncompleteException>(
            () => reader.CompleteAsync());
        Assert.Equal(0UL, missing.CoveredPixels);
    }

    // Forwards to a real source, and cancels the caller's token on the first read after it is armed. The
    // callback runs on the thread that is inside the native call, which is how cancellation is observed.
    private sealed class ArmableSource(ImageByteSource inner, Action onArmedRead) : ImageByteSource
    {
        private volatile bool _armed;
        private bool _fired;

        public override long Length => inner.Length;

        public void Arm()
        {
            _fired = false;
            _armed = true;
        }

        public void Disarm() => _armed = false;

        public override int ReadAt(long offset, Span<byte> destination)
        {
            if (_armed && !_fired)
            {
                _fired = true;
                onArmedRead();
            }

            return inner.ReadAt(offset, destination);
        }
    }
}
