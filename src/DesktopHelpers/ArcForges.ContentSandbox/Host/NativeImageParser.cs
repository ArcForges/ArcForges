// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using ArcForges.Contracts.LocalRpc.Sandbox.V1;
using ArcForges.Native.Image;

namespace ArcForges.ContentSandbox.Host;

/// <summary>Production native opening, with a component-test seam below the real validating adapter.</summary>
internal delegate IImageReader ImageReaderOpener(IImageInput input, ImageLimits limits, uint subimage, uint mip, ImagePixelFormat format, CancellationToken cancellation);

/// <summary>The production still-image parser of the existing restricted helper. It accepts only brokered immutable input.</summary>
internal sealed class NativeImageParser(ImageReaderOpener opener) : IImageParser
{
    private readonly object _gate = new();
    private IImageReader? _reader;
    private bool _disposed;

    public SandboxImageInfo Open(ParserInput input, uint subimage, uint mip, uint outputFormat, ParserContext context)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(context);
        lock (_gate)
        {
            if (_disposed || _reader is not null || outputFormat is not (1 or 2) || !context.Limits.IsWithinProfile())
            {
                throw new ContentParserException("The image parser cannot open this request.");
            }

            context.Cancelled.ThrowIfCancellationRequested();
            var limits = context.Limits;
            // The invocation owns three slots; a single image ABI operation owns at most one 64 MiB tile.
            var native = new ImageLimits(limits.MaxInputBytes, limits.MaxMemoryBytes, Math.Min(limits.MaxOutputBytes, 64UL * 1024 * 1024),
                limits.MaxWidth, limits.MaxHeight, limits.MaxItems, limits.TimeoutMs);
            var reader = Translate(() => opener(new ParserInputAdapter(input), native, subimage, mip, (ImagePixelFormat)outputFormat, context.Cancelled));
            try
            {
                var metadata = reader.Metadata;
                if (metadata.Width == 0 || metadata.Height == 0 || metadata.Width > limits.MaxWidth || metadata.Height > limits.MaxHeight
                    || metadata.Subimage != subimage || metadata.Mip != mip || (uint)metadata.Format != outputFormat
                    || metadata.Subimages == 0 || metadata.Subimages > limits.MaxItems || subimage >= metadata.Subimages
                    || metadata.Mips == 0 || metadata.Mips > limits.MaxItems || mip >= metadata.Mips
                    || metadata.Channels.Count is 0 or > 64 || metadata.Codec is not ("png" or "tiff" or "openexr")
                    || string.IsNullOrEmpty(metadata.SourceColorSpace) || metadata.SourceColorSpace.Length > 256)
                {
                    throw new ContentParserException("The image metadata is not valid.");
                }

                var info = new SandboxImageInfo { Width = metadata.Width, Height = metadata.Height, SubimageCount = metadata.Subimages, MipCount = metadata.Mips };
                foreach (var channel in metadata.Channels)
                {
                    if (string.IsNullOrEmpty(channel.Name) || channel.Name.Length > 256 || string.IsNullOrEmpty(channel.Type) || channel.Type.Length > 32
                        || channel.Bits is 0 or > 64)
                    {
                        throw new ContentParserException("The image channels are not valid.");
                    }

                    info.Channels.Add(new SandboxImageChannel { Name = channel.Name, SampleType = channel.Type });
                    info.Tags.Add(new SandboxTag { Key = "channel." + (info.Channels.Count - 1).ToString(CultureInfo.InvariantCulture) + ".bits", Value = channel.Bits.ToString(CultureInfo.InvariantCulture) });
                }

                info.Tags.Add(new SandboxTag { Key = "codec", Value = metadata.Codec });
                info.Tags.Add(new SandboxTag { Key = "sourceColorSpace", Value = metadata.SourceColorSpace });
                info.Tags.Add(new SandboxTag { Key = "outputFormat", Value = outputFormat.ToString(CultureInfo.InvariantCulture) });
                if (metadata.ConversionLoss)
                {
                    info.Warnings.Add("image.conversion_loss");
                }

                if ((long)info.Channels.Count + info.Tags.Count + info.Warnings.Count > limits.MaxItems)
                {
                    throw new ContentParserException("The image metadata exceeds its item budget.");
                }

                context.Cancelled.ThrowIfCancellationRequested();
                _reader = reader;
                return info;
            }
            catch
            {
                reader.Dispose();
                throw;
            }
        }
    }

    public int ReadTile(SandboxRegion region, uint format, Span<byte> destination, ParserContext context)
    {
        ArgumentNullException.ThrowIfNull(region);
        ArgumentNullException.ThrowIfNull(context);
        lock (_gate)
        {
            var reader = _reader ?? throw new ContentParserException("No image is open.");
            var metadata = reader.Metadata;
            if (_disposed || (uint)metadata.Format != format || !context.Limits.IsWithinProfile()
                || region.Width == 0 || region.Height == 0 || region.Width > 2048 || region.Height > 2048
                || region.X >= metadata.Width || region.Y >= metadata.Height || region.Width > metadata.Width - region.X || region.Height > metadata.Height - region.Y
                || region.FirstSample != 0 || region.SampleCount != 0)
            {
                throw new ContentParserException("The image tile is not valid.");
            }

            var rowBytes = region.Width * (format == 1 ? 4UL : 16UL);
            if (region.RowStride < rowBytes || region.RowStride > 64UL * 1024 * 1024
                || region.Height > (64UL * 1024 * 1024) / region.RowStride)
            {
                throw new ContentParserException("The image stride exceeds its profile.");
            }

            var required = region.RowStride * region.Height;
            if (required > (ulong)destination.Length || required > context.Limits.MaxOutputBytes)
            {
                throw new ContentParserException("The image output exceeds its budget.");
            }

            context.Cancelled.ThrowIfCancellationRequested();
            try
            {
                var written = reader.ReadRegion(region.X, region.Y, region.Width, region.Height, region.RowStride, destination[..(int)required], context.Cancelled);
                return written == (int)required ? written : throw new ContentParserException("The image tile is incomplete.");
            }
            catch (Exception exception) when (IsNativeFailure(exception))
            {
                throw new ContentParserException("The native image decode failed.", exception);
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            _reader?.Dispose();
            _reader = null;
        }
    }

    [SuppressMessage("Design", "CA1031", Justification = "Native and loader failures become one parser refusal; diagnostics never cross the protocol.")]
    private static T Translate<T>(Func<T> call)
    {
        try
        {
            return call();
        }
        catch (Exception exception) when (IsNativeFailure(exception))
        {
            throw new ContentParserException("The native image library failed.", exception);
        }
    }

    private static bool IsNativeFailure(Exception exception) => exception is ImageNativeException or DllNotFoundException or EntryPointNotFoundException
        or BadImageFormatException or PlatformNotSupportedException or InvalidDataException or IOException or ObjectDisposedException
        or ArgumentException or InvalidOperationException or OverflowException;

    private sealed class ParserInputAdapter(ParserInput input) : IImageInput
    {
        public long Length => input.Length;

        public int ReadAt(long offset, Span<byte> destination) => input.Read(offset, destination);
    }
}
