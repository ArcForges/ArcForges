// SPDX-License-Identifier: AGPL-3.0-only

using ArcForges.Native.Abstractions;

namespace ArcForges.Native.Image;

// Closed output formats (Annex 06 section 2). The numeric keys are the ABI values and are never exposed.
public enum ImageOutputFormat
{
    // Never a valid request; present so that the default value is refused rather than silently meaning a format.
    Unspecified = 0,

    // Packed 8-bit unorm RGBA with straight alpha and no transfer change.
    Rgba8 = 1,

    // Packed 32-bit float RGBA, linear light when the source declares sRGB, premultiplied.
    Rgba32fLinearPremultiplied = 2,

    // Source channels kept as 32-bit float, with no transfer or alpha change.
    Float32Interleaved = 3,
}

// Resource bounds for one open. Every value narrows the producer profile and is checked before the call.
public sealed record ImageLimits
{
    public const ulong ProfileMaxInputBytes = 4UL * 1024 * 1024 * 1024;
    public const ulong ProfileMaxMemoryBytes = 4UL * 1024 * 1024 * 1024;
    public const ulong ProfileMaxOutputBytes = 64UL * 1024 * 1024;
    public const uint ProfileMaxDimension = 65535;
    public const uint ProfileMaxItems = 256;
    public const uint ProfileMaxTimeoutMilliseconds = 3_600_000;

    public ulong MaxInputBytes { get; init; } = 1024UL * 1024 * 1024;

    public ulong MaxMemoryBytes { get; init; } = 1024UL * 1024 * 1024;

    // Largest single region read, in bytes of packed output.
    public ulong MaxOutputBytes { get; init; } = ProfileMaxOutputBytes;

    public uint MaxWidth { get; init; } = ProfileMaxDimension;

    public uint MaxHeight { get; init; } = ProfileMaxDimension;

    public uint MaxItems { get; init; } = 256;

    // Per-call deadline. Observed between tiles and source callbacks, not inside one codec call.
    public uint TimeoutMilliseconds { get; init; } = 60_000;

    internal void Validate()
    {
        RequireRange(MaxInputBytes, ProfileMaxInputBytes, nameof(MaxInputBytes));
        RequireRange(MaxMemoryBytes, ProfileMaxMemoryBytes, nameof(MaxMemoryBytes));
        RequireRange(MaxOutputBytes, ProfileMaxOutputBytes, nameof(MaxOutputBytes));
        RequireRange(MaxWidth, ProfileMaxDimension, nameof(MaxWidth));
        RequireRange(MaxHeight, ProfileMaxDimension, nameof(MaxHeight));
        RequireRange(MaxItems, ProfileMaxItems, nameof(MaxItems));
        RequireRange(TimeoutMilliseconds, ProfileMaxTimeoutMilliseconds, nameof(TimeoutMilliseconds));
    }

    private static void RequireRange(ulong value, ulong profileMaximum, string name)
    {
        if (value == 0 || value > profileMaximum)
        {
            throw new ArgumentOutOfRangeException(name, value, "The value must be positive and within the producer profile.");
        }
    }

    internal unsafe NativeLimitsV1 ToNative() => new()
    {
        StructSize = (uint)sizeof(NativeLimitsV1),
        StructVersion = NativeAbiConstants.RecordVersion1,
        MaxInputBytes = MaxInputBytes,
        MaxMemoryBytes = MaxMemoryBytes,
        MaxOutputBytes = MaxOutputBytes,
        MaxWidth = MaxWidth,
        MaxHeight = MaxHeight,
        MaxItems = MaxItems,
        TimeoutMs = TimeoutMilliseconds,
    };
}

// Typed options for ImageReader.OpenAsync. Subimage and mip select one level of a multi-level file.
public sealed record ImageOpenOptions
{
    public uint Subimage { get; init; }

    public uint Mip { get; init; }

    public ImageOutputFormat Format { get; init; } = ImageOutputFormat.Rgba8;

    public ImageLimits Limits { get; init; } = new();

    internal void Validate()
    {
        ArgumentNullException.ThrowIfNull(Limits);
        if (Format == ImageOutputFormat.Unspecified || !Enum.IsDefined(Format))
        {
            throw new ArgumentOutOfRangeException(nameof(Format), Format, "The output format is not supported.");
        }

        Limits.Validate();
    }

    internal unsafe NativeImageOptionsV1 ToNative() => new()
    {
        StructSize = (uint)sizeof(NativeImageOptionsV1),
        StructVersion = NativeAbiConstants.RecordVersion1,
        Subimage = Subimage,
        Mip = Mip,
        Format = (uint)Format,
        Reserved = 0,
        Limits = Limits.ToNative(),
    };
}
