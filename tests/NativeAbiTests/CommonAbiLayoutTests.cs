// SPDX-License-Identifier: AGPL-3.0-only
using System.Reflection;
using System.Runtime.InteropServices;
using ArcForges.Native.Abstractions;

namespace ArcForges.Tests.NativeAbiTests;

public sealed class CommonAbiLayoutTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "NativeAbiLayout")]
    public void ManagedLayoutsMatchTheSeventeenNormativeSizesAndEveryFieldOffset()
    {
        Xunit.Assert.Equal(8, IntPtr.Size);

        (string Name, int Size, (string Field, int Offset)[] Fields)[] layouts =
        [
            ("NativeBoolean", 1, [("Value", 0)]),
            ("NativeStringView", 16, [("Data", 0), ("Size", 8)]),
            ("NativeByteView", 16, [("Data", 0), ("Size", 8)]),
            ("NativeBuffer", 24, [("Data", 0), ("Capacity", 8), ("Required", 16)]),
            ("NativeRational", 16, [("Numerator", 0), ("Denominator", 8)]),
            ("NativeTimeRange", 32, [("Start", 0), ("Duration", 16)]),
            ("NativeErrorBuffer", 48,
                [("StructSize", 0), ("StructVersion", 4), ("Status", 8), ("Domain", 12),
                 ("CorrelationId", 16), ("Message", 24)]),
            ("NativeCancelToken", 24, [("StructSize", 0), ("StructVersion", 4), ("IsCancelled", 8), ("UserData", 16)]),
            ("NativeIoV1", 56,
                [("StructSize", 0), ("StructVersion", 4), ("Context", 8), ("Length", 16),
                 ("MaxLength", 24), ("ReadAt", 32), ("WriteAt", 40), ("Flush", 48)]),
            ("NativeLimitsV1", 48,
                [("StructSize", 0), ("StructVersion", 4), ("MaxInputBytes", 8),
                 ("MaxMemoryBytes", 16), ("MaxOutputBytes", 24), ("MaxWidth", 32),
                 ("MaxHeight", 36), ("MaxItems", 40), ("TimeoutMs", 44)]),
            ("NativeFrameV1", 104,
                [("StructSize", 0), ("StructVersion", 4), ("Buffer", 8), ("Sequence", 16),
                 ("Pts", 24), ("Duration", 32), ("TimeBase", 40), ("Kind", 56), ("Format", 60),
                 ("Width", 64), ("Height", 68), ("SampleRate", 72), ("Channels", 76),
                 ("SampleCount", 80), ("ByteLength", 88), ("Flags", 96), ("Reserved", 100)]),
            ("NativeRegionV1", 48,
                [("StructSize", 0), ("StructVersion", 4), ("X", 8), ("Y", 12), ("Width", 16),
                 ("Height", 20), ("FirstSample", 24), ("SampleCount", 32), ("RowStride", 40)]),
            ("NativeInstrumentOptionsV1", 56,
                [("StructSize", 0), ("StructVersion", 4), ("DeviceId", 8), ("Transport", 24),
                 ("InterfaceNumber", 28), ("Baud", 32), ("DataBits", 36), ("Parity", 40),
                 ("StopBits", 44), ("FlowControl", 48), ("Reserved", 52)]),
            ("NativeTransferV1", 40,
                [("StructSize", 0), ("StructVersion", 4), ("Kind", 8), ("Endpoint", 12),
                 ("TimeoutMs", 16), ("RequestType", 20), ("Request", 24), ("Value", 28),
                 ("Index", 32), ("Reserved", 36)]),
            ("NativeImageOptionsV1", 72,
                [("StructSize", 0), ("StructVersion", 4), ("Subimage", 8), ("Mip", 12),
                 ("Format", 16), ("Reserved", 20), ("Limits", 24)]),
            ("NativePdfPageV1", 32,
                [("StructSize", 0), ("StructVersion", 4), ("PageIndex", 8), ("Rotation", 12),
                 ("WidthPoints", 16), ("HeightPoints", 24)])
        ];

        Xunit.Assert.Equal(17, layouts.Length + 1); // The enum-sized arc_status_t is counted separately.
        Type statusUnderlyingType = Enum.GetUnderlyingType(typeof(NativeStatus));
        Xunit.Assert.Equal(typeof(int), statusUnderlyingType);
        Xunit.Assert.Equal(4, Marshal.SizeOf(statusUnderlyingType));

        Assembly assembly = typeof(NativeAbiConstants).Assembly;
        foreach ((string name, int expectedSize, (string field, int offset)[] fields) in layouts)
        {
            Type type = assembly.GetType($"ArcForges.Native.Abstractions.{name}", throwOnError: true)!;
            Xunit.Assert.Equal(expectedSize, Marshal.SizeOf(type));
            StructLayoutAttribute layout = type.StructLayoutAttribute!;
            Xunit.Assert.Equal(8, layout.Pack);
            Xunit.Assert.Equal(LayoutKind.Sequential, layout.Value);
            foreach ((string field, int offset) in fields)
            {
                Xunit.Assert.Equal((nint)offset, Marshal.OffsetOf(type, field));
            }
        }
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "NativeAbiLayout")]
    public void OpaqueHandleWidthIsAnAdditionalInvariantNotAnEighteenthNormativeSize()
    {
        Xunit.Assert.Equal(8, Marshal.SizeOf<ulong>());
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "NativeAbiLayout")]
    public void ManagedClosedNumericKeysMatchTheNativeDeclarations()
    {
        Xunit.Assert.Equal(1u, NativeAbiConstants.Major);
        Xunit.Assert.Equal(0u, NativeAbiConstants.ProbeMinor);
        Xunit.Assert.Equal(1u, NativeAbiConstants.FunctionalMinor);
        Xunit.Assert.Equal(1u, NativeAbiConstants.RecordVersion1);

        Xunit.Assert.Equal(1u, NativeAbiKeys.IoRead);
        Xunit.Assert.Equal(2u, NativeAbiKeys.IoWrite);
        Xunit.Assert.Equal(1u, NativeAbiKeys.FrameVideo);
        Xunit.Assert.Equal(2u, NativeAbiKeys.FrameAudio);
        Xunit.Assert.Equal(3u, NativeAbiKeys.FrameSubtitle);
        Xunit.Assert.Equal(4u, NativeAbiKeys.FrameData);
        Xunit.Assert.Equal(1u, NativeAbiKeys.FormatRgba8);
        Xunit.Assert.Equal(2u, NativeAbiKeys.FormatRgba32fLinearPremultiplied);
        Xunit.Assert.Equal(3u, NativeAbiKeys.FormatFloat32Interleaved);
        Xunit.Assert.Equal(1u, NativeAbiKeys.InstrumentSerial);
        Xunit.Assert.Equal(2u, NativeAbiKeys.InstrumentUsb);
        Xunit.Assert.Equal(0u, NativeAbiKeys.ParityNone);
        Xunit.Assert.Equal(1u, NativeAbiKeys.ParityOdd);
        Xunit.Assert.Equal(2u, NativeAbiKeys.ParityEven);
        Xunit.Assert.Equal(1u, NativeAbiKeys.StopBitsOne);
        Xunit.Assert.Equal(2u, NativeAbiKeys.StopBitsTwo);
        Xunit.Assert.Equal(0u, NativeAbiKeys.FlowControlNone);
        Xunit.Assert.Equal(1u, NativeAbiKeys.FlowControlRtsCts);
        Xunit.Assert.Equal(2u, NativeAbiKeys.FlowControlXonXoff);
        Xunit.Assert.Equal(1u, NativeAbiKeys.TransferUsbControl);
        Xunit.Assert.Equal(2u, NativeAbiKeys.TransferUsbBulk);
        Xunit.Assert.Equal(3u, NativeAbiKeys.TransferUsbInterrupt);
        Xunit.Assert.Equal(4u, NativeAbiKeys.TransferSerialRead);
        Xunit.Assert.Equal(5u, NativeAbiKeys.TransferSerialWrite);
    }
}
