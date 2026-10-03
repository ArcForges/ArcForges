// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using Google.Protobuf;
using FoundationDecimal = ArcForges.Contracts.Foundation.V1.Decimal;

namespace ArcForges.ReleaseArtifactTests.GrpcWeb;

/// <summary>
/// In-process exact-value checks of the generated Foundation messages under the same trimmed/AOT closure as the
/// client. These never touch a wire or an ingress: they show only that the shipped codec keeps 64-bit extremes and
/// a decimal string exactly, which no deployed Hello method can carry.
/// </summary>
internal static class CodecPrimitives
{
    public static void Run(CheckRecorder checks)
    {
        ArgumentNullException.ThrowIfNull(checks);
        checks.Expect("codec.int64-extremes",
            Exact(new Revision { Value = long.MaxValue }, [0x08, .. Repeat(0xFF, 8), 0x7F], Revision.Parser) &&
            Exact(new Revision { Value = long.MinValue }, [0x08, .. Repeat(0x80, 9), 0x01], Revision.Parser),
            "int64 maximum and minimum encode to the canonical varints and decode to the same values.");
        checks.Expect("codec.uint64-maximum",
            Exact(new NativeContentRev { Value = ulong.MaxValue }, [0x08, .. Repeat(0xFF, 9), 0x01], NativeContentRev.Parser),
            "uint64 maximum encodes to the canonical varint and decodes to the same value.");
        checks.Expect("codec.signed-and-unsigned-pair",
            Exact(new Rational { Numerator = long.MinValue, Denominator = ulong.MaxValue },
                [0x08, .. Repeat(0xFF, 9), 0x01, 0x10, .. Repeat(0xFF, 9), 0x01], Rational.Parser),
            "A zigzag sint64 minimum and a uint64 maximum survive together.");
        const string digits = "-79228162514264337593543950335.0000000000000000001";
        byte[] ascii = Encoding.ASCII.GetBytes(digits);
        checks.Expect("codec.decimal-string",
            Exact(new FoundationDecimal { Value = digits }, [0x0A, (byte)ascii.Length, .. ascii], FoundationDecimal.Parser),
            "A 49 character decimal travels as the exact string, never as a binary number.");
    }

    private static byte[] Repeat(byte value, int count) => [.. Enumerable.Repeat(value, count)];

    internal static bool Exact<T>(T message, byte[] wire, MessageParser<T> parser)
        where T : class, IMessage<T>
    {
        byte[] encoded = message.ToByteArray();
        return encoded.AsSpan().SequenceEqual(wire) && parser.ParseFrom(wire).Equals(message) && parser.ParseFrom(encoded).Equals(message);
    }
}
