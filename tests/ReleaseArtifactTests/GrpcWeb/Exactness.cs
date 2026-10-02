// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.ReleaseArtifactTests.GrpcWeb;

/// <summary>Text values whose exact round trip matters. Built from code points so no editor can normalize them.</summary>
internal static class Exactness
{
    public const int MaximumNameUtf16Units = 256;

    /// <summary>U+00E9 as one code point.</summary>
    public static string Precomposed { get; } = ((char)0x00E9).ToString();

    /// <summary>U+0065 followed by U+0301: the same glyph as <see cref="Precomposed"/> in two code points.</summary>
    public static string Decomposed { get; } = "e" + (char)0x0301;

    /// <summary>U+1F44B, one code point and two UTF-16 code units (a surrogate pair).</summary>
    public static string Emoji { get; } = char.ConvertFromUtf32(0x1F44B);

    public static string CjkPair { get; } = new([(char)0x4E16, (char)0x754C]);

    public static IReadOnlyList<string> Names { get; } =
    [
        "ArcForges",
        CjkPair + " " + Emoji,
        "  padded  ",
        Precomposed,
        Decomposed,
        "tab\tand\nline",
    ];

    /// <summary>128 surrogate pairs: exactly 256 UTF-16 code units but 512 UTF-8 bytes.</summary>
    public static string MaximumPairs { get; } = string.Concat(Enumerable.Repeat(Emoji, MaximumNameUtf16Units / 2));
}
