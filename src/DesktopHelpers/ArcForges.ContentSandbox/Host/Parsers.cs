// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.ContentSandbox.Contracts;
using ArcForges.Contracts.LocalRpc.Sandbox.V1;
using ArcForges.LocalRpc;

namespace ArcForges.ContentSandbox.Host;

/// <summary>A parser stopped on its own or its input was not valid. The host maps it to <c>resource.parser_failed</c>; its text is never sent.</summary>
internal sealed class ContentParserException : Exception
{
    public ContentParserException()
    {
    }

    public ContentParserException(string message)
        : base(message)
    {
    }

    public ContentParserException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>The writable shared memory of one output slot. Only the parent's grant decides which bytes of it a parser may fill.</summary>
internal interface IParserSlot
{
    /// <summary>The size of the mapping in bytes.</summary>
    long Capacity { get; }

    /// <summary>A window over the mapping. The caller keeps within the capacity it was granted.</summary>
    Span<byte> GetSpan(long offset, int length);
}

/// <summary>The immutable input, read through bounded reads. Whoever else holds the mapping cannot change it: it is read-only here.</summary>
internal sealed class ParserInput(ILocalRpcBufferMapping mapping, long length)
{
    /// <summary>The byte length of the input, as the parent minted it.</summary>
    internal long Length { get; } = length;

    /// <summary>Reads up to <paramref name="destination"/>.Length bytes at <paramref name="offset"/>; returns how many were read.</summary>
    internal int Read(long offset, Span<byte> destination)
    {
        if (offset < 0 || offset > Length)
        {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }

        var count = (int)Math.Min(destination.Length, Length - offset);
        return count == 0 ? 0 : mapping.Read(offset, destination[..count]);
    }
}

/// <summary>The budget a parser call runs under, fixed by the launch.</summary>
/// <param name="Limits">The launch budget.</param>
/// <param name="Cancelled">Cancelled on session cancellation, expiry and parent loss.</param>
internal sealed record ParserContext(ContentSandboxLimits Limits, CancellationToken Cancelled);

/// <summary>An image parser that runs only inside the helper process under its restricted profile.</summary>
internal interface IImageParser : IDisposable
{
    /// <summary>Opens the input; returns the bounded description, or throws <see cref="ContentParserException"/>.</summary>
    SandboxImageInfo Open(ParserInput input, uint subimage, uint mip, uint outputFormat, ParserContext context);

    /// <summary>Writes the tile pixels at the start of <paramref name="destination"/> and returns the number of bytes written. The row stride is the one the parent asked for.</summary>
    int ReadTile(SandboxRegion region, uint format, Span<byte> destination, ParserContext context);
}

/// <summary>
/// One approved parser composition, chosen by the identifier of the launch and never by a path or a function name. The production helper
/// composes <see cref="ProductionParserProfile"/>, which composes no parser until the still-image composition is delivered; the hostile test
/// composition exists only in the test fixture. A composition that lacks a parser kind refuses that kind.
/// </summary>
internal interface IContentParserProfile
{
    /// <summary>The identifier the launch names.</summary>
    string Id { get; }

    /// <summary>A new image parser, or null when the composition has none.</summary>
    IImageParser? CreateImageParser();

    /// <summary>
    /// Runs before the operating-system profile is applied: loads and verifies whatever native libraries the composition needs, because a
    /// restricted process can no longer load them. Throws <see cref="ContentParserException"/> when the composition cannot run; the helper
    /// then ends before any parser exists. The default does nothing.
    /// </summary>
    void Prepare()
    {
    }
}

/// <summary>The closed set of parser compositions of one helper build.</summary>
internal sealed class ParserProfiles(IReadOnlyList<IContentParserProfile> profiles)
{
    /// <summary>The compositions of the production helper: the production parser composition only. A launch that names any other is refused.</summary>
    internal static ParserProfiles Production { get; } = new([new ProductionParserProfile()]);

    /// <summary>The composition with this identifier, or null.</summary>
    internal IContentParserProfile? Find(string id) => profiles.FirstOrDefault(profile => string.Equals(profile.Id, id, StringComparison.Ordinal));
}
