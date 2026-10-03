// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using ArcForges.Security.Approvals;

namespace ArcForges.Security.Egress;

/// <summary>
/// What a transfer would carry. The order is the order of sensitivity: a limit of one class admits that class and every class below it,
/// never one above it. <see cref="SecretMaterial"/> is above every limit a rule or grant can state, so secret plaintext never leaves.
/// </summary>
public enum EgressDataClass
{
    None = 0,
    Public = 1,
    Diagnostic = 2,
    WorkspaceContent = 3,
    SensitiveContent = 4,

    /// <summary>Credential or secret plaintext. No allowlist entry or grant can admit it (SE-09).</summary>
    SecretMaterial = 5,
}

/// <summary>The class of a destination. It is stated by the workspace allowlist entry, never by the caller.</summary>
public enum EgressDestinationClass
{
    None = 0,

    /// <summary>A Cloud model provider route (EG-02): its own rules, including the knowledge policy's AI eligibility.</summary>
    CloudAiProvider = 1,

    /// <summary>A configured connector origin.</summary>
    Connector = 2,

    /// <summary>A named third-party service, for example an extension's declared network destination (EG-06).</summary>
    ThirdParty = 3,

    /// <summary>A public destination.</summary>
    Public = 4,
}

/// <summary>Whose authority an egress grant rests on, recorded with every decision and audit event.</summary>
public enum EgressAuthorityKind
{
    None = 0,

    /// <summary>The owning user's explicit consent.</summary>
    UserConsent = 1,

    /// <summary>A workspace policy decision.</summary>
    WorkspacePolicy = 2,

    /// <summary>A declared product or Cloud route.</summary>
    ProductRoute = 3,
}

public enum EgressGrantState
{
    None = 0,
    Granted = 1,

    /// <summary>A standing prohibition: it wins over every grant for the same destination.</summary>
    Denied = 2,
}

/// <summary>
/// The exact identity of an egress destination: one lower-case HTTPS origin (EG-05). "An external service" is not an identity, and
/// neither is a category, a wildcard, an address or a name that can only be reached inside the machine or the local network. Two
/// identities are equal only when their canonical origins are identical, so a suffix, a parent domain, another port, a userinfo
/// prefix or a trailing dot is a different destination.
/// </summary>
public sealed record EgressDestinationIdentity
{
    public const int MaximumLength = 300;

    private const string Scheme = "https://";
    private static readonly string[] InternalSuffixes = [".localhost", ".local", ".internal", ".localdomain", ".lan", ".home.arpa"];

    private EgressDestinationIdentity(string origin, string host, int port)
    {
        Origin = origin;
        Host = host;
        Port = port;
    }

    /// <summary>The canonical origin: <c>https://host</c>, or <c>https://host:port</c> when the port is not 443.</summary>
    public string Origin { get; }

    public string Host { get; }

    public int Port { get; }

    /// <summary>Parses a destination or reports why it is not an acceptable identity. It never throws on input text.</summary>
    public static bool TryParse(string? text, [NotNullWhen(true)] out EgressDestinationIdentity? identity)
    {
        identity = null;
        if (text is null || text.Length > MaximumLength || !text.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var rest = text.AsSpan(Scheme.Length);
        if (rest.EndsWith("/", StringComparison.Ordinal))
        {
            rest = rest[..^1];
        }

        var port = 443;
        var colon = rest.IndexOf(':');
        var host = rest;
        if (colon >= 0)
        {
            host = rest[..colon];
            var digits = rest[(colon + 1)..];
            if (digits.IsEmpty || digits.Length > 5 || digits[0] == '0' || !IsAllDigits(digits)
                || !int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out port) || port is < 1 or > 65535)
            {
                return false;
            }
        }

        if (!IsAcceptableHost(host))
        {
            return false;
        }

        var lower = AsciiLower(host);
        var origin = port == 443
            ? string.Concat(Scheme, lower)
            : string.Concat(Scheme, lower, ":", port.ToString(CultureInfo.InvariantCulture));
        identity = new EgressDestinationIdentity(origin, lower, port);
        return true;
    }

    /// <summary>Parses a destination or throws <see cref="ArgumentException"/>.</summary>
    public static EgressDestinationIdentity Parse(string text) =>
        TryParse(text, out var identity)
            ? identity
            : throw new ArgumentException("The text is not an exact HTTPS destination identity.", nameof(text));

    // The host is ASCII by the time it is lowered, so a character-wise fold is exact and independent of the current culture.
    private static string AsciiLower(ReadOnlySpan<char> host)
    {
        var buffer = new char[host.Length];
        for (var index = 0; index < host.Length; index++)
        {
            var character = host[index];
            buffer[index] = character is >= 'A' and <= 'Z' ? (char)(character + ('a' - 'A')) : character;
        }

        return new string(buffer);
    }

    private static bool IsAllDigits(ReadOnlySpan<char> text)
    {
        foreach (var character in text)
        {
            if (character is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsAcceptableHost(ReadOnlySpan<char> host)
    {
        if (host.IsEmpty || host.Length > 253)
        {
            return false;
        }

        var labels = 0;
        var lastLabelHasLetter = false;
        var start = 0;
        for (var index = 0; index <= host.Length; index++)
        {
            if (index < host.Length && host[index] != '.')
            {
                if (!(host[index] is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '-'))
                {
                    return false;
                }

                continue;
            }

            var label = host[start..index];
            if (label.IsEmpty || label.Length > 63 || label[0] == '-' || label[^1] == '-')
            {
                return false;
            }

            labels++;
            lastLabelHasLetter = false;
            foreach (var character in label)
            {
                if (character is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z'))
                {
                    lastLabelHasLetter = true;
                }
            }

            start = index + 1;
        }

        // A name with a single label (localhost, an intranet host) or whose last label is numeric (an IPv4 literal) is not a public name.
        if (labels < 2 || !lastLabelHasLetter)
        {
            return false;
        }

        foreach (var suffix in InternalSuffixes)
        {
            if (host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }
}

/// <summary>
/// The owner's classification of what a transfer would carry: its data class and whether the knowledge policy makes it eligible for
/// an AI destination (EG-03). It comes from the host's classifier, never from the caller.
/// </summary>
public sealed record EgressContentFacts(EgressDataClass DataClass, bool AiEligible);

/// <summary>
/// One workspace allowlist entry: an exact destination a scope may send to, its class, and the highest data class that may go there.
/// It is policy only: it never grants anything to a principal, and a destination absent from the allowlist is never reachable.
/// </summary>
public sealed class EgressAllowlistEntry
{
    public EgressAllowlistEntry(
        string scopeKey,
        EgressDestinationIdentity destination,
        EgressDestinationClass destinationClass,
        EgressDataClass maxDataClass,
        string sourceGeneration)
    {
        SecurityText.Validate(scopeKey, 256, nameof(scopeKey));
        ArgumentNullException.ThrowIfNull(destination);
        SecurityText.Validate(sourceGeneration, 256, nameof(sourceGeneration));
        if (!Enum.IsDefined(destinationClass) || destinationClass == EgressDestinationClass.None)
        {
            throw new ArgumentOutOfRangeException(nameof(destinationClass));
        }

        if (!Enum.IsDefined(maxDataClass) || maxDataClass is EgressDataClass.None or EgressDataClass.SecretMaterial)
        {
            throw new ArgumentOutOfRangeException(nameof(maxDataClass), "A limit names a data class that may leave; secret material never does.");
        }

        ScopeKey = scopeKey;
        Destination = destination;
        DestinationClass = destinationClass;
        MaxDataClass = maxDataClass;
        SourceGeneration = sourceGeneration;
    }

    public string ScopeKey { get; }

    public EgressDestinationIdentity Destination { get; }

    public EgressDestinationClass DestinationClass { get; }

    public EgressDataClass MaxDataClass { get; }

    public string SourceGeneration { get; }
}

/// <summary>
/// An owner-issued egress permission for one principal, capability, scope and exact destination, with its authority and lifetime. It
/// is a fact of its own, separate from the capability permission that lets the principal read: holding one never implies the other.
/// </summary>
public sealed class EgressGrantRecord
{
    public EgressGrantRecord(
        string issuerKey,
        string principalKey,
        string capabilityKey,
        string scopeKey,
        EgressDestinationIdentity destination,
        EgressGrantState state,
        EgressDataClass maxDataClass,
        EgressAuthorityKind authority,
        string authorityReference,
        DateTimeOffset validFromUtc,
        DateTimeOffset validUntilUtc,
        string sourceGeneration)
    {
        SecurityText.Validate(issuerKey, 256, nameof(issuerKey));
        SecurityText.Validate(principalKey, 256, nameof(principalKey));
        SecurityText.Validate(capabilityKey, 256, nameof(capabilityKey));
        SecurityText.Validate(scopeKey, 256, nameof(scopeKey));
        ArgumentNullException.ThrowIfNull(destination);
        SecurityText.Validate(authorityReference, 256, nameof(authorityReference));
        SecurityText.Validate(sourceGeneration, 256, nameof(sourceGeneration));
        if (!Enum.IsDefined(state) || state == EgressGrantState.None)
        {
            throw new ArgumentOutOfRangeException(nameof(state));
        }

        if (!Enum.IsDefined(maxDataClass) || maxDataClass is EgressDataClass.None or EgressDataClass.SecretMaterial)
        {
            throw new ArgumentOutOfRangeException(nameof(maxDataClass), "A limit names a data class that may leave; secret material never does.");
        }

        if (!Enum.IsDefined(authority) || authority == EgressAuthorityKind.None)
        {
            throw new ArgumentOutOfRangeException(nameof(authority));
        }

        if (validFromUtc.Offset != TimeSpan.Zero || validUntilUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Egress lifetimes are UTC.", nameof(validFromUtc));
        }

        if (validUntilUtc <= validFromUtc)
        {
            throw new ArgumentException("An egress lifetime is not empty.", nameof(validUntilUtc));
        }

        IssuerKey = issuerKey;
        PrincipalKey = principalKey;
        CapabilityKey = capabilityKey;
        ScopeKey = scopeKey;
        Destination = destination;
        State = state;
        MaxDataClass = maxDataClass;
        Authority = authority;
        AuthorityReference = authorityReference;
        ValidFromUtc = validFromUtc;
        ValidUntilUtc = validUntilUtc;
        SourceGeneration = sourceGeneration;
    }

    public string IssuerKey { get; }

    public string PrincipalKey { get; }

    public string CapabilityKey { get; }

    public string ScopeKey { get; }

    public EgressDestinationIdentity Destination { get; }

    public EgressGrantState State { get; }

    public EgressDataClass MaxDataClass { get; }

    public EgressAuthorityKind Authority { get; }

    /// <summary>The identity of the consent, policy or route the grant rests on. It is a reference, never content.</summary>
    public string AuthorityReference { get; }

    /// <summary>Inclusive start of the lifetime.</summary>
    public DateTimeOffset ValidFromUtc { get; }

    /// <summary>Exclusive end of the lifetime: at this exact instant the grant is already over.</summary>
    public DateTimeOffset ValidUntilUtc { get; }

    public string SourceGeneration { get; }
}
