// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;

namespace ArcForges.Node.Core;

/// <summary>
/// The center the node talks to (AF-CTR-04 CTR4-NODE-01): a canonical URL accepted exactly as written, never normalized, in the form the
/// center's own public base URL takes (Cloud <c>config.ParsePublicBaseURL</c>) for the node's admitted subset. node.proto
/// <c>UpdateNodeSettings.center_url</c>: "https URL (http only for localhost, 127.0.0.1, [::1]), no userinfo, query or fragment, lower-case
/// host, no trailing slash, &lt;= 512 chars". In addition: ASCII only without space or control characters (an IDN must be in punycode),
/// no percent-encoding, a port from 1 to 65535 in canonical decimal and never the scheme's default, and a path of segments of
/// <c>[A-Za-z0-9-._~]</c> without empty or dot segments.
/// </summary>
public sealed class CenterEndpoint : IEquatable<CenterEndpoint>
{
    /// <summary>The official center, used only when <c>node.json</c> names none and the node is not in <c>--test-mode</c>.</summary>
    public const string OfficialDefault = "https://arcforges.com/api";

    /// <summary>The contract's bound on the setting (node.proto).</summary>
    public const int MaxLength = 512;

    /// <summary>
    /// The longest base URL a center that serves <c>fleet</c> accepts (Cloud <c>docs/center-fleet.md</c> "Surface": so every URL it
    /// derives stays within 512 characters). A longer setting is accepted (the contract allows 512) and reported with a warning.
    /// </summary>
    public const int FleetBaseMaxLength = 462;

    private CenterEndpoint(string url, string scheme, string host, int? port, string path)
    {
        Url = url;
        Scheme = scheme;
        Host = host;
        Port = port;
        PathBase = path;
        Origin = scheme + "://" + host + (port is { } value ? ":" + value.ToString(System.Globalization.CultureInfo.InvariantCulture) : string.Empty);
    }

    /// <summary>The canonical URL (the node key proof's audience, CTR4-KEY-02 as frozen by C0).</summary>
    public string Url { get; }

    /// <summary><c>https</c> or <c>http</c>.</summary>
    public string Scheme { get; }

    /// <summary>The host as written (lower case; <c>[::1]</c> with its brackets).</summary>
    public string Host { get; }

    /// <summary>The explicit port, or <see langword="null"/> for the scheme's default.</summary>
    public int? Port { get; }

    /// <summary>The port requests go to.</summary>
    public int EffectivePort => Port ?? (Scheme == "https" ? 443 : 80);

    /// <summary>The path prefix (empty, or <c>/segment</c>...), without a trailing slash.</summary>
    public string PathBase { get; }

    /// <summary><c>scheme://host[:port]</c>: key and credential names derive from it with the node ID (fleet.proto, node key proof comment).</summary>
    public string Origin { get; }

    /// <summary>True when the URL is longer than a center that serves <c>fleet</c> accepts (<see cref="FleetBaseMaxLength"/>).</summary>
    public bool ExceedsFleetBase => Url.Length > FleetBaseMaxLength;

    /// <summary>Parses <paramref name="value"/>; on failure <paramref name="reason"/> names the rule.</summary>
    public static bool TryParse(string? value, [NotNullWhen(true)] out CenterEndpoint? endpoint, out string reason)
    {
        endpoint = null;
        if (string.IsNullOrEmpty(value))
        {
            reason = "required";
            return false;
        }

        if (value.Length > MaxLength)
        {
            reason = "longer than 512 characters";
            return false;
        }

        foreach (var c in value)
        {
            if (c <= ' ' || c >= 0x7f)
            {
                reason = "contains a space, a control character or a non-ASCII character";
                return false;
            }
        }

        if (value.AsSpan().IndexOfAny("?#%@\\") >= 0)
        {
            reason = "has user information, a query, a fragment, percent-encoding or a backslash";
            return false;
        }

        string scheme;
        string rest;
        if (value.StartsWith("https://", StringComparison.Ordinal))
        {
            scheme = "https";
            rest = value["https://".Length..];
        }
        else if (value.StartsWith("http://", StringComparison.Ordinal))
        {
            scheme = "http";
            rest = value["http://".Length..];
        }
        else
        {
            reason = "must use https (http only for localhost, 127.0.0.1 or [::1]), in lower case";
            return false;
        }

        var slash = rest.IndexOf('/', StringComparison.Ordinal);
        var authority = slash < 0 ? rest : rest[..slash];
        var path = slash < 0 ? string.Empty : rest[slash..];
        string host;
        string? portText = null;
        if (authority.StartsWith('['))
        {
            var close = authority.IndexOf(']', StringComparison.Ordinal);
            if (close < 0)
            {
                reason = "the host is not a valid IPv6 literal";
                return false;
            }

            host = authority[..(close + 1)];
            var after = authority[(close + 1)..];
            if (after.Length > 0)
            {
                if (after[0] != ':')
                {
                    reason = "the host is not a valid IPv6 literal";
                    return false;
                }

                portText = after[1..];
            }

            if (!IsIpv6Literal(host))
            {
                reason = "the host is not a lower-case IPv6 literal";
                return false;
            }
        }
        else
        {
            var colon = authority.IndexOf(':', StringComparison.Ordinal);
            host = colon < 0 ? authority : authority[..colon];
            portText = colon < 0 ? null : authority[(colon + 1)..];
            if (!IsHostName(host))
            {
                reason = "the host is missing or not in lower-case canonical form";
                return false;
            }
        }

        int? port = null;
        if (portText is not null)
        {
            if (portText.Length is 0 or > 5 || portText[0] == '0' || !portText.All(char.IsAsciiDigit)
                || int.Parse(portText, System.Globalization.CultureInfo.InvariantCulture) is var number && number is < 1 or > 65535)
            {
                reason = "the port is not a number from 1 to 65535 in canonical form";
                return false;
            }

            port = int.Parse(portText, System.Globalization.CultureInfo.InvariantCulture);
            if ((scheme == "https" && port == 443) || (scheme == "http" && port == 80))
            {
                reason = "the port is the scheme's default and is left out";
                return false;
            }
        }

        if (scheme == "http" && host is not ("localhost" or "127.0.0.1" or "[::1]"))
        {
            reason = "must use https (http only for localhost, 127.0.0.1 or [::1])";
            return false;
        }

        if (path.Length > 0)
        {
            if (path.EndsWith('/'))
            {
                reason = "the path has a trailing slash";
                return false;
            }

            foreach (var segment in path[1..].Split('/'))
            {
                if (segment.Length == 0 || segment is "." or "..")
                {
                    reason = "the path has an empty or dot segment";
                    return false;
                }

                if (!segment.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~'))
                {
                    reason = "the path has a character outside letters, digits and -._~";
                    return false;
                }
            }
        }

        endpoint = new CenterEndpoint(value, scheme, host, port, path);
        reason = string.Empty;
        return true;
    }

    /// <summary>Parses a value that must be valid.</summary>
    /// <exception cref="ArgumentException">The value is not a canonical center URL.</exception>
    public static CenterEndpoint Parse(string value) =>
        TryParse(value, out var endpoint, out var reason) ? endpoint : throw new ArgumentException("Not a canonical center URL: " + reason, nameof(value));

    /// <summary>
    /// <c>&lt;center&gt;/connect#flow=&lt;flow_id&gt;</c>, the flow ID in "the lower-case 8-4-4-4-12 hex form of the 16 flow_id bytes in
    /// order (RFC 9562), never a platform GUID byte order" (fleet.proto <c>authorize_url</c>; the node requires an exact match).
    /// </summary>
    public string ConnectUrl(ReadOnlySpan<byte> flowId)
    {
        if (flowId.Length != 16)
        {
            throw new ArgumentException("A flow ID is 16 bytes.", nameof(flowId));
        }

        var hex = Convert.ToHexStringLower(flowId);
        return Url + "/connect#flow=" + hex[..8] + "-" + hex[8..12] + "-" + hex[12..16] + "-" + hex[16..20] + "-" + hex[20..];
    }

    /// <summary><c>&lt;center&gt;/activate</c> (fleet.proto <c>verification_uri</c>).</summary>
    public string ActivateUrl => Url + "/activate";

    /// <summary><c>&lt;center&gt;/activate#code=XXXX-XXXX</c> for an 8-letter user code (fleet.proto <c>verification_uri_complete</c>).</summary>
    public string ActivateCompleteUrl(string userCode)
    {
        ArgumentNullException.ThrowIfNull(userCode);
        if (userCode.Length != 8 || !userCode.All(c => "BCDFGHJKLMNPQRSTVWXZ".Contains(c, StringComparison.Ordinal)))
        {
            throw new ArgumentException("A user code is 8 letters of BCDFGHJKLMNPQRSTVWXZ.", nameof(userCode));
        }

        return Url + "/activate#code=" + userCode[..4] + "-" + userCode[4..];
    }

    /// <inheritdoc />
    public bool Equals(CenterEndpoint? other) => other is not null && string.Equals(Url, other.Url, StringComparison.Ordinal);

    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as CenterEndpoint);

    /// <inheritdoc />
    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Url);

    /// <inheritdoc />
    public override string ToString() => Url;

    private static bool IsHostName(string host)
    {
        if (host.Length is 0 or > 253 || host.EndsWith('.') || host.StartsWith('.'))
        {
            return false;
        }

        foreach (var label in host.Split('.'))
        {
            if (label.Length is 0 or > 63 || label.StartsWith('-') || label.EndsWith('-')
                || !label.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '-'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsIpv6Literal(string host)
    {
        var inner = host[1..^1];
        return inner.Length > 0 && inner.All(c => char.IsAsciiDigit(c) || c is (>= 'a' and <= 'f') or ':' or '.')
            && System.Net.IPAddress.TryParse(inner, out var address) && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
    }
}
