// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Net;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Node.Core;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink;

/// <summary>
/// A URL the node derived itself from the center it captured at the flow's start (AF-CTR-04 CTR4-NODE-17, P-02): the only kind of value the
/// browser opener accepts, printed or returned. It cannot be built from a center's reply.
/// </summary>
internal sealed class DerivedUrl
{
    private DerivedUrl(string value) => Value = value;

    /// <summary>The URL.</summary>
    public string Value { get; }

    /// <inheritdoc />
    public override string ToString() => Value;

    /// <summary>Wraps a string <see cref="SignInUrls"/> derived.</summary>
    internal static DerivedUrl Of(string value) => new(value);
}

/// <summary>The derived URLs of a device authorization, and its validated codes.</summary>
/// <param name="Verification"><c>&lt;center&gt;/activate</c>.</param>
/// <param name="Complete"><c>&lt;center&gt;/activate#code=XXXX-XXXX</c>.</param>
/// <param name="UserCode">The 8 letters.</param>
/// <param name="DeviceCode">The device code (43 base64url characters; never logged).</param>
internal sealed record DeviceUrls(DerivedUrl Verification, DerivedUrl Complete, string UserCode, string DeviceCode);

/// <summary>
/// Center-supplied URLs are never trusted (AF-CTR-04 CTR4-NODE-17, the plan review's protocol-2 corrected fix and node-4). fleet.proto:
/// <c>authorize_url</c> is "&lt;center&gt;/connect#flow=&lt;flow_id&gt;, ... the node derives the same string from its configured center and
/// requires an exact match; &lt;= 512 chars"; <c>verification_uri</c> "&lt;center&gt;/activate, ... the node derives the same string from its
/// configured center and requires an exact match; &lt;= 512 chars"; <c>verification_uri_complete</c> "&lt;center&gt;/activate#code=XXXX-XXXX;
/// derived and matched like verification_uri"; <c>user_code</c> "8 characters from BCDFGHJKLMNPQRSTVWXZ". Each check is a pure function
/// ahead of the opener seam, so a test browser never bypasses it. A failure names the field and <c>center_url_mismatch</c> (or
/// <c>pattern</c>); the reply's text is never opened, printed or returned.
/// </summary>
internal static class SignInUrls
{
    /// <summary>The user code alphabet.</summary>
    public const string UserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ";

    /// <summary>The longest derived URL the contract admits.</summary>
    public const int MaxLength = 512;

    /// <summary>The lowest and highest loopback port the center admits in <c>redirect_uri</c>.</summary>
    public const int LowestPort = 1024;

    /// <summary>The highest loopback port.</summary>
    public const int HighestPort = 65535;

    /// <summary>
    /// The browser sign-in's URL: the derived <c>/connect#flow=</c> of <paramref name="flowId"/>, when the center's
    /// <paramref name="reply"/> equals it byte for byte; otherwise the failure reason (<c>authorize_url: center_url_mismatch</c>).
    /// </summary>
    public static DerivedUrl? Authorize(CenterEndpoint center, ByteString? flowId, string? reply, out string? failure)
    {
        ArgumentNullException.ThrowIfNull(center);
        failure = null;
        if (flowId is not { Length: 16 })
        {
            failure = "flow_id: length";
            return null;
        }

        var derived = center.ConnectUrl(flowId.Span);
        if (derived.Length > MaxLength || !string.Equals(derived, reply, StringComparison.Ordinal))
        {
            failure = "authorize_url: center_url_mismatch";
            return null;
        }

        return DerivedUrl.Of(derived);
    }

    /// <summary>The device sign-in's URLs and codes, when the center's reply matches what the node derives; otherwise the failure reason.</summary>
    public static DeviceUrls? Device(CenterEndpoint center, DeviceAuthorization? authorization, out string? failure)
    {
        ArgumentNullException.ThrowIfNull(center);
        failure = null;
        if (authorization is null)
        {
            failure = "authorization: required";
            return null;
        }

        if (!IsUserCode(authorization.HasUserCode ? authorization.UserCode : null))
        {
            failure = "user_code: pattern";
            return null;
        }

        if (!Pkce.IsBase64Url43(authorization.HasDeviceCode ? authorization.DeviceCode : null))
        {
            failure = "device_code: pattern";
            return null;
        }

        var verification = center.ActivateUrl;
        var complete = center.ActivateCompleteUrl(authorization.UserCode);
        if (verification.Length > MaxLength || !string.Equals(verification, authorization.HasVerificationUri ? authorization.VerificationUri : null, StringComparison.Ordinal))
        {
            failure = "verification_uri: center_url_mismatch";
            return null;
        }

        if (complete.Length > MaxLength
            || !string.Equals(complete, authorization.HasVerificationUriComplete ? authorization.VerificationUriComplete : null, StringComparison.Ordinal))
        {
            failure = "verification_uri_complete: center_url_mismatch";
            return null;
        }

        return new DeviceUrls(DerivedUrl.Of(verification), DerivedUrl.Of(complete), authorization.UserCode, authorization.DeviceCode);
    }

    /// <summary>True for exactly 8 letters of the code alphabet.</summary>
    public static bool IsUserCode(string? value) => value is { Length: 8 } && value.All(c => UserCodeAlphabet.Contains(c, StringComparison.Ordinal));

    /// <summary>The display form <c>XXXX-XXXX</c> of an 8-letter user code.</summary>
    public static string DisplayUserCode(string userCode)
    {
        ArgumentNullException.ThrowIfNull(userCode);
        return userCode.Length == 8 ? userCode[..4] + "-" + userCode[4..] : userCode;
    }

    /// <summary>
    /// The loopback <c>redirect_uri</c> (fleet.proto: "http://127.0.0.1:&lt;port&gt;/callback or http://[::1]:&lt;port&gt;/callback; &lt;port&gt;
    /// 1024..65535, decimal, no leading zero"), or <see langword="null"/> for an address or a port the center does not admit.
    /// </summary>
    public static string? RedirectUri(IPAddress address, int port)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (port is < LowestPort or > HighestPort)
        {
            return null;
        }

        var text = port.ToString(CultureInfo.InvariantCulture);
        if (address.Equals(IPAddress.Loopback))
        {
            return "http://127.0.0.1:" + text + "/callback";
        }

        return address.Equals(IPAddress.IPv6Loopback) ? "http://[::1]:" + text + "/callback" : null;
    }

    /// <summary>The authority a browser sends in <c>Host</c> for <see cref="RedirectUri"/> (<c>127.0.0.1:&lt;port&gt;</c> or <c>[::1]:&lt;port&gt;</c>).</summary>
    public static string Authority(IPAddress address, int port) =>
        (address.Equals(IPAddress.IPv6Loopback) ? "[::1]" : "127.0.0.1") + ":" + port.ToString(CultureInfo.InvariantCulture);
}
