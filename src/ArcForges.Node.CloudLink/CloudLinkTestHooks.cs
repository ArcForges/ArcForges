// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Node.Core;

namespace ArcForges.Node.CloudLink;

/// <summary>
/// The cloud link's <c>--test-mode</c> hooks (AF-CTR-04 N1; node-15 item 5): each is honoured only with <c>--test-mode</c> and only for a
/// well-formed value; otherwise it is ignored. None of them can give the node a credential: a credential arrives only from a center's
/// sign-in reply.
/// </summary>
internal static class CloudLinkTestHooks
{
    /// <summary>The center of a test node (validated by <see cref="CenterEndpoint"/>; never written to <c>node.json</c>; decision G-6).</summary>
    public const string CenterUrl = "ARCFORGES_TEST_CENTER_URL";

    /// <summary>An absolute file the node appends one <c>host:port sent|refused</c> line to per attempted center connection.</summary>
    public const string ConnectLog = "ARCFORGES_TEST_CONNECT_LOG";

    /// <summary>A fixed refresh cadence in whole seconds, 15 to 3,600 (it replaces the computed delay, floor included).</summary>
    public const string RefreshSeconds = "ARCFORGES_TEST_CLOUDLINK_REFRESH_SECONDS";

    /// <summary>The shortest refresh cadence the hook admits: the center admits 60 refreshes of one session per 10 minutes.</summary>
    public const int MinimumRefreshSeconds = 15;

    /// <summary>The test center, when <paramref name="testMode"/> and <paramref name="value"/> is a canonical center URL.</summary>
    public static CenterEndpoint? Center(bool testMode, string? value) =>
        testMode && CenterEndpoint.TryParse(value, out var center, out _) ? center : null;

    /// <summary>The connect log, when <paramref name="testMode"/> and <paramref name="value"/> is an absolute path.</summary>
    public static string? Connections(bool testMode, string? value) =>
        testMode && !string.IsNullOrWhiteSpace(value) && Path.IsPathFullyQualified(value) ? value : null;

    /// <summary>The refresh cadence, when <paramref name="testMode"/> and <paramref name="value"/> is 15..3600 in canonical decimal.</summary>
    public static TimeSpan? Refresh(bool testMode, string? value) =>
        testMode && value is { Length: > 0 and <= 4 } && value[0] != '0' && value.All(char.IsAsciiDigit)
            && int.Parse(value, CultureInfo.InvariantCulture) is var seconds and >= MinimumRefreshSeconds and <= 3600
            ? TimeSpan.FromSeconds(seconds)
            : null;
}
