// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;

namespace ArcForges.ReleaseArtifactTests.GrpcWeb;

internal enum ProbeMode
{
    SelfTest,
    Live,
}

internal sealed record ProbeOptions(ProbeMode Mode, Uri? BaseAddress, string? ExpectedRevision, string? EvidencePath);

internal sealed record OptionsResult(ProbeOptions? Options, string? Error);

/// <summary>
/// Parses the command line. Every refusal here is a guard: the live mode is an explicit local opt-in,
/// never runs in CI, and only accepts a plain origin (no credentials, query or fragment).
/// </summary>
internal static partial class ProbeOptionsParser
{
    public const string Usage =
        "Usage: GrpcWebAotProbe --self-test [--evidence <file>]" +
        " | --live <https-base-address> [--expect-revision <40 lowercase hex>] [--evidence <file>]";

    public static OptionsResult Parse(IReadOnlyList<string> args, Func<string, string?> environment)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(environment);
        bool selfTest = false;
        string? live = null;
        string? expectedRevision = null;
        string? evidencePath = null;
        for (int index = 0; index < args.Count; index++)
        {
            string argument = args[index];
            switch (argument)
            {
                case "--self-test":
                    if (selfTest)
                    {
                        return Refuse("--self-test was given twice.");
                    }

                    selfTest = true;
                    break;
                case "--live" or "--expect-revision" or "--evidence":
                    if (index + 1 >= args.Count || args[index + 1].StartsWith("--", StringComparison.Ordinal))
                    {
                        return Refuse(argument + " needs a value.");
                    }

                    string value = args[++index];
                    string? previous = argument switch
                    {
                        "--live" => live,
                        "--expect-revision" => expectedRevision,
                        _ => evidencePath,
                    };
                    if (previous is not null)
                    {
                        return Refuse(argument + " was given twice.");
                    }

                    switch (argument)
                    {
                        case "--live":
                            live = value;
                            break;
                        case "--expect-revision":
                            expectedRevision = value;
                            break;
                        default:
                            evidencePath = value;
                            break;
                    }

                    break;
                default:
                    return Refuse("Unknown argument: " + argument);
            }
        }

        if (selfTest == (live is not null))
        {
            return Refuse("Choose exactly one of --self-test and --live <base-address>.");
        }

        if (evidencePath is not null && string.IsNullOrWhiteSpace(evidencePath))
        {
            return Refuse("--evidence needs a file name.");
        }

        if (selfTest)
        {
            return expectedRevision is null
                ? new OptionsResult(new ProbeOptions(ProbeMode.SelfTest, null, null, evidencePath), null)
                : Refuse("--expect-revision applies only to --live.");
        }

        if (IsContinuousIntegration(environment))
        {
            return Refuse("--live is a local opt-in and never runs in CI.");
        }

        if (expectedRevision is not null && !RevisionPattern().IsMatch(expectedRevision))
        {
            return Refuse("--expect-revision must be 40 lowercase hexadecimal characters.");
        }

        var address = ValidateBaseAddress(live!);
        return address.Uri is null
            ? Refuse(address.Error!)
            : new OptionsResult(new ProbeOptions(ProbeMode.Live, address.Uri, expectedRevision, evidencePath), null);
    }

    public static bool IsContinuousIntegration(Func<string, string?> environment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        return IsTrue(environment("CI")) || IsTrue(environment("GITHUB_ACTIONS"));

        static bool IsTrue(string? value) => string.Equals(value, "true", StringComparison.OrdinalIgnoreCase);
    }

    public static (Uri? Uri, string? Error) ValidateBaseAddress(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host))
        {
            return (null, "The base address must be an absolute URL.");
        }

        bool secure = uri.Scheme == Uri.UriSchemeHttps;
        if (!secure && !(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback))
        {
            return (null, "The base address must use https (http only for a loopback host).");
        }

        if (uri.UserInfo.Length != 0 || text.Contains('@', StringComparison.Ordinal))
        {
            return (null, "The base address must not carry credentials.");
        }

        if (text.Contains('?', StringComparison.Ordinal) || text.Contains('#', StringComparison.Ordinal))
        {
            return (null, "The base address must not carry a query or fragment.");
        }

        string path = uri.AbsolutePath;
        if (!path.EndsWith('/'))
        {
            path += "/";
        }

        return (new UriBuilder(uri.Scheme, uri.Host, uri.IsDefaultPort ? -1 : uri.Port, path).Uri, null);
    }

    private static OptionsResult Refuse(string error) => new(null, error);

    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex RevisionPattern();
}
