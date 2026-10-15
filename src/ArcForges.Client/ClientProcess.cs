// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Reflection;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Client;

/// <summary>The node contract this build speaks (<c>arcforges.node.v1</c>; contracts README section 7).</summary>
public static class NodeContract
{
    /// <summary>The contract major version: <c>v1</c>.</summary>
    public const uint Major = 1;

    /// <summary>The contract minor version of this build (additions within v1 raise it).</summary>
    public const uint Minor = 0;

    /// <summary>The product version of this build (the assembly's informational version, SemVer).</summary>
    public static string ProductVersion { get; } =
        typeof(NodeContract).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0";
}

/// <summary>Conversions between <see cref="Instant"/> and .NET times.</summary>
public static class ProtoTime
{
    /// <summary>The instant of <paramref name="time"/>.</summary>
    public static Instant ToInstant(DateTimeOffset time)
    {
        var ticks = time.UtcTicks - DateTime.UnixEpoch.Ticks;
        var seconds = Math.DivRem(ticks, TimeSpan.TicksPerSecond, out var remainder);
        if (remainder < 0)
        {
            seconds--;
            remainder += TimeSpan.TicksPerSecond;
        }

        return new Instant { UnixSeconds = seconds, Nanos = (uint)(remainder * 100) };
    }

    /// <summary>The time of <paramref name="instant"/>, or <see langword="null"/> when it is absent.</summary>
    public static DateTimeOffset? ToDateTimeOffset(Instant? instant) => instant is null || (!instant.HasUnixSeconds && !instant.HasNanos)
        ? null
        : new DateTimeOffset(DateTime.UnixEpoch.Ticks + (instant.UnixSeconds * TimeSpan.TicksPerSecond) + (instant.Nanos / 100), TimeSpan.Zero);
}

/// <summary>What a client reports about itself in its hello (architecture 11 section 1; node.proto <c>ClientHello</c>).</summary>
public static class ClientProcess
{
    /// <summary>
    /// Environment variables whose presence marks a CI job (reported in <c>ci_markers</c>; auto-start is refused there,
    /// experience/cli.md section 5).
    /// </summary>
    public static readonly IReadOnlyList<string> CiVariables =
    [
        "CI", "GITHUB_ACTIONS", "TF_BUILD", "GITLAB_CI", "BUILDKITE", "JENKINS_URL", "TEAMCITY_VERSION", "CIRCLECI", "APPVEYOR",
        "TRAVIS", "BITBUCKET_BUILD_NUMBER", "CODEBUILD_BUILD_ID", "DRONE",
    ];

    /// <summary>The CI markers present in this process's environment (a value of <c>false</c> or <c>0</c> is not a marker).</summary>
    public static IReadOnlyList<string> CiMarkers() => [.. CiVariables.Where(name =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
        && !string.Equals(value, "false", StringComparison.OrdinalIgnoreCase) && value != "0")];

    /// <summary>True when standard input is an interactive terminal (console or pty), as reported in the hello.</summary>
    public static bool InteractiveTerminal => !Console.IsInputRedirected;

    /// <summary>This process's identity (pid and start time) for <c>ClientHello.process</c>.</summary>
    public static ProcessIdentity Current()
    {
        using var process = Process.GetCurrentProcess();
        return new ProcessIdentity
        {
            Pid = (uint)process.Id,
            StartTime = ProtoTime.ToInstant(new DateTimeOffset(process.StartTime.ToUniversalTime())),
        };
    }

    /// <summary>The client hello of this process.</summary>
    public static ClientHello Hello(ClientKind kind) => new()
    {
        ClientKind = kind,
        ClientVersion = NodeContract.ProductVersion,
        ContractMajor = NodeContract.Major,
        ContractMinor = NodeContract.Minor,
        Process = Current(),
        InteractiveTerminal = InteractiveTerminal,
        CiMarkers = { CiMarkers() },
    };
}
