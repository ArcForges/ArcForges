// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Api;

/// <summary>
/// The executables that may present each client kind (11 section 1: the connection's client kind is verified against the peer). The CLI,
/// the MCP adapter and the hook handler are roles of the node's own multi-role executable (<c>arcforges</c>, AD-0003); the Desktop is
/// <c>arcforges-desktop</c> beside it. A peer's executable (LocalRpc resolves it with the peer, before HTTP/2: <c>LocalRpcPeer.ExecutablePath</c>)
/// verifies a kind when it is one of these files, by path or by content (the SHA-256 of the file, so a version directory reached through the
/// <c>current</c> junction or a symbolic link still matches). This is a guardrail: a same-user process can run these executables itself, or
/// copy them (11 section 1, documented bypasses).
/// </summary>
public sealed class ClientImages
{
    /// <summary>
    /// The test hook (honoured only with <c>--test-mode</c>): further executables, separated by the platform's path separator, that verify
    /// every client kind, so a closed-loop test's own process can act as the Desktop.
    /// </summary>
    public const string TestVariable = "ARCFORGES_TEST_CLIENT_IMAGES";

    private readonly string[] _node;
    private readonly string[] _desktop;
    private readonly ConcurrentDictionary<(string Path, long Length, DateTime Written), byte[]?> _digests = new();

    /// <summary>Creates the set: <paramref name="node"/> verifies the CLI, MCP adapter and hook kinds; <paramref name="desktop"/> the Desktop.</summary>
    public ClientImages(IEnumerable<string> node, IEnumerable<string> desktop)
    {
        ArgumentNullException.ThrowIfNull(node);
        ArgumentNullException.ThrowIfNull(desktop);
        _node = [.. node.Where(path => path.Length > 0).Select(Path.GetFullPath)];
        _desktop = [.. desktop.Where(path => path.Length > 0).Select(Path.GetFullPath)];
    }

    /// <summary>
    /// True when the test hook may apply (review round 1): test mode, and the node runs on an isolated test instance, so that the endpoint,
    /// the configuration file and the data root are all overridden to values other than the user's real ones. On the real data root or
    /// endpoint the hook is ignored even in test mode.
    /// </summary>
    public static bool TestHookApplies(bool testMode, string endpointAddress, string configPath, string dataRoot)
    {
        ArgumentNullException.ThrowIfNull(endpointAddress);
        ArgumentNullException.ThrowIfNull(configPath);
        ArgumentNullException.ThrowIfNull(dataRoot);
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        static string Full(string path) => Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var defaultRoot = NodeLocations.DefaultDataRoot();
        return testMode
            && !string.Equals(endpointAddress, NodeLocations.Endpoint(testMode: false, defaultRoot).Address, comparison)
            && !string.Equals(Full(configPath), Full(NodeLocations.ConfigFile(testMode: false)), comparison)
            && !string.Equals(Full(dataRoot), Full(defaultRoot), comparison);
    }

    /// <summary>
    /// The node's own executable and the Desktop beside it, plus the test hook's executables when <paramref name="testMode"/> is set (the host
    /// sets it only where <see cref="TestHookApplies"/>).
    /// </summary>
    public static ClientImages ForNode(bool testMode)
    {
        var self = Environment.ProcessPath;
        List<string> node = self is null ? [] : [self];
        List<string> desktop = self is null || Path.GetDirectoryName(self) is not { } directory
            ? []
            : [Path.Combine(directory, OperatingSystem.IsWindows() ? "arcforges-desktop.exe" : "arcforges-desktop")];
        if (testMode && Environment.GetEnvironmentVariable(TestVariable) is { Length: > 0 } extra)
        {
            var paths = extra.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            node.AddRange(paths);
            desktop.AddRange(paths);
        }

        return new ClientImages(node, desktop);
    }

    /// <summary>True when <paramref name="executable"/> may present <paramref name="kind"/>.</summary>
    public bool Verifies(ClientKind kind, string? executable)
    {
        if (string.IsNullOrEmpty(executable))
        {
            return false;
        }

        var candidates = kind switch
        {
            ClientKind.Desktop => _desktop,
            ClientKind.Cli or ClientKind.McpAdapter or ClientKind.Hook or ClientKind.Probe => _node,
            _ => [],
        };
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var full = Path.GetFullPath(executable);
        if (candidates.Any(candidate => string.Equals(candidate, full, comparison)))
        {
            return true;
        }

        var digest = Digest(full);
        return digest is not null && candidates.Any(candidate => Digest(candidate) is { } expected && expected.AsSpan().SequenceEqual(digest));
    }

    private byte[]? Digest(string path)
    {
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists)
            {
                return null;
            }

            return _digests.GetOrAdd((path, file.Length, file.LastWriteTimeUtc), _ =>
            {
                try
                {
                    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    return SHA256.HashData(stream);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    return null;
                }
            });
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }
}
