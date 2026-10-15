// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.LocalRpc;

namespace ArcForges.Client;

/// <summary>
/// Where the node's configuration, data root, endpoint and per-user named objects are (architecture 02 sections 2-4; AD-0012
/// section 1). The node and every client compute them the same way, so nothing is discovered.
/// </summary>
/// <remarks>
/// Test hooks (02 section 4: <c>ARCFORGES_*</c> environment variables) are honoured only when the caller runs in test mode
/// (<c>--test-mode</c>): <see cref="EndpointVariable"/> overrides the endpoint and <see cref="ConfigDirectoryVariable"/> the
/// directory of <c>node.json</c>. Each test node therefore gets its own configuration, data root and endpoint, and its
/// single-instance objects are named after its endpoint (<see cref="InstanceKey"/>), so a test never meets the user's node.
/// </remarks>
public static class NodeLocations
{
    /// <summary>The global option that enables the test hooks.</summary>
    public const string TestModeOption = "--test-mode";

    /// <summary>Endpoint override (testing only): a pipe name on Windows, an absolute socket path on Linux.</summary>
    public const string EndpointVariable = "ARCFORGES_ENDPOINT";

    /// <summary>The directory that holds <c>node.json</c> (testing only).</summary>
    public const string ConfigDirectoryVariable = "ARCFORGES_CONFIG_DIR";

    /// <summary>The systemd user unit that auto-start starts on Linux (testing only; default <see cref="DefaultNodeUnit"/>).</summary>
    public const string NodeUnitVariable = "ARCFORGES_NODE_UNIT";

    /// <summary>Forces the Linux auto-start method (testing only): <c>setsid</c> or <c>systemd</c>.</summary>
    public const string AutostartVariable = "ARCFORGES_AUTOSTART";

    /// <summary>The node's systemd user unit (13 section 3.4).</summary>
    public const string DefaultNodeUnit = "arcforges-node.service";

    /// <summary>The service name of the node's well-known LocalRpc endpoint (02 section 2 step 7).</summary>
    public const string ServiceName = "node";

    /// <summary>The configuration file name.</summary>
    public const string ConfigFileName = "node.json";

    /// <summary>
    /// The configuration directory: <c>%APPDATA%\ArcForges</c> on Windows, <c>~/.config/arcforges</c> on Linux (02 section 2
    /// step 1), or <see cref="ConfigDirectoryVariable"/> in test mode.
    /// </summary>
    public static string ConfigDirectory(bool testMode)
    {
        if (testMode && TestValue(ConfigDirectoryVariable) is { } overridden)
        {
            return RequireAbsolute(overridden, ConfigDirectoryVariable);
        }

        return OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.DoNotVerify), "ArcForges")
            : Path.Combine(Home(), ".config", "arcforges");
    }

    /// <summary>The configuration file, <c>node.json</c>.</summary>
    public static string ConfigFile(bool testMode) => Path.Combine(ConfigDirectory(testMode), ConfigFileName);

    /// <summary>
    /// The default data root (AD-0012 section 1): <c>%LOCALAPPDATA%\ArcForges\data</c> on Windows,
    /// <c>~/.local/share/arcforges/data</c> on Linux.
    /// </summary>
    public static string DefaultDataRoot() => OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify), "ArcForges", "data")
        : Path.Combine(Home(), ".local", "share", "arcforges", "data");

    /// <summary>
    /// The data root: <c>dataRoot</c> of <c>node.json</c> when it names an absolute path, otherwise the default. A missing or
    /// unreadable file means the default; the node reports a malformed one when it starts.
    /// </summary>
    public static string ResolveDataRoot(bool testMode)
    {
        var configured = ReadConfiguredDataRoot(ConfigFile(testMode));
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(configured ?? DefaultDataRoot()));
    }

    /// <summary><c>&lt;data root&gt;/run</c>: the endpoint descriptor and, without <c>XDG_RUNTIME_DIR</c>, the socket.</summary>
    public static string RunDirectory(string dataRoot) => Path.Combine(dataRoot, "run");

    /// <summary><c>&lt;data root&gt;/run/endpoint.json</c> (02 section 2 step 7).</summary>
    public static string EndpointDescriptorFile(string dataRoot) => Path.Combine(RunDirectory(dataRoot), "endpoint.json");

    /// <summary>
    /// The node's endpoint: <see cref="EndpointVariable"/> in test mode, otherwise the well-known per-user endpoint: the pipe
    /// <c>\\.\pipe\arcforges-&lt;user hash&gt;-node</c>, or <c>$XDG_RUNTIME_DIR/arcforges/node.sock</c> (else
    /// <c>&lt;data root&gt;/run/node.sock</c>).
    /// </summary>
    public static LocalRpcEndpoint Endpoint(bool testMode, string dataRoot)
    {
        if (testMode && TestValue(EndpointVariable) is { } overridden)
        {
            return OperatingSystem.IsWindows() ? LocalRpcEndpoint.NamedPipe(overridden) : LocalRpcEndpoint.UnixDomainSocket(overridden);
        }

        return LocalRpcEndpoint.ForCurrentUserService(ServiceName, RunDirectory(dataRoot));
    }

    /// <summary>The endpoint override in effect (test mode only), or <see langword="null"/>.</summary>
    public static string? EndpointOverride(bool testMode) => testMode ? TestValue(EndpointVariable) : null;

    /// <summary>The systemd unit that auto-start starts.</summary>
    public static string NodeUnit(bool testMode) => (testMode ? TestValue(NodeUnitVariable) : null) ?? DefaultNodeUnit;

    /// <summary>The forced Linux auto-start method in test mode (<c>setsid</c> or <c>systemd</c>), or <see langword="null"/>.</summary>
    public static string? ForcedAutostart(bool testMode) => testMode ? TestValue(AutostartVariable) : null;

    /// <summary>
    /// The key of the user's node instance: the user hash of the LocalRpc endpoints (SHA-256 of the user SID or uid, 32 hex
    /// digits). A test-mode node with an endpoint override appends a hash of that endpoint, so test nodes never share the
    /// user's single-instance objects or each other's.
    /// </summary>
    public static string InstanceKey(bool testMode) => InstanceKeyFor(EndpointOverride(testMode));

    /// <summary>The instance key of a node on <paramref name="endpointOverride"/> (the user's own node when it is null).</summary>
    public static string InstanceKeyFor(string? endpointOverride)
    {
        var user = LocalRpcEndpoint.CurrentUserHash;
        return endpointOverride is { } endpoint
            ? user + "-" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(endpoint)).AsSpan(0, 8))
            : user;
    }

    /// <summary>The Windows single-instance mutex <c>Local\ArcForges.Node.&lt;key&gt;</c> (02 section 2 step 2).</summary>
    public static string NodeMutexName(string instanceKey) => @"Local\ArcForges.Node." + instanceKey;

    /// <summary>The Windows readiness event <c>Local\ArcForges.Node.&lt;key&gt;.Ready</c> (02 section 2 step 9).</summary>
    public static string NodeReadyEventName(string instanceKey) => @"Local\ArcForges.Node." + instanceKey + ".Ready";

    /// <summary>The Linux single-instance lock file <c>&lt;data root&gt;/node.lock</c> (02 section 2 step 2).</summary>
    public static string NodeLockFile(string dataRoot) => Path.Combine(dataRoot, "node.lock");

    /// <summary>Reads <c>dataRoot</c> from a <c>node.json</c>, or <see langword="null"/> when absent, unreadable or not absolute.</summary>
    internal static string? ReadConfiguredDataRoot(string configFile)
    {
        try
        {
            if (!File.Exists(configFile))
            {
                return null;
            }

            var reader = new Utf8JsonReader(File.ReadAllBytes(configFile), new JsonReaderOptions { CommentHandling = JsonCommentHandling.Skip });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return null;
            }

            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                var name = reader.GetString();
                if (!reader.Read())
                {
                    return null;
                }

                if (name == "dataRoot" && reader.TokenType == JsonTokenType.String)
                {
                    var value = reader.GetString();
                    return !string.IsNullOrWhiteSpace(value) && Path.IsPathFullyQualified(value) ? value : null;
                }

                reader.Skip();
            }

            return null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    private static string? TestValue(string variable) => Environment.GetEnvironmentVariable(variable) is { Length: > 0 } value ? value : null;

    private static string RequireAbsolute(string path, string variable) => Path.IsPathFullyQualified(path)
        ? Path.TrimEndingDirectorySeparator(Path.GetFullPath(path))
        : throw new InvalidOperationException($"{variable} must be an absolute path.");

    private static string Home()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify);
        return string.IsNullOrEmpty(home) ? Environment.GetEnvironmentVariable("HOME") ?? "/" : home;
    }
}
