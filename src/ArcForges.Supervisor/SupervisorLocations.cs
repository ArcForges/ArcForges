// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace ArcForges.Supervisor;

/// <summary>
/// The supervisor's view of the node's locations. It computes them as <c>ArcForges.Client.NodeLocations</c> does (the user hash of
/// the LocalRpc endpoints, <c>%APPDATA%\ArcForges\node.json</c>, the data root), without referencing the client library, so the
/// supervisor stays a small executable (15 section 1: at most 4 MB).
/// </summary>
/// <param name="TestMode">The test hooks apply and <c>--test-mode</c> is passed to the node.</param>
/// <param name="NodeExecutable"><c>arcforges.exe</c> beside the supervisor.</param>
/// <param name="DataRoot">The node's data root (the supervisor log goes to <c>logs/supervisor</c>).</param>
/// <param name="InstanceKey">The user hash, with the endpoint override's hash in test mode.</param>
[SupportedOSPlatform("windows")]
internal sealed record SupervisorLocations(bool TestMode, string NodeExecutable, string DataRoot, string InstanceKey)
{
    public const string TestModeOption = "--test-mode";
    public const string EndpointVariable = "ARCFORGES_ENDPOINT";
    public const string ConfigDirectoryVariable = "ARCFORGES_CONFIG_DIR";

    /// <summary>The supervisor's single-instance mutex.</summary>
    public string MutexName => @"Local\ArcForges.Supervisor." + InstanceKey;

    /// <summary>The supervisor log.</summary>
    public string LogFile => Path.Combine(DataRoot, "logs", "supervisor", "supervisor.log");

    public static SupervisorLocations Resolve(bool testMode)
    {
        var configDirectory = testMode && Environment.GetEnvironmentVariable(ConfigDirectoryVariable) is { Length: > 0 } overridden && Path.IsPathFullyQualified(overridden)
            ? overridden
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.DoNotVerify), "ArcForges");
        var dataRoot = ReadDataRoot(Path.Combine(configDirectory, "node.json"))
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify), "ArcForges", "data");
        var sid = WindowsIdentity.GetCurrent().User?.Value ?? throw new InvalidOperationException("The user SID is not readable.");
        var key = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(sid)).AsSpan(0, 16));
        if (testMode && Environment.GetEnvironmentVariable(EndpointVariable) is { Length: > 0 } endpoint)
        {
            key += "-" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(endpoint)).AsSpan(0, 8));
        }

        var executable = Path.Combine(AppContext.BaseDirectory, "arcforges.exe");
        return new SupervisorLocations(testMode, executable, Path.TrimEndingDirectorySeparator(Path.GetFullPath(dataRoot)), key);
    }

    private static string? ReadDataRoot(string configFile)
    {
        try
        {
            if (!File.Exists(configFile))
            {
                return null;
            }

            using var document = JsonDocument.Parse(File.ReadAllBytes(configFile), new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
            return document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("dataRoot", out var value) && value.ValueKind == JsonValueKind.String
                && value.GetString() is { Length: > 0 } root && Path.IsPathFullyQualified(root)
                ? root
                : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }
}
