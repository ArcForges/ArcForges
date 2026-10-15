// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core;

/// <summary>
/// The node.json settings the node owns (architecture 02 section 4; <c>NodeService.GetNodeSettings</c> / <c>UpdateNodeSettings</c>):
/// the data root (read-only here; relocation is <c>StorageService.UpdateRoot</c>), the log level and the telemetry consent, with the
/// settings revision. Updates run in the command processor, so they are serialized with every other mutation, and a new log level
/// applies at once (no restart).
/// </summary>
public sealed class NodeSettingsManager
{
    private readonly string _configPath;
    private readonly string _dataRoot;
    private readonly NodeLog _log;

    /// <summary>Creates the manager for <paramref name="configPath"/>.</summary>
    public NodeSettingsManager(string configPath, string dataRoot, NodeLog log)
    {
        _configPath = configPath;
        _dataRoot = dataRoot;
        _log = log;
    }

    /// <summary>The configuration file.</summary>
    public string ConfigPath => _configPath;

    /// <summary>The settings as <c>node.json</c> holds them now.</summary>
    public NodeSettings Current() => ToSettings(NodeConfiguration.Read(_configPath));

    /// <summary>
    /// Applies an update: <paramref name="logLevel"/> (<see cref="LogLevel.Unspecified"/> = unchanged) and
    /// <paramref name="telemetryOptIn"/> (<see langword="null"/> = unchanged). With <paramref name="expectedRevision"/>, a different
    /// current revision is <c>CONFLICT/revision_conflict</c>. Returns the new settings and whether a restart is needed (never: both
    /// settings apply at once).
    /// </summary>
    public (NodeSettings? Settings, bool RestartRequired, ArcError? Error) Update(long? expectedRevision, LogLevel logLevel, bool? telemetryOptIn)
    {
        var file = NodeConfiguration.Read(_configPath);
        if (expectedRevision is { } expected && expected != file.Revision)
        {
            return (null, false, NodeErrors.RevisionConflict(expected, file.Revision));
        }

        if (logLevel != LogLevel.Unspecified)
        {
            file.LogLevel = NodeConfiguration.FormatLogLevel(logLevel);
        }

        if (telemetryOptIn is { } optIn)
        {
            file.TelemetryOptIn = optIn;
        }

        file.Revision++;
        NodeConfiguration.Write(_configPath, file);
        _log.MinimumLevel = NodeConfiguration.ParseLogLevel(file.LogLevel);
        _log.Info("node.settings.updated", new LogField("revision", file.Revision), new LogField("logLevel", file.LogLevel ?? "info"),
            new LogField("telemetryOptIn", file.TelemetryOptIn ?? false));
        return (ToSettings(file), false, null);
    }

    private NodeSettings ToSettings(NodeConfigurationFile file) => new()
    {
        DataRoot = _dataRoot,
        LogLevel = NodeConfiguration.ParseLogLevel(file.LogLevel),
        TelemetryOptIn = file.TelemetryOptIn ?? false,
        ConfigPath = _configPath,
        Revision = new Revision { Value = file.Revision },
    };
}

/// <summary>The node's display name (<c>node_setting</c> <c>node.name</c>; default: the machine name).</summary>
public static class NodeName
{
    /// <summary>The <c>node_setting</c> row.</summary>
    public const string Setting = "node.name";

    /// <summary>The longest name (node.proto: 1..64 printable characters).</summary>
    public const int MaxLength = 64;

    /// <summary>The name, or the machine name when none was set.</summary>
    public static string Get(StoreReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        return reader.Scalar("SELECT value_json FROM node_setting WHERE name = $name;", ("$name", Setting)) is string json
            && JsonSerializer.Deserialize(json, NodeCoreNameJsonContext.Default.String) is { Length: > 0 } name
            ? name
            : Default();
    }

    /// <summary>Sets the name in the command's transaction.</summary>
    public static void Set(StoreTransaction transaction, string name)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        transaction.Execute(
            """
            INSERT INTO node_setting (name, value_json, updated_at, rev) VALUES ($name, $value, $now, 0)
            ON CONFLICT (name) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at, rev = rev + 1;
            """,
            ("$name", Setting),
            ("$value", JsonSerializer.Serialize(name, NodeCoreNameJsonContext.Default.String)),
            ("$now", transaction.NowMicroseconds));
    }

    /// <summary>True when <paramref name="name"/> is 1 to 64 printable characters (no control characters, not all white space).</summary>
    public static bool IsValid(string? name) =>
        name is { Length: > 0 and <= MaxLength } && !string.IsNullOrWhiteSpace(name) && !name.Any(char.IsControl);

    private static string Default()
    {
        var machine = Environment.MachineName;
        return machine.Length > MaxLength ? machine[..MaxLength] : machine.ToLower(CultureInfo.InvariantCulture);
    }
}

[System.Text.Json.Serialization.JsonSerializable(typeof(string))]
internal sealed partial class NodeCoreNameJsonContext : System.Text.Json.Serialization.JsonSerializerContext;
