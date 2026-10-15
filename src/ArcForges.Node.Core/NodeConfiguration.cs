// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using System.Text.Json.Serialization;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core;

/// <summary>
/// <c>node.json</c> (architecture 02 section 4): the data root, the log level and the telemetry consent, with the settings revision
/// that <c>UpdateNodeSettings</c> checks against <c>meta.expected_rev</c>. Behavioural policy lives in the store, not here.
/// </summary>
public sealed class NodeConfigurationFile
{
    /// <summary>The data root, absolute; absent means the default (AD-0012 section 1). Read-only through the API.</summary>
    public string? DataRoot { get; set; }

    /// <summary><c>error</c>, <c>warning</c>, <c>info</c> (default) or <c>debug</c>.</summary>
    public string? LogLevel { get; set; }

    /// <summary>Anonymous aggregate counters opt-in (R-OPS-003; default off).</summary>
    public bool? TelemetryOptIn { get; set; }

    /// <summary>The settings revision; every accepted update increments it.</summary>
    public long Revision { get; set; }
}

/// <summary><c>node.json</c> is malformed; the node does not start with a configuration it cannot read.</summary>
public sealed class NodeConfigurationException : Exception
{
    /// <summary>Creates the exception.</summary>
    public NodeConfigurationException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception.</summary>
    public NodeConfigurationException()
    {
    }

    /// <summary>Creates the exception.</summary>
    public NodeConfigurationException(string message)
        : base(message)
    {
    }
}

/// <summary>Reads and writes <c>node.json</c>.</summary>
public static class NodeConfiguration
{
    /// <summary>The proto log level of a <c>node.json</c> text value (unknown text is <see cref="LogLevel.Unspecified"/>).</summary>
    public static LogLevel ParseLogLevel(string? text) => text?.ToUpperInvariant() switch
    {
        "ERROR" => LogLevel.Error,
        "WARNING" => LogLevel.Warning,
        "INFO" or null => LogLevel.Info,
        "DEBUG" => LogLevel.Debug,
        _ => LogLevel.Unspecified,
    };

    /// <summary>The <c>node.json</c> text of a proto log level.</summary>
    public static string FormatLogLevel(LogLevel level) => level switch
    {
        LogLevel.Error => "error",
        LogLevel.Warning => "warning",
        LogLevel.Debug => "debug",
        _ => "info",
    };

    /// <summary>Reads <c>node.json</c>; a missing file is the defaults (revision 0).</summary>
    /// <exception cref="NodeConfigurationException">The file exists but is not valid configuration.</exception>
    public static NodeConfigurationFile Read(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!File.Exists(path))
        {
            return new NodeConfigurationFile();
        }

        NodeConfigurationFile? file;
        try
        {
            file = JsonSerializer.Deserialize(File.ReadAllBytes(path), NodeCoreJsonContext.Default.NodeConfigurationFile);
        }
        catch (JsonException exception)
        {
            throw new NodeConfigurationException($"{path} is not valid JSON configuration: {exception.Message}", exception);
        }

        if (file is null)
        {
            throw new NodeConfigurationException($"{path} is empty.");
        }

        if (file.DataRoot is { } root && !Path.IsPathFullyQualified(root))
        {
            throw new NodeConfigurationException($"{path}: dataRoot must be an absolute path.");
        }

        if (ParseLogLevel(file.LogLevel) == LogLevel.Unspecified)
        {
            throw new NodeConfigurationException($"{path}: logLevel must be error, warning, info or debug.");
        }

        if (file.Revision < 0)
        {
            throw new NodeConfigurationException($"{path}: revision must not be negative.");
        }

        return file;
    }

    /// <summary>Writes <c>node.json</c> atomically (a temporary file in the same directory, then a rename).</summary>
    public static void Write(string path, NodeConfigurationFile file)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(file);
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(directory, "." + Path.GetFileName(path) + "." + Environment.ProcessId + ".tmp");
        File.WriteAllBytes(temporary, JsonSerializer.SerializeToUtf8Bytes(file, NodeCoreJsonContext.Default.NodeConfigurationFile));
        File.Move(temporary, path, overwrite: true);
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true)]
[JsonSerializable(typeof(NodeConfigurationFile))]
internal sealed partial class NodeCoreJsonContext : JsonSerializerContext;
