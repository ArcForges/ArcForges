// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArcForges.Node.Platform;

/// <summary>
/// The node heartbeat <c>run/node-heartbeat</c>, schema 1 (02 section 2, 06 section 5): renewed every second from the node's enforcement
/// loop with the node instance's ID and an increasing sequence number. The Windows supervisor measures elapsed time with its own
/// monotonic clock and checks whether <c>(instance, seq)</c> changed. The wall-clock time is informational.
/// </summary>
public sealed class NodeHeartbeat
{
    /// <summary>The format version.</summary>
    public int Schema { get; set; } = 1;

    /// <summary>The node instance (a new random ID per node process).</summary>
    public string Instance { get; set; } = string.Empty;

    /// <summary>The renewal number within the instance, starting at 1.</summary>
    public long Seq { get; set; }

    /// <summary>The node's process ID.</summary>
    public int Pid { get; set; }

    /// <summary>When it was written (RFC 3339 UTC; informational).</summary>
    public string At { get; set; } = string.Empty;

    /// <summary>The identity of one renewal.</summary>
    public string Token => Instance + ":" + Seq.ToString(CultureInfo.InvariantCulture);

    /// <summary>The heartbeat file of a Node data root.</summary>
    public static string FilePath(string dataRoot) => Path.Combine(dataRoot, "run", "node-heartbeat");

    /// <summary>Writes the heartbeat atomically (a temporary file renamed over the old one).</summary>
    public void Write(string path)
    {
        var temporary = path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(this, HelperJsonContext.Default.NodeHeartbeat));
        File.Move(temporary, path, overwrite: true);
    }

    /// <summary>Reads the heartbeat, or <see langword="null"/> when it is absent, being replaced, or malformed.</summary>
    public static NodeHeartbeat? TryRead(string path) =>
        HelperFiles.TryRead(path, json => JsonSerializer.Deserialize(json, HelperJsonContext.Default.NodeHeartbeat));
}

/// <summary>Timestamp formatting and tolerant reads for the Node heartbeat.</summary>
public static class HelperFiles
{
    /// <summary>RFC 3339 UTC text with milliseconds.</summary>
    public static string Now(TimeProvider? clock = null) =>
        (clock ?? TimeProvider.System).GetUtcNow().UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    /// <summary>Reads and parses <paramref name="path"/>; <see langword="null"/> when it is absent, locked by a rename, or malformed.</summary>
    public static T? TryRead<T>(string path, Func<string, T?> parse)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(parse);
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream, Encoding.UTF8);
            var text = reader.ReadToEnd();
            return text.Length == 0 ? null : parse(text);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(NodeHeartbeat))]
internal sealed partial class HelperJsonContext : JsonSerializerContext;
