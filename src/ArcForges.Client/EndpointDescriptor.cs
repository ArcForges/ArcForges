// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArcForges.Client;

/// <summary>
/// <c>&lt;data root&gt;/run/endpoint.json</c> (architecture 02 section 2 step 7): the running node's pipe or socket path, node ID,
/// process ID, process start time and contract version. The node writes it atomically once its listener is up and deletes it
/// when it stops; clients use it only when its process is alive with the same start time (02 section 3 step 2).
/// </summary>
public sealed class EndpointDescriptor
{
    /// <summary>The pipe name (Windows) or the absolute socket path (Linux).</summary>
    public required string Endpoint { get; init; }

    /// <summary><c>named-pipe</c> or <c>unix-socket</c>.</summary>
    public required string Transport { get; init; }

    /// <summary>The node ID as Crockford base32 (lower case).</summary>
    public required string NodeId { get; init; }

    /// <summary>The node's process ID.</summary>
    public required int ProcessId { get; init; }

    /// <summary>The node process's start time (milliseconds since the Unix epoch, UTC).</summary>
    public required long ProcessStartUnixMs { get; init; }

    /// <summary>When the node started serving (RFC 3339, UTC).</summary>
    public required string StartedAt { get; init; }

    /// <summary>The node contract major version (<c>arcforges.node.v1</c> = 1).</summary>
    public required uint ContractMajor { get; init; }

    /// <summary>The node contract minor version.</summary>
    public required uint ContractMinor { get; init; }

    /// <summary>The node's version.</summary>
    public required string Version { get; init; }

    /// <summary>Reads a descriptor, or returns <see langword="null"/> when it is absent or unreadable.</summary>
    public static EndpointDescriptor? TryRead(string path)
    {
        try
        {
            return File.Exists(path)
                ? JsonSerializer.Deserialize(File.ReadAllBytes(path), ClientJsonContext.Default.EndpointDescriptor)
                : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    /// <summary>Writes the descriptor atomically: a temporary file in the same directory, then a rename over the old one.</summary>
    public void Write(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var directory = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(directory, "." + Path.GetFileName(path) + "." + Environment.ProcessId + ".tmp");
        File.WriteAllBytes(temporary, JsonSerializer.SerializeToUtf8Bytes(this, ClientJsonContext.Default.EndpointDescriptor));
        File.Move(temporary, path, overwrite: true);
    }

    /// <summary>True when the descriptor's process is alive and started at the recorded time (so its PID was not reused).</summary>
    public bool ProcessIsAlive()
    {
        try
        {
            using var process = Process.GetProcessById(ProcessId);
            if (process.HasExited)
            {
                return false;
            }

            var started = new DateTimeOffset(process.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds();
            return Math.Abs(started - ProcessStartUnixMs) <= 1000;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception
            or NotSupportedException)
        {
            return false;
        }
    }

    /// <summary>The start time of the current process, in the descriptor's unit.</summary>
    public static long CurrentProcessStartUnixMs()
    {
        using var current = Process.GetCurrentProcess();
        return new DateTimeOffset(current.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds();
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(EndpointDescriptor))]
internal sealed partial class ClientJsonContext : JsonSerializerContext;
