// SPDX-License-Identifier: AGPL-3.0-only

using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;
using ArcForges.Node.Platform.Windows.Mxc;
using ArcForges.RunSupervisor.Protocol;

namespace ArcForges.RunSupervisor;

[SupportedOSPlatform("windows")]
internal static class WindowsRunPolicy
{
    private const int MaximumBytes = 256 * 1024;
    private static readonly string[] PrivateNames = ["home", "config", "cache", "tmp", "work", "data"];

    internal static IEnumerable<string> PrivateDirectories(string root) => PrivateNames.Select(name => Path.Combine(root, name));

    internal static string Write(RunLaunchSpec spec, string path, Action<WindowsMxcPathLease.PrivateFileIdentity> capture)
    {
        if (spec.Argv.Length is 0 || !Path.IsPathFullyQualified(spec.Argv[0]) || !Path.IsPathFullyQualified(spec.WorkingDirectory)
            || spec.Argv.Any(arg => arg.Contains('\0')))
        {
            throw new InvalidDataException("Windows MXC requires an explicit executable, working directory and NUL-free arguments.");
        }

        var root = Path.GetFullPath(spec.PrivateRoot);
        var control = Path.GetFullPath(spec.ControlDirectory);
        var writable = PrivateDirectories(root).ToList();
        var readable = new List<string>();
        foreach (var mount in spec.Mounts)
        {
            if (!Path.IsPathFullyQualified(mount.HostPath) || !Path.IsPathFullyQualified(mount.SandboxPath))
            {
                throw new InvalidDataException("Windows MXC grants require fully qualified paths.");
            }

            var source = Path.GetFullPath(mount.HostPath);
            if (!StringComparer.OrdinalIgnoreCase.Equals(source, Path.GetFullPath(mount.SandboxPath)))
            {
                throw new InvalidDataException("The official Windows MXC profile does not support grant path rewrites.");
            }

            (mount.Writable ? writable : readable).Add(source);
        }

        if (writable.Concat(readable).Any(path => Under(path, control) || Under(control, path)))
        {
            throw new InvalidDataException("A Windows MXC grant overlaps the private Run control path.");
        }

        string commandLine;
        try
        {
            commandLine = WindowsCommandLine.Build(spec.Argv);
        }
        catch (CommandRefusedException)
        {
            throw new RunNativeException("windows_mxc_policy", "payload_command_does_not_fit_windows_command_line");
        }

        var bytes = new ArrayBufferWriter<byte>();
        try
        {
            using var json = new Utf8JsonWriter(bytes, new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
            json.WriteStartObject();
            json.WriteString("version", "1.0.0");
            json.WriteString("containment", "processcontainer");
            json.WriteString("containerId", "afv2-win-" + spec.RunId);
            json.WriteStartObject("process");
            json.WriteString("commandLine", commandLine);
            json.WriteString("cwd", spec.WorkingDirectory);
            Strings(json, "env", PayloadEnvironment(spec, root));
            json.WriteBoolean("inheritDefaultEnv", false);
            json.WriteNumber("timeout", 0);
            json.WriteEndObject();

            json.WriteStartObject("filesystem");
            Strings(json, "readwritePaths", writable.Distinct(StringComparer.OrdinalIgnoreCase));
            Strings(json, "readonlyPaths", readable.Distinct(StringComparer.OrdinalIgnoreCase));
            Strings(json, "deniedPaths", [control]);
            json.WriteEndObject();

            json.WriteStartObject("fallback");
            json.WriteBoolean("allowDaclMutation", false);
            json.WriteEndObject();
            WriteNetwork(json, spec.Network);

            // The admitted terminal profile needs Win32k initialization while retaining native UI restrictions.
            json.WriteStartObject("ui");
            json.WriteBoolean("disable", false);
            json.WriteString("clipboard", "none");
            json.WriteBoolean("injection", false);
            json.WriteEndObject();
            json.WriteStartObject("processContainer");
            json.WriteBoolean("leastPrivilege", false);
            json.WriteEndObject();
            json.WriteStartObject("telemetry");
            json.WriteBoolean("enabled", false);
            json.WriteEndObject();
            json.WriteStartObject("lifecycle");
            json.WriteBoolean("destroyOnExit", true);
            json.WriteBoolean("preservePolicy", false);
            json.WriteEndObject();
            json.WriteEndObject();
            json.Flush();

            if (bytes.WrittenCount is 0 or > MaximumBytes)
            {
                throw new InvalidDataException("The Windows MXC policy exceeds the bounded official request size.");
            }

            // Only this file is allowed to contain the native request. The caller already holds its
            // owner-restricted ancestry, and rolls back only the exact identity reported here.
            using var output = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite,
                FileShare.None, 4096, FileOptions.WriteThrough);
            capture(WindowsMxcPathLease.CaptureCreatedPrivateFile(output.SafeFileHandle));
            output.Write(bytes.WrittenSpan);
            output.Flush(flushToDisk: true);
            return PolicyBinding(spec, bytes.WrittenSpan);
        }
        finally
        {
            bytes.Clear();
        }
    }

    internal static void RequireBinding(RunLaunchSpec spec, WindowsMxcPathLease file, string expected)
    {
        var bytes = file.Read(MaximumBytes);
        try
        {
            if (PolicyBinding(spec, bytes) != expected)
            {
                throw new InvalidDataException("The admitted protected Windows MXC policy changed.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static string PolicyBinding(RunLaunchSpec spec, ReadOnlySpan<byte> bytes)
    {
        using var proof = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, spec.ControlKey);
        proof.AppendData("arcforges-windows-mxc-file-policy-v1"u8);
        proof.AppendData(bytes);
        return Convert.ToHexStringLower(proof.GetHashAndReset());
    }

    private static IEnumerable<string> PayloadEnvironment(RunLaunchSpec spec, string root)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var field in spec.Environment)
        {
            if (field.Name.Length == 0 || field.Name.Contains('=') || field.Name.Contains('\0') || field.Value.Contains('\0')
                || !values.TryAdd(field.Name, field.Value))
            {
                throw new InvalidDataException("The Windows MXC environment contains a duplicate or invalid key or value.");
            }
        }

        var system = Environment.SystemDirectory;
        var windows = Path.GetDirectoryName(system) ?? throw new IOException("The Windows system directory is unavailable.");
        values.TryAdd("SystemRoot", windows);
        values.TryAdd("WINDIR", windows);
        values.TryAdd("PATH", system);
        values.TryAdd("HOME", Path.Combine(root, "home"));
        values.TryAdd("USERPROFILE", Path.Combine(root, "home"));
        values.TryAdd("APPDATA", Path.Combine(root, "config"));
        values.TryAdd("LOCALAPPDATA", Path.Combine(root, "cache"));
        values.TryAdd("TEMP", Path.Combine(root, "tmp"));
        values.TryAdd("TMP", Path.Combine(root, "tmp"));
        values.TryAdd("XDG_CONFIG_HOME", Path.Combine(root, "config"));
        values.TryAdd("XDG_CACHE_HOME", Path.Combine(root, "cache"));
        values.TryAdd("XDG_DATA_HOME", Path.Combine(root, "data"));
        return values.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).Select(pair => pair.Key + "=" + pair.Value);
    }

    private static void WriteNetwork(Utf8JsonWriter json, RunNetwork network)
    {
        if (network.EgressAllowed || network.IngressAllowed || network.HostLoopback)
        {
            throw new InvalidDataException("The Windows MXC profile admits default-denied network policy.");
        }

        json.WriteStartObject("network");
        json.WriteStartObject("egress");
        json.WriteString("default", "deny");
        if (network.Destinations.Length > 0)
        {
            json.WriteStartArray("allow");
            foreach (var rule in network.Destinations)
            {
                WriteDestination(json, rule);
            }

            json.WriteEndArray();
        }

        json.WriteEndObject();
        json.WriteStartObject("ingress");
        json.WriteString("default", "deny");
        json.WriteString("hostLoopback", "deny");
        json.WriteEndObject();
        json.WriteEndObject();
    }

    private static void WriteDestination(Utf8JsonWriter json, string rule)
    {
        var separator = rule.LastIndexOf(':');
        if (separator <= 6 || !(rule.StartsWith("tcp://", StringComparison.Ordinal) || rule.StartsWith("udp://", StringComparison.Ordinal))
            || !ushort.TryParse(rule.AsSpan(separator + 1), NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port == 0)
        {
            throw new InvalidDataException("The Windows MXC destination must have its admitted literal TCP or UDP form.");
        }

        var host = rule.AsSpan(6, separator - 6);
        var bracketed = host[0] == '[' && host[^1] == ']';
        if (bracketed) host = host[1..^1];
        if (host.IsEmpty) throw new InvalidDataException("The Windows MXC destination is empty.");
        var slash = host.IndexOf('/');
        var literal = slash < 0 ? host : host[..slash];
        if (literal.Contains('%') || !IPAddress.TryParse(literal, out var address)
            || bracketed != (address.AddressFamily == AddressFamily.InterNetworkV6))
        {
            throw new InvalidDataException("The Windows MXC destination is not a qualified literal address.");
        }

        var maximum = bracketed ? 128 : 32;
        var prefix = maximum;
        if (slash >= 0 && (!int.TryParse(host[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out prefix) || prefix > maximum))
        {
            throw new InvalidDataException("The Windows MXC destination prefix is outside its address family.");
        }

        json.WriteStartObject();
        json.WriteStartArray("to");
        json.WriteStartObject();
        json.WriteString("cidr", string.Create(CultureInfo.InvariantCulture, $"{address}/{prefix}"));
        json.WriteEndObject();
        json.WriteEndArray();
        json.WriteStartArray("ports");
        json.WriteStartObject();
        json.WriteString("protocol", rule[..3]);
        json.WriteNumber("port", port);
        json.WriteEndObject();
        json.WriteEndArray();
        json.WriteEndObject();
    }

    private static bool Under(string ancestor, string path)
    {
        var relative = Path.GetRelativePath(ancestor, path);
        return relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            && !Path.IsPathRooted(relative);
    }

    private static void Strings(Utf8JsonWriter json, string name, IEnumerable<string> values)
    {
        json.WriteStartArray(name);
        foreach (var value in values) json.WriteStringValue(value);
        json.WriteEndArray();
    }
}
