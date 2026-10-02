// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;

namespace ArcForges.LocalRpc;

/// <summary>The only two private-helper stream transports. No TCP, loopback or discovery transport exists.</summary>
public enum LocalRpcTransport
{
    /// <summary>No transport; never a valid endpoint.</summary>
    None = 0,

    /// <summary>A Windows Named Pipe restricted to the current user.</summary>
    NamedPipe = 1,

    /// <summary>A Unix domain socket in an owner-only directory.</summary>
    UnixDomainSocket = 2,
}

/// <summary>
/// A validated, parent-chosen private endpoint address. It names exactly one OS stream endpoint; it is never
/// published, discovered or resolved through DNS, a port or a registry.
/// </summary>
public sealed record LocalRpcEndpoint
{
    /// <summary>Longest Windows pipe name accepted (the OS limit is 256 characters including its prefix).</summary>
    public const int MaximumPipeNameLength = 128;

    /// <summary>Longest UTF-8 Unix socket path accepted; the smallest platform <c>sun_path</c> is 104 bytes.</summary>
    public const int MaximumSocketPathBytes = 100;

    private LocalRpcEndpoint(LocalRpcTransport transport, string address)
    {
        Transport = transport;
        Address = address;
    }

    /// <summary>The OS stream transport that carries this endpoint.</summary>
    public LocalRpcTransport Transport { get; }

    /// <summary>The pipe name (not a <c>\\.\pipe\</c> path) or the canonical absolute socket path.</summary>
    public string Address { get; }

    /// <summary>Creates a Windows Named Pipe endpoint. Names are one flat ASCII segment, never a path.</summary>
    public static LocalRpcEndpoint NamedPipe(string pipeName)
    {
        ArgumentNullException.ThrowIfNull(pipeName);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Named Pipes are the Windows transport; use a Unix domain socket on this platform.");
        }

        return new LocalRpcEndpoint(LocalRpcTransport.NamedPipe, ValidatePipeName(pipeName));
    }

    /// <summary>Creates a Linux/macOS Unix domain socket endpoint at a canonical absolute path.</summary>
    public static LocalRpcEndpoint UnixDomainSocket(string absolutePath)
    {
        ArgumentNullException.ThrowIfNull(absolutePath);
        if (OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Named Pipes are the Windows transport; Unix domain sockets are for Linux and macOS.");
        }

        return new LocalRpcEndpoint(LocalRpcTransport.UnixDomainSocket, ValidateSocketPath(absolutePath));
    }

    /// <summary>
    /// Applies the same address validation without the host-platform restriction. Only offline fixtures and the
    /// explicit local verification of the Unix socket code path on a Windows workstation use this.
    /// </summary>
    internal static LocalRpcEndpoint CreateForVerification(LocalRpcTransport transport, string address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return transport switch
        {
            LocalRpcTransport.NamedPipe => new LocalRpcEndpoint(transport, ValidatePipeName(address)),
            LocalRpcTransport.UnixDomainSocket => new LocalRpcEndpoint(transport, ValidateSocketPath(address)),
            _ => throw new ArgumentOutOfRangeException(nameof(transport)),
        };
    }

    internal static string ValidatePipeName(string name)
    {
        if (name.Length is 0 or > MaximumPipeNameLength || !IsAsciiAlphanumeric(name[0]))
        {
            throw new ArgumentException("A pipe name is 1-128 characters and starts with a letter or digit.", nameof(name));
        }

        foreach (char character in name)
        {
            if (!IsAsciiAlphanumeric(character) && character is not ('.' or '_' or '-'))
            {
                throw new ArgumentException("A pipe name is one flat segment of ASCII letters, digits, '.', '_' or '-'.", nameof(name));
            }
        }

        return name;
    }

    internal static string ValidateSocketPath(string path)
    {
        if (path.Length == 0 || path.Contains('\0', StringComparison.Ordinal))
        {
            throw new ArgumentException("A socket path must be non-empty and contain no NUL.", nameof(path));
        }

        if (path.StartsWith(@"\\", StringComparison.Ordinal) || !Path.IsPathFullyQualified(path))
        {
            throw new ArgumentException("A socket path must be a local, fully qualified path.", nameof(path));
        }

        if (!string.Equals(Path.GetFullPath(path), path, StringComparison.Ordinal)
            || path[^1] == Path.DirectorySeparatorChar || path[^1] == Path.AltDirectorySeparatorChar)
        {
            throw new ArgumentException("A socket path must be canonical: no dot segments, repeated separators or trailing separator.", nameof(path));
        }

        if (Encoding.UTF8.GetByteCount(path) > MaximumSocketPathBytes)
        {
            throw new ArgumentException("A socket path is at most 100 UTF-8 bytes.", nameof(path));
        }

        return path;
    }

    private static bool IsAsciiAlphanumeric(char character) =>
        character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9';
}
