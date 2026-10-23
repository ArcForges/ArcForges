// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.Versioning;

namespace ArcForges.Node.Platform.Linux;

/// <summary>
/// The <c>tcp_listen_port</c> readiness condition on Linux (04 section 8): <c>/proc/net/tcp</c> and <c>/proc/net/tcp6</c> list the
/// listening sockets (state <c>0A</c>) with their local address and inode; a socket counts when it listens on the port on a loopback or
/// wildcard address and one of the service's processes holds it (<c>/proc/&lt;pid&gt;/fd</c> links <c>socket:[inode]</c>).
/// </summary>
[SupportedOSPlatform("linux")]
internal static class ListeningSockets
{
    private const string Listen = "0A";

    public static bool Listens(int port, IReadOnlyCollection<int> processIds)
    {
        if (processIds.Count == 0)
        {
            return false;
        }

        var inodes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var table in (string[])["/proc/net/tcp", "/proc/net/tcp6"])
        {
            string[] lines;
            try
            {
                lines = File.ReadAllLines(table);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var line in lines.Skip(1))
            {
                var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length < 10 || fields[3] != Listen)
                {
                    continue;
                }

                var local = fields[1];
                var colon = local.LastIndexOf(':');
                if (colon <= 0 || !int.TryParse(local.AsSpan(colon + 1), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var listening) || listening != port)
                {
                    continue;
                }

                if (LoopbackOrWildcard(local[..colon]))
                {
                    inodes.Add(fields[9]);
                }
            }
        }

        if (inodes.Count == 0)
        {
            return false;
        }

        foreach (var pid in processIds)
        {
            IEnumerable<string> descriptors;
            try
            {
                descriptors = Directory.EnumerateFileSystemEntries("/proc/" + pid.ToString(CultureInfo.InvariantCulture) + "/fd").ToList();
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var descriptor in descriptors)
            {
                string? target;
                try
                {
                    target = new FileInfo(descriptor).LinkTarget;
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    continue;
                }

                if (target is { Length: > 9 } && target.StartsWith("socket:[", StringComparison.Ordinal) && inodes.Contains(target[8..^1]))
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// The kernel prints IPv4 addresses as one 32-bit word and IPv6 addresses as four, each in host byte order (little-endian here):
    /// 127.x.x.x ends in <c>7F</c>, <c>::1</c> is <c>...01000000</c>, an IPv4-mapped loopback is <c>0000FFFF</c> then the IPv4 word.
    /// </summary>
    private static bool LoopbackOrWildcard(string address) => address.Length switch
    {
        8 => address.EndsWith("7F", StringComparison.OrdinalIgnoreCase) || address == "00000000",
        32 => address == "00000000000000000000000000000000" || address == "00000000000000000000000001000000"
            || (address.StartsWith("0000000000000000FFFF0000", StringComparison.OrdinalIgnoreCase) && (address.EndsWith("7F", StringComparison.OrdinalIgnoreCase)
                || address.EndsWith("00000000", StringComparison.Ordinal))),
        _ => false,
    };
}
