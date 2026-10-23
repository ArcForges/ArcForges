// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ArcForges.Node.Platform.Windows;

/// <summary>
/// The <c>tcp_listen_port</c> readiness condition on Windows (04 section 8): <c>GetExtendedTcpTable</c> with
/// <c>TCP_TABLE_OWNER_PID_LISTENER</c> lists the listening sockets of IPv4 and IPv6 with their owning process; a socket counts when it
/// listens on the port on a loopback or wildcard address and one of the service's processes owns it. No handle to another process is opened.
/// </summary>
[SupportedOSPlatform("windows")]
internal static partial class ListeningSockets
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidListener = 3;
    private const uint ErrorInsufficientBuffer = 122;

    public static bool Listens(int port, IReadOnlyCollection<int> processIds)
    {
        if (processIds.Count == 0)
        {
            return false;
        }

        var owners = processIds.ToHashSet();
        return Rows(AfInet).Any(row => row.Port == port && owners.Contains(row.Pid) && row.LoopbackOrWildcard)
            || Rows(AfInet6).Any(row => row.Port == port && owners.Contains(row.Pid) && row.LoopbackOrWildcard);
    }

    private static List<(int Port, int Pid, bool LoopbackOrWildcard)> Rows(int family)
    {
        var size = 16 * 1024;
        for (var tries = 0; tries < 4; tries++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var length = (uint)size;
                var status = GetExtendedTcpTable(buffer, ref length, false, family, TcpTableOwnerPidListener, 0);
                if (status == ErrorInsufficientBuffer)
                {
                    size = (int)length + 4096;
                    continue;
                }

                if (status != 0)
                {
                    return [];
                }

                var bytes = new byte[length];
                Marshal.Copy(buffer, bytes, 0, (int)length);
                return Parse(bytes, family);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        return [];
    }

    /// <summary>
    /// <c>MIB_TCPTABLE_OWNER_PID</c>: a count, then rows of <c>state, localAddr, localPort, remoteAddr, remotePort, owningPid</c> (24 bytes);
    /// <c>MIB_TCP6TABLE_OWNER_PID</c>: rows of <c>localAddr[16], localScopeId, localPort, remoteAddr[16], remoteScopeId, remotePort, state,
    /// owningPid</c> (56 bytes). Ports are in network byte order in the low 16 bits.
    /// </summary>
    private static List<(int Port, int Pid, bool LoopbackOrWildcard)> Parse(ReadOnlySpan<byte> table, int family)
    {
        var rows = new List<(int, int, bool)>();
        if (table.Length < 4)
        {
            return rows;
        }

        var count = BinaryPrimitives.ReadInt32LittleEndian(table);
        var rowSize = family == AfInet ? 24 : 56;
        for (var index = 0; index < count && 4 + ((index + 1) * rowSize) <= table.Length; index++)
        {
            var row = table.Slice(4 + (index * rowSize), rowSize);
            if (family == AfInet)
            {
                var address = row.Slice(4, 4);
                var port = BinaryPrimitives.ReadUInt16BigEndian(row.Slice(8, 2));
                var pid = BinaryPrimitives.ReadInt32LittleEndian(row.Slice(20, 4));
                rows.Add((port, pid, address[0] == 127 || (address[0] == 0 && address[1] == 0 && address[2] == 0 && address[3] == 0)));
            }
            else
            {
                var address = row[..16];
                var port = BinaryPrimitives.ReadUInt16BigEndian(row.Slice(20, 2));
                var pid = BinaryPrimitives.ReadInt32LittleEndian(row.Slice(52, 4));
                var wildcard = !address.ContainsAnyExcept((byte)0);
                var loopback = !address[..15].ContainsAnyExcept((byte)0) && address[15] == 1;
                rows.Add((port, pid, wildcard || loopback));
            }
        }

        return rows;
    }

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedTcpTable(nint table, ref uint size, [MarshalAs(UnmanagedType.Bool)] bool order, int family, int tableClass, uint reserved);
}
