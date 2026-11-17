// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.MxcProbe.Linux;

internal static partial class LinuxWorkload
{
    // One synthetic DNS datagram. No retries or real names; the selected TCP
    // profile must keep UDP DNS closed, including slirp's resolver forwarder.
    private static async Task<int> DnsDeniedAsync()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var resolver = LinuxDnsResolver.ReadCurrent();
        Emit("dns-resolver", "dns.configuration", writer =>
        {
            writer.WriteString("resolverSha256", resolver.Sha256);
            writer.WriteString("addressSha256", resolver.AddressSha256);
            writer.WriteNumber("ipv4Nameservers", resolver.IPv4Nameservers);
            writer.WriteBoolean("slirpForwarder", resolver.Address.Equals(IPAddress.Parse("10.0.2.3")));
        });
        EmitNetworkNamespace();
        await WaitForNetworkObservationAsync(CancellationToken.None).ConfigureAwait(false);
        Emit("network-attempt", "dns.start", writer =>
        {
            writer.WriteString("mode", "dns");
            writer.WriteNumber("port", 53);
            writer.WriteString("addressSha256", resolver.AddressSha256);
            writer.WriteString("query", "afv2-mxc-probe.invalid");
        });
        // Header: fixed synthetic transaction, recursion requested, one A/IN
        // question. This checks real DNS wire traffic without a public service.
        byte[] query = [0xaf, 0x03, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
            14, (byte)'a', (byte)'f', (byte)'v', (byte)'2', (byte)'-', (byte)'m', (byte)'x', (byte)'c', (byte)'-', (byte)'p', (byte)'r', (byte)'o', (byte)'b', (byte)'e',
            7, (byte)'i', (byte)'n', (byte)'v', (byte)'a', (byte)'l', (byte)'i', (byte)'d', 0, 0, 1, 0, 1];
        using var deadline = new CancellationTokenSource(4000);
        using var socket = new UdpClient(AddressFamily.InterNetwork);
        socket.Connect(resolver.Address, 53);
        var sent = await socket.SendAsync(query, deadline.Token).ConfigureAwait(false);
        Emit("dns-sent", "dns.send", writer => writer.WriteNumber("bytes", sent));
        var received = await socket.ReceiveAsync(deadline.Token).ConfigureAwait(false);
        Emit("network-received", "dns.receive", writer =>
        {
            writer.WriteString("mode", "dns");
            writer.WriteNumber("receivedBytes", received.Buffer.Length);
        });
        return 73; // Any actual DNS response violates this TCP-only profile.
    }
}

internal sealed record LinuxDnsResolverObservation(IPAddress Address, int IPv4Nameservers, string Sha256)
{
    internal string AddressSha256 => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Address.ToString())));
}

// Read the resolver in the observed payload root. openat2 IN_ROOT keeps an
// absolute resolver symlink in that root, rather than following it on the host.
[SupportedOSPlatform("linux")]
internal static partial class LinuxDnsResolver
{
    internal static LinuxDnsResolverObservation ReadCurrent() => ReadRoot("/");
    internal static LinuxDnsResolverObservation ReadPayload(int pid) => ReadRoot("/proc/" + pid.ToString(CultureInfo.InvariantCulture) + "/root");

    private static LinuxDnsResolverObservation ReadRoot(string root)
    {
        var descriptor = Open(root, 0x200000 | 0x10000 | 0x80000); // PATH, DIRECTORY, CLOEXEC.
        if (descriptor < 0) throw Error("dns_payload_root_open");
        using var directory = new SafeFileHandle(descriptor, ownsHandle: true);
        var how = new OpenHow { Flags = 0x80000 | 0x800, Resolve = 0x10 | 0x02 }; // CLOEXEC, NONBLOCK; IN_ROOT, NO_MAGICLINKS.
        var fd = OpenAt2(437, descriptor, "etc/resolv.conf", in how, 24);
        if (fd < 0) throw Error("dns_resolver_open_in_payload_root");
        using var handle = new SafeFileHandle((nint)fd, ownsHandle: true);
        using var file = new FileStream(handle, FileAccess.Read);
        var buffer = new byte[8193];
        var count = 0;
        while (count < buffer.Length)
        {
            var read = file.Read(buffer, count, buffer.Length - count);
            if (read == 0) break;
            count += read;
        }
        if (count > 8192) throw new LinuxProbeException("dns_resolver_size_bound");
        var bytes = buffer.AsSpan(0, count);
        var addresses = Encoding.UTF8.GetString(bytes).Split('\n')
            .Select(line => line.Split('#', 2)[0].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
            .Where(fields => fields.Length == 2 && fields[0] == "nameserver")
            .Select(fields => IPAddress.TryParse(fields[1], out var address) ? address : null)
            .Where(address => address?.AddressFamily == AddressFamily.InterNetwork)
            .Select(address => address!).ToArray();
        if (addresses.Length is < 1 or > 8 || addresses.Any(address => address.Equals(IPAddress.Any)))
            throw new LinuxProbeException("dns_ipv4_resolver_unavailable");
        return new(addresses[0], addresses.Length, Convert.ToHexStringLower(SHA256.HashData(bytes)));
    }

    private static LinuxProbeException Error(string code) => new(code, new Win32Exception(Marshal.GetLastPInvokeError()));
    [StructLayout(LayoutKind.Sequential)] private struct OpenHow { internal ulong Flags, Mode, Resolve; }
    [LibraryImport("libc", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)] private static partial int Open(string path, int flags);
    [LibraryImport("libc", EntryPoint = "syscall", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)] private static partial long OpenAt2(long number, int directory, string path, in OpenHow how, nuint size);
}
