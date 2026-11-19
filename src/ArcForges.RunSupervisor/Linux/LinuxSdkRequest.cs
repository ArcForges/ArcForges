// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text;
using ArcForges.RunSupervisor.Protocol;
using Microsoft.Mxc.Sdk.V1;

namespace ArcForges.RunSupervisor;

[SupportedOSPlatform("linux")]
internal static class LinuxSdkRequest
{
    private static readonly string[] s_runtimePaths = ["/bin", "/lib", "/lib64", "/usr/bin", "/usr/lib", "/usr/lib64", "/etc/ld.so.cache"];
    private static readonly string[] s_privatePaths = ["home", "config", "cache", "tmp", "work", "data"];

    internal static ContainerRequest Build(RunLaunchSpec spec)
    {
        if (spec.Argv.Length == 0 || spec.OutputLimitBytes > long.MaxValue ||
            spec.TerminalMode is not (RunTerminalMode.Interactive or RunTerminalMode.Pipes) ||
            (spec.TerminalMode == RunTerminalMode.Interactive && (spec.Rows is < 1 or > 32767 || spec.Columns is < 1 or > 32767)) ||
            spec.Network is { EgressAllowed: true } or { IngressAllowed: true } or { HostLoopback: true })
        {
            throw new RunNativeException("linux_mxc_request", "unsupported_bubblewrap_policy", payloadNotStarted: true);
        }

        var readable = new HashSet<string>(s_runtimePaths.Where(path => Directory.Exists(path) || File.Exists(path)), StringComparer.Ordinal);
        var writable = new HashSet<string>(s_privatePaths.Select(name => Path.Combine(spec.PrivateRoot, name)), StringComparer.Ordinal);
        foreach (var grant in spec.Mounts)
        {
            RequireAbsolutePath(grant.HostPath);
            if (grant.HostPath != grant.SandboxPath || Overlap(grant.HostPath, spec.ControlDirectory)
                || Overlap(grant.HostPath, spec.InstallationRoot))
            {
                throw new RunNativeException("linux_mxc_request", "unsupported_bind_identity", payloadNotStarted: true);
            }

            _ = (grant.Writable ? writable : readable).Add(grant.HostPath);
        }

        RequirePathCovered(spec.Argv[0], readable, writable);
        RequirePathCovered(spec.WorkingDirectory, readable, writable);
        var env = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var entry in spec.Environment)
        {
            if (entry.Name.Length == 0 || entry.Name.AsSpan().IndexOfAny('=', '\0') >= 0 || entry.Value.Contains('\0') ||
                !env.TryAdd(entry.Name, entry.Value))
            {
                throw new RunNativeException("linux_mxc_request", "invalid_environment", payloadNotStarted: true);
            }
        }

        env.TryAdd("PATH", "/usr/bin:/bin");
        env.TryAdd("HOME", Path.Combine(spec.PrivateRoot, "home"));
        env.TryAdd("XDG_CONFIG_HOME", Path.Combine(spec.PrivateRoot, "config"));
        env.TryAdd("XDG_CACHE_HOME", Path.Combine(spec.PrivateRoot, "cache"));
        env.TryAdd("XDG_DATA_HOME", Path.Combine(spec.PrivateRoot, "data"));
        env.TryAdd("TMPDIR", Path.Combine(spec.PrivateRoot, "tmp"));
        env.TryAdd("TEMP", Path.Combine(spec.PrivateRoot, "tmp"));
        env.TryAdd("TMP", Path.Combine(spec.PrivateRoot, "tmp"));
        if (spec.TerminalMode == RunTerminalMode.Interactive)
        {
            env.TryAdd("TERM", "xterm-256color");
        }

        return new ContainerRequest(QuoteArgv(spec.Argv))
        {
            Containment = new Containment.Bubblewrap(),
            WorkingDirectory = spec.WorkingDirectory,
            InheritDefaultEnvironment = false,
            Environment = env,
            Filesystem = new FilesystemPolicy
            {
                ReadonlyPaths = [.. readable.Order(StringComparer.Ordinal)],
                ReadwritePaths = [.. writable.Order(StringComparer.Ordinal)],
                DeniedPaths = [spec.ControlDirectory, spec.InstallationRoot],
                ClearPolicyOnExit = true,
            },
            Network = new NetworkPolicy
            {
                Egress = new NetworkEgressPolicy
                {
                    Default = NetworkAction.Deny,
                    Allow = [.. spec.Network.Destinations.Select(BuildDestination)],
                },
                Ingress = new NetworkIngressPolicy { Default = NetworkAction.Deny, HostLoopback = NetworkAction.Deny },
            },
        };
    }

    private static NetworkRulePolicy BuildDestination(string value)
    {
        var protocol = value.StartsWith("tcp://", StringComparison.Ordinal) ? NetworkProtocol.Tcp :
            value.StartsWith("udp://", StringComparison.Ordinal) ? NetworkProtocol.Udp :
            throw new RunNativeException("linux_mxc_request", "unsupported_selected_egress_protocol", payloadNotStarted: true);
        var separator = value.LastIndexOf(':');
        if (separator <= 6 || !ushort.TryParse(value.AsSpan(separator + 1), NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port == 0)
        {
            throw new RunNativeException("linux_mxc_request", "unsupported_selected_egress_port", payloadNotStarted: true);
        }

        var address = value[6..separator];
        if (!IPAddress.TryParse(address, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork || ip.ToString() != address)
        {
            throw new RunNativeException("linux_mxc_request", "unsupported_selected_egress_address", payloadNotStarted: true);
        }

        return new NetworkRulePolicy
        {
            To = [new NetworkPeerPolicy(address + "/32")],
            Ports = [new NetworkPortPolicy { Protocol = protocol, Port = port }],
        };
    }

    private static string QuoteArgv(IEnumerable<string> argv)
    {
        var command = new StringBuilder("exec");
        foreach (var argument in argv)
        {
            if (argument.Contains('\0'))
            {
                throw new RunNativeException("linux_mxc_request", "argv_contains_nul", payloadNotStarted: true);
            }

            command.Append(" '");
            command.Append(argument.Replace("'", "'\"'\"'", StringComparison.Ordinal));
            command.Append('\'');
        }

        var text = command.ToString();
        return Encoding.UTF8.GetByteCount(text) <= 65_536
            ? text : throw new RunNativeException("linux_mxc_request", "argv_exceeds_native_bound", payloadNotStarted: true);
    }

    private static void RequirePathCovered(string path, HashSet<string> readable, HashSet<string> writable)
    {
        RequireAbsolutePath(path);
        if (!readable.Concat(writable).Any(root => Contains(root, path)))
        {
            throw new RunNativeException("linux_mxc_request", "path_outside_approved_binds", payloadNotStarted: true);
        }
    }

    private static void RequireAbsolutePath(string path)
    {
        if (!Path.IsPathFullyQualified(path) || path != Path.GetFullPath(path))
        {
            throw new RunNativeException("linux_mxc_request", "path_not_native_absolute", payloadNotStarted: true);
        }
    }

    private static bool Overlap(string left, string right) => Contains(left, right) || Contains(right, left);

    private static bool Contains(string root, string path) => path == root || path.StartsWith(root.TrimEnd('/') + "/", StringComparison.Ordinal);
}
