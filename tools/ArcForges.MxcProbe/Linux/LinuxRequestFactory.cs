// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Mxc.Sdk.V1;

namespace ArcForges.MxcProbe.Linux;

// A single bounded experiment profile, using the public 1.0.1 typed request.
// Bubblewrap's shell evaluates this command only after entering containment.
[SupportedOSPlatform("linux")]
internal static class LinuxRequestFactory
{
    private static readonly string[] RuntimePaths = ["/bin", "/lib", "/lib64", "/usr/bin", "/usr/lib", "/usr/lib64", "/etc/ld.so.cache"];
    private static readonly string[] OwnedDirectories = ["home", "config", "cache", "data", "tmp", "observations"];

    internal static ContainerRequest Create(string executable, IReadOnlyList<string> args, string sandboxData, string control, int timeoutMs)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Native Linux request factory.");
        ArgumentNullException.ThrowIfNull(args);
        ArgumentOutOfRangeException.ThrowIfLessThan(timeoutMs, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(timeoutMs, 180_000);
        var data = OwnedDirectory(sandboxData);
        var privateControl = OwnedDirectory(control);
        if (Overlaps(data, privateControl)) throw new LinuxProbeException("control_overlaps_workload_grant");
        var stage = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory));
        var program = AbsolutePath(executable);
        if (!File.Exists(program)) throw new FileNotFoundException("Selected fixture executable is missing.", program);
        if (Overlaps(stage, data) || Overlaps(stage, privateControl)) throw new LinuxProbeException("stage_overlaps_mutable_fixture");
        foreach (var name in OwnedDirectories)
        {
            var child = Path.Combine(data, name);
            if (!Directory.Exists(child)) Directory.CreateDirectory(child, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            _ = OwnedDirectory(child);
        }
        var readonlyPaths = RuntimePaths.Where(path => Directory.Exists(path) || File.Exists(path)).Append(stage)
            .Distinct(StringComparer.Ordinal).ToList();
        // A directory grant already exposes its executable, including symlinks
        // such as /bin/sh. Binding that file again can target a symlink inside
        // the mounted directory, which Bubblewrap correctly refuses.
        if (!readonlyPaths.Any(path => Directory.Exists(path) && program.StartsWith(path + '/', StringComparison.Ordinal)))
            readonlyPaths.Add(program);
        if (readonlyPaths.Any(path => Overlaps(path, privateControl) || Overlaps(path, data)))
            throw new LinuxProbeException("runtime_overlaps_mutable_fixture");
        return new ContainerRequest(Command(program, args))
        {
            Containment = new Containment.Bubblewrap(),
            WorkingDirectory = data,
            TimeoutMs = checked((uint)timeoutMs),
            InheritDefaultEnvironment = false,
            Environment = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["PATH"] = "/usr/bin:/bin",
                ["LANG"] = "C.UTF-8",
                ["LC_ALL"] = "C.UTF-8",
                ["TERM"] = "xterm-256color",
                ["HOME"] = Path.Combine(data, "home"),
                ["XDG_CONFIG_HOME"] = Path.Combine(data, "config"),
                ["XDG_CACHE_HOME"] = Path.Combine(data, "cache"),
                ["XDG_DATA_HOME"] = Path.Combine(data, "data"),
                ["TMPDIR"] = Path.Combine(data, "tmp"),
                ["TEMP"] = Path.Combine(data, "tmp"),
                ["TMP"] = Path.Combine(data, "tmp"),
                ["AFV2_MXC_OBSERVATIONS_DIR"] = Path.Combine(data, "observations"),
            },
            Filesystem = new FilesystemPolicy
            {
                ReadwritePaths = [data],
                ReadonlyPaths = readonlyPaths,
                DeniedPaths = [privateControl],
                ClearPolicyOnExit = true,
            },
            Network = new NetworkPolicy
            {
                Egress = new NetworkEgressPolicy { Default = NetworkAction.Deny },
                Ingress = new NetworkIngressPolicy { Default = NetworkAction.Deny, HostLoopback = NetworkAction.Deny },
            },
        };
    }

    internal static string Command(string executable, IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Count > 64) throw new LinuxProbeException("fixture_argv_count_bound");
        var output = new StringBuilder("exec ");
        AppendQuoted(output, executable);
        foreach (var argument in args)
        {
            output.Append(' ');
            AppendQuoted(output, argument);
        }
        if (Encoding.UTF8.GetByteCount(output.ToString()) > 65_536) throw new LinuxProbeException("fixture_argv_byte_bound");
        return output.ToString();
    }

    private static void AppendQuoted(StringBuilder output, string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Contains('\0', StringComparison.Ordinal)) throw new LinuxProbeException("fixture_argv_nul");
        output.Append('\'');
        foreach (var character in value)
            if (character == '\'') output.Append("'\"'\"'"); else output.Append(character);
        output.Append('\'');
    }

    internal static string OwnedDirectory(string path)
    {
        var full = AbsolutePath(path);
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException("An owned fixture directory is missing.");
        for (var current = new DirectoryInfo(full); current is not null; current = current.Parent)
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0) throw new LinuxProbeException("fixture_parent_symlink");
        return full;
    }

    private static string AbsolutePath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path) || path.Contains('\0', StringComparison.Ordinal)) throw new LinuxProbeException("fixture_absolute_path_required");
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (full == "/") throw new LinuxProbeException("fixture_root_grant_forbidden");
        return full;
    }

    private static bool Overlaps(string left, string right) => left.Equals(right, StringComparison.Ordinal)
        || left.StartsWith(right + '/', StringComparison.Ordinal) || right.StartsWith(left + '/', StringComparison.Ordinal);
}
