// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArcForges.MxcProbe;

internal sealed record WindowsOwnedPaths(string Home, string Config, string Cache, string Temp, string Work, string Data);
internal sealed record WindowsPolicyArtifact(string ControlDirectory, string Path, string Sha256, int Utf8Bytes);

// A choice of the exact 1.0.0 directional policy, not a claim that this host supports it.
internal sealed record WindowsNetworkChoice(
    string EgressDefault = "deny",
    string IngressDefault = "deny",
    string HostLoopback = "deny",
    WindowsPolicyNetworkRule[]? Allow = null,
    WindowsPolicyNetworkRule[]? Deny = null)
{
    public static WindowsNetworkChoice DenyAll { get; } = new();
}

/// <summary>Private one-shot policies for the bounded MXC-WIN experiment only.</summary>
[SupportedOSPlatform("windows")]
internal static partial class WindowsPolicy
{
    internal const int MaximumUtf8Bytes = 256 * 1024;
    private const uint ReparsePoint = 0x400;
    private const uint DirectoryAttribute = 0x10;

    internal static WindowsPolicyRequest BuildRequest(string executable, IReadOnlyList<string> args,
        WindowsOwnedPaths owned, IEnumerable<string> readOnly, IEnumerable<string> denied, WindowsNetworkChoice network)
    {
        ArgumentNullException.ThrowIfNull(owned);
        ArgumentNullException.ThrowIfNull(network);
        var paths = new WindowsOwnedPaths(FullPath(owned.Home), FullPath(owned.Config), FullPath(owned.Cache),
            FullPath(owned.Temp), FullPath(owned.Work), FullPath(owned.Data));
        var system = FullPath(Environment.SystemDirectory);
        var windows = System.IO.Path.GetDirectoryName(system) ?? throw new InvalidDataException("Windows directory unavailable.");
        return new WindowsPolicyRequest
        {
            ContainerId = "afv2-win02-" + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
            Process = new WindowsPolicyProcess
            {
                CommandLine = QuoteCommandLine(executable, args),
                Cwd = paths.Work,
                // No ambient process/user-profile environment is merged into this list.
                Env = ["SystemRoot=" + windows, "WINDIR=" + windows, "PATH=" + system,
                    "HOME=" + paths.Home, "USERPROFILE=" + paths.Home, "APPDATA=" + paths.Config,
                    "LOCALAPPDATA=" + paths.Cache, "XDG_CONFIG_HOME=" + paths.Config,
                    "XDG_CACHE_HOME=" + paths.Cache, "XDG_DATA_HOME=" + paths.Data,
                    "TEMP=" + paths.Temp, "TMP=" + paths.Temp,
                    "AFV2_MXC_OBSERVATIONS_DIR=" + System.IO.Path.Combine(paths.Work, "probe-observations")],
            },
            Filesystem = new WindowsPolicyFilesystem
            {
                ReadwritePaths = DistinctPaths([paths.Home, paths.Config, paths.Cache, paths.Temp, paths.Work, paths.Data]),
                ReadonlyPaths = DistinctPaths(readOnly),
                DeniedPaths = DistinctPaths(denied),
            },
            Network = new WindowsPolicyNetwork
            {
                Egress = new WindowsPolicyNetworkEgress
                {
                    Default = Action(network.EgressDefault),
                    Allow = Rules(network.Allow),
                    Deny = Rules(network.Deny),
                },
                Ingress = new WindowsPolicyNetworkIngress
                {
                    Default = Action(network.IngressDefault),
                    HostLoopback = Action(network.HostLoopback),
                },
            },
        };
    }

    internal static string QuoteCommandLine(string executable, IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var application = FullPath(executable);
        if (application.Contains('"', StringComparison.Ordinal)) throw new ArgumentException("Executable path contains a quote.", nameof(executable));
        var command = new StringBuilder();
        AppendArgument(command, application);
        foreach (var argument in args)
        {
            ArgumentNullException.ThrowIfNull(argument);
            RejectNul(argument);
            command.Append(' ');
            AppendArgument(command, argument);
        }
        if (command.Length >= 32767) throw new ArgumentException("Windows command line exceeds its native bound.", nameof(args));
        return command.ToString();
    }

    // Quote each argument using the Windows CRT backslash-before-quote rule,
    // including empty values and doubled trailing backslashes before the closing quote.
    private static void AppendArgument(StringBuilder output, string value)
    {
        output.Append('"');
        var slashes = 0;
        foreach (var character in value)
        {
            if (character == '\\') { slashes++; continue; }
            output.Append('\\', character == '"' ? checked(slashes * 2 + 1) : slashes);
            output.Append(character);
            slashes = 0;
        }
        output.Append('\\', checked(slashes * 2));
        output.Append('"');
    }

    internal static WindowsPolicyArtifact WritePrivate(string newControlDirectory, WindowsPolicyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var directory = FullPath(newControlDirectory);
        if (!request.Filesystem.DeniedPaths.Contains(directory, StringComparer.OrdinalIgnoreCase))
            throw new InvalidDataException("The private control directory must be explicitly denied.");
        foreach (var grant in request.Filesystem.ReadonlyPaths.Concat(request.Filesystem.ReadwritePaths))
            if (Overlaps(directory, FullPath(grant))) throw new InvalidDataException("Private control overlaps a workload grant.");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(request, WindowsPolicyJson.Default.WindowsPolicyRequest);
        if (bytes.Length == 0 || bytes.Length > MaximumUtf8Bytes) throw new InvalidDataException("Policy exceeds the bounded UTF-8 size.");
        CreatePrivateControl(directory);
        var path = System.IO.Path.Combine(directory, "request.json");
        // The directory was created atomically with its owner-only protected ACL.
        // CreateNew never truncates or replaces a previous policy; failures retain evidence.
        using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read,
                   4096, FileOptions.WriteThrough))
        {
            file.Write(bytes);
            file.Flush(flushToDisk: true);
        }
        VerifyPrivateFile(path);
        using var stream = File.OpenRead(path);
        var actual = SHA256.HashData(stream);
        var expected = SHA256.HashData(bytes);
        if (!CryptographicOperations.FixedTimeEquals(actual, expected)) throw new IOException("Written private policy hash differs.");
        return new WindowsPolicyArtifact(directory, path, Convert.ToHexStringLower(actual), bytes.Length);
    }

    internal static void CreatePrivateControl(string newControlDirectory)
    {
        var directory = FullPath(newControlDirectory);
        var parent = System.IO.Path.GetDirectoryName(directory) ?? throw new InvalidDataException("Control directory has no parent.");
        CheckParents(parent);
        var sid = CurrentSid();
        var sddl = "O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out var descriptor, out _)) throw NativeError("Create private directory descriptor");
        try
        {
            var attributes = new SecurityAttributes { Length = (uint)Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor };
            if (!CreateDirectory(directory, ref attributes)) throw NativeError("Create new private control directory");
        }
        finally { _ = LocalFree(descriptor); }
        VerifyPrivateControl(directory);
    }

    internal static void VerifyPrivateControl(string directory)
    {
        var full = FullPath(directory);
        CheckParents(full);
        VerifyOwnerAcl(full, requireProtected: true);
    }

    internal static void VerifyPrivateFile(string path)
    {
        var full = FullPath(path);
        CheckParents(System.IO.Path.GetDirectoryName(full) ?? throw new InvalidDataException("Private file has no parent."));
        var attributes = File.GetAttributes(full);
        if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
            throw new InvalidDataException("Private file must be a regular non-reparse file.");
        VerifyOwnerAcl(full, requireProtected: false);
    }

    private static void CheckParents(string directory)
    {
        var parents = new Stack<string>();
        for (var current = directory; current is not null; current = System.IO.Path.GetDirectoryName(current)) parents.Push(current);
        while (parents.TryPop(out var path))
        {
            var attributes = (uint)File.GetAttributes(path);
            if ((attributes & ReparsePoint) != 0 || (attributes & DirectoryAttribute) == 0)
                throw new InvalidDataException("Private control ancestry contains a reparse point or non-directory.");
        }
    }

    private static void VerifyOwnerAcl(string path, bool requireProtected)
    {
        const uint ownerAndDacl = 0x1 | 0x4;
        var error = GetNamedSecurityInfo(path, 1, ownerAndDacl, out var owner, out _, out var dacl, out _, out var descriptor);
        if (error != 0) throw new Win32Exception((int)error, "Read private owner/DACL");
        try
        {
            var sid = CurrentSid();
            if (owner == 0 || dacl == 0 || SidString(owner) != sid) throw new InvalidDataException("Private object has an unexpected owner or missing DACL.");
            if (!GetSecurityDescriptorControl(descriptor, out var control, out _)) throw NativeError("Read private DACL control");
            if (requireProtected && (control & 0x1000) == 0) throw new InvalidDataException("Private control DACL is not protected.");
            if (!GetAclInformation(dacl, out var information, (uint)Marshal.SizeOf<AclSizeInformation>(), 2)) throw NativeError("Read private DACL entries");
            if (information.AceCount is 0 or > 16) throw new InvalidDataException("Unexpected private DACL entry count.");
            for (uint index = 0; index < information.AceCount; index++)
            {
                if (!GetAce(dacl, index, out var ace)) throw NativeError("Read private ACE");
                // ACCESS_ALLOWED_ACE: header(4), mask(4), SID. No other principal/type is admitted.
                if (Marshal.ReadByte(ace) != 0 || SidString(ace + 8) != sid)
                    throw new InvalidDataException("Private DACL grants another principal or uses an unexpected ACE type.");
            }
        }
        finally { _ = LocalFree(descriptor); }
    }

    private static string CurrentSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value ?? throw new InvalidDataException("Current Windows identity has no user SID.");
    }

    private static string SidString(nint sid)
    {
        if (!ConvertSidToStringSid(sid, out var text)) throw NativeError("Read private SID");
        try { return Marshal.PtrToStringUni(text) ?? throw new InvalidDataException("Empty private SID."); }
        finally { _ = LocalFree(text); }
    }

    private static string FullPath(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        RejectNul(path);
        if (!System.IO.Path.IsPathFullyQualified(path)) throw new ArgumentException("An absolute Windows path is required.", nameof(path));
        return System.IO.Path.TrimEndingDirectorySeparator(System.IO.Path.GetFullPath(path));
    }

    private static string[] DistinctPaths(IEnumerable<string> paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        return paths.Select(FullPath).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static bool Overlaps(string left, string right) =>
        left.Equals(right, StringComparison.OrdinalIgnoreCase)
        || left.StartsWith(right.EndsWith(System.IO.Path.DirectorySeparatorChar) ? right : right + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
        || right.StartsWith(left.EndsWith(System.IO.Path.DirectorySeparatorChar) ? left : left + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

    private static void RejectNul(string value)
    {
        if (value.Contains('\0', StringComparison.Ordinal)) throw new ArgumentException("Embedded NUL is not allowed.");
    }

    private static string Action(string value) => value is "allow" or "deny" ? value : throw new ArgumentException("Invalid network action.");

    private static WindowsPolicyNetworkRule[]? Rules(WindowsPolicyNetworkRule[]? rules) => rules?.Select(rule => new WindowsPolicyNetworkRule
    {
        To = rule.To?.Select(peer => new WindowsPolicyNetworkPeer { Cidr = peer.Cidr, Except = peer.Except?.ToArray() }).ToArray(),
        Ports = rule.Ports?.Select(port => new WindowsPolicyNetworkPort { Protocol = port.Protocol, Port = port.Port, EndPort = port.EndPort }).ToArray(),
    }).ToArray();

    private static Win32Exception NativeError(string operation) => new(Marshal.GetLastPInvokeError(), operation);

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes { internal uint Length; internal nint Descriptor; internal int InheritHandle; }
    [StructLayout(LayoutKind.Sequential)]
    private struct AclSizeInformation { internal uint AceCount; internal uint BytesInUse; internal uint BytesFree; }

    [LibraryImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)] private static partial bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision, out nint descriptor, out uint size);
    [LibraryImport("kernel32.dll", EntryPoint = "CreateDirectoryW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)] private static partial bool CreateDirectory(string path, ref SecurityAttributes attributes);
    [LibraryImport("advapi32.dll", EntryPoint = "GetNamedSecurityInfoW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint GetNamedSecurityInfo(string path, int objectType, uint information, out nint owner, out nint group, out nint dacl, out nint sacl, out nint descriptor);
    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static partial bool GetSecurityDescriptorControl(nint descriptor, out ushort control, out uint revision);
    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static partial bool GetAclInformation(nint acl, out AclSizeInformation information, uint size, int informationClass);
    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static partial bool GetAce(nint acl, uint index, out nint ace);
    [LibraryImport("advapi32.dll", EntryPoint = "ConvertSidToStringSidW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static partial bool ConvertSidToStringSid(nint sid, out nint text);
    [LibraryImport("kernel32.dll")] private static partial nint LocalFree(nint memory);
}

// Exact official schema1.0.0 names. Optional backend fields are omitted when null.
internal sealed class WindowsPolicyRequest
{
    public string Version { get; set; } = "1.0.0";
    public string Containment { get; set; } = "processcontainer";
    public string ContainerId { get; set; } = "";
    public WindowsPolicyProcess Process { get; set; } = new();
    public WindowsPolicyFilesystem Filesystem { get; set; } = new();
    public WindowsPolicyFallback Fallback { get; set; } = new();
    public WindowsPolicyNetwork Network { get; set; } = new();
    public WindowsPolicyUi Ui { get; set; } = new();
    public WindowsPolicyProcessContainer ProcessContainer { get; set; } = new();
    public WindowsPolicyTelemetry Telemetry { get; set; } = new();
    public WindowsPolicyLifecycle Lifecycle { get; set; } = new();
    public WindowsPolicyRuntimeConfig? RuntimeConfig { get; set; }
}
internal sealed class WindowsPolicyProcess { public string CommandLine { get; set; } = ""; public string Cwd { get; set; } = ""; public string[] Env { get; set; } = []; public bool InheritDefaultEnv { get; set; } public uint Timeout { get; set; } = 10_000; }
internal sealed class WindowsPolicyFilesystem { public string[] ReadwritePaths { get; set; } = []; public string[] ReadonlyPaths { get; set; } = []; public string[] DeniedPaths { get; set; } = []; }
internal sealed class WindowsPolicyFallback { public bool AllowDaclMutation { get; set; } }
internal sealed class WindowsPolicyTelemetry { public bool Enabled { get; set; } }
internal sealed class WindowsPolicyLifecycle { public bool DestroyOnExit { get; set; } = true; public bool PreservePolicy { get; set; } }
// This console AOT fixture requires Win32k initialization, so ui.disable is explicitly false.
// Clipboard and input injection remain denied; GUI qualification is outside this experiment.
internal sealed class WindowsPolicyUi { public bool Disable { get; set; } public string Clipboard { get; set; } = "none"; public bool Injection { get; set; } }
internal sealed class WindowsPolicyNetwork { public WindowsPolicyNetworkEgress Egress { get; set; } = new(); public WindowsPolicyNetworkIngress Ingress { get; set; } = new(); }
internal sealed class WindowsPolicyNetworkEgress { public string Default { get; set; } = "deny"; public WindowsPolicyNetworkRule[]? Allow { get; set; } public WindowsPolicyNetworkRule[]? Deny { get; set; } }
internal sealed class WindowsPolicyNetworkIngress { public string Default { get; set; } = "deny"; public string HostLoopback { get; set; } = "deny"; }
internal sealed class WindowsPolicyNetworkRule { public WindowsPolicyNetworkPeer[]? To { get; set; } public WindowsPolicyNetworkPort[]? Ports { get; set; } }
internal sealed class WindowsPolicyNetworkPeer { public string Cidr { get; set; } = ""; public string[]? Except { get; set; } }
internal sealed class WindowsPolicyNetworkPort { public string? Protocol { get; set; } public uint? Port { get; set; } public uint? EndPort { get; set; } }
internal sealed class WindowsPolicyRuntimeConfig { public string NetworkProxy { get; set; } = ""; }
internal sealed class WindowsPolicyProcessContainer
{
    public bool LeastPrivilege { get; set; }
    public bool? LearningMode { get; set; }
    public string[]? Capabilities { get; set; }
    public WindowsPolicyCaptureDenials? CaptureDenials { get; set; }
    public WindowsPolicyProcessContainerFilesystem? Filesystem { get; set; }
    public WindowsPolicyProcessContainerNetwork? Network { get; set; }
    public WindowsPolicyProcessContainerUi? Ui { get; set; }
}
internal sealed class WindowsPolicyCaptureDenials { public string? Mode { get; set; } public string? OutputPath { get; set; } public bool? RetainEtl { get; set; } }
internal sealed class WindowsPolicyProcessContainerFilesystem { public string[] EnumeratePaths { get; set; } = []; }
internal sealed class WindowsPolicyProcessContainerNetwork { public string AllowedProxyPeer { get; set; } = ""; }
internal sealed class WindowsPolicyProcessContainerUi { public string? Isolation { get; set; } public bool? Ime { get; set; } public bool? DesktopSystemControl { get; set; } public string? SystemSettings { get; set; } }
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(WindowsPolicyRequest))]
internal sealed partial class WindowsPolicyJson : JsonSerializerContext;
