// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Platform.Capabilities;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Policy;
using ArcForges.RunSupervisor.Protocol;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private const uint RunProfileMaxProcesses = 128;

    private static string ReadRunSupervisorSha256(WorkspacePath installed, string name)
    {
        var handle = installed.OpenRead("mxc-manifest.json");
        WorkspacePath.CheckMxcTrustedObject(handle);
        using var stream = new FileStream(handle, FileAccess.Read);
        if (stream.Length is <= 0 or > 65_536)
        {
            throw new InvalidDataException("Invalid protected MXC manifest size.");
        }

        using var manifest = JsonDocument.Parse(stream);
        var matches = manifest.RootElement.GetProperty("files").EnumerateArray()
            .Where(entry => entry.GetProperty("path").GetString() == name).Take(2).ToArray();
        if (matches.Length != 1 || matches[0].GetProperty("sha256").GetString() is not { Length: 64 } digest
            || !digest.All(char.IsAsciiHexDigitLower))
        {
            throw new InvalidDataException("The protected MXC manifest must bind exactly one Run supervisor.");
        }

        return digest;
    }

    private (RunLaunchSpec? Spec, ArcError? Error) PrepareRunPolicy(RunServiceStartRequest request, StoredSandbox row,
        SandboxPrivateRootLease root, string runId, string epoch, string launchDigest, byte[] controlKey,
        IReadOnlyDictionary<string, string>? secrets, out string[]? requiredSecrets)
    {
        requiredSecrets = null;
        var terminal = request.TerminalMode switch
        {
            TerminalMode.Interactive when request.TerminalSize is
            { Rows: >= 1 and <= 32767, Columns: >= 1 and <= 32767 } => MxcTerminalMode.Interactive,
            TerminalMode.Pipes when request.TerminalSize is null => MxcTerminalMode.Pipes,
            _ => MxcTerminalMode.Unspecified,
        };
        if (terminal == MxcTerminalMode.Unspecified || request.Argv.Count is < 1 or > 256
            || string.IsNullOrWhiteSpace(request.Argv[0]) || request.Argv.Any(argument => argument.Contains('\0')))
        {
            return Invalid("run_launch_shape_invalid");
        }

        var config = FromStored(row.Config);
        if (config.HostGrants.Any(grant => !grant.HasNativeIdentity))
        {
            return Unsupported("host_grant_identity_missing");
        }

        var windows = config.ProfileId == MxcProfileAdmission.WindowsProfileId;
        var environment = new Dictionary<string, EnvironmentEntry>(windows ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        if (!AddRunEnvironment(environment, config.Environment) || !AddRunEnvironment(environment, request.Environment))
        {
            return Invalid("run_environment_invalid");
        }

        if (environment.Values.Any(entry => entry.HasSecretRef && !SandboxRunSecrets.IsReference(entry.SecretRef)))
        {
            return Invalid("run_secret_reference_invalid");
        }

        var ceiling = config.Resources;
        var desired = request.RequestedResources;
        uint? weight = desired?.HasWeight == true ? desired.Weight : ceiling.HasWeight ? ceiling.Weight : null;
        if (desired?.HasMaxConcurrentRuns == true || desired?.HasHostReserveBytes == true || desired?.HasHostReserveMillicores == true
            || (desired?.HasCpuMaxMillicores == true && desired.CpuMaxMillicores == 0)
            || (desired?.HasMemoryMaxBytes == true && desired.MemoryMaxBytes == 0)
            || (desired?.HasExpectedMemoryBytes == true && desired.ExpectedMemoryBytes == 0)
            || weight is < 1 or > 10_000 || desired?.Priority is < -20 or > 20)
        {
            return Invalid("run_resource_request_invalid");
        }

        var hostMemory = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
        if (hostMemory <= 0)
        {
            return BudgetUnavailable("run_host_capacity_unavailable");
        }

        var nodePolicy = _store.Policies.Current();
        if (!CryptographicOperations.FixedTimeEquals(nodePolicy.Digest.Span, PolicyDocuments.Digest(nodePolicy.Document)))
        {
            throw new InvalidDataException("The committed Node resource policy digest did not match.");
        }

        // Preserve the configured Node reserve without the legacy Task scheduling floors.
        var settings = new ExecutionSettings(nodePolicy.Document, Environment.ProcessorCount, hostMemory);
        var availableCpu = settings.CapacityCpu - Math.Clamp(settings.ReserveCpu, 0, settings.CapacityCpu);
        var cpuCeiling = (uint)Math.Min(availableCpu, uint.MaxValue);
        var memoryCeiling = (ulong)(hostMemory - Math.Clamp(settings.ReserveMemory, 0, hostMemory));
        if (ceiling.HasCpuMaxMillicores)
        {
            cpuCeiling = Math.Min(cpuCeiling, ceiling.CpuMaxMillicores);
        }

        if (ceiling.HasMemoryMaxBytes)
        {
            memoryCeiling = Math.Min(memoryCeiling, ceiling.MemoryMaxBytes);
        }

        // The Linux finite memory value must be represented exactly by memory.max. An inherited
        // ceiling can use the largest whole page within it; an explicit Run limit is immutable.
        uint cpu = desired?.HasCpuMaxMillicores == true ? desired.CpuMaxMillicores : cpuCeiling;
        var pageBytes = (ulong)Environment.SystemPageSize;
        ulong memory = desired?.HasMemoryMaxBytes == true ? desired.MemoryMaxBytes
            : windows ? memoryCeiling : memoryCeiling - memoryCeiling % pageBytes;
        ulong expectedMemory = desired?.HasExpectedMemoryBytes == true ? desired.ExpectedMemoryBytes : ceiling.ExpectedMemoryBytes;
        if (cpu == 0 || memory == 0 || cpu > cpuCeiling || memory > memoryCeiling || expectedMemory > memory
            || (ceiling.HasExpectedMemoryBytes && expectedMemory > ceiling.ExpectedMemoryBytes)
            || (desired?.HasWeight == true && ceiling.HasWeight && desired.Weight > ceiling.Weight)
            || (desired?.HasPriority == true && ceiling.HasPriority && desired.Priority > ceiling.Priority)
            || (desired?.Preemptible == true && ceiling.HasPreemptible && !ceiling.Preemptible))
        {
            return BudgetUnavailable("run_resource_ceiling_unavailable_or_exceeded");
        }

        if (!windows && memory % pageBytes != 0)
        {
            return Unsupported("linux_memory_limit_page_alignment_required");
        }

        var priority = desired?.HasPriority == true ? desired.Priority : ceiling.Priority;
        var preemptible = desired?.HasPreemptible == true ? desired.Preemptible : ceiling.Preemptible;
        if ((windows && weight.HasValue) || priority != 0 || preemptible || expectedMemory != 0
            || desired?.PressureAction == PressureAction.StopPreemptible || ceiling.PressureAction == PressureAction.StopPreemptible)
        {
            return Unsupported("run_resource_combination_unavailable");
        }

        (string Path, string Identity) workingDirectory;
        (string Path, string Identity) executable;
        var argv = request.Argv.ToArray();
        try
        {
            var comparison = windows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            workingDirectory = ResolveRunWorkingDirectory(request.HasWorkingDirectory ? request.WorkingDirectory
                : config.HasDefaultWorkdir ? config.DefaultWorkdir : "work", root, config, comparison);
            executable = ResolveRunExecutable(argv[0], workingDirectory.Path, root, config, windows, comparison);
            argv[0] = executable.Path;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return Invalid("run_path_unavailable_or_outside_profile");
        }

        if (_protectedEndpoint?.AllowsPrivateRoot(root.RootPath) == false)
        {
            return Invalid("run_private_root_overlaps_node_endpoint");
        }

        var policy = SandboxPolicyAdmission.Evaluate(config, _dataRoot, _mxcInstallationRoot, terminal, _protectedEndpoint);
        if (!policy.Admission.Admitted || policy.Config is null)
        {
            return (null, PolicyError(request.Meta, policy.Admission));
        }

        string installation;
        string supervisor;
        string supervisorSha256;
        string? bubblewrap = null;
        string? bubblewrapIdentity = null;
        try
        {
            using var installed = WorkspacePath.OpenRoot(_mxcInstallationRoot);
            WorkspacePath.CheckMxcTrustedObject(installed.RootHandle);
            var member = windows ? "arcforges-run-supervisor.exe" : "arcforges-run-supervisor";
            WorkspacePath.CheckMxcTrustedObject(installed.OpenRead(member));
            supervisorSha256 = ReadRunSupervisorSha256(installed, member);
            installation = installed.RootPath;
            supervisor = Path.Combine(installation, member);

            if (!windows)
            {
                bubblewrap = "/usr/bin/bwrap";
                if (policy.Host?.LinuxHelperSha256?.TryGetValue("bwrap", out bubblewrapIdentity) != true)
                {
                    return Unsupported("qualified_bubblewrap_identity_unavailable");
                }

                using var bin = WorkspacePath.OpenRoot("/usr/bin");
                WorkspacePath.CheckMxcTrustedObject(bin.RootHandle, systemOnly: true);
                using var handle = bin.OpenRead("bwrap");
                WorkspacePath.CheckMxcTrustedObject(handle, systemOnly: true);
                using var stream = new FileStream(handle, FileAccess.Read);
                if (stream.Length is <= 0 or > 128 * 1024 * 1024
                    || Convert.ToHexStringLower(SHA256.HashData(stream)) != bubblewrapIdentity)
                {
                    return Unsupported("qualified_bubblewrap_identity_changed");
                }
            }
        }
        catch (Exception error) when (SandboxPolicyHost.IsDiscoveryFailure(error))
        {
            return Unsupported("trusted_run_supervisor_or_bubblewrap_unavailable");
        }

        var inputBytes = argv.Sum(argument => (long)Encoding.UTF8.GetByteCount(argument));
        if (inputBytes > RunWire.LaunchInputsLimit)
        {
            return Invalid("run_launch_inputs_too_large");
        }

        if (secrets is null && environment.Values.Any(entry => entry.HasSecretRef))
        {
            requiredSecrets = [.. environment.Values.Where(entry => entry.HasSecretRef).Select(entry => entry.SecretRef).Distinct(StringComparer.Ordinal)];
            return (null, null);
        }

        var resolvedEnvironment = new List<RunEnvironment>();
        foreach (var entry in environment.Values)
        {
            var value = entry.HasSecretRef ? secrets?.GetValueOrDefault(entry.SecretRef) : entry.Value;
            if (value is null)
            {
                return Unsupported("run_secret_reference_unavailable");
            }

            inputBytes += Encoding.UTF8.GetByteCount(entry.Name) + Encoding.UTF8.GetByteCount(value);
            if (inputBytes > RunWire.LaunchInputsLimit)
            {
                return Invalid("run_launch_inputs_too_large");
            }

            resolvedEnvironment.Add(new RunEnvironment(entry.Name, value));
        }

        var control = Path.Combine(_dataRoot, "control", "run-" + runId);
        var spec = new RunLaunchSpec
        {
            RunId = runId,
            SandboxId = row.SandboxId,
            Epoch = epoch,
            OwnerId = Guid.NewGuid().ToString("N"),
            LaunchSha256 = launchDigest,
            ControlDirectory = control,
            ControlEndpoint = windows ? "arcforges-run-" + runId : Path.Combine(control, "owner.sock"),
            ControlKey = controlKey,
            SupervisorPath = supervisor,
            SupervisorSha256 = supervisorSha256,
            InstallationRoot = installation,
            ProfileId = config.ProfileId,
            ProfileVersion = config.ProfileVersion,
            PrivateRoot = root.RootPath,
            PrivateRootIdentity = row.RootIdentity,
            WorkingDirectory = workingDirectory.Path,
            WorkingDirectoryIdentity = workingDirectory.Identity,
            Argv = argv,
            ExecutablePath = executable.Path,
            ExecutableIdentity = executable.Identity,
            Environment = [.. resolvedEnvironment],
            Mounts = [.. policy.Config.HostGrants.Select(grant =>
                new RunMount(grant.HostPath, grant.SandboxPath, grant.Writable, grant.NativeIdentity))],
            Network = new RunNetwork(config.Network.Egress == NetworkMode.Allow, config.Network.Ingress == NetworkMode.Allow,
                config.Network.HostLoopback, [.. config.Network.AllowedDestinations]),
            TerminalMode = terminal == MxcTerminalMode.Interactive ? RunTerminalMode.Interactive : RunTerminalMode.Pipes,
            Rows = request.TerminalSize?.Rows ?? 0,
            Columns = request.TerminalSize?.Columns ?? 0,
            CpuMillicores = cpu,
            MemoryMaxBytes = memory,
            MaxProcesses = RunProfileMaxProcesses,
            CpuWeight = weight,
            OutputLimitBytes = config.HasOutputRetentionBytes ? config.OutputRetentionBytes : SandboxPolicyAdmission.DefaultOutputRetentionBytes,
            BubblewrapPath = bubblewrap,
            BubblewrapIdentity = bubblewrapIdentity,
        };
        if (!RunWire.CanEncodeLaunchInputs(spec))
        {
            spec.ClearInputs();
            return Invalid("run_launch_inputs_too_large");
        }

        return (spec, null);

        (RunLaunchSpec?, ArcError?) Invalid(string reason) =>
            (null, Error(request.Meta, ErrorCategory.Validation, "invalid_argument", reason));

        (RunLaunchSpec?, ArcError?) BudgetUnavailable(string reason) =>
            (null, Error(request.Meta, ErrorCategory.Resource, "budget_unavailable", reason));

        (RunLaunchSpec?, ArcError?) Unsupported(string reason) =>
            (null, Error(request.Meta, ErrorCategory.Execution, "unsupported_combination", reason));
    }

    private static bool AddRunEnvironment(Dictionary<string, EnvironmentEntry> merged, IEnumerable<EnvironmentEntry> entries)
    {
        var names = new HashSet<string>(merged.Comparer);
        foreach (var entry in entries)
        {
            if (entry.Name.Length is < 1 or > 256 || entry.Name.Contains('=') || entry.Name.Contains('\0')
                || !names.Add(entry.Name) || entry.HasValue == entry.HasSecretRef
                || (entry.HasValue && (entry.Value.Contains('\0') || Encoding.UTF8.GetByteCount(entry.Value) > 32_768))
                || entry.Name.StartsWith("ARCFORGES_", StringComparison.OrdinalIgnoreCase)
                || entry.Name.StartsWith("MXC_", StringComparison.OrdinalIgnoreCase)
                || entry.Name.StartsWith("BWRAP_", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            merged[entry.Name] = entry;
        }

        return true;
    }

    private static (string Path, string Identity) ResolveRunWorkingDirectory(string value, SandboxPrivateRootLease root,
        SandboxConfig config, StringComparison comparison)
    {
        var absolute = Path.IsPathFullyQualified(value);
        var path = absolute ? NormalizeAbsoluteRunPath(value)
            : Path.Combine([root.RootPath, .. WorkspacePath.Components(value)]);
        var anchors = absolute ? config.HostGrants.Select(grant => grant.HostPath) : root.WritablePaths;
        var grant = FindRunPathAnchor(path, anchors, comparison);
        var anchor = absolute ? grant : root.RootPath;
        using var directory = WorkspacePath.OpenRoot(anchor);
        var relative = path.Equals(anchor, comparison) ? "" : Path.GetRelativePath(anchor, path).Replace(Path.DirectorySeparatorChar, '/');
        return BindCanonicalRunPath(directory.OpenDirectory(relative), path, comparison, directory: true);
    }

    private static (string Path, string Identity) ResolveRunExecutable(string value, string workdir, SandboxPrivateRootLease root,
        SandboxConfig config, bool windows, StringComparison comparison)
    {
        var system = windows ? Environment.SystemDirectory : "/usr/bin";
        string path;
        if (Path.IsPathFullyQualified(value))
        {
            path = NormalizeAbsoluteRunPath(value);
        }
        else
        {
            var relative = windows ? value.Replace('\\', '/') : value;
            if (relative.StartsWith("./", StringComparison.Ordinal))
            {
                relative = relative[2..];
            }

            var native = Path.Combine(WorkspacePath.Components(relative));
            bool bareName = relative == value && !relative.Contains('/');
            path = bareName ? Path.Combine(system, windows && !Path.HasExtension(native) ? native + ".exe" : native)
                : Path.Combine(workdir, native);
        }

        // The registered Linux runtime paths include both /bin and /usr/bin. A distribution alias must
        // resolve to the admitted system directory before changing the executable spelling.
        if (!windows && RunPathAtOrBelow(path, "/bin", comparison))
        {
            var alias = Directory.ResolveLinkTarget("/bin", returnFinalTarget: true);
            if (alias is null)
            {
                system = "/bin";
            }
            else if (alias.FullName == system)
            {
                path = Path.Combine(system, Path.GetRelativePath("/bin", path));
            }
            else
            {
                throw new WorkspacePathException("run_system_directory_identity_changed");
            }
        }

        var inRuntime = RunPathAtOrBelow(path, system, comparison);
        var inPrivateRoot = root.WritablePaths.Any(candidate => RunPathAtOrBelow(path, candidate, comparison));
        var anchor = inRuntime ? system : inPrivateRoot ? root.RootPath
            : FindRunPathAnchor(path, config.HostGrants.Select(grant => grant.HostPath), comparison);
        if (inRuntime && !windows && File.ResolveLinkTarget(path, returnFinalTarget: true) is { } systemAlias)
        {
            path = NormalizeAbsoluteRunPath(systemAlias.FullName);
            _ = FindRunPathAnchor(path, [system], comparison);
        }

        var directoryPath = path.Equals(anchor, comparison) ? Path.GetDirectoryName(anchor)! : anchor;
        using var directory = WorkspacePath.OpenRoot(directoryPath);
        var relativePath = Path.GetRelativePath(directoryPath, path).Replace(Path.DirectorySeparatorChar, '/');
        if (OperatingSystem.IsWindows() && windows && inRuntime)
        {
            return BindWindowsSystemExecutable(directory, relativePath, path, comparison);
        }

        var target = directory.OpenRead(relativePath);
        if (inRuntime)
        {
            WorkspacePath.CheckMxcTrustedObject(directory.RootHandle, systemOnly: !windows);
            WorkspacePath.CheckMxcTrustedObject(target, systemOnly: !windows);
        }

        return BindCanonicalRunPath(target, path, comparison, directory: false);
    }

    [SupportedOSPlatform("windows")]
    private static (string Path, string Identity) BindWindowsSystemExecutable(WorkspacePath directory, string relative,
        string path, StringComparison comparison)
    {
        WorkspacePath.CheckMxcTrustedObject(directory.RootHandle);
        var entry = directory.InspectEntry(relative);
        if (entry.Kind != WorkspaceEntryType.File || entry.Identity.Links == 0)
        {
            throw new WorkspacePathException("run_system_executable_not_regular");
        }

        const uint readAttributes = 0x80;
        const uint openExisting = 3;
        const uint openReparsePoint = 0x00200000;
        using var held = OpenRunSystemExecutable(path, readAttributes, FileShare.Read, 0, openExisting, openReparsePoint, 0);
        if (held.IsInvalid)
        {
            throw new WorkspacePathException("native_" + Marshal.GetLastPInvokeError().ToString(CultureInfo.InvariantCulture));
        }

        var identity = WorkspacePath.Identity(held);
        if (!identity.IsFile || identity.Links == 0 || !entry.Identity.SameObject(identity))
        {
            throw new WorkspacePathException("run_system_executable_identity_changed");
        }

        var canonical = RequireCanonicalRunPath(held, path, comparison);
        WorkspacePath.CheckMxcTrustedObject(held);

        // Protected executables under SystemDirectory can have Windows servicing links.
        // Encode their actual FILE_ID_INFO and FILETIME with the same Windows grant layout.
        Span<byte> bytes = stackalloc byte[33];
        bytes[0] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(bytes[1..9], identity.Volume);
        BinaryPrimitives.WriteUInt64BigEndian(bytes[9..17], identity.Low);
        BinaryPrimitives.WriteUInt64BigEndian(bytes[17..25], identity.High);
        BinaryPrimitives.WriteUInt64BigEndian(bytes[25..33], identity.Created);
        return (canonical, "1:" + Convert.ToHexStringLower(bytes));
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeFileHandle OpenRunSystemExecutable(string name, uint access, FileShare share, nint security,
        uint disposition, uint flags, nint template);

    private static (string Path, string Identity) BindCanonicalRunPath(SafeFileHandle handle, string path,
        StringComparison comparison, bool directory)
    {
        var canonical = RequireCanonicalRunPath(handle, path, comparison);
        var native = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(handle), directory);
        return (canonical, FormattableString.Invariant($"{native.Platform}:{Convert.ToHexStringLower(native.Bytes)}"));
    }

    private static string RequireCanonicalRunPath(SafeFileHandle handle, string path, StringComparison comparison)
    {
        var canonical = WorkspacePath.CanonicalMxcGrantPath(handle, path);
        if (!canonical.Equals(path, comparison))
        {
            throw new WorkspacePathException("run_path_identity_changed");
        }

        return canonical;
    }

    private static string NormalizeAbsoluteRunPath(string path)
    {
        var volume = Path.GetPathRoot(path) ?? throw new WorkspacePathException("run_path_not_absolute");
        var relative = path[volume.Length..].Replace(Path.DirectorySeparatorChar, '/');
        return relative.Length == 0 ? volume : Path.Combine([volume, .. WorkspacePath.Components(relative)]);
    }

    private static string FindRunPathAnchor(string path, IEnumerable<string> roots, StringComparison comparison) =>
        roots.Where(candidate => RunPathAtOrBelow(path, candidate, comparison)).OrderByDescending(candidate => candidate.Length)
            .FirstOrDefault() ?? throw new WorkspacePathException("run_path_outside_profile");

    private static bool RunPathAtOrBelow(string path, string root, StringComparison comparison) =>
        path.Equals(root, comparison) || (path.Length > root.Length && path.StartsWith(root, comparison)
            && (Path.EndsInDirectorySeparator(root) || path[root.Length] == Path.DirectorySeparatorChar));
}
