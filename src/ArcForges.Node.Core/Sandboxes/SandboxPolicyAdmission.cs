// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using ArcForges.Contracts.Foundation.Serialization;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Contracts.Sandbox.V2.Serialization;
using ArcForges.Contracts.Sandbox.V2.Shapes;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform.Capabilities;
using Google.Protobuf;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed record SandboxPolicyResult(MxcAdmissionResult Admission, SandboxConfig? Config)
{
    internal MxcHostFacts? Host { get; init; }
}

internal static class SandboxPolicyAdmission
{
    private const string Windows = MxcProfileAdmission.WindowsProfileId;
    private const string Linux = MxcProfileAdmission.LinuxProfileId;
    // The initial local retention policy uses the documented 64 MiB default as its ceiling.
    // An explicit smaller cap is carried unchanged for the Run output owner.
    internal const ulong DefaultOutputRetentionBytes = 64 * 1024 * 1024;

    internal static SandboxPolicyResult Evaluate(SandboxConfig config, string dataRoot) =>
        Evaluate(config, dataRoot, SandboxPolicyHost.InstallationRoot);

    internal static SandboxPolicyResult Evaluate(SandboxConfig config, string dataRoot, string installationRoot) =>
        Evaluate(config, dataRoot, installationRoot, MxcTerminalMode.Interactive);

    internal static SandboxPolicyResult Evaluate(SandboxConfig config, string dataRoot, string installationRoot, MxcTerminalMode terminal)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (!ContractShapeValidation.IsValid(config)
            || config.Network is null || config.Resources is null)
        {
            return Refuse(config, "configuration", "sandbox_configuration_invalid");
        }

        byte[] encoded;
        try
        {
            encoded = V2Wire.Encode(config);
        }
        catch (ContractSerializationException)
        {
            return Refuse(config, "configuration", "sandbox_configuration_invalid");
        }
        var prepared = SandboxConfig.Parser.WithDiscardUnknownFields(true).ParseFrom(encoded);
        if (!encoded.AsSpan().SequenceEqual(V2Wire.Encode(prepared)))
        {
            return Refuse(config, "configuration", "unknown_policy_fields");
        }

        var (mode, networkError) = RequestNetwork(config.Network, config.ProfileId == Windows);
        if (networkError is not null)
        {
            return Refuse(config, "network", networkError, MxcEvidenceStatus.Unsupported);
        }

        if (!ResourcesValid(config.Resources))
        {
            return Refuse(config, "resources", "resource_policy_outside_node_bounds");
        }

        if (config.HasOutputRetentionBytes && config.OutputRetentionBytes > DefaultOutputRetentionBytes)
        {
            return Refuse(config, "resources.output_retention", "output_retention_outside_node_bounds");
        }

        if (!EnvironmentValid(config))
        {
            return Refuse(config, "environment", "invalid_duplicate_or_reserved_environment_name");
        }

        if (config.HasDefaultWorkdir && !SafeWorkdir(config.DefaultWorkdir))
        {
            return Refuse(config, "files.default_workdir", "private_working_directory_required");
        }

        var request = Request(config.ProfileId, config.ProfileVersion, mode) with { Terminal = terminal };
        var receipt = MxcQualificationReceipt.Read(config.ProfileId);
        var staticResult = MxcProfileAdmission.Evaluate(request, null, receipt);
        if (staticResult.Decision != MxcAdmissionDecision.PrerequisiteMissing)
        {
            return new SandboxPolicyResult(staticResult, null);
        }

        try
        {
            if (!BindHostGrants(prepared, dataRoot, installationRoot))
            {
                return Refuse(config, "files.host_grants", "host_grant_unavailable_or_unsafe");
            }
        }
        catch (Exception error) when (SandboxPolicyHost.IsDiscoveryFailure(error))
        {
            return Refuse(config, "files.host_grants", "host_grant_unavailable_or_unsafe");
        }

        var host = SandboxPolicyHost.Read(dataRoot, installationRoot);
        var admission = EvaluateHost(request, host, receipt, installationRoot);
        return new SandboxPolicyResult(admission, admission.Admitted ? prepared : null)
        {
            Host = admission.Admitted ? host : null,
        };
    }

    internal static IReadOnlyList<Capability> Capabilities(MxcAdmissionResult result)
    {
        var state = result.Admitted ? CapabilityState.Available
            : result.Decision == MxcAdmissionDecision.UnsupportedCombination ? CapabilityState.Unsupported
            : CapabilityState.Unverified;
        var capabilities = new List<Capability>
        {
            Capability("mxc.profile", state, result.Admitted ? null : result.Reason, result.EvidenceId),
        };
        if (result.Admitted)
        {
            capabilities.Add(Capability("mxc.network.observation", Observation(result.NetworkEvidence),
                result.NetworkEvidenceScope ?? (result.NetworkEvidence == MxcEvidenceStatus.Unverified
                    ? "external_selected_egress_unverified" : null), result.EvidenceId));
            capabilities.Add(Capability("mxc.terminal.observation", Observation(result.TerminalEvidence),
                result.TerminalEvidence == MxcEvidenceStatus.Unverified ? "explicit_pipes_composition_unverified" : null,
                result.EvidenceId));
        }

        return capabilities;
    }

    internal static IReadOnlyList<Capability> HandshakeCapabilities(string dataRoot) =>
        HandshakeCapabilities(dataRoot, SandboxPolicyHost.InstallationRoot);

    internal static IReadOnlyList<Capability> HandshakeCapabilities(string dataRoot, string installationRoot)
    {
        var profile = OperatingSystem.IsWindows() ? Windows : OperatingSystem.IsLinux() ? Linux : null;
        if (profile is null)
        {
            return [Capability("mxc.profile", CapabilityState.Unsupported, "operating_system_not_supported", null)];
        }

        var windows = profile == Windows;
        var receipt = MxcQualificationReceipt.Read(profile);
        var host = SandboxPolicyHost.Read(dataRoot, installationRoot);
        var revision = windows ? MxcProfileAdmission.WindowsProfileRevision : MxcProfileAdmission.LinuxProfileRevision;
        var baselineRequest = Request(profile, revision, MxcNetworkMode.DefaultDeny);
        var baseline = EvaluateHost(baselineRequest, host, receipt, installationRoot);
        var pipes = EvaluateHost(baselineRequest with { Terminal = MxcTerminalMode.Pipes }, host, receipt, installationRoot);
        var selected = EvaluateHost(Request(profile, revision,
            windows ? MxcNetworkMode.WindowsExternalSelectedTcpUdp : MxcNetworkMode.LinuxSelectedIpv4), host, receipt, installationRoot);
        var capabilities = new List<Capability>(Capabilities(baseline))
        {
            Capability("mxc.network.selected_egress.support", CapabilityState.Available,
                windows ? "official_mxc_1_0_1_external_tcp_udp" : "official_mxc_1_0_1_literal_ipv4_tcp_udp", null),
            Capability("mxc.network.selected_egress.observation",
                selected.Admitted ? Observation(selected.NetworkEvidence) : CapabilityState.Unverified,
                selected.NetworkEvidenceScope ?? selected.Reason, selected.EvidenceId),
            Capability("mxc.terminal.pipes.support", CapabilityState.Available, "official_explicit_pipes", null),
            Capability("mxc.terminal.pipes.observation", pipes.Admitted ? Observation(pipes.TerminalEvidence)
                : CapabilityState.Unverified, pipes.Reason, pipes.EvidenceId),
            Capability("mxc.network.ingress", CapabilityState.Unsupported,
                "host_ingress_not_admitted_by_product_profile", null),
        };

        AddNativePrerequisites(capabilities, host, windows);
        return capabilities;
    }

    private static void AddNativePrerequisites(List<Capability> capabilities, MxcHostFacts? host, bool windows)
    {
        if (windows)
        {
            Add("mxc.resources.windows.nested_job", MxcPrerequisites.WindowsNestedJob);
        }
        else
        {
            Add("mxc.resources.linux.user_manager", MxcPrerequisites.LinuxUserManager);
            Add("mxc.resources.linux.cgroup_v2", MxcPrerequisites.LinuxCgroupV2);
            Add("mxc.resources.linux.cpu", MxcPrerequisites.LinuxCpuController);
            Add("mxc.resources.linux.memory", MxcPrerequisites.LinuxMemoryController);
            Add("mxc.resources.linux.pids", MxcPrerequisites.LinuxPidsController);
        }

        void Add(string key, MxcPrerequisites requirement)
        {
            var state = host is null ? CapabilityState.Unverified
                : (host.Prerequisites & requirement) != 0 ? CapabilityState.Available
                : CapabilityState.Disabled;
            var reason = state switch
            {
                CapabilityState.Unverified => "current_host_facts_missing",
                CapabilityState.Disabled => "required_host_prerequisite_missing",
                _ => null,
            };
            capabilities.Add(Capability(key, state, reason, null));
        }
    }

    private static MxcAdmissionResult EvaluateHost(MxcProfileRequest request, MxcHostFacts? host, byte[] receipt, string installationRoot)
    {
        var result = MxcProfileAdmission.Evaluate(request, host, receipt);
        if (result.Decision != MxcAdmissionDecision.PrerequisiteMissing)
        {
            return result;
        }

        if (host is null)
        {
            return result with
            {
                Feature = "installation",
                Reason = Directory.Exists(installationRoot)
                ? "official_mxc_installation_untrusted_or_unreadable" : "official_mxc_installation_missing"
            };
        }

        return (host.Prerequisites & MxcPrerequisites.ProtectedInstallation) == 0
            ? result with
            {
                Decision = MxcAdmissionDecision.EvidenceMismatch,
                Feature = "installation.native_members",
                Reason = "installed_mxc_artifacts_mismatch"
            }
            : result;
    }

    private static MxcProfileRequest Request(string profile, string revision, MxcNetworkMode network) =>
        new(profile, revision, MxcTerminalMode.Interactive, MxcFilePolicy.OwnedRootWithExplicitGrants, network,
            MxcEnvironmentPolicy.CleanExplicit, MxcResourcePolicy.CpuMemoryAndProcessCount,
            MxcRecoveryPolicy.AuthenticatedOwner);

    private static SandboxPolicyResult Refuse(SandboxConfig config, string feature, string reason,
        MxcEvidenceStatus network = MxcEvidenceStatus.Unverified) =>
        new(new MxcAdmissionResult(MxcAdmissionDecision.UnsupportedCombination, config.ProfileId, config.ProfileVersion,
            network, null, feature, reason), null);

    private static Capability Capability(string key, CapabilityState state, string? reason, string? evidence)
    {
        var item = new Capability { Key = key, State = state };
        if (reason is not null) item.Reason = reason;
        if (evidence is not null && state == CapabilityState.Available) item.EvidenceId = evidence;
        return item;
    }

    private static CapabilityState Observation(MxcEvidenceStatus evidence) => evidence switch
    {
        MxcEvidenceStatus.Verified => CapabilityState.Available,
        MxcEvidenceStatus.Unsupported => CapabilityState.Unsupported,
        _ => CapabilityState.Unverified,
    };

    private static (MxcNetworkMode Mode, string? Error) RequestNetwork(NetworkPolicy policy, bool windows)
    {
        // Egress is the default action, not a replacement for the explicit allow rules.
        // In particular an allow-default policy must never be narrowed to selected destinations.
        if (policy.Egress != NetworkMode.Deny)
        {
            return (MxcNetworkMode.Unspecified, "default_allow_egress_not_admitted");
        }

        if (policy.Ingress != NetworkMode.Deny || policy.HostLoopback)
        {
            return (MxcNetworkMode.Unspecified, windows ? "ingress_or_loopback_not_admitted"
                : "stable_bubblewrap_host_ingress_unavailable");
        }

        foreach (var destination in policy.AllowedDestinations)
        {
            if (!SelectedDestination(destination, windows))
            {
                return (MxcNetworkMode.Unspecified, "unsupported_selected_destination");
            }
        }

        return (policy.AllowedDestinations.Count == 0 ? MxcNetworkMode.DefaultDeny
            : windows ? MxcNetworkMode.WindowsExternalSelectedTcpUdp : MxcNetworkMode.LinuxSelectedIpv4, null);
    }

    // Product spelling for the backend's literal TCP/UDP rule, e.g. tcp://192.0.2.10:443,
    // udp://192.0.2.0/24:53 or tcp://[2001:db8::/64]:443. Stored rules keep original spelling/order.
    private static bool SelectedDestination(string rule, bool windows)
    {
        if (!(rule.StartsWith("tcp://", StringComparison.Ordinal) || rule.StartsWith("udp://", StringComparison.Ordinal)))
        {
            return false;
        }

        var endpoint = rule.AsSpan(6);
        var endOfHost = endpoint.LastIndexOf(':');
        if (endOfHost <= 0 || !ushort.TryParse(endpoint[(endOfHost + 1)..], NumberStyles.None,
                CultureInfo.InvariantCulture, out var port) || port == 0)
        {
            return false;
        }

        var target = endpoint[..endOfHost];
        var bracketed = target[0] == '[' && target[^1] == ']';
        if (bracketed)
        {
            target = target[1..^1];
        }

        var prefixAt = target.IndexOf('/');
        var addressText = prefixAt < 0 ? target : target[..prefixAt];
        if (addressText.Contains('%') || !IPAddress.TryParse(addressText, out var address))
        {
            return false;
        }

        var ipv4 = address.AddressFamily == AddressFamily.InterNetwork;
        if ((ipv4 && (bracketed || !addressText.SequenceEqual(address.ToString()))) ||
            (!ipv4 && (!windows || !bracketed)))
        {
            return false;
        }

        return prefixAt < 0 || (windows && byte.TryParse(target[(prefixAt + 1)..], NumberStyles.None,
            CultureInfo.InvariantCulture, out var prefix) && prefix <= (ipv4 ? 32 : 128));
    }

    private static bool ResourcesValid(ResourcePolicy resources)
    {
        var totalMemory = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
        var maxCpu = (ulong)Environment.ProcessorCount * 1_000;
        return resources.PressureAction is PressureAction.Throttle or PressureAction.StopPreemptible
            && !resources.HasHostReserveBytes && !resources.HasHostReserveMillicores
            && (!resources.HasCpuMaxMillicores || (resources.CpuMaxMillicores > 0 && resources.CpuMaxMillicores <= maxCpu))
            && (!resources.HasMemoryMaxBytes || (resources.MemoryMaxBytes > 0
                && totalMemory > 0 && resources.MemoryMaxBytes <= (ulong)totalMemory))
            && (!resources.HasExpectedMemoryBytes || (resources.ExpectedMemoryBytes > 0 && totalMemory > 0
                && resources.ExpectedMemoryBytes <= (resources.HasMemoryMaxBytes ? resources.MemoryMaxBytes : (ulong)totalMemory)))
            && (!resources.HasWeight || resources.Weight is >= 1 and <= 10_000)
            && (!resources.HasPriority || resources.Priority is >= -20 and <= 20)
            && (!resources.HasMaxConcurrentRuns || resources.MaxConcurrentRuns is >= 1 and <= 1_024);
    }

    private static bool EnvironmentValid(SandboxConfig config)
    {
        var names = new HashSet<string>(config.ProfileId == Windows ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        foreach (var item in config.Environment)
        {
            if (string.IsNullOrEmpty(item.Name) || item.Name.Contains('=') || item.Name.Contains('\0')
                || !names.Add(item.Name) || item.HasValue == item.HasSecretRef
                || (item.HasValue && (item.Value.Contains('\0') || Encoding.UTF8.GetByteCount(item.Value) > 32_768))
                || item.Name.StartsWith("ARCFORGES_", StringComparison.OrdinalIgnoreCase)
                || item.Name.StartsWith("MXC_", StringComparison.OrdinalIgnoreCase)
                || item.Name.StartsWith("BWRAP_", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }

    private static bool SafeWorkdir(string value)
    {
        if (value.Contains('\\') || value.Length == 0)
        {
            return false;
        }

        try
        {
            _ = WorkspacePath.Components(value);
            return true;
        }
        catch (WorkspacePathException)
        {
            return false;
        }
    }

    private static bool BindHostGrants(SandboxConfig policy, string dataRoot, string installationRoot)
    {
        if (policy.HostGrants.Count == 0)
        {
            return true;
        }

        var comparison = policy.ProfileId == Windows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        using var owned = WorkspacePath.OpenRoot(CanonicalPath(dataRoot));
        using var installed = WorkspacePath.OpenRoot(CanonicalPath(installationRoot));
        using var applicationDirectory = WorkspacePath.OpenRoot(CanonicalPath(AppContext.BaseDirectory));
        using var homeDirectory = WorkspacePath.OpenRoot(CanonicalPath(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)));
        var data = owned.RootPath;
        var installation = installed.RootPath;
        var application = applicationDirectory.RootPath;
        var home = homeDirectory.RootPath;
        var grants = new List<HostGrant>();
        foreach (var grant in policy.HostGrants)
        {
            if (!grant.HasWritable || !Path.IsPathFullyQualified(grant.HostPath)
                || !Path.IsPathFullyQualified(grant.SandboxPath))
            {
                return false;
            }

            var requested = CanonicalPath(grant.HostPath);
            var presented = CanonicalPath(grant.SandboxPath);
            var parent = Path.GetDirectoryName(requested);
            if (parent is null || !requested.Equals(grant.HostPath, comparison)
                || !presented.Equals(grant.SandboxPath, comparison) || !requested.Equals(presented, comparison)
                || Overlap(requested, data, comparison) || Overlap(requested, installation, comparison)
                || Overlap(requested, application, comparison) || AtOrBelow(home, requested, comparison))
            {
                return false;
            }

            using var held = WorkspacePath.OpenRoot(parent);
            var child = Path.GetFileName(requested);
            var entry = held.InspectEntry(child);
            if (entry.Kind is not (WorkspaceEntryType.File or WorkspaceEntryType.Directory))
            {
                return false;
            }

            var directory = entry.Kind == WorkspaceEntryType.Directory;
            using var target = directory ? held.OpenDirectory(child) : held.OpenRead(child);
            var observed = WorkspacePath.Identity(target);
            var path = WorkspacePath.CanonicalMxcGrantPath(target, requested);
            if (!entry.Identity.SameObject(observed) || observed.Links == 0 || (!directory && observed.Links != 1)
                || !path.Equals(requested, comparison)
                || IsAlternateLinuxMount(observed, owned.RootIdentity)
                || IsAlternateLinuxMount(observed, installed.RootIdentity)
                || IsAlternateLinuxMount(observed, applicationDirectory.RootIdentity)
                || Overlap(path, data, comparison) || Overlap(path, installation, comparison)
                || Overlap(path, application, comparison) || AtOrBelow(home, path, comparison))
            {
                return false;
            }

            var identity = RegisteredWorkspaces.RootIdentity.Encode(observed, directory);
            var native = identity.Platform.ToString(CultureInfo.InvariantCulture) + ":" + Convert.ToHexStringLower(identity.Bytes);
            if ((grant.HasNativeIdentity && !grant.NativeIdentity.Equals(native, StringComparison.Ordinal))
                || grants.Any(prior => prior.NativeIdentity == native || (prior.Writable != grant.Writable
                    && Overlap(prior.HostPath, path, comparison))))
            {
                return false;
            }

            grant.NativeIdentity = native;
            grants.Add(grant);
        }

        return true;
    }

    private static bool IsAlternateLinuxMount(WorkspaceObjectIdentity target, WorkspaceObjectIdentity protectedRoot) =>
        OperatingSystem.IsLinux() && target.Volume == protectedRoot.Volume && target.High != protectedRoot.High;

    private static string CanonicalPath(string path) => Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
    private static bool Overlap(string first, string other, StringComparison comparison) =>
        AtOrBelow(first, other, comparison) || AtOrBelow(other, first, comparison);
    private static bool AtOrBelow(string path, string root, StringComparison comparison) =>
        path.Equals(root, comparison) || (path.Length > root.Length && path.StartsWith(root, comparison)
            && (Path.EndsInDirectorySeparator(root) || path[root.Length] == Path.DirectorySeparatorChar || path[root.Length] == Path.AltDirectorySeparatorChar));
}
