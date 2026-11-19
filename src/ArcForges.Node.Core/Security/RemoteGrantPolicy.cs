// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Sandboxes;
using ArcForges.Node.Platform.Capabilities;

namespace ArcForges.Node.Core.Security;

internal enum RemoteGrantAction
{
    None,
    GetOperation,
    WatchEvents,
    ListRemoteGrants,
    RevokeRemoteGrant,
    SandboxCreate,
    SandboxConfigure,
    SandboxList,
    SandboxInspect,
    SandboxPlanDelete,
    SandboxDelete,
    RunStart,
    RunList,
    RunInspect,
    RunStop,
    RunWatchOutput,
    ResourceGetBudget,
    ResourceSetPolicy,
    ResourceWatchUsage,
    DataGetUsage,
    DataListEntries,
    DataBeginImport,
    DataWriteImport,
    DataCommitImport,
    DataBeginExport,
    DataReadExport,
    DataInspectTransfer,
    DataCloseTransfer,
}

/// <summary>Recognizes the published V2 grant methods and compares a replacement policy with locally authorized bounds.</summary>
internal static class RemoteGrantPolicy
{
    private const string Node = "/arcforges.sandbox.v2.NodeService/";
    private const string Sandbox = "/arcforges.sandbox.v2.SandboxService/";
    private const string Run = "/arcforges.sandbox.v2.RunService/";
    private const string Resource = "/arcforges.sandbox.v2.ResourceService/";
    private const string Data = "/arcforges.sandbox.v2.DataService/";

    [Flags]
    private enum GrantUse
    {
        None = 0,
        Sandbox = 1,
        Provision = 2,
        Data = 4,
        Delete = 8,
    }

    private const GrantUse AnyScope = GrantUse.Sandbox | GrantUse.Provision;
    private const GrantUse DataScope = GrantUse.Sandbox | GrantUse.Data;
    private const GrantUse DeleteScope = GrantUse.Sandbox | GrantUse.Delete;

    private static readonly Dictionary<string, (RemoteGrantAction Action, GrantUse Use)> Methods = new(StringComparer.Ordinal)
    {
        [Node + "GetOperation"] = (RemoteGrantAction.GetOperation, AnyScope),
        [Node + "WatchEvents"] = (RemoteGrantAction.WatchEvents, GrantUse.Sandbox),
        [Node + "ListRemoteGrants"] = (RemoteGrantAction.ListRemoteGrants, AnyScope),
        [Node + "RevokeRemoteGrant"] = (RemoteGrantAction.RevokeRemoteGrant, AnyScope),
        [Sandbox + "Create"] = (RemoteGrantAction.SandboxCreate, GrantUse.Provision),
        [Sandbox + "Configure"] = (RemoteGrantAction.SandboxConfigure, GrantUse.Sandbox),
        [Sandbox + "List"] = (RemoteGrantAction.SandboxList, GrantUse.Sandbox),
        [Sandbox + "Inspect"] = (RemoteGrantAction.SandboxInspect, GrantUse.Sandbox),
        [Sandbox + "PlanDelete"] = (RemoteGrantAction.SandboxPlanDelete, DeleteScope),
        [Sandbox + "Delete"] = (RemoteGrantAction.SandboxDelete, DeleteScope),
        [Run + "Start"] = (RemoteGrantAction.RunStart, GrantUse.Sandbox),
        [Run + "List"] = (RemoteGrantAction.RunList, GrantUse.Sandbox),
        [Run + "Inspect"] = (RemoteGrantAction.RunInspect, GrantUse.Sandbox),
        [Run + "Stop"] = (RemoteGrantAction.RunStop, GrantUse.Sandbox),
        [Run + "WatchOutput"] = (RemoteGrantAction.RunWatchOutput, GrantUse.Sandbox),
        [Resource + "GetBudget"] = (RemoteGrantAction.ResourceGetBudget, GrantUse.Sandbox),
        [Resource + "SetPolicy"] = (RemoteGrantAction.ResourceSetPolicy, GrantUse.Sandbox),
        [Resource + "WatchUsage"] = (RemoteGrantAction.ResourceWatchUsage, GrantUse.Sandbox),
        [Data + "GetUsage"] = (RemoteGrantAction.DataGetUsage, DataScope),
        [Data + "ListEntries"] = (RemoteGrantAction.DataListEntries, DataScope),
        [Data + "BeginImport"] = (RemoteGrantAction.DataBeginImport, DataScope),
        [Data + "WriteImport"] = (RemoteGrantAction.DataWriteImport, DataScope),
        [Data + "CommitImport"] = (RemoteGrantAction.DataCommitImport, DataScope),
        [Data + "BeginExport"] = (RemoteGrantAction.DataBeginExport, DataScope),
        [Data + "ReadExport"] = (RemoteGrantAction.DataReadExport, DataScope),
        [Data + "InspectTransfer"] = (RemoteGrantAction.DataInspectTransfer, DataScope),
        [Data + "CloseTransfer"] = (RemoteGrantAction.DataCloseTransfer, DataScope),
    };

    internal static bool TryGetAction(string? method, out RemoteGrantAction action)
    {
        if (method is not null && Methods.TryGetValue(method, out var descriptor))
        {
            action = descriptor.Action;
            return true;
        }

        action = RemoteGrantAction.None;
        return false;
    }

    internal static bool HasValidMethods(RemoteGrant grant)
    {
        // A provisioning grant can specify methods that become callable only on its derived Sandbox scope.
        var scopes = grant.ScopeKind switch
        {
            "sandbox" => GrantUse.Sandbox,
            "provision" => AnyScope,
            _ => GrantUse.None,
        };
        return scopes != GrantUse.None && grant.Methods.Count <= Methods.Count
            && grant.Methods.Distinct(StringComparer.Ordinal).Count() == grant.Methods.Count
            && grant.Methods.All(method => Methods.TryGetValue(method, out var descriptor)
                && AllowsUse(grant, scopes, descriptor.Use));
    }

    // This is the method check only. The Core operation must also authorize its exact target and resolve
    // its request-specific restrictions (such as no remote ERROR repair or delete resume).
    internal static bool IsAllowed(RemoteGrant grant, RemoteGrantAction action)
    {
        var scope = grant.ScopeKind switch
        {
            "sandbox" => GrantUse.Sandbox,
            "provision" => GrantUse.Provision,
            _ => GrantUse.None,
        };
        return grant.Methods.Any(method => Methods.TryGetValue(method, out var descriptor)
            && descriptor.Action == action && AllowsUse(grant, scope, descriptor.Use));
    }

    internal static string[] ProjectChildMethods(RemoteGrant provision) =>
        provision.ScopeKind == "provision"
            ? [.. provision.Methods.Where(method => Methods.TryGetValue(method, out var descriptor)
                && AllowsUse(provision, GrantUse.Sandbox, descriptor.Use))]
            : [];

    private static bool AllowsUse(RemoteGrant grant, GrantUse scopes, GrantUse method) =>
        (scopes & method) != 0
        && ((method & GrantUse.Data) == 0 || grant.AllowData)
        && ((method & GrantUse.Delete) == 0 || grant.AllowDelete);

    internal static bool IsNarrower(SandboxConfig candidate, SandboxConfig ceiling) =>
        PolicyWithin(candidate, ceiling) && HostGrantsWithin(candidate, ceiling, bindMissingIdentity: false);

    /// <summary>
    /// Copies the trusted template identity into each requested native grant before current host policy validation.
    /// Caller-supplied identities, when present, must match the same template entry. Revalidate each held object normally.
    /// </summary>
    internal static bool TryPrepareNarrowing(SandboxConfig candidate, SandboxConfig ceiling,
        [NotNullWhen(true)] out SandboxConfig? prepared)
    {
        prepared = null;
        if (!PolicyWithin(candidate, ceiling))
        {
            return false;
        }

        var copy = candidate.Clone();
        if (!HostGrantsWithin(copy, ceiling, bindMissingIdentity: true))
        {
            return false;
        }

        prepared = copy;
        return true;
    }

    internal static bool ResourcesWithin(ResourcePolicy candidate, ResourcePolicy ceiling) =>
        !candidate.HasHostReserveBytes && !candidate.HasHostReserveMillicores
        && !ceiling.HasHostReserveBytes && !ceiling.HasHostReserveMillicores
        && WithinLimit(candidate.HasCpuMaxMillicores ? candidate.CpuMaxMillicores : null,
            ceiling.HasCpuMaxMillicores ? ceiling.CpuMaxMillicores : null)
        && WithinLimit(candidate.HasMemoryMaxBytes ? candidate.MemoryMaxBytes : null,
            ceiling.HasMemoryMaxBytes ? ceiling.MemoryMaxBytes : null)
        && WithinLimit(candidate.HasMaxConcurrentRuns ? candidate.MaxConcurrentRuns : null,
            ceiling.HasMaxConcurrentRuns ? ceiling.MaxConcurrentRuns : null)
        // These values affect scheduling or pressure rather than acting as upper bounds.
        && candidate.HasWeight == ceiling.HasWeight && candidate.Weight == ceiling.Weight
        && candidate.HasPriority == ceiling.HasPriority && candidate.Priority == ceiling.Priority
        && candidate.HasExpectedMemoryBytes == ceiling.HasExpectedMemoryBytes && candidate.ExpectedMemoryBytes == ceiling.ExpectedMemoryBytes
        && candidate.HasPressureAction == ceiling.HasPressureAction && candidate.PressureAction == ceiling.PressureAction
        && candidate.Preemptible == ceiling.Preemptible;

    private static bool WithinLimit(ulong? candidate, ulong? ceiling)
    {
        // Omitting a template cap would restore the wider Node defaults.
        return ceiling is null ? candidate is null or > 0 : candidate > 0 && candidate <= ceiling;
    }

    private static bool PolicyWithin(SandboxConfig candidate, SandboxConfig ceiling) =>
        candidate.HasProfileId && candidate.HasProfileVersion
        && StringComparer.Ordinal.Equals(candidate.ProfileId, ceiling.ProfileId)
        && StringComparer.Ordinal.Equals(candidate.ProfileVersion, ceiling.ProfileVersion)
        && candidate.HasDefaultWorkdir == ceiling.HasDefaultWorkdir
        && StringComparer.Ordinal.Equals(candidate.DefaultWorkdir, ceiling.DefaultWorkdir)
        && (candidate.HasOutputRetentionBytes ? candidate.OutputRetentionBytes : SandboxPolicyAdmission.DefaultOutputRetentionBytes)
            <= (ceiling.HasOutputRetentionBytes ? ceiling.OutputRetentionBytes : SandboxPolicyAdmission.DefaultOutputRetentionBytes)
        && candidate.Resources is { } resources && ceiling.Resources is { } bounds && ResourcesWithin(resources, bounds)
        && candidate.Network is { } network && ceiling.Network is { } networkBounds && NetworkWithin(network, networkBounds)
        && EnvironmentWithin(candidate, ceiling);

    private static bool NetworkWithin(NetworkPolicy candidate, NetworkPolicy ceiling) =>
        AllowsNoMoreTraffic(candidate.Egress, ceiling.Egress)
        && AllowsNoMoreTraffic(candidate.Ingress, ceiling.Ingress)
        && (!candidate.HostLoopback || ceiling.HostLoopback)
        && candidate.AllowedDestinations.All(rule => ceiling.AllowedDestinations.Contains(rule, StringComparer.Ordinal));

    private static bool AllowsNoMoreTraffic(NetworkMode candidate, NetworkMode ceiling) =>
        ceiling is NetworkMode.Deny or NetworkMode.Allow
        && (candidate == NetworkMode.Deny || (candidate == NetworkMode.Allow && ceiling == NetworkMode.Allow));

    private static bool EnvironmentWithin(SandboxConfig candidate, SandboxConfig ceiling)
    {
        var names = PolicyNameComparer(candidate);
        return candidate.Environment.All(entry => entry.HasName && entry.HasValue != entry.HasSecretRef
            && ceiling.Environment.Any(allowed => names.Equals(allowed.Name, entry.Name)
                && allowed.HasValue == entry.HasValue && StringComparer.Ordinal.Equals(allowed.Value, entry.Value)
                && allowed.HasSecretRef == entry.HasSecretRef && StringComparer.Ordinal.Equals(allowed.SecretRef, entry.SecretRef)));
    }

    private static bool HostGrantsWithin(SandboxConfig candidate, SandboxConfig ceiling, bool bindMissingIdentity)
    {
        var paths = PolicyNameComparer(candidate);
        foreach (var grant in candidate.HostGrants)
        {
            if (!(grant.HasHostPath && grant.HasSandboxPath && grant.HasWritable))
            {
                return false;
            }

            var allowed = ceiling.HostGrants.FirstOrDefault(entry =>
                entry.HasNativeIdentity && !string.IsNullOrEmpty(entry.NativeIdentity) && entry.HasWritable
                && paths.Equals(entry.HostPath, grant.HostPath) && paths.Equals(entry.SandboxPath, grant.SandboxPath)
                && (!grant.Writable || entry.Writable));
            if (allowed is null || (grant.HasNativeIdentity
                ? !StringComparer.Ordinal.Equals(grant.NativeIdentity, allowed.NativeIdentity)
                : !bindMissingIdentity))
            {
                return false;
            }

            if (bindMissingIdentity)
            {
                grant.NativeIdentity = allowed.NativeIdentity;
            }
        }

        return true;
    }

    private static StringComparer PolicyNameComparer(SandboxConfig config) =>
        config.ProfileId == MxcProfileAdmission.WindowsProfileId ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
}
