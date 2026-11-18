// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Node.Platform.Capabilities;

public enum MxcTerminalMode
{
    Unspecified,
    Interactive,
    Pipes,
}

public enum MxcFilePolicy
{
    Unspecified,
    OwnedRootWithExplicitGrants,
    PathRemapping,
    UnrestrictedHostFiles,
}

public enum MxcNetworkMode
{
    Unspecified,
    DefaultDeny,
    LinuxSelectedIpv4,
    WindowsExternalSelectedTcpUdp,
    HostIngress,
    Ipv6,
    SharedHostNetwork,
}

public enum MxcEnvironmentPolicy
{
    Unspecified,
    CleanExplicit,
    InheritHost,
}

public enum MxcResourcePolicy
{
    Unspecified,
    CpuMemoryAndProcessCount,
    ObserveOnly,
}

public enum MxcRecoveryPolicy
{
    Unspecified,
    AuthenticatedOwner,
    ReattachAcrossReboot,
}

[Flags]
public enum MxcPrerequisites
{
    None = 0,
    ProtectedInstallation = 1 << 0,
    PrivateControlPaths = 1 << 1,
    WindowsNativeDenyPaths = 1 << 2,
    WindowsConPty = 1 << 3,
    WindowsNestedJob = 1 << 4,
    LinuxBubblewrap = 1 << 5,
    LinuxNamespaces = 1 << 6,
    LinuxPty = 1 << 7,
    LinuxUserManager = 1 << 8,
    LinuxCgroupV2 = 1 << 9,
    LinuxCpuController = 1 << 10,
    LinuxMemoryController = 1 << 11,
    LinuxPidsController = 1 << 12,
    LinuxSelectedNetworkHelpers = 1 << 13,
}

public enum MxcAdmissionDecision
{
    Unspecified,
    Admitted,
    UnsupportedCombination,
    EvidenceMissing,
    EvidenceMismatch,
    PrerequisiteMissing,
    Unverified,
}

public enum MxcEvidenceStatus
{
    Unspecified,
    Verified,
    Unverified,
    Unsupported,
}

/// <summary>A requested policy composition. The caller preserves the exact rules when compiling the official native request.</summary>
public sealed record MxcProfileRequest(
    string ProfileId,
    string ProfileRevision,
    MxcTerminalMode Terminal,
    MxcFilePolicy Files,
    MxcNetworkMode Network,
    MxcEnvironmentPolicy Environment,
    MxcResourcePolicy Resources,
    MxcRecoveryPolicy Recovery,
    bool RequireVerifiedNetwork = false,
    bool RequireLeastPrivilegeAppContainer = false,
    bool RequirePauseResume = false,
    bool RequireVerifiedTerminal = false);

/// <summary>
/// Current facts from trusted local platform discovery. Report native member hashes from verification of the installed files
/// against the protected installation manifest. Resolve and hash Linux helpers from the trusted helper search path.
/// Discover prerequisites independently of the qualification receipt and of any untrusted request.
/// </summary>
public sealed record MxcHostFacts(
    string RuntimeIdentifier,
    string OperatingSystem,
    string? KernelRelease,
    string? KernelVersion,
    string SdkVersion,
    string RequestSchemaVersion,
    string NativeSourceCommit,
    string PackageSha256,
    string ReleaseSha256,
    string Backend,
    IReadOnlyDictionary<string, string> NativeMemberSha256,
    MxcPrerequisites Prerequisites,
    string? SystemdUserManagerVersion = null,
    IReadOnlyDictionary<string, string>? LinuxHelperSha256 = null);

/// <summary>
/// The result of receipt and capability evaluation. <see cref="EvidenceId"/> identifies the registered profile receipt.
/// An unverified capability has no matching native observation in that receipt. The official preflight and pre-execution
/// resource readback still run for each launch. <see cref="NetworkEvidenceScope"/> bounds the observed network effects.
/// </summary>
public sealed record MxcAdmissionResult(
    MxcAdmissionDecision Decision,
    string ProfileId,
    string? ProfileRevision,
    MxcEvidenceStatus NetworkEvidence,
    string? EvidenceId,
    string? Feature,
    string? Reason,
    MxcPrerequisites MissingPrerequisites = MxcPrerequisites.None,
    MxcEvidenceStatus TerminalEvidence = MxcEvidenceStatus.Unverified,
    string? NetworkEvidenceScope = null)
{
    public bool Admitted => Decision == MxcAdmissionDecision.Admitted;
}
