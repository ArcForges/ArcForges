// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;

namespace ArcForges.Node.Platform.Capabilities;

/// <summary>Evaluates the official MXC profiles registered by AFV2-MXC-04.</summary>
public static class MxcProfileAdmission
{
    public const string WindowsProfileId = "windows-process-executor-v1";
    public const string WindowsProfileRevision = "win-wrapper-local-v1";
    public const string LinuxProfileId = "linux-bubblewrap-sdk-v1";
    public const string LinuxProfileRevision = "linux-bubblewrap-sdk-v1";

    private const string SdkVersion = "1.0.1";
    private const string SchemaVersion = "1.0.0";
    private const string NativeSourceCommit = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2";
    private const string PackageSha256 = "d47b1f70c3fcaaed1705a0c3872807e2878fe8c1b778c0dd9eb9325bf421a672";
    private const string ReleaseSha256 = "0e832239454ba7fcd338ff56218a287eef4c0a01c1484084b869f55feff8abe9";

    private const string WindowsQualificationSha256 = "859e376019265796eba30037ddbeb75ebde9658396dd37d30b00ade7883fce4a";
    private const string LinuxQualificationSha256 = "1e863720b27a455bdf2f56b70d3dfd0da763e33c599cdd70a3a4f2f5a1c1380f";
    private const int MaximumReceiptBytes = 64 * 1024;
    private const string LinuxXtablesNftMultiSha256 = "4cf54664bf7bf3388186bfca48c065b5ff675961c78c5ee59fb9648e0e7602d9";

    private const MxcPrerequisites CommonPrerequisites =
        MxcPrerequisites.ProtectedInstallation | MxcPrerequisites.PrivateControlPaths;

    private const MxcPrerequisites WindowsPrerequisites =
        CommonPrerequisites | MxcPrerequisites.WindowsNativeDenyPaths | MxcPrerequisites.WindowsNestedJob;

    private const MxcPrerequisites LinuxPrerequisites = CommonPrerequisites | MxcPrerequisites.LinuxBubblewrap |
        MxcPrerequisites.LinuxNamespaces | MxcPrerequisites.LinuxUserManager | MxcPrerequisites.LinuxCgroupV2 |
        MxcPrerequisites.LinuxCpuController | MxcPrerequisites.LinuxMemoryController | MxcPrerequisites.LinuxPidsController;

    // These are the official native files in the verified stage. The historical stage manifest also
    // identifies the qualification probe, which is a different executable from the future product.
    private static readonly (string FileName, string Sha256)[] WindowsNativeFiles =
    [
        ("mxc_ffi.dll", "bd45522f06dc9cc8001dcd5d7320bc2bf303fb08a39bf10f3404bd9a8001812c"),
        ("plm.exe", "beffc9c9ab974ca9e7455089fd8ecb36eb8c92811ddd1705db91370a689692c3"),
        ("wslcsdk.dll", "8d4d55d4283fb32a5909b57e78b576d01363d7b28bb9b2595115e80faf61db5b"),
        ("wxc-exec.exe", "090f5d1f7bb93104ab08dcd4e8034ef954aeefcdaf6658dde5f7dff4cfc12f3a"),
        ("wxc-wslc-daemon.exe", "84f61c1bc13abde8da1c3f2ff100e6d59368ecaabdbfeca939e6fdb696202d0c"),
    ];

    private static readonly (string FileName, string Sha256)[] LinuxNativeFiles =
    [
        ("libmxc_ffi.so", "18a1cba8f2980af79570141c4eec9cd3982872162ae6b63634d45862913002bc"),
    ];

    private static readonly (string FileName, string Sha256)[] LinuxBaseHelpers =
    [
        ("bwrap", "573236e5328ac2ebb08f59ae3a9805b4f8d12bdef14be8af4450d5463294985f"),
        ("sh", "a6f559e00b69a4aa4d8cb607be18d9386c5aee55c509e2c075549dcf00e00fc7"),
    ];

    private static readonly (string FileName, string Sha256)[] LinuxSelectedNetworkHelpers =
    [
        ("slirp4netns", "c51b2fda8e64140d8856060e1e845542d99994882136fe7ef21a64325a486dda"),
        ("ip", "024784c6d16b183dc7c97d93a943a9270976f167f95f771e14d72442dc657f0c"),
        ("unshare", "d82900dfd64b5dd01493d206236575623c2dcf306c466dbe127e171c18cb4614"),
        ("nsenter", "14da23b43284fac1180840cf2742fc9d25b7d87da7ee5676b8ba487df3793609"),
        ("iptables", LinuxXtablesNftMultiSha256),
        ("ip6tables", LinuxXtablesNftMultiSha256),
        ("iptables-restore", LinuxXtablesNftMultiSha256),
        ("ip6tables-restore", LinuxXtablesNftMultiSha256),
    ];

    /// <summary>
    /// Evaluates a trusted local snapshot and the selected qualification receipt, without starting a workload.
    /// A successful result is specific to that snapshot and request. Pass fresh facts at launch and apply native preflight,
    /// resource membership and readback before releasing the payload.
    /// </summary>
    public static MxcAdmissionResult Evaluate(MxcProfileRequest request, MxcHostFacts? host, ReadOnlySpan<byte> receiptBytes)
    {
        ArgumentNullException.ThrowIfNull(request);

        var windows = request.ProfileId == WindowsProfileId;
        if (!windows && request.ProfileId != LinuxProfileId)
        {
            return new(MxcAdmissionDecision.UnsupportedCombination, request.ProfileId ?? string.Empty, null,
                MxcEvidenceStatus.Unverified, null, "profile.id", "profile_not_registered");
        }

        var revision = windows ? WindowsProfileRevision : LinuxProfileRevision;
        if (request.ProfileRevision != revision)
        {
            return Refuse(MxcAdmissionDecision.EvidenceMismatch, "profile.revision", "profile_revision_not_registered");
        }

        var (feature, reason) = UnsupportedPolicy(request, windows);
        if (reason is not null)
        {
            var network = feature == "network" ? MxcEvidenceStatus.Unsupported : MxcEvidenceStatus.Unverified;
            return Refuse(MxcAdmissionDecision.UnsupportedCombination, feature, reason, network);
        }

        var receiptHash = windows ? WindowsQualificationSha256 : LinuxQualificationSha256;
        if (receiptBytes.IsEmpty)
        {
            return Refuse(MxcAdmissionDecision.EvidenceMissing, "qualification.receipt", "qualification_receipt_missing");
        }

        if (receiptBytes.Length > MaximumReceiptBytes || Convert.ToHexStringLower(SHA256.HashData(receiptBytes)) != receiptHash)
        {
            return Refuse(MxcAdmissionDecision.EvidenceMismatch, "qualification.receipt", "qualification_receipt_not_registered");
        }

        var evidenceId = "sha256:" + receiptHash;
        if (host is null)
        {
            return Refuse(MxcAdmissionDecision.PrerequisiteMissing, "host.facts", "current_host_facts_missing",
                qualification: evidenceId);
        }

        var networkEvidence = request.Network == MxcNetworkMode.WindowsExternalSelectedTcpUdp
            ? MxcEvidenceStatus.Unverified
            : MxcEvidenceStatus.Verified;
        var terminalEvidence = request.Terminal == MxcTerminalMode.Pipes
            ? MxcEvidenceStatus.Unverified
            : MxcEvidenceStatus.Verified;
        var networkScope = request.Network switch
        {
            MxcNetworkMode.DefaultDeny when windows => "host_loopback_denial_tcp_composed_udp_standalone",
            MxcNetworkMode.DefaultDeny => "private_network_denial_tcp_composed_udp_standalone",
            MxcNetworkMode.LinuxSelectedIpv4 => "literal_ipv4_address_protocol_port_tcp_composed_udp_standalone",
            _ => null,
        };

        var missing = RequiredPrerequisites(request, windows) & ~host.Prerequisites;
        if (missing != MxcPrerequisites.None)
        {
            return Refuse(MxcAdmissionDecision.PrerequisiteMissing, "host.prerequisites", "required_host_prerequisite_missing",
                MxcEvidenceStatus.Unverified, evidenceId, missing);
        }

        var hostMismatch = HostMismatch(host, windows, request.Network);
        if (hostMismatch is not null)
        {
            return Refuse(MxcAdmissionDecision.EvidenceMismatch, hostMismatch, "installed_profile_outside_qualification",
                MxcEvidenceStatus.Unverified, evidenceId);
        }

        if (networkEvidence == MxcEvidenceStatus.Unverified && request.RequireVerifiedNetwork)
        {
            return new(MxcAdmissionDecision.Unverified, request.ProfileId, revision, networkEvidence, evidenceId,
                "network", "external_selected_egress_unverified", TerminalEvidence: terminalEvidence);
        }

        if (terminalEvidence == MxcEvidenceStatus.Unverified && request.RequireVerifiedTerminal)
        {
            return new(MxcAdmissionDecision.Unverified, request.ProfileId, revision, networkEvidence, evidenceId,
                "terminal", "explicit_pipes_composition_unverified", TerminalEvidence: terminalEvidence,
                NetworkEvidenceScope: networkScope);
        }

        var (unverifiedFeature, unverifiedReason) = (networkEvidence, terminalEvidence) switch
        {
            (MxcEvidenceStatus.Unverified, _) => ("network", "external_selected_egress_unverified"),
            (_, MxcEvidenceStatus.Unverified) => ("terminal", "explicit_pipes_composition_unverified"),
            _ => ((string?)null, (string?)null),
        };
        return new(MxcAdmissionDecision.Admitted, request.ProfileId, revision, networkEvidence, evidenceId,
            unverifiedFeature, unverifiedReason, TerminalEvidence: terminalEvidence, NetworkEvidenceScope: networkScope);

        MxcAdmissionResult Refuse(
            MxcAdmissionDecision decision, string? failedFeature, string failedReason,
            MxcEvidenceStatus evidence = MxcEvidenceStatus.Unverified, string? qualification = null,
            MxcPrerequisites missingPrerequisites = MxcPrerequisites.None) =>
            new(decision, request.ProfileId, revision, evidence, qualification, failedFeature, failedReason, missingPrerequisites);
    }

    private static (string? Feature, string? Reason) UnsupportedPolicy(MxcProfileRequest request, bool windows)
    {
        if (request.Terminal is not (MxcTerminalMode.Interactive or MxcTerminalMode.Pipes))
        {
            return ("terminal", "explicit_terminal_or_pipes_required");
        }

        if (request.Files != MxcFilePolicy.OwnedRootWithExplicitGrants)
        {
            return ("files", "private_root_and_explicit_native_grants_required");
        }

        var selectedNetwork = windows ? MxcNetworkMode.WindowsExternalSelectedTcpUdp : MxcNetworkMode.LinuxSelectedIpv4;
        if (request.Network != MxcNetworkMode.DefaultDeny && request.Network != selectedNetwork)
        {
            return ("network", (windows, request.Network) switch
            {
                (false, MxcNetworkMode.HostIngress) => "stable_bubblewrap_host_ingress_unavailable",
                (false, MxcNetworkMode.Ipv6) => "stable_bubblewrap_ipv6_unavailable",
                _ => "network_combination_not_admitted",
            });
        }

        if (request.Environment != MxcEnvironmentPolicy.CleanExplicit)
        {
            return ("environment", "explicit_clean_environment_required");
        }

        if (request.Resources != MxcResourcePolicy.CpuMemoryAndProcessCount)
        {
            return ("resources", "pre_execution_cpu_memory_process_limits_required");
        }

        if (request.Recovery != MxcRecoveryPolicy.AuthenticatedOwner)
        {
            return ("recovery", "authenticated_owner_and_confirmed_cleanup_required");
        }

        if (request.RequireLeastPrivilegeAppContainer)
        {
            return ("least_privilege_appcontainer", windows
                ? "base_container_rejects_least_privilege_appcontainer"
                : "least_privilege_appcontainer_not_admitted");
        }

        return request.RequirePauseResume ? ("pause_resume", "stable_generic_pause_resume_unavailable") : (null, null);
    }

    private static MxcPrerequisites RequiredPrerequisites(MxcProfileRequest request, bool windows)
    {
        var required = windows ? WindowsPrerequisites : LinuxPrerequisites;
        if (request.Terminal == MxcTerminalMode.Interactive)
        {
            required |= windows ? MxcPrerequisites.WindowsConPty : MxcPrerequisites.LinuxPty;
        }

        if (request.Network == MxcNetworkMode.LinuxSelectedIpv4)
        {
            required |= MxcPrerequisites.LinuxSelectedNetworkHelpers;
        }

        return required;
    }

    private static string? HostMismatch(MxcHostFacts host, bool windows, MxcNetworkMode network)
    {
        if (host.RuntimeIdentifier != (windows ? "win-x64" : "linux-x64"))
        {
            return "host.rid";
        }

        if (host.OperatingSystem != (windows ? "10.0.26300.0" : "debian/13")
            || (!windows && (host.KernelRelease != "6.12.63+deb13-amd64"
                || host.KernelVersion != "#1 SMP PREEMPT_DYNAMIC Debian 6.12.63-1 (2025-12-30)")))
        {
            return "host.os";
        }

        if (!windows && host.SystemdUserManagerVersion != "257.9-1~deb13u1")
        {
            return "host.systemd_user_manager_version";
        }

        if (host.Backend != (windows ? "process-container/base-container" : "bubblewrap"))
        {
            return "host.backend";
        }

        if (host.SdkVersion != SdkVersion || host.RequestSchemaVersion != SchemaVersion
            || host.NativeSourceCommit != NativeSourceCommit || host.PackageSha256 != PackageSha256
            || host.ReleaseSha256 != ReleaseSha256)
        {
            return "host.mxc_cohort";
        }

        var expected = windows ? WindowsNativeFiles : LinuxNativeFiles;
        var installed = host.NativeMemberSha256;
        if (installed is null || installed.Count != expected.Length)
        {
            return "host.native_members";
        }

        var memberMismatch = FindFileMismatch(installed, expected);
        if (memberMismatch is not null)
        {
            return "host.native_members." + memberMismatch;
        }

        if (windows)
        {
            return null;
        }

        if (host.LinuxHelperSha256 is not { } helpers)
        {
            return "host.linux_helpers";
        }

        var helperMismatch = FindFileMismatch(helpers, LinuxBaseHelpers);
        if (helperMismatch is null && network == MxcNetworkMode.LinuxSelectedIpv4)
        {
            helperMismatch = FindFileMismatch(helpers, LinuxSelectedNetworkHelpers);
        }

        return helperMismatch is null ? null : "host.linux_helpers." + helperMismatch;
    }

    private static string? FindFileMismatch(
        IReadOnlyDictionary<string, string> observed, (string FileName, string Sha256)[] expected)
    {
        foreach (var (fileName, sha256) in expected)
        {
            if (!observed.TryGetValue(fileName, out var observedHash) || observedHash != sha256)
            {
                return fileName;
            }
        }

        return null;
    }
}
