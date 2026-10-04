// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Security.Decisions;

namespace ArcForges.Security.Trust;

// Trust is typed, never a scalar (requirements 07, section 9): there is no TrustLevel number anywhere in this namespace. Each kind has
// its own closed set of states, every set starts at Unknown (which is never eligible), and nothing here can name a permission, a
// capability grant, a resource authorization or a lease. Trust is a separate gate beside permission, risk and entitlement (TR-01).

/// <summary>The five kinds of trust, each answering a different question about a different subject.</summary>
public enum TrustKind
{
    None = 0,

    /// <summary>Who published this.</summary>
    Publisher = 1,

    /// <summary>The artifact's signature and verification state.</summary>
    Package = 2,

    /// <summary>Which binary is executing.</summary>
    SoftwareIdentity = 3,

    /// <summary>May this device act for the user.</summary>
    Device = 4,

    /// <summary>Installed, enabled, revoked, developer or unverified.</summary>
    ExtensionState = 5,
}

/// <summary>The defined points at which trust is evaluated (architecture 08, section 10). Each evaluates only its own kinds.</summary>
public enum TrustEvaluationPoint
{
    None = 0,

    /// <summary>Package installation and update: publisher and package trust.</summary>
    PackageInstallOrUpdate = 1,

    /// <summary>Every start of an extension host: package trust.</summary>
    ExtensionHostStart = 2,

    /// <summary>The local RPC handshake: software identity.</summary>
    LocalRpcHandshake = 3,

    /// <summary>The extension host handshake: software identity.</summary>
    ExtensionHostHandshake = 4,

    /// <summary>Cloud authentication: device trust.</summary>
    CloudAuthentication = 5,

    /// <summary>A remote invocation: device trust.</summary>
    RemoteInvocation = 6,

    /// <summary>Every extension invocation: extension trust state.</summary>
    ExtensionInvocation = 7,
}

public enum PublisherTrustState
{
    Unknown = 0,
    Verified = 1,
    Unverified = 2,
    Revoked = 3,
}

/// <summary>A verified signature proves origin and integrity, never that the package is safe (TR-02).</summary>
public enum PackageTrustState
{
    Unknown = 0,
    SignatureVerified = 1,
    Unverified = 2,
    Revoked = 3,
}

public enum SoftwareIdentityState
{
    Unknown = 0,
    Matched = 1,
    Mismatched = 2,
}

public enum DeviceTrustState
{
    Unknown = 0,
    Trusted = 1,
    Untrusted = 2,
    Revoked = 3,
}

public enum ExtensionTrustState
{
    Unknown = 0,

    /// <summary>Installed, verified and explicitly enabled.</summary>
    Enabled = 1,

    /// <summary>A local unsigned package under Developer Mode: runs, is marked, and is stricter by default (TR-07).</summary>
    Developer = 2,

    /// <summary>Unverified: stricter by default (TR-05).</summary>
    Unverified = 3,

    /// <summary>Installed but not enabled: not eligible until the user enables it explicitly.</summary>
    Installed = 4,

    /// <summary>Revoked: stops running (TR-06).</summary>
    Revoked = 5,
}

/// <summary>What the trust facts of a subject allow. It says nothing about permission, risk or entitlement.</summary>
public enum TrustEligibility
{
    /// <summary>Not known, or a fact was missing or undefined: never eligible.</summary>
    Unknown = 0,

    Eligible = 1,

    /// <summary>Eligible but unverified: the pipeline gives it a higher risk floor and never more permission (TR-05, TR-09).</summary>
    EligibleUnverified = 2,

    /// <summary>Revoked, mismatched, untrusted or not enabled.</summary>
    NotEligible = 3,
}

/// <summary>
/// The subject of a trust evaluation: who acts now (the last delegated actor, if any), on which device and installation, through which
/// caller instance and transport, from which origin. It names the subject for the host's fact sources; it asserts nothing itself.
/// </summary>
public sealed record TrustSubject
{
    public TrustSubject(
        DelegatedActor? actor,
        DeviceId device,
        InstallationId installation,
        InstanceId callerInstance,
        DecisionOrigin origin,
        TransportBinding? transport = null)
    {
        _ = device.ToWire();
        _ = installation.ToWire();
        _ = callerInstance.ToWire();
        if (!Enum.IsDefined(origin) || origin == DecisionOrigin.None)
        {
            throw new ArgumentOutOfRangeException(nameof(origin));
        }

        Actor = actor;
        Device = device;
        Installation = installation;
        CallerInstance = callerInstance;
        Origin = origin;
        Transport = transport;
    }

    public DelegatedActor? Actor { get; }

    public DeviceId Device { get; }

    public InstallationId Installation { get; }

    public InstanceId CallerInstance { get; }

    public DecisionOrigin Origin { get; }

    public TransportBinding? Transport { get; }
}

/// <summary>
/// The host-owned sources of trust facts: the publisher registry, package verification, software attestation, the device registry and
/// the extension state store. Each returns the typed state of its kind; a fact the host does not know is Unknown, which is not eligible.
/// A source is read-only evidence: it consumes nothing and causes no effect.
/// </summary>
public interface ITrustFactSource
{
    ValueTask<PublisherTrustState> ReadPublisherAsync(TrustSubject subject, CancellationToken cancellationToken);

    ValueTask<PackageTrustState> ReadPackageAsync(TrustSubject subject, CancellationToken cancellationToken);

    ValueTask<SoftwareIdentityState> ReadSoftwareIdentityAsync(TrustSubject subject, CancellationToken cancellationToken);

    ValueTask<DeviceTrustState> ReadDeviceAsync(TrustSubject subject, CancellationToken cancellationToken);

    ValueTask<ExtensionTrustState> ReadExtensionStateAsync(TrustSubject subject, CancellationToken cancellationToken);
}

/// <summary>
/// The typed trust states read at one evaluation point: only the kinds that point evaluates are present, the rest are null. Combined
/// eligibility is the strictest of the evaluated kinds. An assessment is evidence for a decision; it is never a grant, and there is no
/// member that converts it into a permission, a lease or an authorization.
/// </summary>
public sealed class TrustAssessment
{
    internal TrustAssessment(
        TrustEvaluationPoint point,
        PublisherTrustState? publisher,
        PackageTrustState? package,
        SoftwareIdentityState? software,
        DeviceTrustState? device,
        ExtensionTrustState? extension)
    {
        Point = point;
        Publisher = publisher;
        Package = package;
        Software = software;
        Device = device;
        Extension = extension;
        Eligibility = TrustPolicy.Combine(Kinds());
    }

    public TrustEvaluationPoint Point { get; }

    public PublisherTrustState? Publisher { get; }

    public PackageTrustState? Package { get; }

    public SoftwareIdentityState? Software { get; }

    public DeviceTrustState? Device { get; }

    public ExtensionTrustState? Extension { get; }

    /// <summary>The strictest eligibility of the evaluated kinds: not eligible, else unknown, else eligible but unverified, else eligible.</summary>
    public TrustEligibility Eligibility { get; }

    private IEnumerable<TrustEligibility> Kinds()
    {
        if (Publisher is { } publisher)
        {
            yield return TrustPolicy.Of(publisher);
        }

        if (Package is { } package)
        {
            yield return TrustPolicy.Of(package);
        }

        if (Software is { } software)
        {
            yield return TrustPolicy.Of(software);
        }

        if (Device is { } device)
        {
            yield return TrustPolicy.Of(device);
        }

        if (Extension is { } extension)
        {
            yield return TrustPolicy.Of(extension);
        }
    }
}

/// <summary>How each typed state maps to eligibility and how eligibilities combine. Closed: an undefined value is Unknown.</summary>
internal static class TrustPolicy
{
    internal static TrustEligibility Of(PublisherTrustState state) => state switch
    {
        PublisherTrustState.Verified => TrustEligibility.Eligible,
        PublisherTrustState.Unverified => TrustEligibility.EligibleUnverified,
        PublisherTrustState.Revoked => TrustEligibility.NotEligible,
        _ => TrustEligibility.Unknown,
    };

    internal static TrustEligibility Of(PackageTrustState state) => state switch
    {
        PackageTrustState.SignatureVerified => TrustEligibility.Eligible,
        PackageTrustState.Unverified => TrustEligibility.EligibleUnverified,
        PackageTrustState.Revoked => TrustEligibility.NotEligible,
        _ => TrustEligibility.Unknown,
    };

    internal static TrustEligibility Of(SoftwareIdentityState state) => state switch
    {
        SoftwareIdentityState.Matched => TrustEligibility.Eligible,
        SoftwareIdentityState.Mismatched => TrustEligibility.NotEligible,
        _ => TrustEligibility.Unknown,
    };

    internal static TrustEligibility Of(DeviceTrustState state) => state switch
    {
        DeviceTrustState.Trusted => TrustEligibility.Eligible,
        DeviceTrustState.Untrusted or DeviceTrustState.Revoked => TrustEligibility.NotEligible,
        _ => TrustEligibility.Unknown,
    };

    internal static TrustEligibility Of(ExtensionTrustState state) => state switch
    {
        ExtensionTrustState.Enabled => TrustEligibility.Eligible,
        ExtensionTrustState.Developer or ExtensionTrustState.Unverified => TrustEligibility.EligibleUnverified,
        ExtensionTrustState.Installed or ExtensionTrustState.Revoked => TrustEligibility.NotEligible,
        _ => TrustEligibility.Unknown,
    };

    /// <summary>The strictest of the given eligibilities; nothing evaluated at all is Unknown.</summary>
    internal static TrustEligibility Combine(IEnumerable<TrustEligibility> eligibilities)
    {
        var any = false;
        var unknown = false;
        var unverified = false;
        foreach (var eligibility in eligibilities)
        {
            any = true;
            switch (eligibility)
            {
                case TrustEligibility.NotEligible:
                    return TrustEligibility.NotEligible;
                case TrustEligibility.Eligible:
                    break;
                case TrustEligibility.EligibleUnverified:
                    unverified = true;
                    break;
                default:
                    unknown = true;
                    break;
            }
        }

        return !any || unknown ? TrustEligibility.Unknown : unverified ? TrustEligibility.EligibleUnverified : TrustEligibility.Eligible;
    }

    internal static TrustVerdict ToVerdict(TrustEligibility eligibility) => eligibility switch
    {
        TrustEligibility.Eligible => TrustVerdict.Verified,
        TrustEligibility.EligibleUnverified => TrustVerdict.Unverified,
        TrustEligibility.NotEligible => TrustVerdict.Revoked,
        _ => TrustVerdict.Unknown,
    };
}
