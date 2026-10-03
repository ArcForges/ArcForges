// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;
using ArcForges.Security.Decisions;

namespace ArcForges.Security.Trust;

/// <summary>The kinds of trust each defined evaluation point reads (architecture 08, section 10).</summary>
public static class TrustPoints
{
    private static readonly ReadOnlyCollection<TrustKind> PublisherAndPackage = Array.AsReadOnly([TrustKind.Publisher, TrustKind.Package]);
    private static readonly ReadOnlyCollection<TrustKind> PackageOnly = Array.AsReadOnly([TrustKind.Package]);
    private static readonly ReadOnlyCollection<TrustKind> SoftwareOnly = Array.AsReadOnly([TrustKind.SoftwareIdentity]);
    private static readonly ReadOnlyCollection<TrustKind> DeviceOnly = Array.AsReadOnly([TrustKind.Device]);
    private static readonly ReadOnlyCollection<TrustKind> ExtensionOnly = Array.AsReadOnly([TrustKind.ExtensionState]);

    /// <summary>The kinds <paramref name="point"/> evaluates and no others. An undefined point is refused.</summary>
    public static IReadOnlyList<TrustKind> KindsAt(TrustEvaluationPoint point) => point switch
    {
        TrustEvaluationPoint.PackageInstallOrUpdate => PublisherAndPackage,
        TrustEvaluationPoint.ExtensionHostStart => PackageOnly,
        TrustEvaluationPoint.LocalRpcHandshake or TrustEvaluationPoint.ExtensionHostHandshake => SoftwareOnly,
        TrustEvaluationPoint.CloudAuthentication or TrustEvaluationPoint.RemoteInvocation => DeviceOnly,
        TrustEvaluationPoint.ExtensionInvocation => ExtensionOnly,
        _ => throw new ArgumentOutOfRangeException(nameof(point)),
    };
}

/// <summary>
/// Evaluates typed trust from the host's fact sources at the defined points, and answers the decision pipeline's step 5. It reads only
/// trust facts: it has no access to a permission, a grant, a lease or an entitlement, and no result of it can create one. A step 5
/// "verified" therefore lets the request go on to the permission step; it never replaces it.
/// <para>
/// For a request, step 5 reads the software identity of the caller (the local RPC handshake point), the package and extension state
/// when an extension acts (the extension host start and the extension invocation points), and the device when the request is remote (the
/// remote invocation point). Eligibility combines strictest first: any kind not eligible refuses, any kind unknown or undefined refuses, any
/// kind eligible but unverified lets the request through with the pipeline's higher risk floor, and only all kinds eligible is verified.
/// "Not eligible" (revoked, mismatched, untrusted, installed but not enabled) reaches the pipeline as <see cref="TrustVerdict.Revoked"/>,
/// its one definite refusal.
/// </para>
/// </summary>
public sealed class TrustEvaluator : ITrustEvaluator
{
    private readonly ITrustFactSource _facts;

    public TrustEvaluator(ITrustFactSource facts)
    {
        _facts = facts ?? throw new ArgumentNullException(nameof(facts));
    }

    /// <summary>Reads exactly the kinds <paramref name="point"/> evaluates, once each, and returns their typed states.</summary>
    public async ValueTask<TrustAssessment> AssessAsync(TrustEvaluationPoint point, TrustSubject subject, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(subject);
        PublisherTrustState? publisher = null;
        PackageTrustState? package = null;
        SoftwareIdentityState? software = null;
        DeviceTrustState? device = null;
        ExtensionTrustState? extension = null;
        foreach (var kind in TrustPoints.KindsAt(point))
        {
            cancellationToken.ThrowIfCancellationRequested();
            switch (kind)
            {
                case TrustKind.Publisher:
                    publisher = await _facts.ReadPublisherAsync(subject, cancellationToken).ConfigureAwait(false);
                    break;
                case TrustKind.Package:
                    package = await _facts.ReadPackageAsync(subject, cancellationToken).ConfigureAwait(false);
                    break;
                case TrustKind.SoftwareIdentity:
                    software = await _facts.ReadSoftwareIdentityAsync(subject, cancellationToken).ConfigureAwait(false);
                    break;
                case TrustKind.Device:
                    device = await _facts.ReadDeviceAsync(subject, cancellationToken).ConfigureAwait(false);
                    break;
                default:
                    extension = await _facts.ReadExtensionStateAsync(subject, cancellationToken).ConfigureAwait(false);
                    break;
            }
        }

        return new TrustAssessment(point, publisher, package, software, device, extension);
    }

    /// <summary>The pipeline's step 5: the combined eligibility of every point the request passes, as a verdict.</summary>
    public async ValueTask<TrustVerdict> EvaluateAsync(DecisionRequest request, TransportBinding? transport, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var chain = request.Actors;
        var actor = chain.Actors.Count == 0 ? null : chain.Actors[^1];
        var subject = new TrustSubject(actor, chain.Device, chain.Installation, chain.CallerInstance, request.Origin, transport);
        var points = new List<TrustEvaluationPoint> { TrustEvaluationPoint.LocalRpcHandshake };
        if (actor is { Kind: ActorKind.Extension })
        {
            points.Add(TrustEvaluationPoint.ExtensionHostStart);
            points.Add(TrustEvaluationPoint.ExtensionInvocation);
        }

        if (request.Origin == DecisionOrigin.Remote)
        {
            points.Add(TrustEvaluationPoint.RemoteInvocation);
        }

        var eligibilities = new List<TrustEligibility>(points.Count);
        foreach (var point in points)
        {
            var assessment = await AssessAsync(point, subject, cancellationToken).ConfigureAwait(false);
            eligibilities.Add(assessment.Eligibility);
        }

        return TrustPolicy.ToVerdict(TrustPolicy.Combine(eligibilities));
    }
}
