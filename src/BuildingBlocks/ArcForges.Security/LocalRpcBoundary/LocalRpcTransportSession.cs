// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.LocalRpc;
using ArcForges.Security.Decisions;

namespace ArcForges.Security.LocalRpcBoundary;

/// <summary>The result of establishing a transport session: the session, or the reason none exists.</summary>
public sealed class LocalRpcEstablishment
{
    internal LocalRpcEstablishment(LocalRpcTransportSession? session, TransportRefusal refusal)
    {
        Session = session;
        Refusal = refusal;
    }

    /// <summary>The established session; null when <see cref="Refusal"/> is not <see cref="TransportRefusal.None"/>.</summary>
    public LocalRpcTransportSession? Session { get; }

    /// <summary>Why no session was established. Callers must not tell the connecting child which cause it was.</summary>
    public TransportRefusal Refusal { get; }
}

/// <summary>
/// The transport boundary (enforcement point 2) over the real parent-owned launch identity of <c>ArcForges.LocalRpc</c>: a child is
/// vouched for only while the parent's own launch authority still verifies the claim it made at the handshake. The session is
/// established once, by verifying the claim and then consuming the launch's one-use secret through the caller's proof check, and it
/// is verified again at every boundary, so a revoked, expired, superseded or abandoned launch stops vouching at the next call.
/// It does not read the peer's operating-system identity and does not run the registration or the bootstrap proof exchange; the
/// proof check is supplied by whoever owns that exchange.
/// </summary>
public sealed class LocalRpcTransportSession : ITransportSession
{
    private readonly LocalRpcLaunchAuthority _authority;
    private readonly LocalRpcLaunchClaim _claim;
    private readonly TransportBinding _binding;

    private LocalRpcTransportSession(LocalRpcLaunchAuthority authority, LocalRpcLaunchClaim claim, TransportBinding binding)
    {
        _authority = authority;
        _claim = claim;
        _binding = binding;
    }

    public TransportKind Kind => TransportKind.LocalRpcChild;

    /// <summary>
    /// Establishes the session of one child. Order: the claim must name exactly this launch; the authority must verify it
    /// (launch, slot, epoch, nonce, build, protocol, parent and child still running, window not passed); only then is the one-use
    /// secret consumed through <paramref name="verifyProof"/>. A claim that does not verify spends nothing. A proof that is rejected
    /// or throws revokes the launch, because the secret is already spent and the launch can never be established again.
    /// </summary>
    /// <param name="boundCallerInstance">The caller instance the registration bound for this child, when it is known.</param>
    [SuppressMessage("Usage", "CA1031:Do not catch general exception types", Justification = "A proof check that throws has already spent the one-use secret; the launch is revoked and the establishment refuses rather than the exception escaping the boundary.")]
    public static LocalRpcEstablishment Establish<TProofState>(
        LocalRpcLaunchAuthority authority,
        LocalRpcLaunch launch,
        LocalRpcLaunchClaim claim,
        TProofState proofState,
        LocalRpcSecretUse<TProofState, bool> verifyProof,
        InstanceId? boundCallerInstance = null)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(launch);
        ArgumentNullException.ThrowIfNull(claim);
        ArgumentNullException.ThrowIfNull(verifyProof);
        var descriptor = launch.Descriptor;
        if (claim.LaunchId != descriptor.LaunchId || claim.Epoch != descriptor.Epoch
            || !string.Equals(claim.Slot, descriptor.Slot, StringComparison.Ordinal))
        {
            return Refused(TransportRefusal.IdentityMismatch);
        }

        var verified = authority.Verify(claim);
        if (verified != LocalRpcLaunchRefusal.None)
        {
            return Refused(Map(verified));
        }

        var proofRan = false;
        bool accepted;
        try
        {
            accepted = launch.ConsumeSecret(
                proofState,
                (state, secret) =>
                {
                    proofRan = true;
                    return verifyProof(state, secret);
                });
        }
        catch (InvalidOperationException) when (!proofRan)
        {
            // The launch refused before the proof ran (spent, revoked, expired, parent or child gone): nothing was spent here.
            var status = launch.Status();
            return Refused(status == LocalRpcLaunchRefusal.None ? TransportRefusal.NotEstablished : Map(status));
        }
        catch (Exception)
        {
            // The proof check ran or the launch changed under it: the secret is spent, so this launch can never be established.
            launch.Revoke();
            return Refused(TransportRefusal.Unavailable);
        }

        if (!accepted)
        {
            launch.Revoke();
            return Refused(TransportRefusal.ProofRejected);
        }

        var binding = new TransportBinding(
            TransportKind.LocalRpcChild,
            TransportAssurance.LaunchClaimWithSecretProof,
            descriptor.LaunchId,
            descriptor.Slot,
            descriptor.Epoch,
            descriptor.Identity.ChildKind.ToString(),
            descriptor.Identity.BuildId,
            boundCallerInstance);
        return new LocalRpcEstablishment(new LocalRpcTransportSession(authority, claim, binding), TransportRefusal.None);
    }

    /// <summary>Verifies the launch again now. A refusal carries no binding; any failure to verify refuses.</summary>
    [SuppressMessage("Usage", "CA1031:Do not catch general exception types", Justification = "A verification that cannot be made must refuse the boundary rather than escape it.")]
    public ValueTask<TransportVerdict> VerifyCurrentAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var refusal = _authority.Verify(_claim);
            return ValueTask.FromResult(refusal == LocalRpcLaunchRefusal.None
                ? new TransportVerdict(TransportRefusal.None, _binding)
                : new TransportVerdict(Map(refusal), null));
        }
        catch (Exception)
        {
            return ValueTask.FromResult(new TransportVerdict(TransportRefusal.Unavailable, null));
        }
    }

    /// <summary>The closed mapping from the launch authority's refusals; an undefined value maps to a refusal, never to success.</summary>
    internal static TransportRefusal Map(LocalRpcLaunchRefusal refusal) => refusal switch
    {
        LocalRpcLaunchRefusal.Revoked => TransportRefusal.Revoked,
        LocalRpcLaunchRefusal.Expired => TransportRefusal.Expired,
        LocalRpcLaunchRefusal.StaleEpoch => TransportRefusal.Superseded,
        LocalRpcLaunchRefusal.ParentMismatch => TransportRefusal.PeerGone,
        LocalRpcLaunchRefusal.ChildGone => TransportRefusal.PeerGone,
        LocalRpcLaunchRefusal.UnknownSlot => TransportRefusal.IdentityMismatch,
        LocalRpcLaunchRefusal.UnknownLaunch => TransportRefusal.IdentityMismatch,
        LocalRpcLaunchRefusal.NonceMismatch => TransportRefusal.IdentityMismatch,
        LocalRpcLaunchRefusal.BuildMismatch => TransportRefusal.IdentityMismatch,
        LocalRpcLaunchRefusal.ProtocolMismatch => TransportRefusal.IdentityMismatch,
        _ => TransportRefusal.Unavailable,
    };

    private static LocalRpcEstablishment Refused(TransportRefusal refusal) => new(null, refusal);
}
