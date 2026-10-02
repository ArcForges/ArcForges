// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Security.Approvals;

namespace ArcForges.Security.Decisions;

public enum TransportKind
{
    None = 0,

    /// <summary>The caller is inside the same process; there is no connection to authenticate. Local is not trusted: every other step still runs.</summary>
    InProcess = 1,

    /// <summary>A child process connected over the private local RPC transport.</summary>
    LocalRpcChild = 2,
}

/// <summary>How strongly the transport boundary established who is connected. Neither level reads the peer's operating-system identity.</summary>
public enum TransportAssurance
{
    None = 0,

    /// <summary>The host asserts an in-process call; nothing was authenticated.</summary>
    InProcessHost = 1,

    /// <summary>The parent verified a launch claim (launch, slot, epoch, nonce, build, protocol) and consumed the one-use secret proof.</summary>
    LaunchClaimWithSecretProof = 2,
}

/// <summary>Why a transport session no longer vouches for its peer. Callers must not reveal the cause to the peer.</summary>
public enum TransportRefusal
{
    None = 0,

    /// <summary>The session was never established, or its one-use proof was already spent.</summary>
    NotEstablished,

    Revoked,
    Expired,

    /// <summary>A newer launch of the same slot exists.</summary>
    Superseded,

    /// <summary>The issuing parent or the bound child process is no longer running.</summary>
    PeerGone,

    /// <summary>The presented launch, nonce, build or protocol does not match the parent's record.</summary>
    IdentityMismatch,

    ProofRejected,

    /// <summary>The verification could not be made; it fails closed.</summary>
    Unavailable,
}

/// <summary>What the transport boundary established about the connected peer. It is evidence for the decision, never a grant.</summary>
public sealed class TransportBinding
{
    public TransportBinding(
        TransportKind kind,
        TransportAssurance assurance,
        Guid? launchId = null,
        string? slot = null,
        ulong epoch = 0,
        string? childKind = null,
        string? buildId = null,
        InstanceId? boundCallerInstance = null)
    {
        if (!Enum.IsDefined(kind) || kind == TransportKind.None || !Enum.IsDefined(assurance) || assurance == TransportAssurance.None)
        {
            throw new ArgumentOutOfRangeException(nameof(kind), "A transport binding names its kind and assurance.");
        }

        if (slot is not null)
        {
            SecurityText.Validate(slot, 64, nameof(slot));
        }

        if (childKind is not null)
        {
            SecurityText.Validate(childKind, 64, nameof(childKind));
        }

        if (buildId is not null)
        {
            SecurityText.Validate(buildId, 64, nameof(buildId));
        }

        if (boundCallerInstance is { } instance)
        {
            _ = instance.ToWire();
        }

        Kind = kind;
        Assurance = assurance;
        LaunchId = launchId;
        Slot = slot;
        Epoch = epoch;
        ChildKind = childKind;
        BuildId = buildId;
        BoundCallerInstance = boundCallerInstance;
    }

    public TransportKind Kind { get; }

    public TransportAssurance Assurance { get; }

    public Guid? LaunchId { get; }

    public string? Slot { get; }

    public ulong Epoch { get; }

    public string? ChildKind { get; }

    public string? BuildId { get; }

    /// <summary>The caller instance the transport itself bound, when it did; the actor chain's caller instance must equal it.</summary>
    public InstanceId? BoundCallerInstance { get; }
}

/// <summary>The current answer of a transport session: either a refusal or the binding that still holds.</summary>
public sealed record TransportVerdict(TransportRefusal Refusal, TransportBinding? Binding);

/// <summary>
/// A live handle to the transport boundary of one connection (enforcement point 2). It is verified again at every boundary, so a
/// revoked, expired, superseded or abandoned connection stops vouching for its peer at the next invocation.
/// </summary>
public interface ITransportSession
{
    TransportKind Kind { get; }

    ValueTask<TransportVerdict> VerifyCurrentAsync(CancellationToken cancellationToken);
}

/// <summary>Well-known transport sessions.</summary>
public static class TransportSessions
{
    /// <summary>
    /// The session of a caller inside the same process. It authenticates nobody: the actor, scope, permission, risk and owner steps
    /// all still run, and the binding records that only the host asserted the call.
    /// </summary>
    public static ITransportSession InProcess { get; } = new InProcessSession();

    private sealed class InProcessSession : ITransportSession
    {
        private static readonly TransportBinding Binding = new(TransportKind.InProcess, TransportAssurance.InProcessHost);

        public TransportKind Kind => TransportKind.InProcess;

        public ValueTask<TransportVerdict> VerifyCurrentAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(new TransportVerdict(TransportRefusal.None, Binding));
    }
}
