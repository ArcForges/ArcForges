// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using Grpc.Core;

namespace ArcForges.LocalRpc;

/// <summary>
/// What is known about whether a command's effect happened. The numbers equal the published
/// <c>EffectCertainty</c> values (<c>DID_NOT_HAPPEN</c> = 1, <c>HAPPENED</c> = 2, <c>UNKNOWN</c> = 3); the library does not reference
/// the Foundation packages, and the test project asserts the equality so a drift cannot go unnoticed.
/// </summary>
public enum LocalRpcEffect
{
    /// <summary>Not a certainty; never reported (the published <c>EFFECT_CERTAINTY_UNSPECIFIED</c>).</summary>
    Unspecified = 0,

    /// <summary>The effect did not happen, and that is certain (a typed refusal before dispatch, no connection, a cancel before the commit point).</summary>
    DidNotHappen = 1,

    /// <summary>The effect happened.</summary>
    Happened = 2,

    /// <summary>
    /// The effect may or may not have happened: the request was sent and no answer proved either. Nothing resolves this except
    /// an owner reconciliation; it is never turned into a guess and never replayed on its own.
    /// </summary>
    Unknown = 3,
}

/// <summary>How the owner declares a command may be repeated. The default for anything that changes state is <see cref="NonIdempotent"/>.</summary>
public enum LocalRpcIdempotency
{
    /// <summary>Not a class; never valid.</summary>
    None = 0,

    /// <summary>A read with no effect. It may be retried after a transient failure and is not recorded in the command journal.</summary>
    Query = 1,

    /// <summary>
    /// A mutation whose owner returns the recorded result for the same command id and the same input (the checked-duplicate
    /// property of the <c>IW</c>, <c>CC</c> and <c>DE</c> classes) <em>within one helper launch</em>. It may be replayed after an
    /// unknown effect only when the command says so explicitly, only to the launch that first received it and only inside the replay window.
    /// </summary>
    DuplicateSafe = 2,

    /// <summary>A mutation that is never replayed after an unknown effect (<c>NI</c>). Only reconciliation resolves it.</summary>
    NonIdempotent = 3,
}

/// <summary>The shape of a command outcome. It mirrors <c>Outcome&lt;T&gt;</c> of the Foundation package: a result is a success, a failure or a cancellation, and each carries an effect certainty.</summary>
public enum LocalRpcOutcomeKind
{
    /// <summary>Not an outcome; never reported.</summary>
    None = 0,

    /// <summary>The call returned and the effect happened.</summary>
    Success = 1,

    /// <summary>The command failed; <see cref="LocalRpcCommandOutcome{TResponse}.Effect"/> says whether it may have had an effect.</summary>
    Failure = 2,

    /// <summary>The command was cancelled, by its caller or by an explicit cancel; the effect certainty still applies.</summary>
    Cancelled = 3,
}

/// <summary>The typed cause of a failed or cancelled command.</summary>
public enum LocalRpcFailureReason
{
    /// <summary>No failure (a success).</summary>
    None = 0,

    /// <summary>The peer refused the call before dispatch with a typed refusal. Nothing ran.</summary>
    Refused = 1,

    /// <summary>No connection could be made, so nothing was sent.</summary>
    ConnectFailed = 2,

    /// <summary>The connection broke or the peer was unavailable after the request may have been sent.</summary>
    TransportLost = 3,

    /// <summary>The deadline passed after the request may have been sent.</summary>
    DeadlineExceeded = 4,

    /// <summary>The peer answered with a status that proves nothing about the effect.</summary>
    PeerError = 5,

    /// <summary>The peer's own answer reports the effect (a response interpreted as a failure, or an effect trailer on a failed call).</summary>
    ReportedByPeer = 6,

    /// <summary>The owner declared the launch the command was sent to lost.</summary>
    PeerLost = 7,

    /// <summary>The caller's token was cancelled.</summary>
    CancelledByCaller = 8,

    /// <summary>The command id is recorded with an unknown effect and this call may not replay it; nothing was sent.</summary>
    ReplayNotAllowed = 9,

    /// <summary>The command id is already being run by another call; nothing was sent.</summary>
    AlreadyInFlight = 10,

    /// <summary>The command id is recorded with a different operation, input or idempotency; nothing was sent.</summary>
    CommandConflict = 11,

    /// <summary>The command journal holds only commands it may not forget; nothing was sent.</summary>
    JournalFull = 12,

    /// <summary>The send or interpret delegate threw an exception that is not a transport failure; the exception is rethrown after the command is recorded as unknown.</summary>
    Unclassified = 13,

    /// <summary>A cancel was requested for the command (the cancellation is the cause).</summary>
    CancelRequested = 14,
}

/// <summary>Where a recorded command stands.</summary>
public enum LocalRpcCommandState
{
    /// <summary>Not a state; never reported.</summary>
    None = 0,

    /// <summary>A call is running it, or waiting to retry it.</summary>
    InFlight = 1,

    /// <summary>The effect is known: it happened, or it certainly did not.</summary>
    Resolved = 2,

    /// <summary>The effect is unknown. Only reconciliation, or an explicitly allowed replay, changes this.</summary>
    Unknown = 3,
}

/// <summary>
/// One command's stable identity: the id the owner minted, the operation it names, a digest of its canonical input
/// and how it may be repeated. The same id always names the same operation and input; a different input under a recorded id is a conflict.
/// </summary>
public sealed class LocalRpcCommand
{
    /// <summary>The length of an input digest (SHA-256).</summary>
    public const int DigestBytes = 32;

    private readonly byte[] _inputDigest;

    /// <summary>Creates a command identity.</summary>
    /// <param name="commandId">The owner-minted command id; never empty.</param>
    /// <param name="operation">The wire operation, <c>full.service.Name/Method</c>.</param>
    /// <param name="inputDigest">The 32-byte digest of the canonical input (<see cref="DigestOf"/>, or the owner's canonical command hash).</param>
    /// <param name="idempotency">How the command may be repeated.</param>
    /// <param name="replayAfterUnknown">
    /// Explicit permission to send the command again after an unknown effect. Allowed only for <see cref="LocalRpcIdempotency.DuplicateSafe"/>
    /// commands, and then only to the launch that first received it.
    /// </param>
    public LocalRpcCommand(Guid commandId, string operation, ReadOnlySpan<byte> inputDigest, LocalRpcIdempotency idempotency, bool replayAfterUnknown = false)
    {
        if (commandId == Guid.Empty)
        {
            throw new ArgumentException("A command id is never empty.", nameof(commandId));
        }

        ArgumentNullException.ThrowIfNull(operation);
        if (!IsOperation(operation))
        {
            throw new ArgumentException("An operation is a protobuf service name and a method name separated by a slash.", nameof(operation));
        }

        if (inputDigest.Length != DigestBytes)
        {
            throw new ArgumentException("An input digest is exactly 32 bytes.", nameof(inputDigest));
        }

        if (idempotency == LocalRpcIdempotency.None || !Enum.IsDefined(idempotency))
        {
            throw new ArgumentOutOfRangeException(nameof(idempotency), idempotency, "Unknown idempotency.");
        }

        if (replayAfterUnknown && idempotency != LocalRpcIdempotency.DuplicateSafe)
        {
            throw new ArgumentException("Only a duplicate-safe command may be replayed after an unknown effect.", nameof(replayAfterUnknown));
        }

        CommandId = commandId;
        Operation = operation;
        _inputDigest = inputDigest.ToArray();
        Idempotency = idempotency;
        ReplayAfterUnknown = replayAfterUnknown;
    }

    /// <summary>The owner-minted command id, the same across every attempt and every launch.</summary>
    public Guid CommandId { get; }

    /// <summary>The wire operation, <c>full.service.Name/Method</c>.</summary>
    public string Operation { get; }

    /// <summary>The digest of the canonical input.</summary>
    public ReadOnlyMemory<byte> InputDigest => _inputDigest;

    /// <summary>How the command may be repeated.</summary>
    public LocalRpcIdempotency Idempotency { get; }

    /// <summary>Whether the owner explicitly allows sending the command again after an unknown effect.</summary>
    public bool ReplayAfterUnknown { get; }

    /// <summary>The SHA-256 digest of an owner-canonicalized input, for commands whose owner has no canonical hash of its own.</summary>
    public static byte[] DigestOf(ReadOnlySpan<byte> canonicalInput) => SHA256.HashData(canonicalInput);

    internal bool IsSameCommandAs(string operation, ReadOnlySpan<byte> inputDigest, LocalRpcIdempotency idempotency) =>
        string.Equals(Operation, operation, StringComparison.Ordinal)
        && _inputDigest.AsSpan().SequenceEqual(inputDigest)
        && Idempotency == idempotency;

    private static bool IsOperation(string operation)
    {
        var slash = operation.IndexOf('/', StringComparison.Ordinal);
        if (slash <= 0 || slash != operation.LastIndexOf('/'))
        {
            return false;
        }

        var method = operation[(slash + 1)..];
        return LocalRpcServerBuilder.IsProtoName(operation[..slash])
            && LocalRpcServerBuilder.IsProtoName(method)
            && !method.Contains('.', StringComparison.Ordinal);
    }
}

/// <summary>
/// The identity of one launch of a helper: its launch id and epoch. A helper that crashes is relaunched under a new
/// generation, and nothing recorded for the old one (a receipt table, a lease, a grant) carries over.
/// </summary>
/// <param name="LaunchId">The parent's id of the launch.</param>
/// <param name="Epoch">The epoch of the launch's slot.</param>
public readonly record struct LocalRpcPeerGeneration(Guid LaunchId, ulong Epoch)
{
    /// <summary>The generation a launch descriptor names.</summary>
    public static LocalRpcPeerGeneration From(LocalRpcLaunchDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        return new LocalRpcPeerGeneration(descriptor.LaunchId, descriptor.Epoch);
    }
}

/// <summary>A point-in-time view of one recorded command.</summary>
public sealed class LocalRpcCommandRecord
{
    internal LocalRpcCommandRecord(
        Guid commandId,
        string operation,
        LocalRpcIdempotency idempotency,
        LocalRpcCommandState state,
        LocalRpcOutcomeKind? kind,
        LocalRpcEffect effect,
        LocalRpcFailureReason reason,
        int attempts,
        LocalRpcPeerGeneration generation,
        bool cancelRequested,
        bool hasResponse)
    {
        CommandId = commandId;
        Operation = operation;
        Idempotency = idempotency;
        State = state;
        Kind = kind;
        Effect = effect;
        Reason = reason;
        Attempts = attempts;
        Generation = generation;
        CancelRequested = cancelRequested;
        HasResponse = hasResponse;
    }

    /// <summary>The command id.</summary>
    public Guid CommandId { get; }

    /// <summary>The wire operation.</summary>
    public string Operation { get; }

    /// <summary>How the command may be repeated.</summary>
    public LocalRpcIdempotency Idempotency { get; }

    /// <summary>Where the command stands.</summary>
    public LocalRpcCommandState State { get; }

    /// <summary>The shape of the outcome once the command is no longer in flight; null while it runs.</summary>
    public LocalRpcOutcomeKind? Kind { get; }

    /// <summary>What is known about the effect (<see cref="LocalRpcEffect.Unknown"/> while the command runs).</summary>
    public LocalRpcEffect Effect { get; }

    /// <summary>The typed cause of the latest failure or cancellation.</summary>
    public LocalRpcFailureReason Reason { get; }

    /// <summary>How many times the command was sent, across calls and launches.</summary>
    public int Attempts { get; }

    /// <summary>The launch the latest attempt was sent to.</summary>
    public LocalRpcPeerGeneration Generation { get; }

    /// <summary>Whether a cancel was requested; a cancelled command is never replayed.</summary>
    public bool CancelRequested { get; }

    /// <summary>Whether the response is retained (a reconciled command never has one).</summary>
    public bool HasResponse { get; }
}

/// <summary>
/// The typed result of one command call. A success carries the response; a failure or cancellation carries the typed
/// reason and the effect certainty. An unknown effect is a <see cref="LocalRpcOutcomeKind.Failure"/> or
/// <see cref="LocalRpcOutcomeKind.Cancelled"/> whose <see cref="Effect"/> is <see cref="LocalRpcEffect.Unknown"/>.
/// </summary>
/// <typeparam name="TResponse">The response message of the command.</typeparam>
public sealed class LocalRpcCommandOutcome<TResponse>
{
    internal LocalRpcCommandOutcome(
        Guid commandId,
        LocalRpcOutcomeKind kind,
        LocalRpcEffect effect,
        LocalRpcFailureReason reason,
        int attempts,
        bool sent,
        StatusCode? status,
        LocalRpcRefusal? refusal,
        bool hasResponse,
        TResponse? response)
    {
        CommandId = commandId;
        Kind = kind;
        Effect = effect;
        Reason = reason;
        Attempts = attempts;
        Sent = sent;
        Status = status;
        Refusal = refusal;
        HasResponse = hasResponse;
        Response = response;
    }

    /// <summary>The command id.</summary>
    public Guid CommandId { get; }

    /// <summary>Success, failure or cancellation.</summary>
    public LocalRpcOutcomeKind Kind { get; }

    /// <summary>What is known about the effect.</summary>
    public LocalRpcEffect Effect { get; }

    /// <summary>The typed cause; <see cref="LocalRpcFailureReason.None"/> for a success.</summary>
    public LocalRpcFailureReason Reason { get; }

    /// <summary>How many times the command was sent in total.</summary>
    public int Attempts { get; }

    /// <summary>Whether this call put a request on the wire; false when it was answered from the journal or refused before sending.</summary>
    public bool Sent { get; }

    /// <summary>The gRPC status of the latest failed attempt, when there was one.</summary>
    public StatusCode? Status { get; }

    /// <summary>The peer's typed refusal of the latest attempt, when there was one.</summary>
    public LocalRpcRefusal? Refusal { get; }

    /// <summary>Whether <see cref="Response"/> is set. A command that was reconciled to <see cref="LocalRpcEffect.Happened"/> succeeded without one.</summary>
    public bool HasResponse { get; }

    /// <summary>The response message, when <see cref="HasResponse"/>.</summary>
    public TResponse? Response { get; }
}
