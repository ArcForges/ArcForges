// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core;
using Google.Protobuf;
using RelayShapes = ArcForges.Contracts.Relay.Shapes.ContractShapeValidation;

namespace ArcForges.Node.CloudLink;

/// <summary>
/// The refusals a node sends in <c>ResultHeader.error</c> (relay.proto, rule routedRefusal; Plan PN-6; C2 review A B-1): closed identifier
/// fields only. The code is catalogued under its category, the message key is the catalogue's, the details carry <c>state</c> only, and
/// <c>state.state</c> and <c>state.reason</c> are identifier tokens of a closed vocabulary; never a message, a path or a value from the call.
/// </summary>
internal static partial class RoutedRefusals
{
    /// <summary><c>AUTHENTICATION/signature_invalid</c>: a verification refusal, a replayed call included (<c>state.reason</c> = the step).</summary>
    public const string SignatureInvalid = "signature_invalid";

    /// <summary><c>STATE/expired</c>: past its expiry plus the 120 s skew, at verification or at the re-check before the effect.</summary>
    public const string Expired = "expired";

    /// <summary><c>AUTHORIZATION/permission_denied</c>: refused by the node's policy for center-routed callers.</summary>
    public const string PermissionDenied = "permission_denied";

    /// <summary>The <c>state.state</c> of a verification refusal.</summary>
    public const string VerificationState = "routed_call";

    /// <summary>
    /// The <c>state.reason</c> of the refusal every verified call gets until part N2 dispatches routed calls (AF-CTR-05 N1: the closed loop
    /// runs, nothing executes): the catalogued <c>center_routed_disabled</c> of <c>AUTHORIZATION/permission_denied</c> ("any routed call while
    /// the target's center-routed policy is off"; review A N-5), which N1's node is until N2. Transient: N2 replaces the dispatcher.
    /// </summary>
    public const string DispatchUnavailable = "center_routed_disabled";

    /// <summary>A verification refusal: <c>AUTHENTICATION/signature_invalid</c> with the step, or <c>STATE/expired</c>.</summary>
    public static ArcError Verification(CallRefusal refusal, Id correlation)
    {
        ArgumentNullException.ThrowIfNull(refusal);
        return refusal.Code == Expired
            ? Build(ErrorCategory.State, Expired, VerificationState, "expired", correlation)
            : Build(ErrorCategory.Authentication, SignatureInvalid, VerificationState, refusal.Step, correlation);
    }

    /// <summary>A policy refusal: <c>AUTHORIZATION/permission_denied</c>, <c>state.state</c> the matrix operation, <c>state.reason</c> the reason.</summary>
    public static ArcError Policy(string operation, string reason, Id correlation) =>
        Build(ErrorCategory.Authorization, PermissionDenied, operation, reason, correlation);

    /// <summary>The expiry re-check immediately before the effect failed (decision 4).</summary>
    public static ArcError ExpiredBeforeEffect(Id correlation) => Build(ErrorCategory.State, Expired, VerificationState, "expired_before_effect", correlation);

    /// <summary>The matrix operation of a routed method (Plan CTR5-NODE-09), the <c>state.state</c> of its policy refusals.</summary>
    public static string Operation(RoutedMethod method) => method switch
    {
        RoutedMethod.SubmitNodeTask => "task.submit",
        RoutedMethod.ReadNodeTaskOutput => "task.read_output",
        RoutedMethod.CancelNodeTask => "task.cancel",
        _ => "task.read",
    };

    /// <summary>True when <paramref name="error"/> holds closed fields only (the node's own check before it signs; the validator agrees).</summary>
    public static bool Closed(ArcError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return CodeShape().IsMatch(error.Code) && error.MessageKey == "error." + error.Category.ToString().ToLowerInvariant() + "." + error.Code
            && error.Retry is { HasReconciliationOperation: false }
            && (error.Details is null || (error.Details.State is { } state && error.Details.Revision is null && error.Details.Limit is null
                && error.Details.Upgrade is null && TokenShape().IsMatch(state.State) && TokenShape().IsMatch(state.Reason) && state.Native is null
                && state.Resource is null))
            && error.CalculateSize() <= 512;
    }

    private static ArcError Build(ErrorCategory category, string code, string state, string reason, Id correlation)
    {
        var error = new ArcError
        {
            Category = category,
            Code = code,
            MessageKey = "error." + category.ToString().ToLowerInvariant() + "." + code,
            Retry = new RetryAdvice { Mode = RetryMode.Never },
            Effect = EffectCertainty.DidNotHappen,
            CorrelationId = correlation,
            Details = new ErrorDetails { State = new StateFailure { State = state, Reason = reason } },
        };
        if (!Closed(error))
        {
            throw new InvalidOperationException("A routed refusal holds closed identifier fields only.");
        }

        return error;
    }

    [GeneratedRegex("^[a-z][a-z0-9_]{0,63}$")]
    private static partial Regex CodeShape();

    [GeneratedRegex("^[a-z0-9_.]{1,64}$")]
    private static partial Regex TokenShape();
}

/// <summary>
/// Signs routed results with the node key (AF-CTR-05 CTR5-NODE-07, CTR5-SIG-03; PB-3): the <see cref="ResultHeader"/> is serialized once, and
/// the node signs the result domain string followed by exactly those bytes, low-S, with the key whose public half the center registered for
/// the credential's installation at sign-in. A result whose header the contract's own validator refuses is never sent.
/// </summary>
internal sealed class ResultSigner(INodeKey key, ReadOnlyMemory<byte> nodeId, TimeProvider clock)
{
    /// <summary>The largest result payload (relay.proto ChannelResult.payload).</summary>
    public const int MaxPayloadBytes = 1_040_384;

    /// <summary>The answer to a verification refusal: nothing it could not verify is echoed (no command ID, method or request digest).</summary>
    public ChannelResult RefusedVerification(CallRefusal refusal)
    {
        ArgumentNullException.ThrowIfNull(refusal);
        var callId = refusal.CallId ?? throw new InvalidOperationException("A frame without a valid call ID is not answered.");
        var header = Base(callId, RoutedOutcome.RefusedVerification);
        header.Error = RoutedRefusals.Verification(refusal, NewCorrelation());
        return Seal(header, ByteString.Empty);
    }

    /// <summary>A verified call refused by policy (decision 2) or expired at the re-check (decision 4): the call's echoes and the closed error.</summary>
    public ChannelResult Refused(CallHeader call, RoutedOutcome outcome, ArcError error)
    {
        ArgumentNullException.ThrowIfNull(call);
        ArgumentNullException.ThrowIfNull(error);
        if (outcome is not (RoutedOutcome.RefusedByPolicy or RoutedOutcome.Expired))
        {
            throw new ArgumentOutOfRangeException(nameof(outcome));
        }

        var header = Echo(call, outcome);
        header.Error = error;
        return Seal(header, ByteString.Empty);
    }

    /// <summary>An executed call (decision 1): the exact node.v1 response bytes and their digest and size.</summary>
    public ChannelResult Executed(CallHeader call, ByteString response)
    {
        ArgumentNullException.ThrowIfNull(call);
        ArgumentNullException.ThrowIfNull(response);
        var header = Echo(call, RoutedOutcome.Executed);
        header.ResponseSha256 = ByteString.CopyFrom(SHA256.HashData(response.Span));
        header.ResponseSize = (uint)response.Length;
        return Seal(header, response);
    }

    /// <summary>A new correlation ID of the node (never part of a digest).</summary>
    public Id NewCorrelation() => new() { Value = ByteString.CopyFrom(CommandIds.New(clock).Value.Span) };

    private ResultHeader Echo(CallHeader call, RoutedOutcome outcome)
    {
        var header = Base(call.CallId, outcome);
        header.Method = call.Method;
        header.RequestSha256 = call.RequestSha256;
        if (call.CommandId is { } command)
        {
            header.CommandId = command;
        }

        return header;
    }

    private ResultHeader Base(Id callId, RoutedOutcome outcome) => new()
    {
        CallId = callId,
        NodeId = new Id { Value = ByteString.CopyFrom(nodeId.Span) },
        ExecutedAt = ProtoTime.ToInstant(clock.GetUtcNow()),
        Outcome = outcome,
    };

    private ChannelResult Seal(ResultHeader header, ByteString payload)
    {
        if (!RelayShapes.IsValid(header) || payload.Length > MaxPayloadBytes || (header.Error is { } error && !RoutedRefusals.Closed(error)))
        {
            throw new InvalidOperationException("The node never sends a result header its contract refuses.");
        }

        var bytes = header.ToByteString();
        var result = new ChannelResult
        {
            CallId = header.CallId,
            Header = new SignedHeader
            {
                Header = bytes,
                Signature = ByteString.CopyFrom(key.Sign(RelaySignatures.ResultInput(bytes.Span))),
                Algorithm = CallVerifier.Algorithm,
            },
            Payload = payload,
        };
        if (!RelayShapes.IsValid(result))
        {
            throw new InvalidOperationException("The node never sends a result frame its contract refuses.");
        }

        return result;
    }
}

/// <summary>What the dispatcher answers for a verified call.</summary>
/// <param name="Outcome">EXECUTED, REFUSED_BY_POLICY or EXPIRED.</param>
/// <param name="Response">The exact node.v1 response bytes of EXECUTED.</param>
/// <param name="Error">The closed refusal of REFUSED_BY_POLICY or EXPIRED.</param>
/// <param name="TaskId">The task the call named or created (16 bytes), for <c>routed_call_log.task_id</c>.</param>
/// <param name="Risk">The risk class (1..3), for <c>routed_call_log.risk</c>.</param>
internal sealed record RoutedAnswer(RoutedOutcome Outcome, ByteString? Response, ArcError? Error, byte[]? TaskId = null, int? Risk = null);

/// <summary>
/// The routed dispatch seam that part N2 implements (Plan CTR5-NODE-08): it receives only verified calls, parses the payload, applies the
/// center-routed policy and re-checks the expiry immediately before any effect (<see cref="CallVerifier.StillValid"/>).
/// </summary>
internal interface IRoutedDispatcher
{
    /// <summary>Answers a verified call.</summary>
    Task<RoutedAnswer> DispatchAsync(VerifiedCall call, CancellationToken cancellationToken);
}

/// <summary>
/// Part N1's dispatcher: every verified call is refused by policy, signed, without parsing its payload or any effect
/// (<c>AUTHORIZATION/permission_denied</c>, <c>state.reason</c> <c>center_routed_disabled</c>), so the closed loop runs end to end.
/// </summary>
internal sealed class RefusingDispatcher(TimeProvider clock) : IRoutedDispatcher
{
    /// <inheritdoc />
    public Task<RoutedAnswer> DispatchAsync(VerifiedCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        var correlation = CommandIds.New(clock);
        return Task.FromResult(new RoutedAnswer(RoutedOutcome.RefusedByPolicy, null,
            RoutedRefusals.Policy(RoutedRefusals.Operation(call.Header.Method), RoutedRefusals.DispatchUnavailable, correlation)));
    }
}
