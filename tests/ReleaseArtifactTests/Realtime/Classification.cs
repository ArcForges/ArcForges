// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Contracts.Events.V1;
using ArcForges.Contracts.Foundation.V1;
using Google.Protobuf;
using Grpc.Core;

namespace RealtimeAotProbe;

/// <summary>What a typed failure obliges the client to do.</summary>
internal enum Disposition
{
    /// <summary>Retry the identical read within the bounded backoff.</summary>
    Retry,

    /// <summary>A permission failure: no retry until a newly authorized session exists (annex 10 section 5).</summary>
    StopAuthorization,

    /// <summary>The server does not implement the operation: report it, never retry it.</summary>
    StopUnsupported,

    /// <summary>A validation, state or conflict refusal that a retry cannot change.</summary>
    StopNonRetryable,

    /// <summary>The server sent bytes that are not the generated message: a retry would repeat the violation.</summary>
    StopProtocol,
}

internal readonly record struct Classified(Disposition Disposition, TimeSpan RetryAfter, string Detail);

/// <summary>Maps the typed <c>ArcError</c> envelope and the gRPC trailer status to a client obligation.</summary>
/// <remarks>
/// Authentication, authorization and entitlement refusals always stop, whatever retry advice accompanies them.
/// Otherwise an explicit retry time is honored (bounded by the policy), an explicit "never" stops, and the
/// transient categories (resource, execution, internal) retry while validation, conflict and state refusals stop.
/// Details carry only the stable code and category, never a message or a request value.
/// </remarks>
internal static class ErrorClassifier
{
    public static Classified FromArcError(ArcError? error, DateTimeOffset now, RealtimePolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (error is null)
        {
            return new Classified(Disposition.StopNonRetryable, TimeSpan.Zero, "an error frame without an ArcError");
        }

        string detail = string.Create(CultureInfo.InvariantCulture, $"code={(error.HasCode ? error.Code : "none")} category={error.Category}");
        if (error.Category is ErrorCategory.Authentication or ErrorCategory.Authorization or ErrorCategory.Entitlement)
        {
            return new Classified(Disposition.StopAuthorization, TimeSpan.Zero, detail);
        }

        RetryMode mode = error.Retry?.Mode ?? RetryMode.Unspecified;
        if (mode == RetryMode.Never)
        {
            return new Classified(Disposition.StopNonRetryable, TimeSpan.Zero, detail);
        }

        if (mode == RetryMode.AfterTime)
        {
            return new Classified(Disposition.Retry, RetryDelay(error.Retry?.RetryAt, now, policy), detail);
        }

        bool transient = error.Category is ErrorCategory.Resource or ErrorCategory.Execution or ErrorCategory.Internal;
        return new Classified(transient ? Disposition.Retry : Disposition.StopNonRetryable, TimeSpan.Zero, detail);
    }

    public static Classified FromRpc(RpcException exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        string detail = "grpc-status=" + exception.StatusCode;
        if (exception.Status.DebugException is InvalidProtocolBufferException)
        {
            return new Classified(Disposition.StopProtocol, TimeSpan.Zero, detail + " malformed message");
        }

        Disposition disposition = exception.StatusCode switch
        {
            StatusCode.Unauthenticated or StatusCode.PermissionDenied => Disposition.StopAuthorization,
            StatusCode.Unimplemented => Disposition.StopUnsupported,
            StatusCode.InvalidArgument or StatusCode.NotFound or StatusCode.AlreadyExists or StatusCode.FailedPrecondition
                or StatusCode.OutOfRange => Disposition.StopNonRetryable,
            _ => Disposition.Retry,
        };
        return new Classified(disposition, TimeSpan.Zero, detail);
    }

    private static TimeSpan RetryDelay(Instant? retryAt, DateTimeOffset now, RealtimePolicy policy)
    {
        if (retryAt is null)
        {
            return TimeSpan.Zero;
        }

        try
        {
            DateTimeOffset at = DateTimeOffset.FromUnixTimeSeconds(retryAt.UnixSeconds).AddTicks(retryAt.Nanos / 100);
            TimeSpan delay = at - now;
            return delay <= TimeSpan.Zero ? TimeSpan.Zero : delay > policy.MaximumRetryAfter ? policy.MaximumRetryAfter : delay;
        }
        catch (ArgumentOutOfRangeException)
        {
            return policy.MaximumRetryAfter;
        }
    }
}
