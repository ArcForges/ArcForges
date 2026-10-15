// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using Google.Protobuf;

namespace ArcForges.Node.Core;

/// <summary>
/// The catalogued errors (ArcForges-Design <c>docs/contracts/errors.md</c>) that the node's API returns in <c>ArcError</c>: category,
/// code, <c>message_key = error.&lt;category&gt;.&lt;code&gt;</c>, retry advice and effect certainty, with the listed details.
/// </summary>
public static class NodeErrors
{
    /// <summary><c>VALIDATION/invalid_argument</c>: <c>state.reason</c> names the field path and rule.</summary>
    public static ArcError InvalidArgument(string fieldAndRule) =>
        Create(ErrorCategory.Validation, "invalid_argument", RetryMode.Never, new StateFailure { Reason = fieldAndRule });

    /// <summary><c>VALIDATION/invalid_cursor</c>: a page or stream cursor is malformed or from another generation.</summary>
    public static ArcError InvalidCursor() => Create(ErrorCategory.Validation, "invalid_cursor", RetryMode.Never, null);

    /// <summary><c>VALIDATION/incompatible_version</c> with <c>upgrade</c> (<c>VersionFailure</c>).</summary>
    public static ArcError IncompatibleVersion(string minReadable, string received)
    {
        var error = Create(ErrorCategory.Validation, "incompatible_version", RetryMode.Never, null);
        error.Details = new ErrorDetails { Upgrade = new VersionFailure { MinReadable = minReadable, MinWritable = minReadable, Received = received } };
        return error;
    }

    /// <summary><c>AUTHORIZATION/permission_denied</c>: <c>state.reason</c> names the operation.</summary>
    public static ArcError PermissionDenied(string operation) =>
        Create(ErrorCategory.Authorization, "permission_denied", RetryMode.Never, new StateFailure { Reason = operation });

    /// <summary><c>CONFLICT/revision_conflict</c> with the expected and the actual revision.</summary>
    public static ArcError RevisionConflict(long expected, long actual)
    {
        var error = Create(ErrorCategory.Conflict, "revision_conflict", RetryMode.Never, null);
        error.Details = new ErrorDetails
        {
            Revision = new RevisionConflict { Expected = new Revision { Value = expected }, Actual = new Revision { Value = actual } },
        };
        return error;
    }

    /// <summary><c>STATE/not_found</c>: <c>state.resource</c> names the object.</summary>
    public static ArcError NotFound(string kind, ReadOnlySpan<byte> id) => Create(ErrorCategory.State, "not_found", RetryMode.Never,
        new StateFailure { Resource = new AggregateRef { Kind = kind, Id = new Id { Value = ByteString.CopyFrom(id) } } });

    /// <summary><c>STATE/invalid_state</c>: <c>state.state</c> and <c>state.reason</c>.</summary>
    public static ArcError InvalidState(string state, string reason) =>
        Create(ErrorCategory.State, "invalid_state", RetryMode.Never, new StateFailure { State = state, Reason = reason });

    /// <summary><c>STATE/node_stopping</c>: retry <c>AFTER_TIME</c> (2 s), effect <c>DID_NOT_HAPPEN</c>.</summary>
    public static ArcError NodeStopping(DateTimeOffset now)
    {
        var error = Create(ErrorCategory.State, "node_stopping", RetryMode.AfterTime, null);
        error.Retry.RetryAt = ArcForges.Client.ProtoTime.ToInstant(now.AddSeconds(2));
        return error;
    }

    /// <summary><c>RESOURCE/overloaded</c>: the command queue is full; retry after a short time.</summary>
    public static ArcError Overloaded(DateTimeOffset now)
    {
        var error = Create(ErrorCategory.Resource, "overloaded", RetryMode.AfterTime, null);
        error.Retry.RetryAt = ArcForges.Client.ProtoTime.ToInstant(now.AddSeconds(1));
        return error;
    }

    /// <summary>
    /// <c>INTERNAL/internal</c>: an unexpected failure; retry <c>AFTER_TIME</c> once (errors.md; 1 s), effect <c>UNKNOWN</c>. A retry
    /// with the same command ID returns the recorded outcome if the first attempt did take effect.
    /// </summary>
    public static ArcError Internal(DateTimeOffset now)
    {
        var error = Create(ErrorCategory.Internal, "internal", RetryMode.AfterTime, null);
        error.Retry.RetryAt = ArcForges.Client.ProtoTime.ToInstant(now.AddSeconds(1));
        error.Effect = EffectCertainty.Unknown;
        return error;
    }

    private static ArcError Create(ErrorCategory category, string code, RetryMode retry, StateFailure? state)
    {
        var error = new ArcError
        {
            Code = code,
            Category = category,
            MessageKey = "error." + category.ToString().ToLowerInvariant() + "." + code,
            Retry = new RetryAdvice { Mode = retry },
            Effect = EffectCertainty.DidNotHappen,
        };
        if (state is not null)
        {
            error.Details = new ErrorDetails { State = state };
        }

        return error;
    }
}
