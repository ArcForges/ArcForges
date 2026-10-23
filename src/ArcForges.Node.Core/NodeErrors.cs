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

    /// <summary>A catalogued <c>VALIDATION</c> error with <c>state.reason</c> (unsafe_batch_argument, program_not_found, unsupported_shell, path_not_found, invalid_dependency).</summary>
    public static ArcError Validation(string code, string reason) =>
        Create(ErrorCategory.Validation, code, RetryMode.Never, new StateFailure { Reason = reason });

    /// <summary><c>STATE/not_attached</c>: a stdin call without the caller's current attach.</summary>
    public static ArcError NotAttached() => Create(ErrorCategory.State, "not_attached", RetryMode.Never, null);

    /// <summary><c>STATE/pause_unsupported</c>.</summary>
    public static ArcError PauseUnsupported() => Create(ErrorCategory.State, "pause_unsupported", RetryMode.Never, null);

    /// <summary><c>VALIDATION/invalid_dependency</c>: <c>state.resource</c> names the dependency (when it has an ID) and <c>state.reason</c> the rule.</summary>
    public static ArcError InvalidDependency(ReadOnlySpan<byte> taskId, string reason)
    {
        var state = new StateFailure { Reason = reason };
        if (taskId.Length == 16)
        {
            state.Resource = new AggregateRef { Kind = "task", Id = new Id { Value = ByteString.CopyFrom(taskId) } };
        }

        return Create(ErrorCategory.Validation, "invalid_dependency", RetryMode.Never, state);
    }

    /// <summary><c>VALIDATION/invalid_policy</c>: the document's ERROR issues, as <c>path: message</c> in <c>state.reason</c>.</summary>
    public static ArcError InvalidPolicy(IEnumerable<string> issues) =>
        Create(ErrorCategory.Validation, "invalid_policy", RetryMode.Never, new StateFailure { Reason = string.Join("; ", issues) });

    /// <summary><c>CONFLICT/already_exists</c>: <c>state.resource</c> names the object (kind and name in <c>state.state</c>).</summary>
    public static ArcError AlreadyExists(string kind, string name) =>
        Create(ErrorCategory.Conflict, "already_exists", RetryMode.Never, new StateFailure { Resource = new AggregateRef { Kind = kind }, State = name });

    /// <summary><c>STATE/not_found</c> for an object named by text (a pool): <c>state.resource</c> has the kind, <c>state.state</c> the name.</summary>
    public static ArcError NotFound(string kind, string name) =>
        Create(ErrorCategory.State, "not_found", RetryMode.Never, new StateFailure { Resource = new AggregateRef { Kind = kind }, State = name });

    /// <summary><c>STATE/in_use</c>: retry <c>AFTER_TIME</c>; <c>state.reason</c> names the holder.</summary>
    public static ArcError InUse(string holder) => Create(ErrorCategory.State, "in_use", RetryMode.AfterTime, new StateFailure { Reason = holder });

    /// <summary><c>RESOURCE/enforcement_unavailable</c>: <c>state.reason</c> names the capability.</summary>
    public static ArcError EnforcementUnavailable(string capability) =>
        Create(ErrorCategory.Resource, "enforcement_unavailable", RetryMode.Never, new StateFailure { Reason = capability });

    /// <summary><c>EXECUTION/adopt_not_permitted</c>: the OS refused to place the process under management; <c>state.reason</c> says why.</summary>
    public static ArcError AdoptNotPermitted(string reason) =>
        Create(ErrorCategory.Execution, "adopt_not_permitted", RetryMode.Never, new StateFailure { Reason = reason });

    /// <summary><c>STATE/not_found</c> for a process: <c>state.resource.kind</c> is <c>process</c>, <c>state.reason</c> names it.</summary>
    public static ArcError ProcessNotFound(string reason) =>
        Create(ErrorCategory.State, "not_found", RetryMode.Never, new StateFailure { Resource = new AggregateRef { Kind = "process" }, Reason = reason });

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
