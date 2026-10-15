// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.Node.Store;

/// <summary>The catalogued errors (ArcForges-Design docs/contracts/errors.md) that store operations return.</summary>
public static class StoreErrors
{
    /// <summary>
    /// <c>CONFLICT/command_id_reused</c>: the same <c>command_id</c> arrived with a different payload digest. Retry
    /// <c>NEVER</c>, effect <c>DID_NOT_HAPPEN</c>.
    /// </summary>
    public static ArcError CommandIdReused() => new()
    {
        Code = "command_id_reused",
        Category = ErrorCategory.Conflict,
        MessageKey = "error.conflict.command_id_reused",
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        Effect = EffectCertainty.DidNotHappen,
    };

    /// <summary>
    /// <c>STATE/secrets_unavailable</c>: a retry needs sealed secret environment values that are gone. Retry <c>NEVER</c>
    /// (submit again with the environment), effect <c>DID_NOT_HAPPEN</c>. Per errors.md, <c>details.state.reason</c> is the
    /// purge time and nothing else: the RFC 3339 UTC instant of <paramref name="purgedAt"/>. Values that were not purged but
    /// cannot be opened (the node data key is lost, or another key) have no purge time, so the error carries no details;
    /// <c>ArcError</c> has no free-text field, and the explanation stays a local diagnostic
    /// (<see cref="UnsealResult.UnavailableReason"/>).
    /// </summary>
    /// <param name="purgedAt">The purge time in microseconds since the Unix epoch, or <see langword="null"/> when not purged.</param>
    public static ArcError SecretsUnavailable(long? purgedAt)
    {
        var error = new ArcError
        {
            Code = "secrets_unavailable",
            Category = ErrorCategory.State,
            MessageKey = "error.state.secrets_unavailable",
            Retry = new RetryAdvice { Mode = RetryMode.Never },
            Effect = EffectCertainty.DidNotHappen,
        };
        if (purgedAt is { } at)
        {
            error.Details = new ErrorDetails { State = new StateFailure { Reason = StoreTime.ToRfc3339(at) } };
        }

        return error;
    }
}
