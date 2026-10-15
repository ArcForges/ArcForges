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
    /// (submit again with the environment), effect <c>DID_NOT_HAPPEN</c>; <c>details.state.reason</c> is the purge time,
    /// or why the node data key cannot open them.
    /// </summary>
    public static ArcError SecretsUnavailable(string reason) => new()
    {
        Code = "secrets_unavailable",
        Category = ErrorCategory.State,
        MessageKey = "error.state.secrets_unavailable",
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        Effect = EffectCertainty.DidNotHappen,
        Details = new ErrorDetails { State = new StateFailure { Reason = reason } },
    };
}
