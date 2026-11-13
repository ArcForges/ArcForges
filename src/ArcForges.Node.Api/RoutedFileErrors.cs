// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.Node.Api;

/// <summary>Complete the published foundation error shape before it is stored or signed.</summary>
internal static class RoutedFileErrors
{
    internal static Id Correlation(RequestMeta? meta, Id callId)
    {
        if (Valid(meta?.CorrelationId))
        {
            return meta!.CorrelationId.Clone();
        }

        if (!Valid(callId))
        {
            throw new InvalidOperationException("A verified routed call must have a valid call ID.");
        }

        return callId.Clone();
    }

    internal static void Complete(ArcError error, RequestMeta? meta, Id callId, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(error);
        error.CorrelationId = Correlation(meta, callId);
        if (error.Details?.State is { } state)
        {
            if (!state.HasState || state.State.Length == 0)
            {
                state.State = state.Resource is { HasKind: true, Kind.Length: > 0 } resource ? resource.Kind : "file";
            }

            if (!state.HasReason || state.Reason.Length == 0)
            {
                state.Reason = error.Code;
            }

            if (error.Category == ErrorCategory.Validation && error.Code == "invalid_argument" &&
                !state.Reason.Contains(": ", StringComparison.Ordinal))
            {
                state.Reason = "request: " + state.Reason;
            }
        }

        if (error.Retry is { Mode: RetryMode.AfterTime, RetryAt: null })
        {
            error.Retry.RetryAt = ProtoTime.ToInstant(clock.GetUtcNow().AddSeconds(2));
        }

        if (error.Category == ErrorCategory.Internal && error.Effect == EffectCertainty.Unknown && error.Retry is not null)
        {
            error.Retry.Mode = RetryMode.Never;
            error.Retry.RetryAt = null;
        }
    }

    private static bool Valid(Id? id) =>
        id is { Value.Length: 16 } && id.Value.Span.IndexOfAnyExcept((byte)0) >= 0;
}
