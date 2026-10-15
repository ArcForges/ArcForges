// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.Node.Store.Tests;

/// <summary>The catalogued error shapes of ArcForges-Design docs/contracts/errors.md.</summary>
public sealed class StoreErrorsTests
{
    [Fact]
    public void SecretsUnavailableReasonIsExactlyThePurgeTime()
    {
        var purgedAt = StoreTime.ToMicroseconds(new DateTimeOffset(2026, 10, 19, 12, 0, 0, TimeSpan.Zero).AddTicks(1_234_560));

        var error = StoreErrors.SecretsUnavailable(purgedAt);

        Assert.Equal("secrets_unavailable", error.Code);
        Assert.Equal(ErrorCategory.State, error.Category);
        Assert.Equal("error.state.secrets_unavailable", error.MessageKey);
        Assert.Equal(RetryMode.Never, error.Retry.Mode);
        Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);
        Assert.Equal(ErrorDetails.DetailOneofCase.State, error.Details.DetailCase);
        Assert.Equal("2026-10-19T12:00:00.123456Z", error.Details.State.Reason);
        Assert.False(error.Details.State.HasState);
    }

    [Fact]
    public void SecretsUnavailableWithoutAPurgeTimeHasNoDetails()
    {
        var error = StoreErrors.SecretsUnavailable(purgedAt: null);

        Assert.Equal("secrets_unavailable", error.Code);
        Assert.Null(error.Details);
    }

    [Fact]
    public void CommandIdReusedHasNoDetails()
    {
        var error = StoreErrors.CommandIdReused();

        Assert.Equal("command_id_reused", error.Code);
        Assert.Equal(ErrorCategory.Conflict, error.Category);
        Assert.Equal(RetryMode.Never, error.Retry.Mode);
        Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);
        Assert.Null(error.Details);
    }
}
