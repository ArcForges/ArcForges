// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;
using Google.Protobuf;

namespace ArcForges.Foundation.Tests;

public sealed class OutcomeTests
{
    [Xunit.Fact]
    public void RegistryProjectionIsCompleteAndHasStableRequiredMetadata()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "DesktopPlatform.slnx")))
        {
            root = root.Parent;
        }

        Xunit.Assert.NotNull(root);
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(root.FullName, "eng/policy/reason-codes.json")));
        var rows = document.RootElement.GetProperty("codes").EnumerateArray().ToArray();
        Xunit.Assert.Equal(44, rows.Length);
        Xunit.Assert.Equal(ReasonCodes.All.Count, rows.Length);
        Xunit.Assert.Equal(rows.Length, rows.Select(row => row.GetProperty("code").GetString()).Distinct(StringComparer.Ordinal).Count());
        foreach (var row in rows)
        {
            var reason = ReasonCodes.Get(row.GetProperty("code").GetString()!);
            Xunit.Assert.Equal(reason.Category.ToString(), row.GetProperty("category").GetString());
            Xunit.Assert.Equal(reason.Retry.ToString(), row.GetProperty("retry").GetString());
            Xunit.Assert.Equal(reason.Effect.ToString(), row.GetProperty("effect").GetString());
            Xunit.Assert.Equal(reason.MessageKey, row.GetProperty("messageKey").GetString());
            var failure = TypedFailure.Create(reason.Code);
            Xunit.Assert.Equal(reason.Code, failure.ToWire().Code);
            Xunit.Assert.Equal(reason.Category, failure.Category);
            Xunit.Assert.Equal(RetryMode.Never, failure.Retry);
        }
    }

    [Xunit.Theory]
    [Xunit.InlineData("identity.last_credential", ErrorCategory.State)]
    [Xunit.InlineData("validation.ast_bounds_exceeded", ErrorCategory.Validation)]
    [Xunit.InlineData("validation.invalid_request", ErrorCategory.Validation)]
    public void BoundaryRefusalsRemainRegisteredNonretryableAndBeforeEffects(string code, ErrorCategory category)
    {
        var failure = TypedFailure.Create(code);
        Xunit.Assert.Equal(category, failure.Category);
        Xunit.Assert.Equal(EffectCertainty.DidNotHappen, failure.Effect);
        Xunit.Assert.Throws<ArgumentException>(() => TypedFailure.Create(code, effect: EffectCertainty.Happened));
        Xunit.Assert.Throws<ArgumentException>(() => TypedFailure.Create(code, retry: new RetryAdvice { Mode = RetryMode.SameCommand }));
        int effects = 0;
        // The owner supplies its already-decided validation refusal; this primitive never runs the effect.
        var refused = Outcome<int>.Failure(failure).Map(value => { effects++; return value + 1; });
        Xunit.Assert.Equal(0, effects);
        Xunit.Assert.True(refused.TryGetFailure(out var preserved));
        Xunit.Assert.Same(failure, preserved);
    }

    [Xunit.Fact]
    public void UnknownFutureErrorsStayGenericWithoutAutomaticRetryAndPreserveCorrelationAndEffect()
    {
        var wire = new ArcError
        {
            Code = "future.condition", Category = (ErrorCategory)123,
            Effect = EffectCertainty.Happened, MessageKey = "unsafe.producer.label",
            Retry = new RetryAdvice { Mode = RetryMode.SameCommand },
            CorrelationId = new Id { Value = ByteString.CopyFrom(new byte[16]) },
        };
        var result = Outcome<int>.Failure(TypedFailure.FromWire(wire));
        wire.Effect = EffectCertainty.DidNotHappen;
        Xunit.Assert.False(result.TryGetValue(out _));
        Xunit.Assert.True(result.TryGetFailure(out var failure));
        Xunit.Assert.False(failure.IsKnownCode);
        Xunit.Assert.Equal("future.condition", failure.Code);
        Xunit.Assert.Equal("error.generic", failure.MessageKey);
        Xunit.Assert.Equal(RetryMode.Never, failure.Retry);
        Xunit.Assert.Equal(EffectCertainty.Happened, failure.Effect);
        Xunit.Assert.Equal(16, failure.CorrelationId!.Value.Length);
        Xunit.Assert.Throws<InvalidOperationException>(() => failure.ToWire());
        Xunit.Assert.Throws<ArgumentException>(() => TypedFailure.Create("future.condition"));
        wire.Category = ErrorCategory.Validation;
        Xunit.Assert.Equal(ErrorCategory.Validation, TypedFailure.FromWire(wire).Category);
    }

    [Xunit.Theory]
    [Xunit.InlineData(0)]
    [Xunit.InlineData(999)]
    public void MissingOrUnknownEffectCannotAuthorizeRetry(int effect)
    {
        var failure = TypedFailure.FromWire(new ArcError
        {
            Code = "resource.unavailable", Effect = (EffectCertainty)effect,
            Retry = new RetryAdvice { Mode = RetryMode.SameCommand },
        });
        Xunit.Assert.Equal(EffectCertainty.Unknown, failure.Effect);
        Xunit.Assert.Equal(RetryMode.Never, failure.Retry);
    }

    [Xunit.Fact]
    public void UnknownCategoryOrContradictoryEffectCannotAuthorizeRetry()
    {
        var input = TypedFailure.Create("resource.unavailable").ToWire();
        input.Category = (ErrorCategory)999;
        input.Retry = new RetryAdvice { Mode = RetryMode.SameCommand };
        Xunit.Assert.Equal(RetryMode.Never, TypedFailure.FromWire(input).Retry);
        input.Category = ErrorCategory.Resource;
        input.Effect = EffectCertainty.Happened;
        var reader = TypedFailure.FromWire(input);
        Xunit.Assert.Equal(EffectCertainty.Happened, reader.Effect);
        Xunit.Assert.Equal(RetryMode.Never, reader.Retry);
        Xunit.Assert.Throws<InvalidOperationException>(() => reader.ToWire());
    }

    [Xunit.Fact]
    public void RetryRequiresRegisteredModeAndRecoveryEvidence()
    {
        Xunit.Assert.Throws<ArgumentException>(() => TypedFailure.Create("capacity.busy", retry: new RetryAdvice { Mode = RetryMode.AfterTime }));
        var retry = new RetryAdvice { Mode = RetryMode.AfterTime, RetryAt = new() { UnixSeconds = 100, Nanos = 0 } };
        var failure = TypedFailure.Create("capacity.rate_limited", retry: retry);
        retry.RetryAt.Nanos = 1_000_000_000;
        Xunit.Assert.Equal(0U, failure.RetryAdvice.RetryAt.Nanos);
        Xunit.Assert.Equal(RetryMode.AfterTime, failure.Retry);
        Xunit.Assert.Throws<ArgumentException>(() => TypedFailure.Create("capacity.busy", retry: retry));
        Xunit.Assert.Throws<ArgumentException>(() => TypedFailure.Create("dependency.timeout", retry: new RetryAdvice { Mode = RetryMode.SameCommand }));
        var reconcile = TypedFailure.Create("dependency.timeout", retry: new RetryAdvice { Mode = RetryMode.Reconcile, ReconciliationOperation = "task.get" });
        Xunit.Assert.Equal(EffectCertainty.Unknown, reconcile.Effect);
        Xunit.Assert.Equal(RetryMode.Reconcile, reconcile.Retry);
    }

    [Xunit.Fact]
    public void CancellationSurvivesMappingAndNeverBecomesFailure()
    {
        int calls = 0;
        var cancelled = Outcome<int>.Cancelled(EffectCertainty.Unknown).Map(value => { calls++; return value.ToString(System.Globalization.CultureInfo.InvariantCulture); });
        Xunit.Assert.Equal(OutcomeKind.Cancelled, cancelled.Kind);
        Xunit.Assert.Equal(EffectCertainty.Unknown, cancelled.CancellationEffect);
        Xunit.Assert.False(cancelled.TryGetFailure(out _));
        Xunit.Assert.False(cancelled.TryGetValue(out _));
        Xunit.Assert.Equal(0, calls);
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => Outcome<int>.Cancelled(EffectCertainty.Unspecified));
        var success = Outcome<int>.Success(0).Map(value => value + 1);
        Xunit.Assert.True(success.TryGetValue(out int result));
        Xunit.Assert.Equal(1, result);
        Xunit.Assert.Throws<InvalidOperationException>(() => success.CancellationEffect);
    }

    [Xunit.Fact]
    public void KnownWireRoundTripsAreImmutableAndCannotSupplyUnregisteredRetryMetadata()
    {
        var input = TypedFailure.Create("validation.invalid_request").ToWire();
        input.Retry = new RetryAdvice { Mode = (RetryMode)998 };
        input.MessageKey = "untrusted";
        var failure = TypedFailure.FromWire(input);
        Xunit.Assert.Equal("error.validation.invalid_request", failure.MessageKey);
        Xunit.Assert.Equal(RetryMode.Never, failure.Retry);
        var output = failure.ToWire();
        output.Code = "mutated";
        Xunit.Assert.Equal("validation.invalid_request", failure.Code);
    }
}
