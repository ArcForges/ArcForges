// SPDX-License-Identifier: AGPL-3.0-only

using ArcForges.Contracts.Foundation.V1;
using ArcForges.Desktop.Shell.Errors;
using ArcForges.Foundation.Errors;
using Google.Protobuf;
using Xunit;

namespace ArcForges.Desktop.Shell.Tests;

public sealed class ErrorPresentationTests
{
    [Fact]
    public void AllRegisteredReasonCodesHaveACompleteUserPresentation()
    {
        var messages = new HashSet<string>(StringComparer.Ordinal);

        foreach (ReasonCode reason in ReasonCodes.All)
        {
            var presentation = ErrorPresenter.Present(TypedFailure.Create(reason.Code));

            Assert.False(string.IsNullOrWhiteSpace(presentation.Title));
            Assert.False(string.IsNullOrWhiteSpace(presentation.WhatHappened));
            Assert.False(string.IsNullOrWhiteSpace(presentation.RetryGuidance));
            Assert.False(string.IsNullOrWhiteSpace(presentation.UserAction));
            Assert.True(Guid.TryParseExact(presentation.SupportReferenceId, "D", out Guid supportId));
            Assert.NotEqual(Guid.Empty, supportId);
            Assert.True(messages.Add(presentation.WhatHappened), $"Duplicate user message for reason code {reason.Code}.");
        }

        Assert.Equal(ReasonCodes.All.Count, messages.Count);
    }

    [Fact]
    public void PresentationUsesOnlyRegisteredTextAndNeverEchoesExceptionDetailsOrPaths()
    {
        const string canary = "InvalidOperationException: C:\\private\\customer-token.txt";
        var wire = new ArcError
        {
            Code = "internal.unexpected",
            Category = ErrorCategory.Internal,
            MessageKey = canary,
            Effect = EffectCertainty.Unknown,
            Retry = new RetryAdvice
            {
                Mode = RetryMode.Reconcile,
                ReconciliationOperation = canary,
            },
            Details = new ErrorDetails
            {
                State = new StateFailure
                {
                    State = canary,
                    Reason = canary,
                },
            },
        };

        var presentation = ErrorPresenter.Present(TypedFailure.FromWire(wire));
        string[] visible = [presentation.Title, presentation.WhatHappened, presentation.RetryGuidance, presentation.UserAction, presentation.SupportReferenceId];

        Assert.All(visible, text => Assert.DoesNotContain(canary, text, StringComparison.Ordinal));
        Assert.All(visible, text => Assert.DoesNotContain("C:\\private", text, StringComparison.OrdinalIgnoreCase));
        Assert.Contains("Check whether the action completed", presentation.RetryGuidance, StringComparison.Ordinal);
    }

    [Fact]
    public void UnknownFutureCodeAndMessageKeyFallBackWithoutDisplayingUntrustedValues()
    {
        const string canary = "future.secret.C:\\private\\file.txt";
        var wire = new ArcError
        {
            Code = canary,
            Category = (ErrorCategory)999,
            MessageKey = canary,
            Effect = EffectCertainty.Unknown,
            Retry = new RetryAdvice
            {
                Mode = RetryMode.Reconcile,
                ReconciliationOperation = canary,
            },
            CorrelationId = new Id { Value = ByteString.CopyFromUtf8(canary) },
        };

        var presentation = ErrorPresenter.Present(TypedFailure.FromWire(wire));
        string[] visible = [presentation.Title, presentation.WhatHappened, presentation.RetryGuidance, presentation.UserAction, presentation.SupportReferenceId];

        Assert.All(visible, text => Assert.DoesNotContain(canary, text, StringComparison.Ordinal));
        Assert.All(visible, text => Assert.DoesNotContain("C:\\private", text, StringComparison.OrdinalIgnoreCase));
        Assert.Contains("unexpected error", presentation.WhatHappened, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not available", presentation.RetryGuidance, StringComparison.OrdinalIgnoreCase);
        Assert.True(Guid.TryParseExact(presentation.SupportReferenceId, "D", out Guid supportId));
        Assert.NotEqual(Guid.Empty, supportId);
    }

    [Fact]
    public void SupportReferenceUsesCanonicalNetworkOrderAndRejectsInvalidCorrelationShape()
    {
        byte[] canonicalId = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        var valid = TypedFailure.Create("internal.unexpected", correlationId: new Id { Value = ByteString.CopyFrom(canonicalId) });
        var invalid = TypedFailure.Create("internal.unexpected", correlationId: new Id { Value = ByteString.CopyFrom(canonicalId.AsSpan(0, 15)) });
        var empty = TypedFailure.Create("internal.unexpected", correlationId: new Id { Value = ByteString.CopyFrom(new byte[16]) });

        Assert.Equal("00112233-4455-6677-8899-aabbccddeeff", ErrorPresenter.Present(valid).SupportReferenceId);
        Assert.True(Guid.TryParseExact(ErrorPresenter.Present(invalid).SupportReferenceId, "D", out Guid invalidFallback));
        Assert.NotEqual(Guid.Empty, invalidFallback);
        Assert.True(Guid.TryParseExact(ErrorPresenter.Present(empty).SupportReferenceId, "D", out Guid emptyFallback));
        Assert.NotEqual(Guid.Empty, emptyFallback);
    }

    [Fact]
    public void RetryGuidanceReflectsValidatedTypedAdviceRatherThanReasonText()
    {
        var never = ErrorPresenter.Present(TypedFailure.Create("auth.unauthenticated"));
        var sameCommand = ErrorPresenter.Present(TypedFailure.Create(
            "resource.unavailable",
            retry: new RetryAdvice { Mode = RetryMode.SameCommand }));
        var afterTime = ErrorPresenter.Present(TypedFailure.Create(
            "capacity.busy",
            retry: new RetryAdvice { Mode = RetryMode.AfterTime, RetryAt = new Instant { UnixSeconds = 1_800_000_000, Nanos = 0 } }));
        var reconcile = ErrorPresenter.Present(TypedFailure.Create(
            "internal.unexpected",
            retry: new RetryAdvice { Mode = RetryMode.Reconcile, ReconciliationOperation = "owner.inspect" },
            effect: EffectCertainty.Unknown));

        Assert.Contains("not available", never.RetryGuidance, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("same action again", sameCommand.RetryGuidance, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("recover", afterTime.RetryGuidance, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Check whether the action completed", reconcile.RetryGuidance, StringComparison.Ordinal);
        Assert.DoesNotContain("owner.inspect", reconcile.RetryGuidance, StringComparison.Ordinal);
    }

    [Fact]
    public void PermissionPresentationGivesAUsefulSafeNextStep()
    {
        var presentation = ErrorPresenter.Present(TypedFailure.Create("perm.resource_denied"));

        Assert.Contains("cannot access", presentation.WhatHappened, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("owner or an administrator", presentation.UserAction, StringComparison.OrdinalIgnoreCase);
    }
}
