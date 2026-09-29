// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Resources;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;

namespace ArcForges.Desktop.Shell.Errors;

/// <summary>Projects registered failures into display-only, disclosure-safe text.</summary>
public static class ErrorPresenter
{
    private const string GenericMessageKey = "error.generic";

    private static readonly ResourceManager Strings = new(
        "ArcForges.Desktop.Shell.Errors.ErrorPresentationStrings",
        typeof(ErrorPresenter).Assembly);

    /// <summary>Creates a human-readable presentation without exposing exception or wire-detail text.</summary>
    public static (string Title, string WhatHappened, string RetryGuidance, string UserAction, string SupportReferenceId)
        Present(TypedFailure failure)
    {
        ArgumentNullException.ThrowIfNull(failure);

        ReasonCode? registered = null;
        bool known = failure.IsKnownCode && ReasonCodes.TryGet(failure.Code, out registered);
        ReasonCode reason = known ? registered! : ReasonCodes.Get("internal.unexpected");
        CultureInfo culture = CultureInfo.CurrentUICulture;
        string message = GetText(known ? reason.MessageKey : GenericMessageKey, culture);
        RetryMode retry = known ? failure.Retry : RetryMode.Never;

        return (
            GetText("error.presentation.title", culture),
            message,
            GetText(RetryResourceKey(retry), culture),
            GetText(ActionResourceKey(reason.Category), culture),
            SupportReferenceId(failure));
    }

    private static string GetText(string key, CultureInfo culture) =>
        Strings.GetString(key, culture)
        ?? Strings.GetString(GenericMessageKey, culture)
        ?? throw new InvalidOperationException("The safe error presentation resources are unavailable.");

    private static string RetryResourceKey(RetryMode mode) => mode switch
    {
        RetryMode.SameCommand => "error.retry.same-command",
        RetryMode.AfterTime => "error.retry.after-time",
        RetryMode.Reconcile => "error.retry.reconcile",
        _ => "error.retry.never",
    };

    private static string ActionResourceKey(ErrorCategory category) => category switch
    {
        ErrorCategory.Authentication => "error.action.authentication",
        ErrorCategory.Authorization => "error.action.authorization",
        ErrorCategory.Entitlement => "error.action.entitlement",
        ErrorCategory.Validation => "error.action.validation",
        ErrorCategory.Conflict => "error.action.conflict",
        ErrorCategory.State => "error.action.state",
        ErrorCategory.Resource => "error.action.resource",
        ErrorCategory.Execution => "error.action.execution",
        _ => "error.action.internal",
    };

    private static string SupportReferenceId(TypedFailure failure)
    {
        Id? correlationId = failure.CorrelationId;
        if (correlationId is { HasValue: true } && correlationId.Value.Length == 16)
        {
            // Wire IDs are canonical UUID bytes in network order, not Guid's platform byte layout.
            Guid parsed = new(correlationId.Value.Span, bigEndian: true);
            if (parsed != Guid.Empty)
            {
                return parsed.ToString("D", CultureInfo.InvariantCulture);
            }
        }

        return Guid.NewGuid().ToString("D", CultureInfo.InvariantCulture);
    }
}
