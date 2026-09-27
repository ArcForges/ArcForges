// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.Foundation.Errors;

/// <summary>Stable metadata; retry advice describes a prerequisite, not permission to repeat effects.</summary>
public sealed class ReasonCode
{
    internal ReasonCode(string code, ErrorCategory category, RetryMode retry, EffectCertainty effect, string messageKey)
    {
        Code = code;
        Category = category;
        Retry = retry;
        Effect = effect;
        MessageKey = messageKey;
    }

    public string Code { get; }
    public ErrorCategory Category { get; }
    public RetryMode Retry { get; }
    public EffectCertainty Effect { get; }
    public string MessageKey { get; }
}

/// <summary>Producer registry from operation catalogue section 3.2; append stable codes only.</summary>
public static class ReasonCodes
{
    private static readonly ReadOnlyCollection<ReasonCode> Entries = Array.AsReadOnly<ReasonCode>(
    [
        new("auth.unauthenticated", ErrorCategory.Authentication, RetryMode.Never, EffectCertainty.DidNotHappen, "error.auth.unauthenticated"),
        new("auth.session_expired", ErrorCategory.Authentication, RetryMode.Never, EffectCertainty.DidNotHappen, "error.auth.session_expired"),
        new("auth.step_up_required", ErrorCategory.Authentication, RetryMode.Never, EffectCertainty.DidNotHappen, "error.auth.step_up_required"),
        new("auth.local_presence_required", ErrorCategory.Authorization, RetryMode.Never, EffectCertainty.DidNotHappen, "error.auth.local_presence_required"),
        new("perm.capability_denied", ErrorCategory.Authorization, RetryMode.Never, EffectCertainty.DidNotHappen, "error.perm.capability_denied"),
        new("perm.resource_denied", ErrorCategory.Authorization, RetryMode.Never, EffectCertainty.DidNotHappen, "error.perm.resource_denied"),
        new("perm.egress_denied", ErrorCategory.Authorization, RetryMode.Never, EffectCertainty.DidNotHappen, "error.perm.egress_denied"),
        new("perm.approval_required", ErrorCategory.Authorization, RetryMode.Never, EffectCertainty.DidNotHappen, "error.perm.approval_required"),
        new("perm.approval_expired", ErrorCategory.Authorization, RetryMode.Never, EffectCertainty.DidNotHappen, "error.perm.approval_expired"),
        new("perm.lease_expired", ErrorCategory.Authorization, RetryMode.Never, EffectCertainty.DidNotHappen, "error.perm.lease_expired"),
        new("entitlement.no_service_term", ErrorCategory.Entitlement, RetryMode.Never, EffectCertainty.DidNotHappen, "error.entitlement.no_service_term"),
        new("entitlement.not_entitled", ErrorCategory.Entitlement, RetryMode.Never, EffectCertainty.DidNotHappen, "error.entitlement.not_entitled"),
        new("entitlement.quota_exceeded", ErrorCategory.Entitlement, RetryMode.Never, EffectCertainty.DidNotHappen, "error.entitlement.quota_exceeded"),
        new("entitlement.capacity_exhausted", ErrorCategory.Entitlement, RetryMode.AfterTime, EffectCertainty.DidNotHappen, "error.entitlement.capacity_exhausted"),
        new("entitlement.extra_credits_required", ErrorCategory.Entitlement, RetryMode.Never, EffectCertainty.DidNotHappen, "error.entitlement.extra_credits_required"),
        new("entitlement.credits_exhausted", ErrorCategory.Entitlement, RetryMode.Never, EffectCertainty.DidNotHappen, "error.entitlement.credits_exhausted"),
        new("validation.invalid_request", ErrorCategory.Validation, RetryMode.Never, EffectCertainty.DidNotHappen, "error.validation.invalid_request"),
        new("validation.ast_bounds_exceeded", ErrorCategory.Validation, RetryMode.Never, EffectCertainty.DidNotHappen, "error.validation.ast_bounds_exceeded"),
        new("identity.last_credential", ErrorCategory.State, RetryMode.Never, EffectCertainty.DidNotHappen, "error.identity.last_credential"),
        new("validation.unsupported_version", ErrorCategory.Validation, RetryMode.Never, EffectCertainty.DidNotHappen, "error.validation.unsupported_version"),
        new("conflict.revision_mismatch", ErrorCategory.Conflict, RetryMode.Reconcile, EffectCertainty.DidNotHappen, "error.conflict.revision_mismatch"),
        new("conflict.local_changes_pending", ErrorCategory.Conflict, RetryMode.Reconcile, EffectCertainty.DidNotHappen, "error.conflict.local_changes_pending"),
        new("conflict.duplicate_identifier", ErrorCategory.Conflict, RetryMode.Never, EffectCertainty.DidNotHappen, "error.conflict.duplicate_identifier"),
        new("command.reused_identifier", ErrorCategory.Conflict, RetryMode.Never, EffectCertainty.DidNotHappen, "error.command.reused_identifier"),
        new("state.not_found", ErrorCategory.State, RetryMode.Never, EffectCertainty.DidNotHappen, "error.state.not_found"),
        new("state.invalid_transition", ErrorCategory.State, RetryMode.Never, EffectCertainty.DidNotHappen, "error.state.invalid_transition"),
        new("state.gone", ErrorCategory.State, RetryMode.Never, EffectCertainty.DidNotHappen, "error.state.gone"),
        new("resource.unavailable", ErrorCategory.Resource, RetryMode.SameCommand, EffectCertainty.DidNotHappen, "error.resource.unavailable"),
        new("resource.integrity_failed", ErrorCategory.Resource, RetryMode.Never, EffectCertainty.DidNotHappen, "error.resource.integrity_failed"),
        new("capacity.rate_limited", ErrorCategory.Resource, RetryMode.AfterTime, EffectCertainty.DidNotHappen, "error.capacity.rate_limited"),
        new("capacity.busy", ErrorCategory.Resource, RetryMode.AfterTime, EffectCertainty.DidNotHappen, "error.capacity.busy"),
        new("dependency.unavailable", ErrorCategory.Execution, RetryMode.Reconcile, EffectCertainty.Unknown, "error.dependency.unavailable"),
        new("dependency.timeout", ErrorCategory.Execution, RetryMode.Reconcile, EffectCertainty.Unknown, "error.dependency.timeout"),
        new("provider.declined", ErrorCategory.Execution, RetryMode.Never, EffectCertainty.DidNotHappen, "error.provider.declined"),
        new("internal.unexpected", ErrorCategory.Internal, RetryMode.Reconcile, EffectCertainty.Unknown, "error.internal.unexpected"),
        new("validation.invalid_offset", ErrorCategory.Validation, RetryMode.Reconcile, EffectCertainty.DidNotHappen, "error.validation.invalid_offset"),
        new("sync.cursor_expired", ErrorCategory.State, RetryMode.Reconcile, EffectCertainty.DidNotHappen, "error.sync.cursor_expired"),
        new("sync.bootstrap_expired", ErrorCategory.State, RetryMode.Reconcile, EffectCertainty.DidNotHappen, "error.sync.bootstrap_expired"),
        new("resource.upload_expired", ErrorCategory.Resource, RetryMode.Reconcile, EffectCertainty.DidNotHappen, "error.resource.upload_expired"),
        new("entitlement.request_too_large", ErrorCategory.Entitlement, RetryMode.Never, EffectCertainty.DidNotHappen, "error.entitlement.request_too_large"),
        new("commerce.supplier_budget_exhausted", ErrorCategory.Entitlement, RetryMode.Never, EffectCertainty.DidNotHappen, "error.commerce.supplier_budget_exhausted"),
        new("security.isolation_unavailable", ErrorCategory.Execution, RetryMode.Never, EffectCertainty.DidNotHappen, "error.security.isolation_unavailable"),
        new("resource.parser_failed", ErrorCategory.Resource, RetryMode.Reconcile, EffectCertainty.Unknown, "error.resource.parser_failed"),
        new("state.stale_fence", ErrorCategory.State, RetryMode.Reconcile, EffectCertainty.DidNotHappen, "error.state.stale_fence"),
    ]);

    public static IReadOnlyList<ReasonCode> All => Entries;

    public static bool TryGet(string code, [NotNullWhen(true)] out ReasonCode? reason)
    {
        reason = Entries.FirstOrDefault(entry => string.Equals(entry.Code, code, StringComparison.Ordinal));
        return reason is not null;
    }

    public static ReasonCode Get(string code)
    {
        ArgumentNullException.ThrowIfNull(code);
        return TryGet(code, out var reason) ? reason : throw new ArgumentException("Unregistered producer reason code.", nameof(code));
    }
}
