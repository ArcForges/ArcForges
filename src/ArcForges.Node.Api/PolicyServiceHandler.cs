// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Store.Policy;
using Grpc.Core;

namespace ArcForges.Node.Api;

/// <summary>
/// <c>arcforges.node.v1.PolicyService</c> (policy.proto; node-store.md <c>policy_document</c>): the current document and its revision, the
/// default document, validation (ERROR and WARNING issues with field paths), replacement under <c>meta.expected_rev</c>, the revision list
/// and restoring an earlier revision as a new one. Every applied change is a new revision (the last 200 are kept) and takes effect at once:
/// the supervisor re-reads its settings and admission runs. The <c>retry_safety</c> section is HUMAN-edited (AD-0006 section 4): a change
/// of it from another origin is refused. <c>ExplainPermission</c> belongs to the permission matrix (AF-SEC-01); the generated base answers
/// it <c>UNIMPLEMENTED</c>.
/// </summary>
public sealed class PolicyServiceHandler : PolicyService.PolicyServiceBase
{
    private const string ServiceName = "arcforges.node.v1.PolicyService";
    private readonly NodeRuntime _node;
    private readonly ApiCommands _api;

    /// <summary>Creates the service over the running node.</summary>
    public PolicyServiceHandler(NodeRuntime node, ClientSessions sessions)
    {
        _node = node ?? throw new ArgumentNullException(nameof(node));
        _api = new ApiCommands(node, sessions ?? throw new ArgumentNullException(nameof(sessions)), ServiceName);
    }

    private ExecutionSupervisor Execution => _node.Execution ?? throw new InvalidOperationException("The node has no execution supervisor.");

    /// <inheritdoc />
    public override Task<PolicyServiceGetPolicyResponse> GetPolicy(PolicyServiceGetPolicyRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new PolicyServiceGetPolicyResponse { Meta = ApiCommands.Meta(request.Meta) };
        if (_api.Stopping() is { } refused)
        {
            response.Error = refused;
            return Task.FromResult(response);
        }

        var current = _node.Store.Read(PolicyRules.Current);
        response.Value = new PolicyServiceGetPolicyValue { Document = current.Document, Revision = PolicyRules.Revision(current) };
        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override Task<PolicyServiceGetDefaultPolicyResponse> GetDefaultPolicy(PolicyServiceGetDefaultPolicyRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new PolicyServiceGetDefaultPolicyResponse { Meta = ApiCommands.Meta(request.Meta) };
        if (_api.Stopping() is { } refused)
        {
            response.Error = refused;
        }
        else
        {
            response.Value = new PolicyServiceGetDefaultPolicyValue { Document = DefaultPolicy.Create() };
        }

        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override Task<PolicyServiceValidatePolicyResponse> ValidatePolicy(PolicyServiceValidatePolicyRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new PolicyServiceValidatePolicyResponse { Meta = ApiCommands.Meta(request.Meta) };
        var refused = _api.Stopping() ?? (request.Document is null ? NodeErrors.InvalidArgument("document: required") : null);
        if (refused is not null)
        {
            response.Error = refused;
            return Task.FromResult(response);
        }

        var issues = Validate(request.Document!);
        var value = new PolicyServiceValidatePolicyValue { Valid = issues.All(issue => issue.Severity != Severity.Error) };
        value.Issues.Add(issues);
        response.Value = value;
        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override async Task<PolicyServiceUpdatePolicyResponse> UpdatePolicy(PolicyServiceUpdatePolicyRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new PolicyServiceUpdatePolicyResponse { Meta = ApiCommands.Meta(request.Meta) };
        var refused = _api.Stopping() ?? Validation.CommandId(request.Meta) ?? _api.AgentNeedsApproval(context, "UpdatePolicy")
            ?? (request.Document is null ? NodeErrors.InvalidArgument("document: required") : null)
            ?? (request.HasComment && request.Comment.Length > 500 ? NodeErrors.InvalidArgument("comment: <= 500 chars") : null)
            ?? (request.Meta.ExpectedRev is not { HasValue: true } ? NodeErrors.InvalidArgument("meta.expected_rev: required (the current policy revision)") : null);
        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        var issues = Validate(request.Document!);
        if (issues.Any(issue => issue.Severity == Severity.Error))
        {
            response.Error = NodeErrors.InvalidPolicy(issues.Where(issue => issue.Severity == Severity.Error).Select(issue => issue.Path + ": " + issue.Message));
            return response;
        }

        var expected = request.Meta.ExpectedRev.Value;
        var actor = _api.Actor(context);
        var human = _api.OriginOf(context) == Origin.Human;
        var (result, replayed) = await _api.IdempotentAsync(request, request.Meta, context, "UpdatePolicy", PolicyServiceUpdatePolicyResponse.Parser,
            failure => new PolicyServiceUpdatePolicyResponse { Meta = ApiCommands.Meta(request.Meta), Error = failure }, command =>
            {
                var current = PolicyRules.Current(command.Transaction);
                if (current.Revision != expected)
                {
                    return new PolicyServiceUpdatePolicyResponse { Meta = ApiCommands.Meta(request.Meta), Error = NodeErrors.RevisionConflict(expected, current.Revision) };
                }

                if (!human && !Equals(current.Document.RetrySafety ?? new RetrySafetyPolicy(), request.Document!.RetrySafety ?? new RetrySafetyPolicy()))
                {
                    return new PolicyServiceUpdatePolicyResponse
                    {
                        Meta = ApiCommands.Meta(request.Meta),
                        Error = NodeErrors.PermissionDenied("UpdatePolicy.retry_safety (HUMAN only: AD-0006 section 4)"),
                    };
                }

                var row = PolicyRules.Write(command.Transaction, Normalized(request.Document!), actor, request.HasComment ? request.Comment : null);
                var value = new PolicyServiceUpdatePolicyValue { Revision = PolicyRules.Revision(row) };
                value.Warnings.Add(issues.Where(issue => issue.Severity == Severity.Warning));
                return new PolicyServiceUpdatePolicyResponse { Meta = ApiCommands.Meta(request.Meta), Value = value };
            }).ConfigureAwait(false);
        if (!replayed && result.OutcomeCase == PolicyServiceUpdatePolicyResponse.OutcomeOneofCase.Value)
        {
            Execution.PolicyChanged();
            _node.Log.Info("api.policy.updated", new LogField("revision", result.Value.Revision.Revision.Value), new LogField("origin", actor.Origin));
        }

        return result;
    }

    /// <inheritdoc />
    public override Task<PolicyServiceListPolicyRevisionsResponse> ListPolicyRevisions(PolicyServiceListPolicyRevisionsRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new PolicyServiceListPolicyRevisionsResponse { Meta = ApiCommands.Meta(request.Meta) };
        var limit = 50;
        long before = long.MaxValue;
        var refused = _api.Stopping();
        if (refused is null && request.Page is { } page)
        {
            if (page.HasLimit && page.Limit is < 1 or > 200)
            {
                refused = NodeErrors.InvalidArgument("page.limit: 1..200");
            }
            else if (page.HasLimit)
            {
                limit = page.Limit;
            }

            if (refused is null && page.HasCursor && page.Cursor.Length > 0
                && !long.TryParse(page.Cursor, NumberStyles.None, CultureInfo.InvariantCulture, out before))
            {
                refused = NodeErrors.InvalidCursor();
            }
        }

        if (refused is not null)
        {
            response.Error = refused;
            return Task.FromResult(response);
        }

        var rows = _node.Store.Read(reader => PolicyRules.List(reader, before, limit + 1));
        var value = new PolicyServiceListPolicyRevisionsValue { Page = new PageState { HasMore = rows.Count > limit } };
        value.Revisions.Add(rows.Take(limit).Select(PolicyRules.Revision));
        if (rows.Count > limit)
        {
            value.Page.NextCursor = rows[limit - 1].Revision.ToString(CultureInfo.InvariantCulture);
        }

        response.Value = value;
        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override async Task<PolicyServiceRestorePolicyRevisionResponse> RestorePolicyRevision(PolicyServiceRestorePolicyRevisionRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new PolicyServiceRestorePolicyRevisionResponse { Meta = ApiCommands.Meta(request.Meta) };
        var refused = _api.Stopping() ?? Validation.CommandId(request.Meta) ?? _api.AgentNeedsApproval(context, "RestorePolicyRevision")
            ?? (request.Revision is not { HasValue: true } ? NodeErrors.InvalidArgument("revision: required") : null)
            ?? (request.HasComment && request.Comment.Length > 500 ? NodeErrors.InvalidArgument("comment: <= 500 chars") : null);
        if (refused is not null)
        {
            response.Error = refused;
            return response;
        }

        long? expected = request.Meta.ExpectedRev is { HasValue: true } revision ? revision.Value : null;
        var actor = _api.Actor(context);
        var human = _api.OriginOf(context) == Origin.Human;
        var (result, replayed) = await _api.IdempotentAsync(request, request.Meta, context, "RestorePolicyRevision", PolicyServiceRestorePolicyRevisionResponse.Parser,
            failure => new PolicyServiceRestorePolicyRevisionResponse { Meta = ApiCommands.Meta(request.Meta), Error = failure }, command =>
            {
                var current = PolicyRules.Current(command.Transaction);
                ArcError? error = null;
                var earlier = PolicyRules.Get(command.Transaction, request.Revision.Value);
                if (expected is { } rev && rev != current.Revision)
                {
                    error = NodeErrors.RevisionConflict(rev, current.Revision);
                }
                else if (earlier is null)
                {
                    error = NodeErrors.NotFound("policy_revision", request.Revision.Value.ToString(CultureInfo.InvariantCulture));
                }
                else if (!human && !Equals(current.Document.RetrySafety ?? new RetrySafetyPolicy(), earlier.Document.RetrySafety ?? new RetrySafetyPolicy()))
                {
                    error = NodeErrors.PermissionDenied("RestorePolicyRevision.retry_safety (HUMAN only: AD-0006 section 4)");
                }

                if (error is not null)
                {
                    return new PolicyServiceRestorePolicyRevisionResponse { Meta = ApiCommands.Meta(request.Meta), Error = error };
                }

                var comment = request.HasComment ? request.Comment : string.Create(CultureInfo.InvariantCulture, $"restore revision {earlier!.Revision}");
                var row = PolicyRules.Write(command.Transaction, earlier!.Document, actor, comment);
                return new PolicyServiceRestorePolicyRevisionResponse
                {
                    Meta = ApiCommands.Meta(request.Meta),
                    Value = new PolicyServiceRestorePolicyRevisionValue { Revision = PolicyRules.Revision(row) },
                };
            }).ConfigureAwait(false);
        if (!replayed && result.OutcomeCase == PolicyServiceRestorePolicyRevisionResponse.OutcomeOneofCase.Value)
        {
            Execution.PolicyChanged();
        }

        return result;
    }

    private List<PolicyIssue> Validate(PolicyDocument document)
    {
        var settings = Execution.Settings;
        return PolicyRules.Validate(document, settings.CapacityMemory, (int)(settings.CapacityCpu / 1000));
    }

    /// <summary>The document as stored: <c>built_in</c> is output only, so it is set from the built-in pool names.</summary>
    private static PolicyDocument Normalized(PolicyDocument document)
    {
        var stored = document.Clone();
        foreach (var pool in stored.Pools)
        {
            pool.BuiltIn = DefaultPolicy.BuiltInPools.Contains(pool.Name);
        }

        return stored;
    }
}
