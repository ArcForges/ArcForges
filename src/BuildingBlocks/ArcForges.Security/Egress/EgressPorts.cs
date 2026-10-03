// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Security.Decisions;

namespace ArcForges.Security.Egress;

// Each port is the authoritative source of one egress fact the authority must not decide itself. None has a permissive default: a
// source that returns nothing, throws, times out or answers an undefined value refuses the transfer. Ports are read-only evaluators
// except the audit sink, which is the one place a record is written.

/// <summary>
/// The host's classifier of what a transfer would carry (content classification and the knowledge policy's AI eligibility). The
/// answer is taken from the owner of the content and the knowledge policy, never from the caller or the request's own fields.
/// </summary>
public interface IEgressContentClassifier
{
    /// <summary>Returns the facts of the content the request would send to the destination, or null when it cannot be classified.</summary>
    ValueTask<EgressContentFacts?> ClassifyAsync(DecisionRequest request, EgressDestinationIdentity destination, CancellationToken cancellationToken);
}

/// <summary>The workspace policy: the exact destinations a scope may send to. A destination that is not listed is never reachable.</summary>
public interface IEgressAllowlist
{
    /// <summary>
    /// Returns the entry of the exact destination for the scope, or null when it is not allowlisted. The authority re-checks that the
    /// entry names exactly the requested scope and destination.
    /// </summary>
    ValueTask<EgressAllowlistEntry?> FindAsync(string scopeKey, EgressDestinationIdentity destination, CancellationToken cancellationToken);
}

/// <summary>The owner-issued egress permissions of principals. They are not the capability permissions the pipeline's step 6 reads.</summary>
public interface IEgressGrantSource
{
    /// <summary>
    /// Returns every egress grant record that may apply to the request's principal, capability and scope for the exact destination
    /// (at most <see cref="EgressAuthority.MaximumGrantRecords"/>). The authority re-checks every record against the request.
    /// </summary>
    ValueTask<IReadOnlyList<EgressGrantRecord>> FindAsync(DecisionRequest request, EgressDestinationIdentity destination, CancellationToken cancellationToken);
}

/// <summary>
/// The sink of every egress decision. It owns durability and must return only after the record is durable and throw on any failure:
/// an allowed decision whose record cannot be written is refused, so no egress is ever authorized without its audit event.
/// </summary>
public interface IEgressAuditSink
{
    ValueTask WriteAsync(EgressAuditRecord record, CancellationToken cancellationToken);
}
