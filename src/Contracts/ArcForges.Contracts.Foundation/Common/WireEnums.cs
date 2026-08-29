// SPDX-License-Identifier: AGPL-3.0-only

using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>
/// Where a resource's bytes currently are.
/// </summary>
/// <remarks>
/// Wire values are the frozen lower-case snake_case strings <c>local_online</c>, <c>local_offline</c>,
/// <c>cloud</c>, <c>preparing</c> and <c>unavailable</c>, as used throughout the plan (Step 13 states
/// <c>availability=local_online|local_offline</c> literally). Availability constrains which locator a
/// <see cref="ResourceRef"/> may carry; see <see cref="ResourceRef.Validate"/>.
/// </remarks>
[JsonConverter(typeof(ResourceAvailabilityJsonConverter))]
public enum ResourceAvailability
{
    /// <summary>Owned locally and the owning product is reachable.</summary>
    LocalOnline,

    /// <summary>Owned locally but the owning product is not reachable right now.</summary>
    LocalOffline,

    /// <summary>Held in cloud object storage.</summary>
    Cloud,

    /// <summary>Being materialised. Content facts are not final yet.</summary>
    Preparing,

    /// <summary>Not reachable from anywhere the caller may use.</summary>
    Unavailable,
}

/// <summary>How sensitive a resource's content is.</summary>
/// <remarks>
/// Wire values are <c>public</c>, <c>internal</c>, <c>confidential</c> and <c>restricted</c>. Sensitivity is
/// an input to egress and redaction decisions (architecture §9); it is not an authorisation result.
/// </remarks>
[JsonConverter(typeof(ResourceSensitivityJsonConverter))]
public enum ResourceSensitivity
{
    Public,
    Internal,
    Confidential,
    Restricted,
}

/// <summary>How much preview an artifact can offer.</summary>
/// <remarks>
/// Wire values are <c>none</c>, <c>metadata</c>, <c>thin</c> and <c>rich</c>. This declares what may be
/// requested. Preview bytes themselves live in a deletable cache and are never authoritative.
/// </remarks>
[JsonConverter(typeof(PreviewAvailabilityJsonConverter))]
public enum PreviewAvailability
{
    None,
    Metadata,
    Thin,
    Rich,
}

/// <summary>
/// The three separate error shapes a boundary can produce (architecture §5.3).
/// </summary>
/// <remarks>
/// Wire values are <c>connection_protocol</c>, <c>remote_invocation</c> and <c>business</c>. Only
/// <see cref="Business"/> travels as an <see cref="ArcError"/>; the other two are runtime exception
/// categories owned by Step 03 and are named here so the classification itself is a contract.
/// </remarks>
[JsonConverter(typeof(ErrorCategoryJsonConverter))]
public enum ErrorCategory
{
    /// <summary>The connection or protocol failed. An exception, never an <see cref="ArcError"/>.</summary>
    ConnectionProtocol,

    /// <summary>The remote call threw. Carries no server stack, path or secret.</summary>
    RemoteInvocation,

    /// <summary>The operation was understood and refused. Travels as an <see cref="ArcError"/>.</summary>
    Business,
}
