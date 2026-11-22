// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json.Nodes;
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.Client;

/// <summary>Local operator actions handled by the Node composition.</summary>
public enum NodeUpdateAction { Apply, Resume, Status, Rollback, Compatibility }

/// <summary>Only Apply supplies already verified cohort identities.</summary>
public sealed record NodeUpdateRequest(NodeUpdateAction Action, bool TestMode, NodeUpdateInstallation? Candidate = null,
    NodeUpdateInstallation? Previous = null);

/// <summary>An exact update outcome or refusal.</summary>
public sealed record NodeUpdateResponse(JsonObject Report, string? Refusal = null, EffectCertainty RefusalEffect = EffectCertainty.Unknown);
