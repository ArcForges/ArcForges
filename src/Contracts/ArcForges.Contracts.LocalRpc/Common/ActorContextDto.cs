// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;

namespace ArcForges.Contracts.LocalRpc;

public sealed partial record SecurityPrincipalDto
{
    public required string Kind { get; init; }
    public required string PrincipalId { get; init; }
    public string? DisplayNameKey { get; init; }
}

public sealed partial record ActorChainEntryDto
{
    public required SecurityPrincipalDto Principal { get; init; }
    public required string Role { get; init; }
    public string? AuthoritySourcePrincipalId { get; init; }
}

public sealed partial record InvocationCorrelationDto
{
    public required Guid CorrelationId { get; init; }
    public Guid? CausationId { get; init; }
    public TaskId? TaskId { get; init; }
    public RunId? RunId { get; init; }
    public StepId? StepId { get; init; }
    public Guid? ToolRequestId { get; init; }
}

public sealed partial record ActorContextDto
{
    public required IReadOnlyList<ActorChainEntryDto> ActorChain { get; init; }
    public required IReadOnlyList<string> GrantedScopes { get; init; }
    public required InvocationCorrelationDto Correlation { get; init; }
}
