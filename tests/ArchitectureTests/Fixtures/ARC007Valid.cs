// SPDX-License-Identifier: AGPL-3.0-only
// ARC-007 compliant sample. This file participates in compilation; its violating twin is
// ARC007Violation.cs.txt, which is stored as text and compiled only at test time.

namespace ArcForges.Tests.ArchitectureTests.Fixtures;

internal sealed record SearchDocumentsRequest(string Query, int Limit);

internal sealed record SearchDocumentsResponse(System.Collections.Generic.IReadOnlyList<string> DocumentIds);

internal interface ICompliantRpc
{
    System.Threading.Tasks.Task<SearchDocumentsResponse> SearchDocumentsAsync(
        SearchDocumentsRequest request,
        System.Threading.CancellationToken cancellationToken);
}
