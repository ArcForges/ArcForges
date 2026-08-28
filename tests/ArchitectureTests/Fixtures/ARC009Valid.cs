// SPDX-License-Identifier: AGPL-3.0-only
// ARC-009 compliant sample. This file participates in compilation; its violating twin is
// ARC009Violation.cs.txt, which is stored as text and compiled only at test time.

namespace ArcForges.Tests.ArchitectureTests.Fixtures;

internal sealed class GenerateShapeAttribute : System.Attribute;

internal sealed class JsonRpcContractAttribute : System.Attribute;

[JsonRpcContract]
[GenerateShape]
internal partial interface IShapedRpc
{
    System.Threading.Tasks.Task PingAsync(System.Threading.CancellationToken cancellationToken);
}
