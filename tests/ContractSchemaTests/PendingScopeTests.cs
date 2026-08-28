// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.ContractSchemaTests;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 02. Unlock when the JSON Schema 2020-12 documents are generated from the contract assemblies and compared against goldens.")]
    [Xunit.Trait("Category", "Contract")]
    public void GeneratedSchemasMatchTheContractGoldens() =>
        Xunit.Assert.Fail("Step 02 must replace this placeholder with real assertions before removing the skip.");
}
