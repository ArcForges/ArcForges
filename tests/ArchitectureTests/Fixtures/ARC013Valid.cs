// SPDX-License-Identifier: AGPL-3.0-only
// ARC-013 compliant sample. This file participates in compilation; its violating twin is
// ARC013Violation.cs.txt, which is stored as text and compiled only at test time.

namespace ArcForges.Tests.ArchitectureTests.Fixtures;

internal interface IExternalUriLauncher
{
    System.Threading.Tasks.Task OpenAsync(System.Uri uri, System.Threading.CancellationToken cancellationToken);
}
