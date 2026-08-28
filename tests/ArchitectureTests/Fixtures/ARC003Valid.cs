// SPDX-License-Identifier: AGPL-3.0-only
// ARC-003 compliant sample. This file participates in compilation; its violating twin is
// ARC003Violation.cs.txt, which is stored as text and compiled only at test time.

namespace ArcForges.Tests.ArchitectureTests.Fixtures;

internal sealed record RenameDocumentRequest(System.Guid DocumentId, string Title, long ExpectedRevision);
