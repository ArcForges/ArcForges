// SPDX-License-Identifier: AGPL-3.0-only
// ARC-012 compliant sample. This file participates in compilation; its violating twin is
// ARC012Violation.cs.txt, which is stored as text and compiled only at test time.

namespace ArcForges.Tests.ArchitectureTests.Fixtures;

internal sealed record ChatModuleEvent(System.Guid ConversationId, long Sequence);
