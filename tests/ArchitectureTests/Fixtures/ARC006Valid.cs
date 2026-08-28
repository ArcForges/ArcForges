// SPDX-License-Identifier: AGPL-3.0-only
// ARC-006 compliant sample. This file participates in compilation; its violating twin is
// ARC006Violation.cs.txt, which is stored as text and compiled only at test time.

namespace ArcForges.Tests.ArchitectureTests.Fixtures;

internal sealed record CloudTaskProjection(System.Guid TaskId, string Lifecycle, long Revision);
