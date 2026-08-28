// SPDX-License-Identifier: AGPL-3.0-only
// ARC-002 compliant sample. This file participates in compilation; its violating twin is
// ARC002Violation.cs.txt, which is stored as text and compiled only at test time.

namespace ArcForges.Tests.ArchitectureTests.Fixtures;

internal interface IConversationFacade { string Title { get; } }

internal sealed class CompliantConversationViewModel(IConversationFacade facade)
{
    public string Title => facade.Title;
}
