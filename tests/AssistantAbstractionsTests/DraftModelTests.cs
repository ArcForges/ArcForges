// SPDX-License-Identifier: AGPL-3.0-only
#pragma warning disable CA2007 // Test code has no synchronization context to preserve.
using ArcForges.Assistant.Abstractions;
using A = Xunit.Assert;

namespace AssistantAbstractionsTests;

public sealed class DraftModelTests
{
    private static AssistantDraft Draft(long revision = 0, string text = "t", AssistantConversationId? conversation = null)
        => new(AssistantDraftId.New(), AssistantWindowId.New(), conversation, revision, text);

    [Xunit.Fact]
    public void DraftIdentityIsInitializedAndUnique()
    {
        A.Throws<ArgumentException>(() => new AssistantDraftId(Guid.Empty));
        A.NotEqual(AssistantDraftId.New(), AssistantDraftId.New());
    }

    [Xunit.Fact]
    public void DraftsAreBoundedAndRequireInitializedIdentities()
    {
        A.Throws<ArgumentException>(() => new AssistantDraft(default, AssistantWindowId.New(), null, 0, "t"));
        A.Throws<ArgumentException>(() => new AssistantDraft(AssistantDraftId.New(), default, null, 0, "t"));
        A.Throws<ArgumentException>(() => new AssistantDraft(AssistantDraftId.New(), AssistantWindowId.New(),
            default(AssistantConversationId), 0, "t"));
        A.Throws<ArgumentOutOfRangeException>(() => Draft(revision: -1));
        A.Throws<ArgumentNullException>(() => Draft(text: null!));
        A.Throws<ArgumentOutOfRangeException>(() => Draft(text: new string('x', AssistantDraft.MaximumTextLength + 1)));
        A.Equal(AssistantDraft.MaximumTextLength, Draft(text: new string('x', AssistantDraft.MaximumTextLength)).Text.Length);
        A.NotNull(Draft(conversation: AssistantConversationId.New()).Conversation);
    }

    [Xunit.Fact]
    public void LaunchReportsCarryAKnownRemoteStateAndACopyOfTheDrafts()
    {
        List<AssistantDraft> drafts = [Draft(1)];
        var report = new AssistantLaunchReport(drafts, AssistantRemoteState.Available, null);
        drafts.Clear();

        A.Single(report.RecoveredDrafts);
        A.Throws<ArgumentOutOfRangeException>(() => new AssistantLaunchReport([], AssistantRemoteState.None, null));
        A.Throws<ArgumentOutOfRangeException>(() => new AssistantLaunchReport([], (AssistantRemoteState)99, null));
        A.Throws<ArgumentNullException>(() => new AssistantLaunchReport(null!, AssistantRemoteState.Available, null));
    }
}
