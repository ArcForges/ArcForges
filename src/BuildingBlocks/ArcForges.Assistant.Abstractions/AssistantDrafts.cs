// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Foundation.Errors;

namespace ArcForges.Assistant.Abstractions;

/// <summary>A draft identity that is independent of any window, so a draft outlives the view that edits it.</summary>
public readonly record struct AssistantDraftId
{
    public AssistantDraftId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Draft identity must be initialized.", nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }
    public static AssistantDraftId New() => new(Guid.NewGuid());
}

/// <summary>
/// One durable revision of an unsent user draft. Revision 0 is a draft that has never been stored; every stored
/// revision is exactly one greater than the previous one. The text is user content: it is bounded, never logged
/// and never used as a key.
/// </summary>
public sealed record AssistantDraft
{
    /// <summary>The largest draft text accepted, in UTF-16 code units.</summary>
    public const int MaximumTextLength = 65_536;

    public AssistantDraft(AssistantDraftId id, AssistantWindowId window, AssistantConversationId? conversation,
        long revision, string text)
    {
        if (id.Value == Guid.Empty)
        {
            throw new ArgumentException("Draft identity must be initialized.", nameof(id));
        }

        if (window.Value == Guid.Empty)
        {
            throw new ArgumentException("Window identity must be initialized.", nameof(window));
        }

        if (conversation is { Value: var value } && value == Guid.Empty)
        {
            throw new ArgumentException("Conversation identity must be initialized.", nameof(conversation));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(revision);
        ArgumentNullException.ThrowIfNull(text);
        if (text.Length > MaximumTextLength)
        {
            throw new ArgumentOutOfRangeException(nameof(text), "The draft text exceeds the bounded draft size.");
        }

        Id = id;
        Window = window;
        Conversation = conversation;
        Revision = revision;
        Text = text;
    }

    public AssistantDraftId Id { get; }
    public AssistantWindowId Window { get; }
    public AssistantConversationId? Conversation { get; }
    public long Revision { get; }
    public string Text { get; }

    internal AssistantDraft Successor(AssistantWindowId window, string text)
        => new(Id, window, Conversation, checked(Revision + 1), text);
}

/// <summary>
/// The durable local home of unsent drafts for exactly one profile partition. Drafts are not canonical data: they
/// are a recovery aid that must survive an application crash, and the store never touches committed
/// conversations. A product binds this port to its real local store; this package defines no storage.
/// </summary>
public interface IAssistantDraftStore : IAssistantHostPort
{
    /// <summary>The one profile partition this store serves; it must equal the services' store scope.</summary>
    AssistantStorePartition Partition { get; }

    /// <summary>
    /// Atomically replaces the stored revision <paramref name="expectedRevision"/> (0 for a draft not yet stored)
    /// with <paramref name="draft"/>, whose revision must be <paramref name="expectedRevision"/> plus one. On
    /// success the revision is durable. After a failure, a cancellation or a process crash the previously stored
    /// revision is intact and no partial revision is ever returned by <see cref="RecoverAsync"/>. A different
    /// stored revision is refused with <c>conflict.revision_mismatch</c>.
    /// </summary>
    ValueTask<Outcome<AssistantDraft>> SaveAsync(AssistantDraft draft, long expectedRevision,
        CancellationToken cancellationToken = default);

    /// <summary>Returns the last durable revision of every stored draft of this partition.</summary>
    ValueTask<Outcome<IReadOnlyList<AssistantDraft>>> RecoverAsync(CancellationToken cancellationToken = default);

    /// <summary>Removes a stored draft at its expected revision; an absent draft reports false.</summary>
    ValueTask<Outcome<bool>> DiscardAsync(AssistantDraftId id, long expectedRevision,
        CancellationToken cancellationToken = default);
}
