// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Persistence.Sqlite;

/// <summary>The owner maps this refusal to its registered storage-pressure outcome before committing.</summary>
internal sealed class JournalCapacityException : InvalidOperationException
{
    public JournalCapacityException()
        : base("A verified snapshot is required before the bounded journal can accept another commit.")
    {
    }

    public JournalCapacityException(string message) : base(message)
    {
    }

    public JournalCapacityException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
