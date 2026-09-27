// SPDX-License-Identifier: AGPL-3.0-only

using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Foundation.Versions;

namespace ArcForges.Persistence.Sqlite.Migrations;

/// <summary>An immutable, owner-authored schema step. SQL is trusted application code, not user input.</summary>
public sealed class MigrationStep
{
    public StorageSchemaVersion Version { get; }
    public string Id { get; }
    public ReadOnlyCollection<string> Statements { get; }
    public string Checksum { get; }

    public MigrationStep(StorageSchemaVersion version, string id, IEnumerable<string> statements)
    {
        if (!version.IsValid || version.Number == 0)
            throw new ArgumentException("Migration numbers must be positive.", nameof(version));
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentNullException.ThrowIfNull(statements);
        var copy = statements.ToArray();
        if (copy.Length == 0 || copy.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException("A migration must contain nonempty SQL statements.", nameof(statements));
        Version = version;
        Id = id;
        Statements = Array.AsReadOnly(copy);

        // Length-prefix each field so statement boundaries cannot collide with SQL contents.
        var identity = new StringBuilder(version.Number.ToString(CultureInfo.InvariantCulture));
        foreach (var field in new[] { id }.Concat(copy))
            identity.Append(':').Append(field.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(field);
        Checksum = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(identity.ToString())));
    }
}
