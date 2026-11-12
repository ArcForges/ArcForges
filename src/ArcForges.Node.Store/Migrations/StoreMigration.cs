// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;

namespace ArcForges.Node.Store.Migrations;

/// <summary>
/// One forward-only schema step (13-distribution-updates section 6). A released step never changes: its SQL digest is
/// recorded in <c>Schema/schema-history.json</c>. Each release's steps are expand-only (new tables, nullable or defaulted
/// columns, indexes); contract steps (drop, rename) come in a later release with a higher <see cref="MinReaderVersion"/>.
/// </summary>
public sealed class StoreMigration
{
    /// <summary>Creates a step.</summary>
    /// <param name="version">The schema version after the step (consecutive from 1).</param>
    /// <param name="minReaderVersion">The lowest binary schema that may read the store after the step.</param>
    /// <param name="name">The step's file name.</param>
    /// <param name="sql">The step's SQL (trusted node code).</param>
    public StoreMigration(int version, int minReaderVersion, string name, string sql)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(version, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(minReaderVersion, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(minReaderVersion, version);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(sql);
        Version = version;
        MinReaderVersion = minReaderVersion;
        Name = name;
        Sql = sql;
        Sha256 = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(sql)));
    }

    /// <summary>The schema version after the step.</summary>
    public int Version { get; }

    /// <summary>The <c>min_reader_version</c> after the step.</summary>
    public int MinReaderVersion { get; }

    /// <summary>The step's file name.</summary>
    public string Name { get; }

    /// <summary>The step's SQL.</summary>
    public string Sql { get; }

    /// <summary>Lowercase hexadecimal SHA-256 of the UTF-8 SQL.</summary>
    public string Sha256 { get; }
}

/// <summary>An ordered, consecutive list of steps from version 1.</summary>
public sealed class MigrationPlan
{
    /// <summary>Validates and wraps the steps.</summary>
    public MigrationPlan(IEnumerable<StoreMigration> steps)
    {
        ArgumentNullException.ThrowIfNull(steps);
        Steps = [.. steps];
        if (Steps.Count == 0)
        {
            throw new ArgumentException("A migration plan needs at least schema version 1.", nameof(steps));
        }

        for (var index = 0; index < Steps.Count; index++)
        {
            if (Steps[index].Version != index + 1)
            {
                throw new ArgumentException("Migration versions must be consecutive from 1.", nameof(steps));
            }

            if (index > 0 && Steps[index].MinReaderVersion < Steps[index - 1].MinReaderVersion)
            {
                throw new ArgumentException("min_reader_version never decreases.", nameof(steps));
            }
        }
    }

    /// <summary>The steps in version order.</summary>
    public IReadOnlyList<StoreMigration> Steps { get; }

    /// <summary>The schema version this binary writes and reads (the last step).</summary>
    public int LatestVersion => Steps[^1].Version;
}

/// <summary>The released migrations of this binary.</summary>
public static class StoreMigrations
{
    /// <summary>The schema version this binary writes; it reads stores whose <c>min_reader_version</c> is at most this.</summary>
    public const int SupportedSchemaVersion = 14;

    /// <summary>The released steps, loaded from the embedded <c>Schema/*.sql</c> resources.</summary>
    public static MigrationPlan Released { get; } = new([
        // Version 1 is ArcForges-Design docs/data/node-store.sql verbatim (all tables of schema version 1).
        Load(1, 1, "0001-schema-v1.sql"),

        // Version 2 is ArcForges-Design docs/data/node-store.sql at 611dda6, the "schema step 2" block verbatim (node-store.md section 2a:
        // task.local_diagnostic and routed_call_log; AF-CTR-05 N1). Expand-only, so readers of version 1 still read the store.
        Load(2, 1, "0002-schema-step-2.sql"),

        // AF-CTR-06: new bounded file receipt log and call-ID registry, enforced for compatible old writers too.
        Load(3, 1, "0003-schema-step-3.sql"),

        // AF-CTR-06: bounded file/workspace audit scope and metadata digests, cascading with the existing audit retention.
        Load(4, 1, "0004-schema-step-4.sql"),

        // AF-CTR-06: inventory changes invalidate bounded workspace-list continuation cursors.
        Load(5, 1, "0005-schema-step-5.sql"),

        // AF-CTR-06: durable time floor and protected retention for file/workspace receipts and audit.
        Load(6, 1, "0006-schema-step-6.sql"),

        // AF-CTR-06: metadata-only file effect journal and protected recovery holds.
        Load(7, 1, "0007-schema-step-7.sql"),

        // AF-CTR-06: bounded metadata-only private stage reservations and opened-object identities.
        Load(8, 1, "0008-schema-step-8.sql"),

        // AF-CTR-06: durable fence for private stages abandoned before target effects.
        Load(9, 1, "0009-schema-step-9.sql"),

        // AF-CTR-06: keep target holds until a recorded Linux effect worker has actually ended.
        Load(10, 1, "0010-schema-step-10.sql"),

        // AF-CTR-06: old writers fail closed on target holds; only a native-checked transaction can witness distinct objects.
        Load(11, 1, "0011-schema-step-11.sql"),

        // AF-CTR-06: exact removal-plan evidence and requester-bound command receipts.
        Load(12, 1, "0012-schema-step-12.sql"),

        // AF-CTR-06: prior binaries can delete untracked attempt directories without checking provenance or protection.
        // They must not open a store whose attempt-directory retention has switched to the new semantics.
        Load(13, 13, "0013-schema-step-13.sql"),

        // AF-CTR-06: creation evidence changes ownership decisions; prior writers cannot safely share this store.
        Load(14, 14, "0014-schema-step-14.sql"),
    ]);

    private static StoreMigration Load(int version, int minReaderVersion, string name)
    {
        var resource = "ArcForges.Node.Store.Schema." + name;
        using var stream = typeof(StoreMigrations).Assembly.GetManifestResourceStream(resource)
            ?? throw new InvalidOperationException($"The migration resource {resource} is missing.");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return new StoreMigration(version, minReaderVersion, name, reader.ReadToEnd());
    }
}
