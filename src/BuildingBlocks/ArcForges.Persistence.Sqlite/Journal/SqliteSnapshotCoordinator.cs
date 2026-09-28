// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Versions;
using Microsoft.Data.Sqlite;

namespace ArcForges.Persistence.Sqlite;

/// <summary>Publishes verifiable, atomic database snapshots and restores only from those snapshots.</summary>
internal sealed class SqliteSnapshotCoordinator(string databasePath, Guid storeId,
    Action<SnapshotStage>? fault = null) : IJournalSnapshotVerifier
{
    private const int FormatVersion = 1;
    private const int HeaderLength = 120;
    private const int DigestLength = 32;
    private const string LeaseFileName = ".snapshot-coordinator.lock";
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("AFSNAP01");
    private static readonly string[] SidecarSuffixes = ["-wal", "-shm", "-journal"];
    private readonly string fullDatabasePath = Path.GetFullPath(databasePath);
    private readonly string snapshotDirectory = Path.GetFullPath(databasePath) + ".snapshots";
    private readonly HashSet<string> authorizedBoundaries = new(StringComparer.Ordinal);
    private readonly object boundaryLock = new();

    public bool IsVerified(VerifiedSnapshotBoundary boundary)
    {
        ArgumentNullException.ThrowIfNull(boundary);
        lock (boundaryLock) return authorizedBoundaries.Contains(BoundaryKey(boundary));
    }

    internal StoreRecoveryReport PrepareForOpen()
    {
        using var snapshotLease = AcquireSnapshotLease(createDirectory: false);
        if (snapshotLease is not null) ScavengeAbandonedTemporaryFiles();
        var databaseExists = File.Exists(fullDatabasePath);
        var databaseIsEmpty = databaseExists && new FileInfo(fullDatabasePath).Length == 0;
        if (!databaseExists || databaseIsEmpty)
        {
            var hasOrphanedSidecars = SidecarSuffixes.Any(suffix => File.Exists(fullDatabasePath + suffix));
            var hasCommittedSnapshots = HasCommittedSnapshotEvidence();
            var snapshot = FindLatestVerifiedSnapshot();
            var databaseDescription = databaseExists ? "empty" : "missing";
            if (snapshot is null)
            {
                if (hasOrphanedSidecars || hasCommittedSnapshots)
                {
                    string? preservedSidecarsPath = null;
                    Exception? evidenceFailure = null;
                    try
                    {
                        if (databaseExists || hasOrphanedSidecars)
                            preservedSidecarsPath = PreserveEvidence();
                    }
                    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                    { evidenceFailure = exception; }
                    var report = new StoreRecoveryReport(StoreRecoveryOutcome.UnrecoverableWithPreservedEvidence,
                        0, 0, preservedSidecarsPath ?? (hasCommittedSnapshots ? snapshotDirectory : fullDatabasePath + "-wal"),
                        hasOrphanedSidecars
                            ? $"The owner database is {databaseDescription} but SQLite sidecars remain. They were preserved as evidence; automatic initialization was refused because the sidecars may contain committed content."
                            : $"The owner database is {databaseDescription} and committed snapshot envelopes exist, but none can be verified. Evidence was preserved and automatic initialization was refused.");
                    throw new StoreRecoveryException(report, evidenceFailure);
                }
                if (databaseIsEmpty)
                {
                    var report = new StoreRecoveryReport(StoreRecoveryOutcome.UnrecoverableWithPreservedEvidence,
                        0, 0, fullDatabasePath,
                        "The zero-byte owner database is not a valid empty SQLite store and no verified snapshot is available. Automatic initialization was refused.");
                    throw new StoreRecoveryException(report);
                }
                return new(StoreRecoveryOutcome.Clean, 0, 0, null,
                    "The owner database does not exist and no retained snapshot is available; a new store will be initialized.");
            }
            string? replacementEvidencePath = null;
            try
            {
                if (databaseExists || hasOrphanedSidecars) replacementEvidencePath = PreserveEvidence();
                RestoreSnapshot(snapshot, replacementEvidencePath);
                var missingReport = new StoreRecoveryReport(StoreRecoveryOutcome.RecoveredWithLossOfUncommittedWork,
                    snapshot.Through, snapshot.Through, replacementEvidencePath,
                    $"Restored verified sequence {snapshot.Through} because the owner database was {databaseDescription}. Work after that checkpoint is unavailable; enter read-first safe start.");
                DeleteTemporary(snapshot.DatabasePath);
                return missingReport;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SqliteException or InvalidDataException or InvalidOperationException)
            {
                DeleteTemporary(snapshot.DatabasePath);
                var missingReport = new StoreRecoveryReport(StoreRecoveryOutcome.UnrecoverableWithPreservedEvidence,
                    snapshot.Through, 0, replacementEvidencePath ?? (hasOrphanedSidecars ? fullDatabasePath + "-wal" : databaseExists ? fullDatabasePath : null),
                    $"The owner database was {databaseDescription} and its verified snapshot at sequence {snapshot.Through} could not be restored.");
                throw new StoreRecoveryException(missingReport, exception);
            }
        }

        var inspection = InspectDatabase();
        if (inspection.IsUninitialized)
        {
            var hasOrphanedSidecars = SidecarSuffixes.Any(suffix => File.Exists(fullDatabasePath + suffix));
            var hasCommittedSnapshots = HasCommittedSnapshotEvidence();
            if (!hasOrphanedSidecars && !hasCommittedSnapshots)
                return new(StoreRecoveryOutcome.Clean, 0, 0, null,
                    "The valid empty owner database has no journal, sidecars, or retained snapshot; a new store will be initialized.");

            var snapshot = FindLatestVerifiedSnapshot();
            if (snapshot is null)
            {
                string? preservedEvidencePath = null;
                Exception? evidenceFailure = null;
                try { preservedEvidencePath = PreserveEvidence(); }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                { evidenceFailure = exception; }
                var report = new StoreRecoveryReport(StoreRecoveryOutcome.UnrecoverableWithPreservedEvidence,
                    0, 0, preservedEvidencePath ?? fullDatabasePath,
                    hasOrphanedSidecars
                        ? "The valid empty owner database has SQLite sidecars but no verified snapshot. Evidence was preserved and automatic initialization was refused."
                        : "The valid empty owner database has committed snapshot envelopes, but none can be verified. Evidence was preserved and automatic initialization was refused.");
                throw new StoreRecoveryException(report, evidenceFailure);
            }

            string? emptyDatabaseEvidencePath = null;
            try
            {
                emptyDatabaseEvidencePath = PreserveEvidence();
                RestoreSnapshot(snapshot, emptyDatabaseEvidencePath);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SqliteException or InvalidDataException or InvalidOperationException)
            {
                DeleteTemporary(snapshot.DatabasePath);
                var report = new StoreRecoveryReport(StoreRecoveryOutcome.UnrecoverableWithPreservedEvidence,
                    snapshot.Through, 0, emptyDatabaseEvidencePath ?? fullDatabasePath,
                    $"The valid empty owner database had recovery evidence, but its verified snapshot at sequence {snapshot.Through} could not be restored.");
                throw new StoreRecoveryException(report, exception);
            }
            DeleteTemporary(snapshot.DatabasePath);
            return new(StoreRecoveryOutcome.RecoveredWithLossOfUncommittedWork, snapshot.Through,
                snapshot.Through, emptyDatabaseEvidencePath,
                $"Restored verified sequence {snapshot.Through} because the owner database was a valid but uninitialized SQLite file. Work after that checkpoint is unavailable; enter read-first safe start.");
        }
        if (!inspection.RequiresRecovery)
            return new(StoreRecoveryOutcome.Clean, inspection.Head ?? 0, inspection.Head ?? 0, null,
                "The owner database and its retained journal are structurally valid.");

        var candidate = FindLatestVerifiedSnapshot();
        if (candidate is null)
        {
            var report = new StoreRecoveryReport(StoreRecoveryOutcome.UnrecoverableWithPreservedEvidence,
                0, 0, File.Exists(fullDatabasePath) ? fullDatabasePath : null,
                $"Recovery was required ({inspection.Detail}), but no verified snapshot is available. The original database was left untouched.");
            throw new StoreRecoveryException(report);
        }

        JournalPrefix? tail = null;
        if (inspection.CanReadJournal)
            tail = ReadValidTail(candidate.Through);

        string? evidencePath = null;
        try
        {
            if (File.Exists(fullDatabasePath)) evidencePath = PreserveEvidence();
            RestoreSnapshot(candidate, evidencePath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SqliteException or InvalidDataException or InvalidOperationException)
        {
            DeleteTemporary(candidate.DatabasePath);
            var report = new StoreRecoveryReport(StoreRecoveryOutcome.UnrecoverableWithPreservedEvidence,
                candidate.Through, 0, evidencePath ?? (File.Exists(fullDatabasePath) ? fullDatabasePath : null),
                $"A verified snapshot exists at sequence {candidate.Through}, but safe restoration failed. Evidence was preserved and no further repair was attempted.");
            throw new StoreRecoveryException(report, exception);
        }

        var recoveredThrough = candidate.Through;
        var replayFailed = false;
        if (tail is not null)
        {
            using var replayStore = new SqliteStore(fullDatabasePath, storeId, new RecoveryAuthorization(), null,
                new JournalSnapshotPolicy(), performRecovery: false, runSnapshotPolicy: false);
            foreach (var entry in tail.Entries)
            {
                if (entry.Sequence.Value <= candidate.Through) continue;
                try
                {
                    var content = StoredContent.FromJournal(entry);
                    replayStore.Write(new WriteCommand(entry.CommandId, entry.AggregateKind, entry.AggregateId,
                        entry.Previous, content, entry.Operation, entry.ActorId, entry.CorrelationId,
                        entry.CommittedAt, entry.LocalSequence));
                    recoveredThrough = entry.Sequence.Value;
                }
                catch (Exception exception) when (exception is ArgumentException or InvalidDataException or InvalidOperationException or IOException or UnauthorizedAccessException or SqliteException)
                {
                    replayFailed = true;
                    break;
                }
            }
        }

        var knownHead = inspection.Head;
        var lostTail = replayFailed || tail?.HasCorruption == true ||
            (knownHead.HasValue && knownHead.Value > recoveredThrough) || !knownHead.HasValue;
        var outcome = lostTail
            ? StoreRecoveryOutcome.RecoveredWithLossOfUncommittedWork
            : StoreRecoveryOutcome.Clean;
        var detail = lostTail
            ? $"Restored verified sequence {candidate.Through} and replayed through {recoveredThrough}. The remaining damaged or unavailable tail is preserved as evidence; enter read-first safe start."
            : $"Restored verified sequence {candidate.Through} and replayed every verified committed journal entry through {recoveredThrough}.";
        var result = new StoreRecoveryReport(outcome, candidate.Through, recoveredThrough, evidencePath, detail);
        DeleteTemporary(candidate.DatabasePath);
        return result;
    }

    internal JournalSnapshotReceipt? CreateSnapshot(StoreDatabase database, SqliteJournal journal)
    {
        ArgumentNullException.ThrowIfNull(database);
        ArgumentNullException.ThrowIfNull(journal);
        using var snapshotLease = AcquireSnapshotLease(createDirectory: true)
            ?? throw new InvalidOperationException("Snapshot storage is unavailable.");
        ScavengeAbandonedTemporaryFiles();

        var scratchDatabase = Path.Combine(snapshotDirectory, $".snapshot-{Guid.NewGuid():N}.db.tmp");
        var scratchEnvelope = Path.Combine(snapshotDirectory, $".snapshot-{Guid.NewGuid():N}.afsnap.tmp");
        SnapshotCandidate? verified = null;
        string? publishedPath = null;
        try
        {
            using (var source = Open(fullDatabasePath, readOnly: true))
            using (var destination = Open(scratchDatabase, readOnly: false))
                source.BackupDatabase(destination);

            var boundaryInfo = ReadSnapshotBoundary(scratchDatabase, journal);
            if (boundaryInfo is null) return null;
            WriteEnvelope(scratchEnvelope, scratchDatabase, boundaryInfo.Value);
            fault?.Invoke(SnapshotStage.EnvelopeFlushed);
            verified = VerifySnapshot(scratchEnvelope);
            if (verified is null) throw new InvalidDataException("The newly written snapshot did not verify.");
            fault?.Invoke(SnapshotStage.SnapshotVerified);

            publishedPath = Path.Combine(snapshotDirectory,
                $"snapshot-{verified.Through:D20}-{Guid.NewGuid():N}.afsnap");
            File.Move(scratchEnvelope, publishedPath);
            lock (boundaryLock) authorizedBoundaries.Add(BoundaryKey(verified.Boundary));
            fault?.Invoke(SnapshotStage.EnvelopePublished);
            database.WithTransaction(context =>
            {
                journal.Truncate(context, verified.Boundary);
                return 0;
            });
            fault?.Invoke(SnapshotStage.JournalTruncated);
            PruneVerifiedSnapshots();
            return new(verified.Through, new StorageSchemaVersion(verified.SchemaVersion), publishedPath);
        }
        finally
        {
            DeleteTemporary(scratchDatabase);
            DeleteTemporary(scratchEnvelope);
            if (verified is not null) DeleteTemporary(verified.DatabasePath);
        }
    }

    internal static bool RequiresSnapshot(StoreDatabase database, SqliteJournal journal, Instant now) =>
        database.Read(context => journal.RequiresSnapshot(context, now));

    private DatabaseInspection InspectDatabase()
    {
        if (!File.Exists(fullDatabasePath))
            return new(false, false, 0, 0, "the owner database file is missing");
        if (new FileInfo(fullDatabasePath).Length == 0)
            return new(false, false, 0, 0, "an empty new owner database will be initialized");

        try
        {
            using var connection = Open(fullDatabasePath, readOnly: true);
            using (var integrity = connection.CreateCommand())
            {
                integrity.CommandText = "PRAGMA integrity_check";
                using var rows = integrity.ExecuteReader();
                while (rows.Read())
                    if (!string.Equals(rows.GetString(0), "ok", StringComparison.OrdinalIgnoreCase))
                        return new(true, false, ReadHeadIfAvailable(connection), null,
                            "SQLite integrity_check found damaged pages");
            }

            if (!TableExists(connection, "store_identity"))
            {
                using var tables = connection.CreateCommand();
                tables.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'";
                if (Convert.ToInt64(tables.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) == 0)
                    return new(false, false, 0, 0, "the store has not been initialized yet", IsUninitialized: true);
                return new(true, false, ReadHeadIfAvailable(connection), null,
                    "the owner identity table is missing from an initialized database");
            }
            using (var identity = connection.CreateCommand())
            {
                identity.CommandText = "SELECT id FROM store_identity LIMIT 1";
                var actual = identity.ExecuteScalar() as string;
                if (actual is null)
                    return new(true, false, ReadHeadIfAvailable(connection), null,
                        "the initialized database has no owner identity row");
                if (actual != storeId.ToString("D"))
                    throw new InvalidOperationException("The file belongs to another store identity; recovery will not cross owner boundaries.");
            }

            if (!TableExists(connection, "journal_state") || !TableExists(connection, "journal"))
                return new(true, false, null, null, "the initialized store is missing journal state");
            using var transaction = connection.BeginTransaction(deferred: true);
            var context = new SqliteReadContext(storeId, connection, transaction);
            using var state = context.CreateCommand("SELECT last_sequence,truncated_through FROM journal_state WHERE store_id=$store");
            state.Parameters.AddWithValue("$store", storeId.ToString("D"));
            using var stateRow = state.ExecuteReader();
            if (!stateRow.Read()) return new(true, false, null, null, "the journal has no durable state row");
            var head = stateRow.GetInt64(0);
            var floor = stateRow.GetInt64(1);
            stateRow.Close();
            if (head < floor || floor < 0) return new(true, true, head, floor, "journal watermarks are invalid");

            var journal = new SqliteJournal();
            var after = floor == 0 ? (JournalSequence?)null : new JournalSequence(storeId, floor);
            var verifiedThrough = floor;
            while (verifiedThrough < head)
            {
                var entries = journal.Read(context, after, 4096);
                if (entries.Count == 0) return new(true, true, head, floor, "journal replay ended before its durable high watermark");
                verifiedThrough = entries[^1].Sequence.Value;
                after = entries[^1].Sequence;
            }
            // A full final page stops at the head; probe beyond it so orphaned tail rows cannot hide at that boundary.
            if (SqliteJournal.HasRowsBeyondHead(context, head))
                return new(true, true, head, floor, "journal contains rows beyond the durable high watermark");
            return new(false, true, head, floor, "the owner database and retained journal are valid");
        }
        catch (InvalidDataException exception)
        {
            return new(true, true, ReadHeadSafely(), null, exception.Message);
        }
        catch (InvalidOperationException exception) when (exception.Message.Contains("journal", StringComparison.OrdinalIgnoreCase))
        {
            return new(true, true, ReadHeadSafely(), null, exception.Message);
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode is 11 or 26)
        {
            return new(true, false, ReadHeadSafely(), null, "SQLite reported a corrupt or non-database file");
        }
    }

    private SnapshotCandidate? FindLatestVerifiedSnapshot()
    {
        if (!Directory.Exists(snapshotDirectory)) return null;
        RejectReparsePoint(snapshotDirectory);
        SnapshotCandidate? latest = null;
        try
        {
            foreach (var path in Directory.EnumerateFiles(snapshotDirectory, "*.afsnap", SearchOption.TopDirectoryOnly))
            {
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) continue;
                var candidate = VerifySnapshot(path);
                if (candidate is null) continue;
                if (latest is null || candidate.Through > latest.Through ||
                    (candidate.Through == latest.Through && candidate.CreatedAtMilliseconds > latest.CreatedAtMilliseconds))
                {
                    if (latest is not null) DeleteTemporary(latest.DatabasePath);
                    latest = candidate;
                }
                else DeleteTemporary(candidate.DatabasePath);
            }
        }
        catch
        {
            if (latest is not null) DeleteTemporary(latest.DatabasePath);
            throw;
        }
        if (latest is not null)
            lock (boundaryLock) authorizedBoundaries.Add(BoundaryKey(latest.Boundary));
        return latest;
    }

    private bool HasCommittedSnapshotEvidence()
    {
        if (!Directory.Exists(snapshotDirectory)) return false;
        RejectReparsePoint(snapshotDirectory);
        return Directory.EnumerateFiles(snapshotDirectory, "*.afsnap", SearchOption.TopDirectoryOnly).Any();
    }

    private SnapshotCandidate? VerifySnapshot(string path)
    {
        string? databaseTemp = null;
        try
        {
            using var source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (source.Length < HeaderLength + DigestLength) return null;
            var headerBytes = new byte[HeaderLength];
            source.ReadExactly(headerBytes);
            var header = ParseHeader(headerBytes);
            if (header.StoreId != storeId || header.Through <= 0 ||
                header.PayloadLength <= 0 || header.PayloadLength != source.Length - HeaderLength - DigestLength)
                return null;

            databaseTemp = Path.Combine(snapshotDirectory, $".verify-{Guid.NewGuid():N}.db.tmp");
            using var payloadHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var envelopeHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            envelopeHash.AppendData(headerBytes);
            using (var destination = new FileStream(databaseTemp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                var buffer = new byte[64 * 1024];
                var remaining = header.PayloadLength;
                while (remaining > 0)
                {
                    var read = source.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                    if (read == 0) throw new EndOfStreamException("The snapshot payload ended early.");
                    destination.Write(buffer, 0, read);
                    payloadHash.AppendData(buffer, 0, read);
                    envelopeHash.AppendData(buffer, 0, read);
                    remaining -= read;
                }
                destination.Flush(flushToDisk: true);
            }
            var storedEnvelopeDigest = new byte[DigestLength];
            source.ReadExactly(storedEnvelopeDigest);
            if (source.ReadByte() != -1 ||
                !CryptographicOperations.FixedTimeEquals(payloadHash.GetHashAndReset(), header.DatabaseChecksum) ||
                !CryptographicOperations.FixedTimeEquals(envelopeHash.GetHashAndReset(), storedEnvelopeDigest))
                throw new InvalidDataException("The snapshot checksum does not match its contents.");

            VerifySnapshotDatabase(databaseTemp, header);
            var boundary = new VerifiedSnapshotBoundary(new JournalSequence(storeId, header.Through),
                header.JournalChecksum, storedEnvelopeDigest);
            return new(path, databaseTemp, header.Through, header.CreatedAtMilliseconds,
                header.SchemaVersion, header.DatabaseChecksum, boundary);
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or SqliteException or
            ArgumentException or FormatException or OverflowException or UnauthorizedAccessException)
        {
            if (databaseTemp is not null) DeleteTemporary(databaseTemp);
            return null;
        }
    }

    private static Header ParseHeader(byte[] bytes)
    {
        using var stream = new MemoryStream(bytes, writable: false);
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: false);
        if (!CryptographicOperations.FixedTimeEquals(reader.ReadBytes(Magic.Length), Magic) || reader.ReadInt32() != FormatVersion)
            throw new InvalidDataException("The snapshot envelope format is unknown.");
        var store = new Guid(reader.ReadBytes(16));
        var through = reader.ReadInt64();
        var created = reader.ReadInt64();
        var schemaVersion = reader.ReadUInt32();
        var length = reader.ReadInt64();
        var journalChecksum = reader.ReadBytes(DigestLength);
        var databaseChecksum = reader.ReadBytes(DigestLength);
        if (stream.Position != HeaderLength || journalChecksum.Length != DigestLength || databaseChecksum.Length != DigestLength)
            throw new InvalidDataException("The snapshot envelope header is incomplete.");
        return new(store, through, created, schemaVersion, length, journalChecksum, databaseChecksum);
    }

    private static byte[] EncodeHeader(Header header)
    {
        using var stream = new MemoryStream(HeaderLength);
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(Magic);
            writer.Write(FormatVersion);
            writer.Write(header.StoreId.ToByteArray());
            writer.Write(header.Through);
            writer.Write(header.CreatedAtMilliseconds);
            writer.Write(header.SchemaVersion);
            writer.Write(header.PayloadLength);
            writer.Write(header.JournalChecksum);
            writer.Write(header.DatabaseChecksum);
        }
        if (stream.Length != HeaderLength) throw new InvalidDataException("The snapshot header length is not canonical.");
        return stream.ToArray();
    }

    private void WriteEnvelope(string path, string databasePath, SnapshotBoundaryInfo boundary)
    {
        var databaseLength = new FileInfo(databasePath).Length;
        var header = new Header(storeId, boundary.Through, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), boundary.SchemaVersion,
            databaseLength, boundary.JournalChecksum, HashFile(databasePath));
        var encodedHeader = EncodeHeader(header);
        using var envelopeHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        envelopeHash.AppendData(encodedHeader);
        using var input = new FileStream(databasePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        output.Write(encodedHeader);
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = input.Read(buffer, 0, buffer.Length);
            if (read == 0) break;
            output.Write(buffer, 0, read);
            envelopeHash.AppendData(buffer, 0, read);
        }
        output.Write(envelopeHash.GetHashAndReset());
        output.Flush(flushToDisk: true);
    }

    private void VerifySnapshotDatabase(string path, Header header)
    {
        using var connection = Open(path, readOnly: true);
        VerifyIntegrity(connection);
        using (var identity = connection.CreateCommand())
        {
            identity.CommandText = "SELECT id FROM store_identity LIMIT 1";
            if (identity.ExecuteScalar() is not string actual || actual != storeId.ToString("D"))
                throw new InvalidDataException("The snapshot belongs to another or uninitialized store.");
        }
        if (ReadSchemaVersion(connection) != header.SchemaVersion)
            throw new InvalidDataException("The snapshot schema version does not match its self-description.");
        using var state = connection.CreateCommand();
        state.CommandText = "SELECT last_sequence,truncated_through FROM journal_state WHERE store_id=$store";
        state.Parameters.AddWithValue("$store", storeId.ToString("D"));
        using var row = state.ExecuteReader();
        if (!row.Read() || row.GetInt64(0) != header.Through || row.GetInt64(1) > header.Through)
            throw new InvalidDataException("The snapshot sequence does not match its self-description.");
        row.Close();
        using (var rowsBeyondHead = connection.CreateCommand())
        {
            rowsBeyondHead.CommandText = "SELECT 1 FROM journal WHERE store_id=$store AND sequence>$through LIMIT 1";
            rowsBeyondHead.Parameters.AddWithValue("$store", storeId.ToString("D"));
            rowsBeyondHead.Parameters.AddWithValue("$through", header.Through);
            if (rowsBeyondHead.ExecuteScalar() is not null)
                throw new InvalidDataException("The snapshot contains journal rows beyond its durable high watermark.");
        }
        using var boundary = connection.CreateCommand();
        boundary.CommandText = "SELECT checksum FROM journal WHERE store_id=$store AND sequence=$through";
        boundary.Parameters.AddWithValue("$store", storeId.ToString("D"));
        boundary.Parameters.AddWithValue("$through", header.Through);
        if (boundary.ExecuteScalar() is not byte[] checksum ||
            !CryptographicOperations.FixedTimeEquals(checksum, header.JournalChecksum))
            throw new InvalidDataException("The snapshot does not bind its journal boundary.");
    }

    private static void VerifyIntegrity(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA integrity_check";
        using var rows = command.ExecuteReader();
        while (rows.Read())
            if (!string.Equals(rows.GetString(0), "ok", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("SQLite integrity_check rejected a snapshot.");
    }

    private SnapshotBoundaryInfo? ReadSnapshotBoundary(string path, SqliteJournal journal)
    {
        using var connection = Open(path, readOnly: true);
        using var transaction = connection.BeginTransaction(deferred: true);
        if (ReadStoreId(connection) != storeId.ToString("D"))
            throw new InvalidDataException("The copied database belongs to another store identity.");
        var context = new SqliteReadContext(storeId, connection, transaction);
        using var state = context.CreateCommand("SELECT last_sequence,truncated_through FROM journal_state WHERE store_id=$store");
        state.Parameters.AddWithValue("$store", context.StoreId.ToString("D"));
        using var row = state.ExecuteReader();
        if (!row.Read()) throw new InvalidDataException("The copied database has no journal watermark.");
        var head = row.GetInt64(0);
        var floor = row.GetInt64(1);
        row.Close();
        var schemaVersion = ReadSchemaVersion(connection);
        if (head <= floor) return null;

        var after = floor == 0 ? (JournalSequence?)null : new JournalSequence(context.StoreId, floor);
        var position = floor;
        while (position < head)
        {
            var entries = journal.Read(context, after, 4096);
            if (entries.Count == 0) throw new InvalidDataException("The copied database journal is incomplete.");
            position = entries[^1].Sequence.Value;
            after = entries[^1].Sequence;
        }
        if (SqliteJournal.HasRowsBeyondHead(context, head))
            throw new InvalidDataException("The copied database contains journal rows beyond its durable high watermark.");
        using var checksum = context.CreateCommand("SELECT checksum FROM journal WHERE store_id=$store AND sequence=$through");
        checksum.Parameters.AddWithValue("$store", context.StoreId.ToString("D"));
        checksum.Parameters.AddWithValue("$through", head);
        if (checksum.ExecuteScalar() is not byte[] value || value.Length != DigestLength)
            throw new InvalidDataException("The copied database has no verifiable journal boundary.");
        return new(head, value, schemaVersion);
    }

    private JournalPrefix? ReadValidTail(long after)
    {
        try
        {
            using var connection = Open(fullDatabasePath, readOnly: true);
            using var transaction = connection.BeginTransaction(deferred: true);
            return SqliteJournal.ReadValidPrefix(new SqliteReadContext(storeId, connection, transaction),
                new JournalSequence(storeId, after));
        }
        catch (Exception exception) when (exception is SqliteException or InvalidDataException or IOException)
        {
            return null;
        }
    }

    private void RestoreSnapshot(SnapshotCandidate candidate, string? evidenceDirectory)
    {
        var restorePath = fullDatabasePath + $".restore-{Guid.NewGuid():N}.tmp";
        try
        {
            using (var source = new FileStream(candidate.DatabasePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var destination = new FileStream(restorePath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                source.CopyTo(destination);
                destination.Flush(flushToDisk: true);
            }
            fault?.Invoke(SnapshotStage.RestoreCopied);
            if (!CryptographicOperations.FixedTimeEquals(HashFile(restorePath), candidate.DatabaseChecksum))
                throw new InvalidDataException("The restored snapshot copy does not match its verified database checksum.");
            VerifySnapshotDatabase(restorePath, new Header(storeId, candidate.Through,
                candidate.CreatedAtMilliseconds, candidate.SchemaVersion, new FileInfo(restorePath).Length,
                candidate.Boundary.JournalChecksum.ToArray(), candidate.DatabaseChecksum));

            if (File.Exists(fullDatabasePath))
            {
                if (evidenceDirectory is null) throw new InvalidOperationException("Recovery evidence was not recorded.");
            }
            var sidecars = SidecarSuffixes.Select(suffix => fullDatabasePath + suffix).Where(File.Exists).ToArray();
            if (sidecars.Length > 0 && evidenceDirectory is null)
                throw new InvalidOperationException("SQLite sidecars must be preserved before replacing the owner database.");
            foreach (var sidecar in sidecars) File.Delete(sidecar);
            File.Move(restorePath, fullDatabasePath, overwrite: true);
        }
        finally { DeleteTemporary(restorePath); }
    }

    private string PreserveEvidence()
    {
        var parent = Path.GetDirectoryName(fullDatabasePath) ?? Environment.CurrentDirectory;
        var name = Path.GetFileName(fullDatabasePath) + ".evidence-" + DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmssfffZ", System.Globalization.CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N");
        var directory = Path.Combine(parent, name);
        Directory.CreateDirectory(directory);
        try
        {
            foreach (var suffix in new[] { "", "-wal", "-shm", "-journal" })
            {
                var source = fullDatabasePath + suffix;
                if (!File.Exists(source)) continue;
                var destinationPath = Path.Combine(directory, Path.GetFileName(source));
                using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var output = new FileStream(destinationPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                input.CopyTo(output);
                output.Flush(flushToDisk: true);
            }
            return directory;
        }
        catch
        {
            // A partial evidence directory is retained rather than silently erased.
            throw;
        }
    }

    private void PruneVerifiedSnapshots()
    {
        var candidates = new List<(string Path, long Through, long Created)>();
        foreach (var path in Directory.EnumerateFiles(snapshotDirectory, "*.afsnap", SearchOption.TopDirectoryOnly))
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) continue;
            var candidate = VerifySnapshot(path);
            if (candidate is null) continue;
            candidates.Add((path, candidate.Through, candidate.CreatedAtMilliseconds));
            DeleteTemporary(candidate.DatabasePath);
        }
        foreach (var old in candidates.OrderByDescending(item => item.Through).ThenByDescending(item => item.Created).Skip(2))
            File.Delete(old.Path);
    }

    private static byte[] HashFile(string path)
    {
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return SHA256.HashData(input);
    }

    private static string ReadStoreId(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id FROM store_identity LIMIT 1";
        return command.ExecuteScalar() as string ?? throw new InvalidDataException("The copied database has no owner identity.");
    }

    private static uint ReadSchemaVersion(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT value FROM sys_meta WHERE key='storageSchemaVersion'";
        if (command.ExecuteScalar() is not string text || !StorageSchemaVersion.TryParse(text, out var version))
            throw new InvalidDataException("The owner database has no valid storage schema version.");
        return version.Number;
    }

    private long? ReadHeadSafely()
    {
        try { using var connection = Open(fullDatabasePath, readOnly: true); return ReadHeadIfAvailable(connection); }
        catch (SqliteException) { return null; }
    }

    private static long? ReadHeadIfAvailable(SqliteConnection connection)
    {
        try
        {
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT last_sequence FROM journal_state LIMIT 1";
            return command.ExecuteScalar() is long value ? value : null;
        }
        catch (SqliteException) { return null; }
    }

    private static bool TableExists(SqliteConnection connection, string table)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1 FROM sqlite_master WHERE type='table' AND name=$name";
        command.Parameters.AddWithValue("$name", table);
        return command.ExecuteScalar() is not null;
    }

    private static SqliteConnection Open(string path, bool readOnly)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Pooling = false,
            DefaultTimeout = 30,
            Mode = readOnly ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWriteCreate
        }.ToString());
        connection.Open();
        return connection;
    }

    private static string BoundaryKey(VerifiedSnapshotBoundary boundary) =>
        $"{boundary.Through.StoreId:D}:{boundary.Through.Value}:{Convert.ToHexString(boundary.JournalChecksum.Span)}:{Convert.ToHexString(boundary.SnapshotChecksum.Span)}";

    private FileStream? AcquireSnapshotLease(bool createDirectory)
    {
        if (!Directory.Exists(snapshotDirectory))
        {
            if (!createDirectory) return null;
            Directory.CreateDirectory(snapshotDirectory);
        }
        RejectReparsePoint(snapshotDirectory);
        var leasePath = Path.Combine(snapshotDirectory, LeaseFileName);
        if (File.Exists(leasePath) || Directory.Exists(leasePath)) RejectReparsePoint(leasePath);

        var deadline = Environment.TickCount64 + 30_000;
        while (true)
        {
            try { return new FileStream(leasePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException) when (Environment.TickCount64 < deadline)
            {
                Thread.Sleep(TimeSpan.FromMilliseconds(50));
            }
            catch (IOException exception)
            {
                throw new IOException("Timed out waiting for the snapshot operation lease.", exception);
            }
        }
    }

    private void ScavengeAbandonedTemporaryFiles()
    {
        ScavengeOwnedFiles(snapshotDirectory, IsOwnedTemporaryFileName);
        var databaseDirectory = Path.GetDirectoryName(fullDatabasePath) ?? Environment.CurrentDirectory;
        if (Directory.Exists(databaseDirectory))
            ScavengeOwnedFiles(databaseDirectory, IsOwnedRestoreTemporaryFileName);
    }

    private void ScavengeOwnedFiles(string directory, Func<string, bool> isOwned)
    {
        RejectReparsePoint(directory);
        foreach (var path in Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly))
        {
            if (!isOwned(Path.GetFileName(path))) continue;
            FileAttributes attributes;
            try { attributes = File.GetAttributes(path); }
            catch (FileNotFoundException) { continue; }
            if ((attributes & FileAttributes.ReparsePoint) != 0) continue;
            DeleteTemporary(path);
        }
    }

    private static bool IsOwnedTemporaryFileName(string name) =>
        HasOwnedTemporaryIdentity(name, ".snapshot-", ".db.tmp") ||
        HasOwnedTemporaryIdentity(name, ".snapshot-", ".afsnap.tmp") ||
        HasOwnedTemporaryIdentity(name, ".verify-", ".db.tmp");

    private bool IsOwnedRestoreTemporaryFileName(string name) =>
        HasOwnedTemporaryIdentity(name, Path.GetFileName(fullDatabasePath) + ".restore-", ".tmp");

    private static bool HasOwnedTemporaryIdentity(string name, string prefix, string suffix)
    {
        if (!name.StartsWith(prefix, StringComparison.Ordinal) || !name.EndsWith(suffix, StringComparison.Ordinal))
            return false;
        var identityLength = name.Length - prefix.Length - suffix.Length;
        if (identityLength != 32) return false;
        var identity = name.Substring(prefix.Length, identityLength);
        return Guid.TryParseExact(identity, "N", out var parsed) &&
            string.Equals(parsed.ToString("N"), identity, StringComparison.Ordinal);
    }

    private static void RejectReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Snapshot storage cannot be a symbolic link or reparse point.");
    }

    private void DeleteTemporary(string path)
    {
        var full = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(full);
        var name = Path.GetFileName(full);
        var databaseDirectory = Path.GetDirectoryName(fullDatabasePath) ?? Environment.CurrentDirectory;
        var isSnapshotTemporary = string.Equals(parent, snapshotDirectory, StringComparison.OrdinalIgnoreCase) &&
            IsOwnedTemporaryFileName(name);
        var isRestoreTemporary = string.Equals(parent, databaseDirectory, StringComparison.OrdinalIgnoreCase) &&
            IsOwnedRestoreTemporaryFileName(name);
        if (!isSnapshotTemporary && !isRestoreTemporary)
            throw new InvalidOperationException("Refusing to remove a file outside the snapshot temporary scope.");
        if (File.Exists(full)) File.Delete(full);
    }

    private sealed record Header(Guid StoreId, long Through, long CreatedAtMilliseconds, uint SchemaVersion,
        long PayloadLength, byte[] JournalChecksum, byte[] DatabaseChecksum);
    private readonly record struct SnapshotBoundaryInfo(long Through, byte[] JournalChecksum, uint SchemaVersion);
    private sealed record SnapshotCandidate(string EnvelopePath, string DatabasePath, long Through,
        long CreatedAtMilliseconds, uint SchemaVersion, byte[] DatabaseChecksum, VerifiedSnapshotBoundary Boundary);
    private sealed record DatabaseInspection(bool RequiresRecovery, bool CanReadJournal,
        long? Head, long? Floor, string Detail, bool IsUninitialized = false);

    private sealed class RecoveryAuthorization : IStoreAuthorization
    {
        public bool CanWrite(WriteCommand command) => true;
    }
}

internal enum SnapshotStage
{
    EnvelopeFlushed,
    EnvelopePublished,
    JournalTruncated,
    SnapshotVerified,
    RestoreCopied
}
