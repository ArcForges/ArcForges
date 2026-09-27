// SPDX-License-Identifier: AGPL-3.0-only
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Persistence.Sqlite;
using Microsoft.Data.Sqlite;
using Xunit;

namespace ArcForges.Tests.PersistenceTests;

public sealed class StoreTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public void EveryBoundaryReopensAtomicallyAndRetryHasOneEffect(int stage)
    {
        using var file = new DatabaseFile();
        var command = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1)));
        using (var store = new SqliteStore(file.Path, file.Id, new Allow(), point => { if ((int)point == stage) throw new IOException("injected crash"); }))
            Assert.Throws<IOException>(() => store.Write(command));
        using var reopened = new SqliteStore(file.Path, file.Id, new Allow());
        var committed = stage == (int)CommitStage.Committed;
        Assert.Equal(committed, reopened.Read(command.AggregateKind, command.AggregateId) is not null);
        foreach (var table in new[] { "store_content", "store_history", "store_origins", "journal", "sync_outbox", "command_log" })
            Assert.Equal(committed ? 1L : 0L, file.Count(table));
        var receipt = reopened.Write(command);
        Assert.Equal(committed, receipt.Replayed);
        Assert.Equal(EffectCertainty.Happened, receipt.Effect);
        Assert.Equal(1, receipt.Sequence.Value);
        Assert.True(reopened.Write(command).Replayed);
        Assert.Single(reopened.ReadJournal(null, 10));
        var replay = StoredContent.FromJournal(reopened.ReadJournal(null, 10)[0]);
        Assert.Equal(command.Content.Payload.ToArray(), replay.Payload.ToArray());
        Assert.Equal(command.Content.Origin, replay.Origin);
        Assert.Equal(1, file.Count("sync_outbox"));
    }

    [Fact]
    public void ReceiptBindsSemanticCommandAndAuthorizationPrecedesDisclosure()
    {
        using var file = new DatabaseFile();
        var gate = new Allow();
        using var store = new SqliteStore(file.Path, file.Id, gate);
        var command = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1)));
        store.Write(command);
        var changed = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1)), command.CommandId, command.AggregateId, "different");
        Assert.Throws<InvalidOperationException>(() => store.Write(changed));
        gate.Allowed = false;
        Assert.Throws<UnauthorizedAccessException>(() => store.Write(command));
        Assert.Equal(1, file.Count("command_log"));
    }

    [Fact]
    public void CompositeLocalTokenRejectsStaleIndexWorkAfterEditAndAcknowledgement()
    {
        using var file = new DatabaseFile(); using var store = new SqliteStore(file.Path, file.Id, new Allow());
        var first = Command(StoreVersion.NewRoot, StoreVersion.Local(null, 1)); store.Write(first);
        var second = Command(first.Content.Version, StoreVersion.Local(null, 2), aggregate: first.AggregateId); store.Write(second);
        var acknowledgement = Command(second.Content.Version, StoreVersion.Local(new(7), 2), aggregate: first.AggregateId); store.Write(acknowledgement);
        Assert.Throws<InvalidOperationException>(() => store.Write(Command(first.Content.Version, StoreVersion.Local(null, 2), aggregate: first.AggregateId)));
        Assert.Throws<InvalidOperationException>(() => store.Write(Command(second.Content.Version, StoreVersion.Local(null, 3), aggregate: first.AggregateId)));
        Assert.Equal(acknowledgement.Content.Version, store.Read("report", first.AggregateId)!.Version);
        Assert.Equal(new[] { first.Content.Version, second.Content.Version, acknowledgement.Content.Version }, store.ReadJournal(null, 10).Select(entry => entry.Next));
    }

    [Fact]
    public async Task ConcurrentWritersSerializeAndReadWhileOtherCommitIsStaged()
    {
        using var file = new DatabaseFile();
        using var staged = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        using var store = new SqliteStore(file.Path, file.Id, new Allow(), point => { if (point == CommitStage.Applied) { staged.Set(); Assert.True(release.Wait(TimeSpan.FromSeconds(15), TestContext.Current.CancellationToken)); } });
        var first = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1)));
        var task = Task.Run(() => store.Write(first), TestContext.Current.CancellationToken);
        Assert.True(staged.Wait(TimeSpan.FromSeconds(15), TestContext.Current.CancellationToken));
        try { Assert.Null(store.Read("report", first.AggregateId)); }
        finally { release.Set(); }
        await task.ConfigureAwait(true);
        using var competitor = new SqliteStore(file.Path, file.Id, new Allow());
        var attempts = Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
        {
            try { competitor.Write(Command(first.Content.Version, StoreVersion.Native(new(2)), aggregate: first.AggregateId)); return true; }
            catch (InvalidOperationException) { return false; }
        }, TestContext.Current.CancellationToken));
        Assert.Single(await Task.WhenAll(attempts).ConfigureAwait(true), value => value);
        Assert.Equal(2, competitor.ReadJournal(null, 10).Count);
    }

    [Fact]
    public void OriginValidationAndUnknownProfileRefuseWithoutPartialRows()
    {
        using var file = new DatabaseFile(); using var store = new SqliteStore(file.Path, file.Id, new Allow());
        var valid = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1)));
        var invalidOrigin = valid.Content.Origin; invalidOrigin.PayloadSha256 = new string('0', 64);
        var bad = new WriteCommand(valid.CommandId, valid.AggregateKind, valid.AggregateId, valid.Expected,
            new(valid.Content.Version, valid.Content.Payload.Span, invalidOrigin), valid.Operation, valid.Actor, valid.CorrelationId, valid.CommittedAt);
        Assert.Throws<ArgumentException>(() => store.Write(bad));
        invalidOrigin.Profile = "arcforges.content-origin.v99";
        var future = new WriteCommand(valid.CommandId, valid.AggregateKind, valid.AggregateId, valid.Expected,
            new(valid.Content.Version, valid.Content.Payload.Span, invalidOrigin), valid.Operation, valid.Actor, valid.CorrelationId, valid.CommittedAt);
        Assert.Throws<InvalidOperationException>(() => store.Write(future));
        Assert.Equal(0, file.Count("store_content")); Assert.Equal(0, file.Count("journal"));
    }

    [Fact]
    public void NotificationSeesCommittedStateAndFailureCannotChangeReceipt()
    {
        using var file = new DatabaseFile(); using var store = new SqliteStore(file.Path, file.Id, new Allow());
        var command = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1)));
        var notified = false;
        store.Committed += (_, args) => { Assert.Equal(args.Receipt.Version, store.Read("report", command.AggregateId)!.Version); notified = true; throw new IOException("observer"); };
        Assert.Throws<IOException>(() => store.Write(command));
        var result = store.Write(command);
        Assert.True(notified); Assert.Equal(EffectCertainty.Happened, result.Effect); Assert.True(result.Replayed);
    }

    [Fact]
    public void StorageWriterPolicyExposesOnlyCanonicalCommitAndNoRawProviderHandles()
    {
        var assembly = typeof(SqliteStore).Assembly;
        Assert.False(assembly.GetType("ArcForges.Persistence.Sqlite.StoreDatabase")!.IsPublic);
        Assert.False(assembly.GetType("ArcForges.Persistence.Sqlite.SqliteCommitContext")!.IsPublic);
        Assert.False(assembly.GetType("ArcForges.Persistence.Sqlite.CommitUnit")!.IsPublic);
        Assert.Single(typeof(SqliteStore).GetMethods(), method => method.Name == "Write");
        foreach (var type in assembly.GetExportedTypes())
            foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            {
                Assert.DoesNotContain("Microsoft.Data.Sqlite", method.ReturnType.FullName ?? "", StringComparison.Ordinal);
                Assert.All(method.GetParameters(), parameter => Assert.DoesNotContain("Microsoft.Data.Sqlite", parameter.ParameterType.FullName ?? "", StringComparison.Ordinal));
            }
    }

    [Fact]
    public void HistoryCollectionPreservesCurrentContentAndOriginIdentityFence()
    {
        using var file = new DatabaseFile(); using var store = new SqliteStore(file.Path, file.Id, new Allow());
        var first = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1))); store.Write(first);
        for (ulong index = 2; index <= 66; index++)
            store.Write(Command(StoreVersion.Native(new(index - 1)), StoreVersion.Native(new(index)), aggregate: first.AggregateId));
        Assert.Equal(64, file.Count("store_history"));
        Assert.Equal(64, file.Count("store_origins"));
        Assert.Equal(StoreVersion.Native(new(66)), store.Read("report", first.AggregateId)!.Version);
        var altered = first.Content.Origin; altered.ProducerKind = "deterministic";
        Assert.Throws<InvalidOperationException>(() => store.Write(new(new(Guid.NewGuid()), "report", first.AggregateId,
            StoreVersion.Native(new(66)), new(StoreVersion.Native(new(67)), first.Content.Payload.Span, altered),
            "report.edit", first.Actor, Guid.NewGuid(), first.CommittedAt)));
    }

    [Fact]
    public void CollectionBudgetRetainsLongLiveLineageAndMakesBoundedProgress()
    {
        using var file = new DatabaseFile(); using var store = new SqliteStore(file.Path, file.Id, new Allow());
        var previous = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1))); store.Write(previous);
        for (ulong revision = 2; revision <= 130; revision++)
        {
            var next = Command(previous.Content.Version, StoreVersion.Native(new(revision)), aggregate: previous.AggregateId, parent: previous.Content.Origin);
            store.Write(next); previous = next;
        }
        Assert.Equal(130, file.Count("store_origins")); // Only 64 history roots, but every ancestor remains live.
        for (ulong revision = 131; revision <= 193; revision++)
        {
            var next = Command(previous.Content.Version, StoreVersion.Native(new(revision)), aggregate: previous.AggregateId);
            store.Write(next); previous = next;
        }
        Assert.Equal(193, file.Count("store_origins"));
        foreach (var expectedCount in new long[] { 130, 67, 64 })
        {
            var next = Command(previous.Content.Version, StoreVersion.Native(new(previous.Content.Version.NativeRevision!.Value.Value + 1)), aggregate: previous.AggregateId);
            store.Write(next); previous = next;
            Assert.Equal(expectedCount, file.Count("store_origins"));
            Assert.Equal(next.Content.Origin, store.Read("report", next.AggregateId)!.Origin);
        }
    }

    private static WriteCommand Command(StoreVersion expected, StoreVersion next, CommandId? command = null, Guid? aggregate = null, string body = "payload", ContentOrigin? parent = null)
    {
        var payload = Encoding.UTF8.GetBytes(body);
        var origin = new ContentOrigin
        {
            Profile = "arcforges.content-origin.v1",
            OriginId = new ContentOriginId(Guid.NewGuid()).ToWire(),
            ContentUnitId = new ContentUnitId(Guid.NewGuid()).ToWire(),
            PayloadSha256 = Convert.ToHexStringLower(SHA256.HashData(payload)),
            ProducerKind = "human",
            OmittedParentCount = 0
        };
        origin.Kinds.Add("nonAi");
        if (parent is not null) origin.ParentOriginIds.Add(parent.OriginId.Clone());
        return new(command ?? new(Guid.NewGuid()), "report", aggregate ?? Guid.NewGuid(), expected, new(next, payload, origin),
            "report.edit", new(Guid.Parse("00000000-0000-4000-8000-000000000001")), Guid.NewGuid(), new(0, 0));
    }
    private sealed class Allow : IStoreAuthorization { public bool Allowed { get; set; } = true; public bool CanWrite(WriteCommand command) => Allowed; }
    private sealed class DatabaseFile : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "arcforges-store-" + Guid.NewGuid().ToString("N") + ".db");
        public Guid Id { get; } = Guid.NewGuid();
        public long Count(string table)
        {
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Path, Pooling = false }.ToString()); connection.Open();
            using var command = connection.CreateCommand();
            switch (table)
            {
                case "store_content": command.CommandText = "SELECT COUNT(*) FROM store_content"; break;
                case "store_history": command.CommandText = "SELECT COUNT(*) FROM store_history"; break;
                case "store_origins": command.CommandText = "SELECT COUNT(*) FROM store_origins"; break;
                case "journal": command.CommandText = "SELECT COUNT(*) FROM journal"; break;
                case "sync_outbox": command.CommandText = "SELECT COUNT(*) FROM sync_outbox"; break;
                case "command_log": command.CommandText = "SELECT COUNT(*) FROM command_log"; break;
                default: throw new ArgumentException("Unknown table.", nameof(table));
            }
            return (long)command.ExecuteScalar()!;
        }
        public void Dispose() { foreach (var suffix in new[] { "", "-wal", "-shm", "-journal" }) File.Delete(Path + suffix); }
    }
}

