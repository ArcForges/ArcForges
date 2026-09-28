// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Capabilities;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Contributions;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using ArcForges.Persistence.Sqlite;

namespace ArcForges.Contributions.Tests;

public sealed class ContributionRegistryTests
{
    private static readonly DeviceId Device = new(new Guid("10000000-0000-0000-0000-000000000001"));
    private static readonly InstallationId InstallationId = new(new Guid("20000000-0000-0000-0000-000000000001"));
    private const string DeclaredSchema = "arcscope.session.compare.input.v1";
    private static readonly ContributionDefinition SessionCompare = Definition(
        "arcscope.session.compare", ContributionKind.Capability, DeclaredSchema);
    private static readonly ContributionDefinition SessionOpen = Definition(
        "arcscope.session.open", ContributionKind.Action);

    private static InstallationIdentity Installed(AppIdentity? app = null) =>
        new(app ?? AppIdentity.ArcScope, Device, InstallationId);

    private static ApplicationComposition<FixtureOwner> Start(InstallationIdentity? installation = null, ulong epoch = 1) =>
        ApplicationComposition.Start<FixtureOwner>(installation ?? Installed(), epoch, identity => new(identity));

    [Xunit.Fact]
    public async Task StaticHandlerIsTypedAndBoundToItsExactOwnerComposition()
    {
        var composition = Start();
        var store = new MemoryStore();
        var registry = new ContributionRegistry<FixtureOwner>(composition, store, ArcScopeCatalog());
        var descriptor = Definition("arcscope.session.compare", ContributionKind.Capability, DeclaredSchema);

        var registration = registry.Register<int, string>(descriptor,
            (owner, value, _) => ValueTask.FromResult(Outcome.Success($"{owner.Identity.Installation.App.ProductId}:{value}")));
        var result = await registration.DispatchAsync(composition.Identity, 7, Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.Equal(ContributionPersistenceResult.Added, registration.PersistenceResult);
        Xunit.Assert.True(result.TryGetValue(out var value));
        Xunit.Assert.Equal("arcscope:7", value);
        var definitions = registry.Definitions;
        Xunit.Assert.Single(definitions);
        Xunit.Assert.Equal(descriptor, definitions[0]);
        Xunit.Assert.Equal(1, store.AddCalls);
    }

    [Xunit.Fact]
    public void DuplicateIdsAreRefusedBeforeASecondDurableWrite()
    {
        var composition = Start();
        var store = new MemoryStore();
        var registry = new ContributionRegistry<FixtureOwner>(composition, store, ArcScopeCatalog());
        var descriptor = Definition("arcscope.session.compare", ContributionKind.Capability, DeclaredSchema);
        Func<FixtureOwner, string, CancellationToken, ValueTask<Outcome<string>>> handler =
            (_, value, _) => ValueTask.FromResult(Outcome.Success(value));

        _ = registry.Register(descriptor, handler);
        var refusal = Xunit.Assert.Throws<ContributionRegistrationException>(() => registry.Register(descriptor, handler));

        Xunit.Assert.Equal(ContributionRegistrationFailure.DuplicateId, refusal.Failure);
        Xunit.Assert.Equal(1, store.AddCalls);
    }

    [Xunit.Fact]
    public void WrongOwnerAndForeignProductNamespacesAreRefused()
    {
        var composition = Start();
        var store = new MemoryStore();
        var registry = new ContributionRegistry<FixtureOwner>(composition, store, ArcScopeCatalog());

        var wrongOwner = Xunit.Assert.Throws<ContributionRegistrationException>(() => registry.Register<string, string>(
            Definition("arcscope.session.open", ContributionKind.Action, ownerProductId: "companion"), Handler));
        var foreignNamespace = Xunit.Assert.Throws<ContributionRegistrationException>(() => registry.Register<string, string>(
            Definition("companion.session.open", ContributionKind.Action, ownerProductId: "arcscope"), Handler));

        Xunit.Assert.Equal(ContributionRegistrationFailure.WrongOwner, wrongOwner.Failure);
        Xunit.Assert.Equal(ContributionRegistrationFailure.ForeignNamespace, foreignNamespace.Failure);
        Xunit.Assert.Empty(registry.Definitions);
        Xunit.Assert.Equal(0, store.AddCalls);
    }

    [Xunit.Fact]
    public void UndeclaredOrMisappliedToolSchemasAreRefused()
    {
        var composition = Start();
        var store = new MemoryStore();
        var registry = new ContributionRegistry<FixtureOwner>(composition, store, ArcScopeCatalog());

        var unknown = Xunit.Assert.Throws<ContributionRegistrationException>(() => registry.Register<string, string>(
            Definition("arcscope.session.compare", ContributionKind.Capability, "arcscope.session.compare.output.v1"), Handler));
        var actionSchema = Xunit.Assert.Throws<ContributionRegistrationException>(() => registry.Register<string, string>(
            Definition("arcscope.session.open", ContributionKind.Action, DeclaredSchema), Handler));

        Xunit.Assert.Equal(ContributionRegistrationFailure.UndeclaredToolSchema, unknown.Failure);
        Xunit.Assert.Equal(ContributionRegistrationFailure.UndeclaredToolSchema, actionSchema.Failure);
        Xunit.Assert.Equal(0, store.AddCalls);
    }

    [Xunit.Fact]
    public void ForgedDescriptorsAndCallerDeclaredExternalSchemasAreRefused()
    {
        var registry = new ContributionRegistry<FixtureOwner>(Start(), new MemoryStore(), ArcScopeCatalog());

        var forged = Xunit.Assert.Throws<ContributionRegistrationException>(() => registry.Register<string, string>(
            Definition("arcscope.session.invented", ContributionKind.Action), Handler));
        var externalSchema = Xunit.Assert.Throws<ContributionRegistrationException>(() => registry.Register<string, string>(
            Definition(SessionCompare.Id, ContributionKind.Capability, "external.session.read.input.v1"), Handler));

        Xunit.Assert.Equal(ContributionRegistrationFailure.UndeclaredContribution, forged.Failure);
        Xunit.Assert.Equal(ContributionRegistrationFailure.UndeclaredToolSchema, externalSchema.Failure);
        Xunit.Assert.Empty(registry.Definitions);
    }

    [Xunit.Fact]
    public void CompositionValidatesCatalogFingerprintAndProductBinding()
    {
        var store = new MemoryStore();
        var invalidFingerprint = new StaticCatalogFixture("arcscope", [SessionCompare], new string('0', 64));
        var fingerprintFailure = Xunit.Assert.Throws<ContributionRegistrationException>(() =>
            new ContributionRegistry<FixtureOwner>(Start(), store, invalidFingerprint));
        var companionCatalog = new StaticCatalogFixture("companion",
            [Definition("companion.extension.example", ContributionKind.Action, ownerProductId: "companion")]);
        var ownerFailure = Xunit.Assert.Throws<ContributionRegistrationException>(() =>
            new ContributionRegistry<FixtureOwner>(Start(), store, companionCatalog));

        Xunit.Assert.Equal(ContributionRegistrationFailure.InvalidDescriptor, fingerprintFailure.Failure);
        Xunit.Assert.Equal(ContributionRegistrationFailure.WrongOwner, ownerFailure.Failure);
        Xunit.Assert.Equal(0, store.AddCalls);
    }

    [Xunit.Fact]
    public void RegistrySnapshotCannotBeExtendedByMutatingTheInjectedCatalog()
    {
        var descriptors = new List<ContributionDefinition> { SessionCompare };
        var catalog = new MutableCatalogFixture("arcscope", descriptors);
        var registry = new ContributionRegistry<FixtureOwner>(Start(), new MemoryStore(), catalog);

        descriptors.Add(SessionOpen);
        var refusal = Xunit.Assert.Throws<ContributionRegistrationException>(() => registry.Register<string, string>(
            SessionOpen, Handler));

        Xunit.Assert.Equal(ContributionRegistrationFailure.UndeclaredContribution, refusal.Failure);
        Xunit.Assert.Empty(registry.Definitions);
    }

    [Xunit.Fact]
    public void UnavailableChildRegistrationIsExplicitlyRefused()
    {
        var composition = Start();
        var registry = new ContributionRegistry<FixtureOwner>(composition, new MemoryStore(), ArcScopeCatalog());

        var refusal = Xunit.Assert.Throws<ContributionRegistrationException>(() =>
            registry.RegisterChild(Definition("arcscope.extension.example.item", ContributionKind.Action)));

        Xunit.Assert.Equal(ContributionRegistrationFailure.ChildUnavailable, refusal.Failure);
        Xunit.Assert.Empty(registry.Definitions);
    }

    [Xunit.Fact]
    public void ConflictingDurableMetadataForAnExistingIdIsRefused()
    {
        var installation = Installed();
        var store = new MemoryStore();
        var second = new ContributionRegistry<FixtureOwner>(Start(installation, epoch: 2), store, ArcScopeCatalog());
        var descriptor = Definition("arcscope.session.compare", ContributionKind.Capability, DeclaredSchema);

        store.Add(installation, Definition(descriptor.Id, ContributionKind.Action));
        var refusal = Xunit.Assert.Throws<ContributionRegistrationException>(() => second.Register<string, string>(
            descriptor, Handler));

        Xunit.Assert.Equal(ContributionRegistrationFailure.PersistenceConflict, refusal.Failure);
        Xunit.Assert.Empty(second.Definitions);
    }

    [Xunit.Fact]
    public async Task IdenticalRegistrationSurvivesAStoreAndApplicationRestart()
    {
        using var file = new DatabaseFile();
        var installation = Installed();
        var descriptor = Definition("arcscope.session.compare", ContributionKind.Capability, DeclaredSchema);
        var firstComposition = Start(installation, epoch: 1);
        using (var store = new SqliteStore(file.Path, file.StoreId, new AllowWrites()))
        {
            var registry = new ContributionRegistry<FixtureOwner>(firstComposition,
                new StoreBackedRegistrationStore(store), ArcScopeCatalog());
            var registration = registry.Register<int, int>(descriptor,
                (owner, value, _) => ValueTask.FromResult(Outcome.Success(owner.Identity.Epoch == 1 ? value + 1 : value + 2)));
            Xunit.Assert.Equal(ContributionPersistenceResult.Added, registration.PersistenceResult);
        }

        var restartedComposition = Start(installation, epoch: 2);
        Xunit.Assert.NotEqual(firstComposition.Identity.InstanceId, restartedComposition.Identity.InstanceId);
        using var reopenedStore = new SqliteStore(file.Path, file.StoreId, new AllowWrites());
        var reopenedRegistry = new ContributionRegistry<FixtureOwner>(restartedComposition,
            new StoreBackedRegistrationStore(reopenedStore), ArcScopeCatalog());
        var restoredRegistration = reopenedRegistry.Register<int, int>(descriptor,
            (owner, value, _) => ValueTask.FromResult(Outcome.Success(owner.Identity.Epoch == 2 ? value + 2 : value + 1)));
        var result = await restoredRegistration.DispatchAsync(restartedComposition.Identity, 40,
            Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.Equal(ContributionPersistenceResult.AlreadyPresent, restoredRegistration.PersistenceResult);
        Xunit.Assert.True(result.TryGetValue(out var value));
        Xunit.Assert.Equal(42, value);
    }

    [Xunit.Fact]
    public async Task ConcurrentIdenticalRegistrationsDistinguishIStoreReplayFromNewInsert()
    {
        using var file = new DatabaseFile();
        using var innerStore = new SqliteStore(file.Path, file.StoreId, new AllowWrites());
        using var store = new InitialReadBarrierStore(innerStore, participants: 2);
        var installation = Installed();
        var registrationStore = new StoreBackedRegistrationStore(store);

        var outcomes = await Task.WhenAll(
            Task.Run(() => TryAdd(registrationStore, installation, SessionCompare)),
            Task.Run(() => TryAdd(registrationStore, installation, SessionCompare)));

        Xunit.Assert.All(outcomes, outcome => Xunit.Assert.Null(outcome.Exception));
        Xunit.Assert.Single(outcomes, outcome => outcome.Result == ContributionPersistenceResult.Added);
        Xunit.Assert.Single(outcomes, outcome => outcome.Result == ContributionPersistenceResult.AlreadyPresent);
    }

    [Xunit.Fact]
    public async Task SeparateCompositionInstancesRegisterTheSameCatalogEntryIdempotently()
    {
        using var file = new DatabaseFile();
        using var innerStore = new SqliteStore(file.Path, file.StoreId, new AllowWrites());
        using var store = new InitialReadBarrierStore(innerStore, participants: 2);
        var installation = Installed();
        var stateStore = new StoreBackedRegistrationStore(store);
        var first = new ContributionRegistry<FixtureOwner>(Start(installation, epoch: 1), stateStore, ArcScopeCatalog());
        var second = new ContributionRegistry<FixtureOwner>(Start(installation, epoch: 2), stateStore, ArcScopeCatalog());

        var results = await Task.WhenAll(
            Task.Run(() => first.Register<string, string>(SessionCompare, Handler).PersistenceResult),
            Task.Run(() => second.Register<string, string>(SessionCompare, Handler).PersistenceResult));

        Xunit.Assert.Single(results, result => result == ContributionPersistenceResult.Added);
        Xunit.Assert.Single(results, result => result == ContributionPersistenceResult.AlreadyPresent);
        Xunit.Assert.Single(first.Definitions);
        Xunit.Assert.Single(second.Definitions);
    }

    [Xunit.Fact]
    public async Task ConcurrentDifferentMetadataReturnsTypedPersistenceConflict()
    {
        using var file = new DatabaseFile();
        using var innerStore = new SqliteStore(file.Path, file.StoreId, new AllowWrites());
        using var store = new InitialReadBarrierStore(innerStore, participants: 2);
        var installation = Installed();
        var registrationStore = new StoreBackedRegistrationStore(store);
        var conflicting = Definition(SessionCompare.Id, ContributionKind.Action);

        var outcomes = await Task.WhenAll(
            Task.Run(() => TryAdd(registrationStore, installation, SessionCompare)),
            Task.Run(() => TryAdd(registrationStore, installation, conflicting)));

        Xunit.Assert.Single(outcomes, outcome => outcome.Result == ContributionPersistenceResult.Added);
        var failure = Xunit.Assert.Single(outcomes, outcome => outcome.Exception is not null).Exception;
        Xunit.Assert.IsType<ContributionPersistenceConflictException>(failure);
    }

    private static ContributionDefinition Definition(string id, ContributionKind kind, string? toolSchemaId = null,
        string ownerProductId = "arcscope") => new(id, ownerProductId, kind, toolSchemaId);

    private static StaticCatalogFixture ArcScopeCatalog() => new("arcscope", [SessionCompare, SessionOpen]);

    private static (ContributionPersistenceResult? Result, Exception? Exception) TryAdd(
        IContributionRegistrationStore store, InstallationIdentity installation, ContributionDefinition definition)
    {
        try
        {
            return (store.Add(installation, definition), null);
        }
        catch (ContributionPersistenceConflictException exception)
        {
            return (null, exception);
        }
    }

    private static ValueTask<Outcome<string>> Handler(FixtureOwner _, string value, CancellationToken __) =>
        ValueTask.FromResult(Outcome.Success(value));

    private sealed record FixtureOwner(InstanceIdentity Identity);

    private sealed class StaticCatalogFixture : IContributionCatalog
    {
        public StaticCatalogFixture(string ownerProductId, IEnumerable<ContributionDefinition> descriptors, string? fingerprint = null)
        {
            OwnerProductId = ownerProductId;
            Descriptors = Array.AsReadOnly(descriptors.ToArray());
            Fingerprint = fingerprint ?? ContributionCatalogFingerprint.Compute(OwnerProductId, Descriptors);
        }

        public string OwnerProductId { get; }
        public IReadOnlyList<ContributionDefinition> Descriptors { get; }
        public string Fingerprint { get; }
    }

    private sealed class MutableCatalogFixture : IContributionCatalog
    {
        public MutableCatalogFixture(string ownerProductId, List<ContributionDefinition> descriptors)
        {
            OwnerProductId = ownerProductId;
            Descriptors = descriptors;
            Fingerprint = ContributionCatalogFingerprint.Compute(OwnerProductId, Descriptors);
        }

        public string OwnerProductId { get; }
        public IReadOnlyList<ContributionDefinition> Descriptors { get; }
        public string Fingerprint { get; }
    }

    private sealed class MemoryStore : IContributionRegistrationStore
    {
        private readonly Dictionary<(Guid Installation, string Id), ContributionDefinition> entries = new();
        public int AddCalls { get; private set; }

        public ContributionPersistenceResult Add(InstallationIdentity installation, ContributionDefinition definition)
        {
            AddCalls++;
            var key = (installation.InstallationId.Value, definition.Id);
            if (!entries.TryGetValue(key, out var existing))
            {
                entries.Add(key, definition);
                return ContributionPersistenceResult.Added;
            }

            if (existing == definition) return ContributionPersistenceResult.AlreadyPresent;
            throw new ContributionPersistenceConflictException("The contribution key already has different metadata.");
        }
    }

    private sealed class StoreBackedRegistrationStore(IStore store) : IContributionRegistrationStore
    {
        private const string AggregateKind = "contribution.registration.v1";
        private static readonly UserId Actor = new(Guid.Parse("00000000-0000-4000-8000-000000000001"));

        public ContributionPersistenceResult Add(InstallationIdentity installation, ContributionDefinition definition)
        {
            var aggregateId = StableGuid($"{installation.App.ProductId}\0{installation.DeviceId.Value:D}\0{installation.InstallationId.Value:D}\0{definition.Id}");
            var payload = Encode(installation, definition);
            var current = store.Read(AggregateKind, aggregateId);
            if (current is not null) return Compare(current.Payload.Span, payload);

            var origin = CreateOrigin(aggregateId, payload);
            var command = new WriteCommand(
                new(StableGuid("command\0" + aggregateId.ToString("D"))),
                AggregateKind,
                aggregateId,
                StoreVersion.NewRoot,
                new StoredContent(StoreVersion.Native(new(1)), payload, origin),
                "contribution.register",
                Actor,
                StableGuid("correlation\0" + aggregateId.ToString("D")),
                new ArcForges.Foundation.Instant(0, 0));

            try
            {
                var receipt = store.Write(command);
                if (!receipt.Replayed) return ContributionPersistenceResult.Added;

                var replayed = store.Read(AggregateKind, aggregateId);
                if (replayed is null)
                {
                    throw new ContributionPersistenceConflictException(
                        "The owner store replayed a registration command without its durable contribution record.");
                }

                return Compare(replayed.Payload.Span, payload);
            }
            catch (ContributionPersistenceConflictException)
            {
                throw;
            }
            catch (InvalidOperationException exception)
            {
                var raced = store.Read(AggregateKind, aggregateId);
                if (raced is null) throw;
                if (raced.Payload.Span.SequenceEqual(payload)) return ContributionPersistenceResult.AlreadyPresent;

                throw new ContributionPersistenceConflictException(
                    "The contribution key was concurrently committed with different durable metadata.", exception);
            }
        }

        private static ContributionPersistenceResult Compare(ReadOnlySpan<byte> existing, ReadOnlySpan<byte> requested)
        {
            if (existing.SequenceEqual(requested)) return ContributionPersistenceResult.AlreadyPresent;
            throw new ContributionPersistenceConflictException("The contribution key already has different durable metadata.");
        }

        private static byte[] Encode(InstallationIdentity installation, ContributionDefinition definition)
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, true);
            writer.Write("ArcForges.Contributions.Registration.v1");
            writer.Write(installation.App.ProductId);
            writer.Write(installation.DeviceId.Value.ToString("D"));
            writer.Write(installation.InstallationId.Value.ToString("D"));
            writer.Write(definition.Id);
            writer.Write(definition.OwnerProductId);
            writer.Write((int)definition.Kind);
            writer.Write(definition.ToolSchemaId is not null);
            if (definition.ToolSchemaId is not null) writer.Write(definition.ToolSchemaId);
            writer.Flush();
            return stream.ToArray();
        }

        private static ContentOrigin CreateOrigin(Guid aggregateId, byte[] payload)
        {
            var origin = new ContentOrigin
            {
                Profile = "arcforges.content-origin.v1",
                OriginId = new ContentOriginId(StableGuid("origin\0" + aggregateId.ToString("D"))).ToWire(),
                ContentUnitId = new ContentUnitId(StableGuid("unit\0" + aggregateId.ToString("D"))).ToWire(),
                PayloadSha256 = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(payload)),
                ProducerKind = "deterministic",
                OmittedParentCount = 0,
            };
            origin.Kinds.Add("nonAi");
            return origin;
        }

        private static Guid StableGuid(string value)
        {
            var digest = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value));
            return new Guid(digest.AsSpan(0, 16));
        }
    }

    private sealed class AllowWrites : IStoreAuthorization
    {
        public bool CanWrite(WriteCommand command) => true;
    }

    private sealed class InitialReadBarrierStore(IStore inner, int participants) : IStore
    {
        private const string RegistrationAggregateKind = "contribution.registration.v1";
        private readonly Barrier barrier = new(participants);
        private int initialReads;

        public StoredContent? Read(string aggregateKind, Guid aggregateId)
        {
            if (aggregateKind == RegistrationAggregateKind && Interlocked.Increment(ref initialReads) <= participants)
            {
                if (!barrier.SignalAndWait(TimeSpan.FromSeconds(15)))
                {
                    throw new TimeoutException("Concurrent registration reads did not reach the test barrier.");
                }

                return null;
            }

            return inner.Read(aggregateKind, aggregateId);
        }

        public CommitReceipt Write(WriteCommand command) => inner.Write(command);
        public IReadOnlyList<JournalEntry> ReadJournal(JournalSequence? after, int limit) => inner.ReadJournal(after, limit);
        public void Dispose() => barrier.Dispose();
    }

    private sealed class DatabaseFile : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
            "arcforges-contributions-" + Guid.NewGuid().ToString("N") + ".db");
        public Guid StoreId { get; } = Guid.NewGuid();

        public void Dispose()
        {
            foreach (var suffix in new[] { "", "-wal", "-shm", "-journal" })
            {
                var path = Path + suffix;
                if (File.Exists(path)) File.Delete(path);
            }
        }
    }
}
