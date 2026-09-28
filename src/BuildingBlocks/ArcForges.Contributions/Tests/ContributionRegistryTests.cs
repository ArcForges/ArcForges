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

    private static InstallationIdentity Installed(AppIdentity? app = null) =>
        new(app ?? AppIdentity.ArcScope, Device, InstallationId);

    private static ApplicationComposition<FixtureOwner> Start(InstallationIdentity? installation = null, ulong epoch = 1) =>
        ApplicationComposition.Start<FixtureOwner>(installation ?? Installed(), epoch, identity => new(identity));

    [Xunit.Fact]
    public async Task StaticHandlerIsTypedAndBoundToItsExactOwnerComposition()
    {
        var composition = Start();
        var store = new MemoryStore();
        var registry = new ContributionRegistry<FixtureOwner>(composition, store, [DeclaredSchema]);
        var descriptor = Definition("arcscope.session.compare", ContributionKind.Capability, DeclaredSchema);

        var registration = registry.Register<int, string>(descriptor,
            (owner, value, _) => ValueTask.FromResult(Outcome.Success($"{owner.Identity.Installation.App.ProductId}:{value}")));
        var result = await registration.DispatchAsync(composition.Identity, 7, Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.Equal(ContributionPersistenceResult.Added, registration.PersistenceResult);
        Xunit.Assert.True(result.TryGetValue(out var value));
        Xunit.Assert.Equal("arcscope:7", value);
        var definitions = registry.Definitions;
        Xunit.Assert.Single(definitions);
        Xunit.Assert.Same(descriptor, definitions[0]);
        Xunit.Assert.Equal(1, store.AddCalls);
    }

    [Xunit.Fact]
    public void DuplicateIdsAreRefusedBeforeASecondDurableWrite()
    {
        var composition = Start();
        var store = new MemoryStore();
        var registry = new ContributionRegistry<FixtureOwner>(composition, store, [DeclaredSchema]);
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
        var registry = new ContributionRegistry<FixtureOwner>(composition, store, [DeclaredSchema]);

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
        var registry = new ContributionRegistry<FixtureOwner>(composition, store, [DeclaredSchema]);

        var unknown = Xunit.Assert.Throws<ContributionRegistrationException>(() => registry.Register<string, string>(
            Definition("arcscope.session.compare", ContributionKind.Capability, "arcscope.session.compare.output.v1"), Handler));
        var actionSchema = Xunit.Assert.Throws<ContributionRegistrationException>(() => registry.Register<string, string>(
            Definition("arcscope.session.open", ContributionKind.Action, DeclaredSchema), Handler));

        Xunit.Assert.Equal(ContributionRegistrationFailure.UndeclaredToolSchema, unknown.Failure);
        Xunit.Assert.Equal(ContributionRegistrationFailure.UndeclaredToolSchema, actionSchema.Failure);
        Xunit.Assert.Equal(0, store.AddCalls);
    }

    [Xunit.Fact]
    public void UnavailableChildRegistrationIsExplicitlyRefused()
    {
        var composition = Start();
        var registry = new ContributionRegistry<FixtureOwner>(composition, new MemoryStore(), [DeclaredSchema]);

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
        var first = new ContributionRegistry<FixtureOwner>(Start(installation), store, [DeclaredSchema]);
        var second = new ContributionRegistry<FixtureOwner>(Start(installation, epoch: 2), store, [DeclaredSchema]);
        var descriptor = Definition("arcscope.session.compare", ContributionKind.Capability, DeclaredSchema);

        _ = first.Register<string, string>(descriptor, Handler);
        var refusal = Xunit.Assert.Throws<ContributionRegistrationException>(() => second.Register<string, string>(
            Definition(descriptor.Id, ContributionKind.Action), Handler));

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
                new StoreBackedRegistrationStore(store), [DeclaredSchema]);
            var registration = registry.Register<int, int>(descriptor,
                (owner, value, _) => ValueTask.FromResult(Outcome.Success(owner.Identity.Epoch == 1 ? value + 1 : value + 2)));
            Xunit.Assert.Equal(ContributionPersistenceResult.Added, registration.PersistenceResult);
        }

        var restartedComposition = Start(installation, epoch: 2);
        Xunit.Assert.NotEqual(firstComposition.Identity.InstanceId, restartedComposition.Identity.InstanceId);
        using var reopenedStore = new SqliteStore(file.Path, file.StoreId, new AllowWrites());
        var reopenedRegistry = new ContributionRegistry<FixtureOwner>(restartedComposition,
            new StoreBackedRegistrationStore(reopenedStore), [DeclaredSchema]);
        var restoredRegistration = reopenedRegistry.Register<int, int>(descriptor,
            (owner, value, _) => ValueTask.FromResult(Outcome.Success(owner.Identity.Epoch == 2 ? value + 2 : value + 1)));
        var result = await restoredRegistration.DispatchAsync(restartedComposition.Identity, 40,
            Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.Equal(ContributionPersistenceResult.AlreadyPresent, restoredRegistration.PersistenceResult);
        Xunit.Assert.True(result.TryGetValue(out var value));
        Xunit.Assert.Equal(42, value);
    }

    private static ContributionDefinition Definition(string id, ContributionKind kind, string? toolSchemaId = null,
        string ownerProductId = "arcscope") => new(id, ownerProductId, kind, toolSchemaId);

    private static ValueTask<Outcome<string>> Handler(FixtureOwner _, string value, CancellationToken __) =>
        ValueTask.FromResult(Outcome.Success(value));

    private sealed record FixtureOwner(InstanceIdentity Identity);

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
                store.Write(command);
                return ContributionPersistenceResult.Added;
            }
            catch (InvalidOperationException) when (store.Read(AggregateKind, aggregateId) is { } raced &&
                raced.Payload.Span.SequenceEqual(payload))
            {
                return ContributionPersistenceResult.AlreadyPresent;
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
