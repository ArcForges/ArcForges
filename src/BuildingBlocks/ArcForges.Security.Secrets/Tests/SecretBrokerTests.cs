// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Execution;
using ArcForges.Security;
using Xunit;

namespace ArcForges.Security.Secrets.Tests;

public sealed class SecretBrokerTests
{
    public static bool LocalWindowsStoreEnabled => OperatingSystem.IsWindows()
        && Environment.GetEnvironmentVariable("ARCFORGES_LOCAL_OS_SECRET_STORE") == "1";

    private static readonly Guid Realm = Guid.Parse("10000000-0000-0000-0000-000000000001");
    private static readonly Guid User = Guid.Parse("20000000-0000-0000-0000-000000000002");
    private static readonly Guid Device = Guid.Parse("30000000-0000-0000-0000-000000000003");
    private static readonly Guid Installation = Guid.Parse("40000000-0000-0000-0000-000000000004");

    [Fact]
    public void ReferencesAreOpaqueAndPersonalWorkspaceScopesAreSeparated()
    {
        var fixture = new Fixture(SecretApplicationDimension.ArcScope);
        var personal = fixture.Broker.Store(SecretPartition.Personal(), "personal"u8);
        var workspace = fixture.Broker.Store(SecretPartition.ForWorkspace(new WorkspaceId(Guid.NewGuid())), "workspace"u8);

        Assert.Equal("SecretRef:[redacted]", personal.ToString());
        Assert.DoesNotContain("personal", personal.ToString(), StringComparison.Ordinal);
        Assert.NotSame(personal, workspace);
        Assert.Equal(SHA256.HashData("personal"u8), fixture.UseDigest(personal));
        Assert.Equal(SHA256.HashData("workspace"u8), fixture.UseDigest(workspace));
        Assert.True(fixture.Broker.Delete(personal));
        Assert.Throws<KeyNotFoundException>(() => fixture.UseDigest(personal));
    }

    [Fact]
    public void PublicBrokerSurfaceNeverReturnsSecretMaterialToCallers()
    {
        var publicMethods = typeof(SecretBroker).GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance);

        Assert.All(publicMethods, method =>
        {
            Assert.NotEqual(typeof(byte[]), method.ReturnType);
            Assert.NotEqual(typeof(ReadOnlySpan<byte>), method.ReturnType);
            Assert.NotEqual(typeof(Span<byte>), method.ReturnType);
        });
        var useMethod = typeof(SecretBroker).GetMethod(nameof(SecretBroker.UseConnectorGrant))!;
        Assert.Equal(typeof(void), useMethod.ReturnType);
        Assert.DoesNotContain(useMethod.GetParameters(), parameter => parameter.ParameterType == typeof(ReadOnlySpan<byte>));
    }

    [Theory]
    [InlineData("arcscope")]
    [InlineData("companion")]
    public void ApplicationDimensionAcceptsOnlyFrozenFirstPartyProductValues(string productId)
    {
        var parsed = SecretApplicationDimension.Parse(productId);

        Assert.Equal(productId, parsed.ProductId);
        Assert.Same(productId == "arcscope" ? SecretApplicationDimension.ArcScope : SecretApplicationDimension.Companion,
            parsed);
        Assert.Throws<ArgumentException>(() => SecretApplicationDimension.Parse("third-party-app"));
    }

    [Fact]
    public void InstallationBindingRejectsUninitializedDeviceOrInstallation()
    {
        Assert.Throws<ArgumentException>(() => new SecretInstallationBinding(SecretApplicationDimension.ArcScope,
            default, new InstallationId(Installation)));
        Assert.Throws<ArgumentException>(() => new SecretInstallationBinding(SecretApplicationDimension.ArcScope,
            new DeviceId(Device), default));
    }

    [Fact]
    public void ProductNamespaceRejectsSiblingApplicationReferences()
    {
        var backing = new MemoryBackingStore();
        var source = new Fixture(SecretApplicationDimension.ArcScope, backing);
        var reference = source.Broker.Store(SecretPartition.Personal(), "arcscope-secret"u8);
        var sibling = new Fixture(SecretApplicationDimension.Companion, backing);

        Assert.Throws<UnauthorizedAccessException>(() => sibling.UseDigest(reference));
        Assert.Equal(SHA256.HashData("arcscope-secret"u8), source.UseDigest(reference));
    }

    [Fact]
    public void RealmAccountDeviceAndInstallationArePartOfTheSecretNamespace()
    {
        var backing = new MemoryBackingStore();
        var source = new Fixture(SecretApplicationDimension.ArcScope, backing);
        var reference = source.Broker.Store(SecretPartition.Personal(), "scoped-secret"u8);

        Assert.Throws<UnauthorizedAccessException>(() => new Fixture(SecretApplicationDimension.ArcScope, backing,
            realm: Guid.NewGuid()).UseDigest(reference));
        Assert.Throws<UnauthorizedAccessException>(() => new Fixture(SecretApplicationDimension.ArcScope, backing,
            user: Guid.NewGuid()).UseDigest(reference));
        Assert.Throws<UnauthorizedAccessException>(() => new Fixture(SecretApplicationDimension.ArcScope, backing,
            device: Guid.NewGuid()).UseDigest(reference));
        Assert.Throws<UnauthorizedAccessException>(() => new Fixture(SecretApplicationDimension.ArcScope, backing,
            installation: Guid.NewGuid()).UseDigest(reference));
    }

    [Fact]
    public void DelegatedActorCannotUseHumanCredentialsDirectly()
    {
        var fixture = new Fixture(SecretApplicationDimension.ArcScope);
        var reference = fixture.Broker.Store(SecretPartition.Personal(), "owner-only"u8);
        fixture.Provider.Current = fixture.Context(actors: [new DelegatedActor(ActorKind.Agent, Guid.NewGuid(),
            new InstanceId(Guid.NewGuid()), "agent.test")]);

        Assert.Throws<UnauthorizedAccessException>(() => fixture.Broker.Store(SecretPartition.Personal(), "agent"u8));
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Broker.Delete(reference));
        var agentChain = fixture.Provider.Current.ActorChain;
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Broker.GrantConnectorUse(reference, agentChain,
            "agent.test", TimeSpan.FromMinutes(1)));
        Assert.Equal(0, fixture.Executor.InvocationCount);
    }

    [Fact]
    public void ConnectorChildCannotMintItsOwnSecretGrant()
    {
        var fixture = new Fixture(SecretApplicationDimension.ArcScope);
        var reference = fixture.Broker.Store(SecretPartition.Personal(), "owner-only"u8);
        const string definition = "connector.calendar.v2";
        var childContext = fixture.ConnectorContext(definition);
        fixture.Provider.Current = childContext;

        Assert.Throws<UnauthorizedAccessException>(() => fixture.Broker.GrantConnectorUse(reference,
            childContext.ActorChain, definition, TimeSpan.FromMinutes(1)));
        Assert.Equal(0, fixture.Executor.InvocationCount);
    }

    [Fact]
    public void ConnectorGrantIsForegroundAndDefinitionBoundAndRevokesImmediately()
    {
        var fixture = new Fixture(SecretApplicationDimension.ArcScope);
        var reference = fixture.Broker.Store(SecretPartition.Personal(), "connector-key"u8);
        const string definition = "connector.cloud-drive.v1";
        var grant = fixture.CreateConnectorGrant(reference, definition, TimeSpan.FromMinutes(1));

        Assert.Equal("ConnectorSecretGrant:[redacted]", grant.ToString());
        fixture.Broker.UseConnectorGrant(grant, definition);
        Assert.Equal(SHA256.HashData("connector-key"u8), fixture.Executor.LastDigest);
        int usesBeforeWrongDefinition = fixture.Executor.InvocationCount;
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Broker.UseConnectorGrant(grant, "other.definition"));
        Assert.Equal(usesBeforeWrongDefinition, fixture.Executor.InvocationCount);

        Assert.True(fixture.Broker.Revoke(grant));
        Assert.False(fixture.Broker.Revoke(grant));
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Broker.UseConnectorGrant(grant, definition));
        Assert.Equal(usesBeforeWrongDefinition, fixture.Executor.InvocationCount);

        var useMethod = typeof(SecretBroker).GetMethod(nameof(SecretBroker.UseConnectorGrant))!;
        Assert.Equal(typeof(void), useMethod.ReturnType);
        Assert.Equal([typeof(ConnectorSecretGrant), typeof(string)],
            useMethod.GetParameters().Select(parameter => parameter.ParameterType));
    }

    [Fact]
    public void ChildGrantFailsWhenRecoveryGenerationChangesOrForegroundEnds()
    {
        var fixture = new Fixture(SecretApplicationDimension.ArcScope);
        var reference = fixture.Broker.Store(SecretPartition.Personal(), "connector-key"u8);
        const string definition = "connector.calendar.v2";
        var grant = fixture.CreateConnectorGrant(reference, definition, TimeSpan.FromMinutes(1));

        var current = fixture.Provider.Current;
        fixture.Provider.Current = new SecretHostContext(current.ActorChain, current.Installation, current.Session,
            recoveryGeneration: 2, isSignedIn: true, isForeground: true);
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Broker.UseConnectorGrant(grant, definition));

        fixture.Provider.Current = new SecretHostContext(current.ActorChain, current.Installation, current.Session,
            recoveryGeneration: current.RecoveryGeneration, isSignedIn: true, isForeground: false);
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Broker.UseConnectorGrant(grant, definition));

        var signedOutSession = new SessionId(Guid.NewGuid());
        var signedOutChain = new ActorChain(current.ActorChain.Owner, current.ActorChain.Device,
            current.ActorChain.Installation, signedOutSession, current.ActorChain.CallerInstance,
            current.ActorChain.Actors);
        fixture.Provider.Current = new SecretHostContext(signedOutChain, current.Installation,
            signedOutSession, recoveryGeneration: current.RecoveryGeneration,
            isSignedIn: true, isForeground: true);
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Broker.UseConnectorGrant(grant, definition));

        fixture.Provider.Current = new SecretHostContext(current.ActorChain, current.Installation, current.Session,
            recoveryGeneration: current.RecoveryGeneration, isSignedIn: false, isForeground: false);
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Broker.UseConnectorGrant(grant, definition));
    }

    [Fact]
    public void ConnectorGrantIsBoundToTheExactChildActorChain()
    {
        var fixture = new Fixture(SecretApplicationDimension.ArcScope);
        var reference = fixture.Broker.Store(SecretPartition.Personal(), "connector-key"u8);
        const string definition = "connector.calendar.v2";
        var grant = fixture.CreateConnectorGrant(reference, definition, TimeSpan.FromMinutes(1));
        var issuedFor = fixture.Provider.Current;
        fixture.Provider.Current = fixture.ConnectorContext(definition, issuedFor.Session, issuedFor.RecoveryGeneration);

        Assert.Throws<UnauthorizedAccessException>(() => fixture.Broker.UseConnectorGrant(grant, definition));
        Assert.Equal(0, fixture.Executor.InvocationCount);
    }

    [Fact]
    public void ConnectorGrantHasABoundedLifetime()
    {
        var time = new TestTimeProvider(DateTimeOffset.Parse("2026-09-28T12:00:00Z", System.Globalization.CultureInfo.InvariantCulture));
        var fixture = new Fixture(SecretApplicationDimension.ArcScope, timeProvider: time);
        var reference = fixture.Broker.Store(SecretPartition.Personal(), "connector-key"u8);
        const string definition = "connector.calendar.v2";
        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.CreateConnectorGrant(reference, definition,
            SecretBroker.MaximumConnectorGrantLifetime + TimeSpan.FromTicks(1)));
        var grant = fixture.CreateConnectorGrant(reference, definition, TimeSpan.FromMinutes(1));

        time.Advance(TimeSpan.FromMinutes(1));

        Assert.Throws<UnauthorizedAccessException>(() => fixture.Broker.UseConnectorGrant(grant, definition));
    }

    [Fact]
    public void SignOutEndsOnlyItsSessionAndDoesNotDeleteEitherApplicationVault()
    {
        var backing = new MemoryBackingStore();
        var arcscope = new Fixture(SecretApplicationDimension.ArcScope, backing);
        var companion = new Fixture(SecretApplicationDimension.Companion, backing);
        var arcscopeRef = arcscope.Broker.Store(SecretPartition.Personal(), "local-arcscope"u8);
        var companionRef = companion.Broker.Store(SecretPartition.Personal(), "local-companion"u8);

        arcscope.Provider.Current = arcscope.Context(isSignedIn: false);
        Assert.Throws<UnauthorizedAccessException>(() => arcscope.UseDigest(arcscopeRef));
        Assert.Equal(SHA256.HashData("local-companion"u8), companion.UseDigest(companionRef));

        arcscope.Provider.Current = arcscope.Context(session: new SessionId(Guid.NewGuid()));
        Assert.Equal(SHA256.HashData("local-arcscope"u8), arcscope.UseDigest(arcscopeRef));
        Assert.Equal(SHA256.HashData("local-companion"u8), companion.UseDigest(companionRef));
    }

    [Fact]
    public void SignOutRevokesEveryOutstandingGrantImmediatelyWithoutDeletingSecretsOrOtherAppGrants()
    {
        var backing = new MemoryBackingStore();
        var arcscope = new Fixture(SecretApplicationDimension.ArcScope, backing);
        var companion = new Fixture(SecretApplicationDimension.Companion, backing);
        var arcscopeRef = arcscope.Broker.Store(SecretPartition.Personal(), "local-arcscope"u8);
        var companionRef = companion.Broker.Store(SecretPartition.Personal(), "local-companion"u8);
        const string definition = "connector.calendar.v2";
        var first = arcscope.CreateConnectorGrant(arcscopeRef, definition, TimeSpan.FromMinutes(1));
        arcscope.Provider.Current = arcscope.Context();
        var second = arcscope.CreateConnectorGrant(arcscopeRef, definition, TimeSpan.FromMinutes(1));
        var other = companion.CreateConnectorGrant(companionRef, definition, TimeSpan.FromMinutes(1));

        Assert.Equal(2, arcscope.Broker.RevokeAllConnectorGrants());
        Assert.Equal(0, arcscope.Broker.RevokeAllConnectorGrants());

        Assert.Throws<UnauthorizedAccessException>(() => arcscope.Broker.UseConnectorGrant(first, definition));
        Assert.Throws<UnauthorizedAccessException>(() => arcscope.Broker.UseConnectorGrant(second, definition));
        Assert.Equal(0, arcscope.Executor.InvocationCount);
        companion.Broker.UseConnectorGrant(other, definition);
        Assert.Equal(SHA256.HashData("local-companion"u8), companion.Executor.LastDigest);
        Assert.Throws<UnauthorizedAccessException>(() => companion.Broker.Revoke(first));
        arcscope.Provider.Current = arcscope.Context();
        Assert.Equal(SHA256.HashData("local-arcscope"u8), arcscope.UseDigest(arcscopeRef));
    }

    [Fact]
    public void BrokerFailsClosedUnlessTheStoreEnforcesPerApplicationIsolationOrTheHostAcceptsTheLimitation()
    {
        var installation = new SecretInstallationBinding(SecretApplicationDimension.ArcScope, new DeviceId(Device),
            new InstallationId(Installation));
        var provider = new ContextProvider();
        var executor = new RecordingConnectorExecutor();
        var shared = new MemoryBackingStore { Isolation = SecretStoreIsolation.SameUserShared };

        Assert.Throws<NotSupportedException>(() => new SecretBroker(installation, provider, shared, executor,
            SecretIsolationPolicy.RequireOsEnforcedPerApplication));
        Assert.Throws<ArgumentOutOfRangeException>(() => new SecretBroker(installation, provider, shared, executor,
            (SecretIsolationPolicy)42));
        var accepted = new SecretBroker(installation, provider, shared, executor,
            SecretIsolationPolicy.AllowSameUserSharedStore);
        Assert.Equal(SecretStoreIsolation.SameUserShared, accepted.IsolationAssurance);

        var enforced = new MemoryBackingStore { Isolation = SecretStoreIsolation.OsEnforcedPerApplication };
        var strict = new SecretBroker(installation, provider, enforced, executor,
            SecretIsolationPolicy.RequireOsEnforcedPerApplication);
        enforced.Isolation = SecretStoreIsolation.SameUserShared;
        Assert.Equal(SecretStoreIsolation.OsEnforcedPerApplication, strict.IsolationAssurance);
    }

    [Fact]
    public void PlatformStoreSelectionIsFailClosedAndNeverOverstatesIsolation()
    {
        Assert.Throws<PlatformNotSupportedException>(() => OsSecretStore.Create(isWindows: false));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Throws<PlatformNotSupportedException>(() => OsSecretStore.CreateForCurrentPlatform());
            Assert.Throws<PlatformNotSupportedException>(() => OsSecretStore.Create(isWindows: true));
            return;
        }

        var store = Assert.IsType<WindowsCredentialManagerSecretStore>(OsSecretStore.CreateForCurrentPlatform());
        Assert.Equal(SecretStoreIsolation.SameUserShared, store.Isolation);
        var installation = new SecretInstallationBinding(SecretApplicationDimension.ArcScope, new DeviceId(Device),
            new InstallationId(Installation));
        Assert.Throws<NotSupportedException>(() => new SecretBroker(installation, new ContextProvider(), store,
            new RecordingConnectorExecutor(), SecretIsolationPolicy.RequireOsEnforcedPerApplication));
    }

    [Theory]
    [InlineData("product")]
    [InlineData("realm")]
    [InlineData("account")]
    [InlineData("device")]
    [InlineData("installation")]
    public void SiblingBrokerCannotDeleteAnotherApplicationsSecret(string dimension)
    {
        var backing = new MemoryBackingStore();
        var owner = new Fixture(SecretApplicationDimension.ArcScope, backing);
        var reference = owner.Broker.Store(SecretPartition.Personal(), "owner-secret"u8);
        var sibling = dimension switch
        {
            "product" => new Fixture(SecretApplicationDimension.Companion, backing),
            "realm" => new Fixture(SecretApplicationDimension.ArcScope, backing, realm: Guid.NewGuid()),
            "account" => new Fixture(SecretApplicationDimension.ArcScope, backing, user: Guid.NewGuid()),
            "device" => new Fixture(SecretApplicationDimension.ArcScope, backing, device: Guid.NewGuid()),
            _ => new Fixture(SecretApplicationDimension.ArcScope, backing, installation: Guid.NewGuid()),
        };

        Assert.Throws<UnauthorizedAccessException>(() => sibling.Broker.Delete(reference));
        Assert.Equal(SHA256.HashData("owner-secret"u8), owner.UseDigest(reference));
        Assert.True(owner.Broker.Delete(reference));
    }

    [Theory]
    [InlineData("session")]
    [InlineData("device")]
    [InlineData("installation")]
    [InlineData("owner")]
    [InlineData("agent-final-actor")]
    [InlineData("empty-chain")]
    [InlineData("definition-mismatch")]
    public void GrantTargetOutsideTheHumanSessionOrNotTheNamedConnectorIsRefused(string defect)
    {
        var fixture = new Fixture(SecretApplicationDimension.ArcScope);
        var reference = fixture.Broker.Store(SecretPartition.Personal(), "connector-key"u8);
        const string definition = "connector.calendar.v2";
        var human = fixture.Context(isForeground: true);
        fixture.Provider.Current = human;
        var good = human.ActorChain;
        DelegatedActor Actor(ActorKind kind, string identity) =>
            new(kind, Guid.NewGuid(), new InstanceId(Guid.NewGuid()), identity);
        ActorChain Chain(HumanPrincipal? owner = null, DeviceId? device = null, InstallationId? installation = null,
            SessionId? session = null, IEnumerable<DelegatedActor>? actors = null) =>
            new(owner ?? good.Owner, device ?? good.Device, installation ?? good.Installation,
                session ?? good.Session, good.CallerInstance, actors ?? []);

        var control = Chain(actors: [Actor(ActorKind.Extension, definition)]);
        var defective = defect switch
        {
            "session" => Chain(session: new SessionId(Guid.NewGuid()), actors: [Actor(ActorKind.Extension, definition)]),
            "device" => Chain(device: new DeviceId(Guid.NewGuid()), actors: [Actor(ActorKind.Extension, definition)]),
            "installation" => Chain(installation: new InstallationId(Guid.NewGuid()), actors: [Actor(ActorKind.Extension, definition)]),
            "owner" => Chain(owner: new HumanPrincipal(new RealmId(Realm), new UserId(Guid.NewGuid()),
                HumanIdentityKind.LocalHuman), actors: [Actor(ActorKind.Extension, definition)]),
            "agent-final-actor" => Chain(actors: [Actor(ActorKind.Agent, definition)]),
            "empty-chain" => Chain(),
            _ => Chain(actors: [Actor(ActorKind.Extension, "other.definition")]),
        };

        Assert.Throws<UnauthorizedAccessException>(() => fixture.Broker.GrantConnectorUse(reference, defective,
            definition, TimeSpan.FromMinutes(1)));
        // The same call with a well-formed target succeeds, so the refusal above is the named defect alone.
        Assert.NotNull(fixture.Broker.GrantConnectorUse(reference, control, definition, TimeSpan.FromMinutes(1)));
        Assert.Equal(0, fixture.Executor.InvocationCount);
    }

    [Fact]
    public void GrantRequiresAForegroundHumanAndAPositiveBoundedLifetime()
    {
        var fixture = new Fixture(SecretApplicationDimension.ArcScope);
        var reference = fixture.Broker.Store(SecretPartition.Personal(), "connector-key"u8);
        const string definition = "connector.calendar.v2";
        var background = fixture.Context(isForeground: false);
        var target = fixture.ConnectorContext(definition, background.Session).ActorChain;
        fixture.Provider.Current = background;

        Assert.Throws<UnauthorizedAccessException>(() => fixture.Broker.GrantConnectorUse(reference, target,
            definition, TimeSpan.FromMinutes(1)));

        var foreground = fixture.Context(isForeground: true, session: background.Session);
        fixture.Provider.Current = foreground;
        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.Broker.GrantConnectorUse(reference, target,
            definition, TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.Broker.GrantConnectorUse(reference, target,
            definition, TimeSpan.FromSeconds(-1)));
        Assert.NotNull(fixture.Broker.GrantConnectorUse(reference, target, definition, TimeSpan.FromTicks(1)));
    }

    [Fact]
    public void SecretValuesMustBeNonEmptyAndWithinTheCredentialStoreBound()
    {
        var fixture = new Fixture(SecretApplicationDimension.ArcScope);
        byte[] empty = [];
        byte[] atLimit = new byte[SecretBroker.MaximumSecretBytes];
        byte[] overLimit = new byte[SecretBroker.MaximumSecretBytes + 1];
        atLimit.AsSpan().Fill(7);

        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.Broker.Store(SecretPartition.Personal(), empty));
        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.Broker.Store(SecretPartition.Personal(), overLimit));
        var reference = fixture.Broker.Store(SecretPartition.Personal(), atLimit);
        Assert.Equal(SHA256.HashData(atLimit), fixture.UseDigest(reference));
    }

    [Fact]
    public void GrantExpiryFollowsTheMonotonicClockAndNotWallClockChanges()
    {
        var time = new TestTimeProvider(DateTimeOffset.Parse("2026-09-28T12:00:00Z", System.Globalization.CultureInfo.InvariantCulture));
        var fixture = new Fixture(SecretApplicationDimension.ArcScope, timeProvider: time);
        var reference = fixture.Broker.Store(SecretPartition.Personal(), "connector-key"u8);
        const string definition = "connector.calendar.v2";
        var grant = fixture.CreateConnectorGrant(reference, definition, TimeSpan.FromMinutes(1));

        time.ChangeWallClock(TimeSpan.FromHours(-2));
        fixture.Broker.UseConnectorGrant(grant, definition);
        time.ChangeWallClock(TimeSpan.FromHours(5));
        fixture.Broker.UseConnectorGrant(grant, definition);
        Assert.Equal(2, fixture.Executor.InvocationCount);

        time.Advance(TimeSpan.FromMinutes(1));
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Broker.UseConnectorGrant(grant, definition));
        Assert.Equal(2, fixture.Executor.InvocationCount);
    }

    [Fact]
    public void ExpiredGrantsAreEvictedWhenTheNextGrantIsIssued()
    {
        var time = new TestTimeProvider(DateTimeOffset.Parse("2026-09-28T12:00:00Z", System.Globalization.CultureInfo.InvariantCulture));
        var fixture = new Fixture(SecretApplicationDimension.ArcScope, timeProvider: time);
        var reference = fixture.Broker.Store(SecretPartition.Personal(), "connector-key"u8);
        const string definition = "connector.calendar.v2";
        _ = fixture.CreateConnectorGrant(reference, definition, TimeSpan.FromMinutes(1));
        time.Advance(TimeSpan.FromMinutes(2));
        fixture.Provider.Current = fixture.Context();
        _ = fixture.CreateConnectorGrant(reference, definition, TimeSpan.FromMinutes(1));

        // Only the fresh grant is still tracked; the expired one was evicted at issue time.
        Assert.Equal(1, fixture.Broker.RevokeAllConnectorGrants());
    }

    [Fact]
    public void WindowsStoreAcceptsOnlyCanonicalOpaqueTargetsBeforeAnyNativeCall()
    {
        var validate = typeof(WindowsCredentialManagerSecretStore).GetMethod("ValidateTarget",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        void Check(string? target) => validate.Invoke(null, [target]);
        string valid = "ArcForges.Secrets.v1." + new string('A', 64);

        Check(valid);
        Check("ArcForges.Secrets.v1." + string.Concat(Enumerable.Repeat("0123456789ABCDEF", 4)));
        foreach (string? bad in new string?[]
        {
            null, "", valid[..^1], valid + "A", "ArcForges.Secrets.v2." + new string('A', 64),
            "ArcForges.Secrets.v1." + new string('a', 64), "ArcForges.Secrets.v1." + new string('G', 64),
            "arcforges.secrets.v1." + new string('A', 64), " " + valid,
        })
        {
            var failure = Assert.Throws<System.Reflection.TargetInvocationException>(() => Check(bad));
            Assert.IsAssignableFrom<ArgumentException>(failure.InnerException);
        }
    }

    [Fact(Skip = "Explicit local Windows Credential Manager opt-in (ARCFORGES_LOCAL_OS_SECRET_STORE=1).", SkipUnless = nameof(LocalWindowsStoreEnabled))]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public void WindowsCredentialManagerRoundTripIsExplicitlyLocalOptIn()
    {
        string target = "ArcForges.Secrets.v1." + Convert.ToHexString(SHA256.HashData(RandomNumberGenerator.GetBytes(32)));
        var store = new WindowsCredentialManagerSecretStore();
        byte[] value = RandomNumberGenerator.GetBytes(32);
        try
        {
            store.Write(target, value);
            Assert.Equal(value, store.Read(target));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
            _ = store.Delete(target);
        }

        Assert.Null(store.Read(target));
    }

    [Fact(Skip = "Explicit local Windows Credential Manager opt-in (ARCFORGES_LOCAL_OS_SECRET_STORE=1).", SkipUnless = nameof(LocalWindowsStoreEnabled))]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public void WindowsCredentialManagerEntryIsVisibleToASameUserSiblingProcessSoItIsNotAnOsIsolationBoundary()
    {
        string target = "ArcForges.Secrets.v1." + Convert.ToHexString(SHA256.HashData(RandomNumberGenerator.GetBytes(32)));
        var store = new WindowsCredentialManagerSecretStore();
        byte[] value = RandomNumberGenerator.GetBytes(32);
        try
        {
            store.Write(target, value);
            // A different process of the same Windows user, with no ArcForges code, addresses the entry by name.
            string cmdkey = Path.Combine(Environment.SystemDirectory, "cmdkey.exe");
            using var sibling = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(cmdkey)
            {
                ArgumentList = { "/list:" + target },
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            })!;
            string output = sibling.StandardOutput.ReadToEnd();
            sibling.WaitForExit();
            Assert.Contains(target, output, StringComparison.Ordinal);
            Assert.Equal(SecretStoreIsolation.SameUserShared, store.Isolation);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
            _ = store.Delete(target);
        }
    }

    private sealed class Fixture
    {
        private readonly SecretInstallationBinding _installation;
        private readonly MemoryBackingStore _backing;
        private readonly Guid _realm;
        private readonly Guid _user;
        private readonly Guid _device;
        private readonly Guid _installationId;

        public Fixture(SecretApplicationDimension app, MemoryBackingStore? backing = null, TimeProvider? timeProvider = null,
            Guid? realm = null, Guid? user = null, Guid? device = null, Guid? installation = null)
        {
            _backing = backing ?? new MemoryBackingStore();
            _realm = realm ?? Realm;
            _user = user ?? User;
            _device = device ?? Device;
            _installationId = installation ?? Installation;
            _installation = new SecretInstallationBinding(app, new DeviceId(_device), new InstallationId(_installationId));
            Provider = new ContextProvider();
            Provider.Current = Context();
            Executor = new RecordingConnectorExecutor();
            Broker = new SecretBroker(_installation, Provider, _backing, Executor,
                SecretIsolationPolicy.AllowSameUserSharedStore, timeProvider);
        }

        public ContextProvider Provider { get; }
        public RecordingConnectorExecutor Executor { get; }
        public SecretBroker Broker { get; }
        public SecretHostContext Context(bool isSignedIn = true, bool isForeground = false, ulong recoveryGeneration = 1,
            SessionId? session = null, IEnumerable<DelegatedActor>? actors = null)
        {
            var currentSession = session ?? new SessionId(Guid.NewGuid());
            return new SecretHostContext(new ActorChain(
                    new HumanPrincipal(new RealmId(_realm), new UserId(_user), HumanIdentityKind.LocalHuman),
                    new DeviceId(_device), new InstallationId(_installationId), currentSession,
                    new InstanceId(Guid.NewGuid()), actors ?? []),
                _installation, currentSession, recoveryGeneration, isSignedIn, isForeground);
        }

        public byte[] UseDigest(SecretRef reference, string definition = "connector.test.v1")
        {
            var previous = Provider.Current;
            var grant = CreateConnectorGrant(reference, definition, TimeSpan.FromMinutes(1));
            try
            {
                Broker.UseConnectorGrant(grant, definition);
                return Executor.LastDigest?.ToArray() ?? throw new InvalidOperationException("Connector operation did not run.");
            }
            finally
            {
                _ = Broker.Revoke(grant);
                Provider.Current = previous;
            }
        }

        public ConnectorSecretGrant CreateConnectorGrant(SecretRef reference, string definition, TimeSpan lifetime)
        {
            var previous = Provider.Current;
            var grantor = new SecretHostContext(previous.ActorChain, previous.Installation, previous.Session,
                previous.RecoveryGeneration, previous.IsSignedIn, isForeground: true);
            var target = ConnectorContext(definition, previous.Session, previous.RecoveryGeneration);
            Provider.Current = grantor;
            try
            {
                var grant = Broker.GrantConnectorUse(reference, target.ActorChain, definition, lifetime);
                Provider.Current = target;
                return grant;
            }
            catch
            {
                Provider.Current = previous;
                throw;
            }
        }

        public SecretHostContext ConnectorContext(string definition, SessionId? session = null, ulong recoveryGeneration = 1) =>
            Context(isForeground: true, recoveryGeneration: recoveryGeneration, session: session, actors: [
                new DelegatedActor(ActorKind.Extension, Guid.NewGuid(), new InstanceId(Guid.NewGuid()), definition)]);
    }

    private sealed class ContextProvider : ISecretHostContextProvider
    {
        public SecretHostContext Current { get; set; } = null!;
        public SecretHostContext GetCurrent() => Current;
    }

    private sealed class MemoryBackingStore : ISecretBackingStore
    {
        private readonly Dictionary<string, byte[]> _secrets = new(StringComparer.Ordinal);

        public SecretStoreIsolation Isolation { get; set; } = SecretStoreIsolation.SameUserShared;

        public void Write(string opaqueTarget, ReadOnlySpan<byte> secret)
        {
            if (_secrets.Remove(opaqueTarget, out var old)) CryptographicOperations.ZeroMemory(old);
            _secrets.Add(opaqueTarget, secret.ToArray());
        }

        public byte[]? Read(string opaqueTarget) => _secrets.TryGetValue(opaqueTarget, out var value) ? value.ToArray() : null;

        public bool Delete(string opaqueTarget)
        {
            if (!_secrets.Remove(opaqueTarget, out var old)) return false;
            CryptographicOperations.ZeroMemory(old);
            return true;
        }
    }

    private sealed class RecordingConnectorExecutor : IConnectorSecretOperationExecutor
    {
        public int InvocationCount { get; private set; }
        public byte[]? LastDigest { get; private set; }

        public void Execute(string connectorDefinitionId, ReadOnlySpan<byte> secret)
        {
            Assert.False(string.IsNullOrWhiteSpace(connectorDefinitionId));
            InvocationCount++;
            LastDigest = SHA256.HashData(secret);
        }
    }

    private sealed class TestTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        private long _ticks;
        public override DateTimeOffset GetUtcNow() => _now;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _ticks;
        public void Advance(TimeSpan duration)
        {
            _now += duration;
            _ticks += duration.Ticks;
        }

        // A wall-clock change only: the monotonic timestamp does not move.
        public void ChangeWallClock(TimeSpan delta) => _now += delta;
    }

}
